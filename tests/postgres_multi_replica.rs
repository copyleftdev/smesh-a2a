#![cfg(all(unix, debug_assertions))]
#![allow(clippy::match_wild_err_arm, clippy::too_many_lines)]

//! Real-process PostgreSQL gateway evidence. Transport authentication is deliberately
//! replaced here by a test-only outer middleware which constructs the immutable
//! principal server-side and strips the selector before protocol parsing. Production
//! mTLS composition remains covered by `authorized_gateway_process` and `tls_integration`.

use std::io::{BufRead as _, BufReader, Write as _};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::str::FromStr as _;
use std::sync::{Arc, mpsc};
use std::time::Duration;

use smesh_a2a::auth::{Principal, PrincipalLimits};
use smesh_a2a::{
    AuthorityDiagnostics, AuthorityShutdown, AuthorizationMiddlewareState, AuthorizationPolicy,
    DurableLoopbackEndpoint, GatewayConfig, InjectedClock, IntoDurableAuthority, MeshEvent,
    PostgresStoreConfig, PostgresTaskStore, ReceiverAuthority, ReceiverLease, SystemClockTicker,
    build_durable_loopback_gateway,
};
use wait_timeout::ChildExt as _;

const WATCHDOG: Duration = Duration::from_secs(20);
const TEST_NAME: &str =
    "two_independent_postgres_gateway_processes_share_authority_and_survive_failover";

fn required(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(value) => Some(value),
        Err(_) if std::env::var("SMESH_POSTGRES_TEST_REQUIRED").as_deref() == Ok("1") => {
            panic!("{name} is required")
        }
        Err(_) => None,
    }
}

fn policy() -> Arc<AuthorizationPolicy> {
    Arc::new(AuthorizationPolicy::from_json(br#"{
      "schemaVersion":"smesh-authz-policy/v1","policyId":"multi-process-policy","revision":1,
      "tenants":[{"id":"tenant-process","enabled":true}],
      "accounts":[{"id":"agent-process","kind":"serviceAccount","memberships":[{"tenantId":"tenant-process","roles":["taskAgent"]}]}],
      "principalBindings":[{"principal":{"issuer":"test:server","subject":"agent-process"},"accountId":"agent-process"}]
    }"#).unwrap())
}

async fn inject_server_principal(
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    request
        .headers_mut()
        .remove(smesh_a2a::TENANT_SELECTOR_HEADER);
    request.extensions_mut().insert(Arc::new(
        Principal::bearer_for_verifier(
            "test:server".into(),
            "agent-process".into(),
            PrincipalLimits::default(),
        )
        .unwrap(),
    ));
    next.run(request).await
}

async fn child_main() {
    let admin = std::env::var("SMESH_TEST_POSTGRES_ADMIN_URL").unwrap();
    let runtime = std::env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap();
    let schema = std::env::var("SMESH_MULTI_PROCESS_SCHEMA").unwrap();
    let replica = std::env::var("SMESH_A2A_REPLICA_ID").unwrap();
    let config = PostgresStoreConfig::new(admin, runtime, schema)
        .unwrap()
        .with_test_only_insecure_loopback(true)
        .with_test_only_parent_managed_cleanup()
        .with_pool_size(2)
        .unwrap()
        .with_timeouts(Duration::from_secs(5), Duration::from_secs(5))
        .unwrap();
    let store = PostgresTaskStore::open(config).await.unwrap();
    let clock = InjectedClock::new(chrono::Utc::now().timestamp_millis());
    let authority = store.into_durable_authority();
    let barrier_started = Arc::new(tokio::sync::Notify::new());
    let barrier_release = Arc::new(tokio::sync::Notify::new());
    let completion_committed = Arc::new(tokio::sync::Notify::new());
    let publish_release = Arc::new(tokio::sync::Notify::new());
    let endpoint = if std::env::var("SMESH_TEST_BARRIER_MODE").as_deref() == Ok("race") {
        DurableLoopbackEndpoint::with_completion_race_barrier(
            Arc::clone(&barrier_started),
            Arc::clone(&barrier_release),
            Arc::clone(&completion_committed),
            Arc::clone(&publish_release),
        )
    } else {
        DurableLoopbackEndpoint::new()
    };
    let gateway = build_durable_loopback_gateway(
        GatewayConfig::new("http://127.0.0.1", format!("multi-{replica}")),
        Arc::clone(&authority),
        endpoint,
        clock.clone(),
    )
    .unwrap();
    let ticker = SystemClockTicker::spawn(clock.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    println!("READY {replica} {port} {}", std::process::id());
    std::io::stdout().flush().unwrap();
    let go = tokio::task::spawn_blocking(|| {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        line
    })
    .await
    .unwrap();
    assert_eq!(go.trim(), "GO");
    let authz = AuthorizationMiddlewareState::with_audit(policy(), authority, clock);
    let app = gateway
        .router()
        .layer(axum::middleware::from_fn_with_state(
            authz,
            smesh_a2a::authorize_request,
        ))
        .layer(axum::middleware::from_fn(inject_server_principal));
    if std::env::var("SMESH_TEST_BARRIER_MODE").as_deref() == Ok("race") {
        let label = replica.clone();
        let started = Arc::clone(&barrier_started);
        tokio::spawn(async move {
            started.notified().await;
            println!("CHECKPOINT {label} before-effect");
            std::io::stdout().flush().unwrap();
        });
        let label = replica.clone();
        let completed = Arc::clone(&completion_committed);
        tokio::spawn(async move {
            completed.notified().await;
            println!("CHECKPOINT {label} after-receiver-complete-before-delivery-commit");
            std::io::stdout().flush().unwrap();
        });
    }
    let shutdown = tokio_util::sync::CancellationToken::new();
    let server_shutdown = shutdown.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(server_shutdown.cancelled_owned())
            .await
            .unwrap();
    });
    println!("GO_ACK {replica}");
    std::io::stdout().flush().unwrap();
    let command_shutdown = shutdown.clone();
    tokio::task::spawn_blocking(move || {
        loop {
            let mut line = String::new();
            if std::io::stdin().read_line(&mut line).unwrap() == 0 {
                command_shutdown.cancel();
                break;
            }
            match line.trim() {
                "RELEASE_PRE" => {
                    barrier_release.notify_waiters();
                    println!("RELEASED pre");
                }
                "RELEASE_PUBLISH" => {
                    publish_release.notify_waiters();
                    println!("RELEASED publish");
                }
                "STOP" => {
                    command_shutdown.cancel();
                    break;
                }
                value => panic!("unknown child command: {value}"),
            }
            std::io::stdout().flush().unwrap();
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(WATCHDOG, server)
        .await
        .unwrap()
        .unwrap();
    ticker.shutdown().await.unwrap();
    gateway.shutdown().await.unwrap();
    println!("STOPPED {replica}");
}

struct Replica {
    child: Child,
    stdin: ChildStdin,
    lines: mpsc::Receiver<String>,
    reader: Option<std::thread::JoinHandle<()>>,
    port: u16,
}

impl Replica {
    fn spawn(
        replica: &str,
        schema: &str,
        admin: &str,
        runtime: &str,
        barrier_mode: Option<&str>,
        disable_driver: bool,
    ) -> Self {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(TEST_NAME)
            .arg("--nocapture")
            .env("SMESH_MULTI_PROCESS_CHILD", "1")
            .env("SMESH_MULTI_PROCESS_SCHEMA", schema)
            .env("SMESH_A2A_REPLICA_ID", replica)
            .env("SMESH_TEST_POSTGRES_ADMIN_URL", admin)
            .env("SMESH_TEST_POSTGRES_RUNTIME_URL", runtime)
            .env("SMESH_TEST_BARRIER_MODE", barrier_mode.unwrap_or("none"))
            .env(
                "SMESH_TEST_DISABLE_DRIVER",
                if disable_driver { "1" } else { "0" },
            )
            .env("SMESH_TEST_DRIVER_LEASE_MILLIS", "900")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if tx.send(line.unwrap()).is_err() {
                    break;
                }
            }
        });
        let ready = rx.recv_timeout(WATCHDOG).unwrap();
        let ready = if ready.starts_with("READY ") {
            ready
        } else {
            loop {
                let line = rx.recv_timeout(WATCHDOG).unwrap();
                if line.starts_with("READY ") {
                    break line;
                }
            }
        };
        let fields: Vec<_> = ready.split_whitespace().collect();
        assert_eq!(fields[1], replica);
        let port = fields[2].parse().unwrap();
        assert_ne!(fields[3].parse::<u32>().unwrap(), std::process::id());
        Self {
            child,
            stdin,
            lines: rx,
            reader: Some(reader),
            port,
        }
    }

    fn send(&mut self, value: &str) {
        writeln!(self.stdin, "{value}").unwrap();
        self.stdin.flush().unwrap();
    }

    fn wait_checkpoint(&self, checkpoint: &str) {
        loop {
            let line = self.lines.recv_timeout(WATCHDOG).unwrap();
            if line.starts_with(checkpoint) {
                break;
            }
        }
    }

    fn command(&mut self, value: &str, checkpoint: &str) {
        self.send(value);
        self.wait_checkpoint(checkpoint);
    }

    fn kill_and_reap(&mut self) {
        let _ = self.child.kill();
        let _ = self
            .child
            .wait_timeout(WATCHDOG)
            .unwrap()
            .unwrap_or_else(|| {
                let _ = self.child.kill();
                self.child.wait().unwrap()
            });
        if let Some(reader) = self.reader.take() {
            reader.join().unwrap();
        }
    }
}

impl Drop for Replica {
    fn drop(&mut self) {
        self.kill_and_reap();
    }
}

struct SchemaPrivilegeGuard {
    superuser_url: String,
    schema: String,
    armed: bool,
}

impl Drop for SchemaPrivilegeGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let url = self.superuser_url.clone();
        let schema = self.schema.clone();
        let _ = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let config = tokio_postgres::Config::from_str(&url).unwrap();
                if let Ok((client, connection)) = config.connect(tokio_postgres::NoTls).await {
                    let driver = tokio::spawn(async move {
                        let _ = connection.await;
                    });
                    let _ = client
                        .batch_execute(&format!(
                            "GRANT USAGE ON SCHEMA {schema} TO {schema}_runtime"
                        ))
                        .await;
                    driver.abort();
                }
            });
        })
        .join();
    }
}

struct SchemaCleanupGuard(Option<PostgresStoreConfig>);

impl Drop for SchemaCleanupGuard {
    fn drop(&mut self) {
        let Some(config) = self.0.take() else { return };
        let _ = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let _ = PostgresTaskStore::drop_test_schema(&config).await;
            });
        })
        .join();
    }
}

async fn json(request: reqwest::RequestBuilder) -> serde_json::Value {
    let response = tokio::time::timeout(WATCHDOG, request.send())
        .await
        .unwrap()
        .unwrap();
    let status = response.status();
    let body = response.bytes().await.unwrap();
    assert!(
        status.is_success(),
        "{status}: {}",
        String::from_utf8_lossy(&body)
    );
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn two_independent_postgres_gateway_processes_share_authority_and_survive_failover() {
    if std::env::var("SMESH_MULTI_PROCESS_CHILD").as_deref() == Ok("1") {
        child_main().await;
        return;
    }
    let Some(admin) = required("SMESH_TEST_POSTGRES_ADMIN_URL") else {
        return;
    };
    let Some(runtime_base) = required("SMESH_TEST_POSTGRES_RUNTIME_URL") else {
        return;
    };
    let Some(superuser) = required("SMESH_TEST_POSTGRES_SUPERUSER_URL") else {
        return;
    };
    let schema = format!("smesh_multi_{:016x}", rand::random::<u64>());
    let mut runtime_url = url::Url::parse(&runtime_base).unwrap();
    runtime_url
        .query_pairs_mut()
        .append_pair("application_name", &schema);
    let runtime = runtime_url.to_string();
    let cleanup = PostgresStoreConfig::new(&admin, &runtime, &schema)
        .unwrap()
        .with_test_only_insecure_loopback(true)
        .with_test_only_parent_managed_cleanup();
    let bootstrap = PostgresTaskStore::open(cleanup.clone()).await.unwrap();
    bootstrap.shutdown().await.unwrap();
    let mut schema_cleanup = SchemaCleanupGuard(Some(cleanup.clone()));

    let mut a = Replica::spawn("replica-a", &schema, &admin, &runtime, None, false);
    let mut b = Replica::spawn("replica-b", &schema, &admin, &runtime, None, false);
    assert_ne!(a.child.id(), b.child.id());
    assert_ne!(a.port, b.port);
    a.command("GO", "GO_ACK replica-a");
    b.command("GO", "GO_ACK replica-b");
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(2))
        .timeout(WATCHDOG)
        .build()
        .unwrap();
    let base_a = format!("http://127.0.0.1:{}", a.port);
    let base_b = format!("http://127.0.0.1:{}", b.port);
    let send_body = serde_json::json!({
        "jsonrpc":"2.0","id":"send","method":a2a::jsonrpc::methods::SEND_MESSAGE,
        "params":{"message":{"messageId":"multi-process-message","role":"ROLE_USER","parts":[{"text":"independent process work"}]},"configuration":{"returnImmediately":false}}
    });
    let sent = json(client.post(format!("{base_a}/jsonrpc")).json(&send_body)).await;
    let task_id = sent["result"]["task"]["id"]
        .as_str()
        .or_else(|| sent["result"]["id"].as_str())
        .unwrap_or_else(|| panic!("unexpected send response: {sent}"))
        .to_owned();
    let through_b = json(client.get(format!("{base_b}/rest/tasks/{task_id}"))).await;
    assert_eq!(through_b["id"], task_id);
    let listed = json(client.get(format!("{base_b}/rest/tasks"))).await;
    assert_eq!(listed["totalSize"], 1);

    a.command("STOP", "STOPPED replica-a");
    a.kill_and_reap();
    let returned = Replica::spawn("replica-a-returned", &schema, &admin, &runtime, None, false);
    a = returned;
    a.command("GO", "GO_ACK replica-a-returned");
    let returned_base = format!("http://127.0.0.1:{}", a.port);
    let replay = json(
        client
            .post(format!("{returned_base}/jsonrpc"))
            .json(&send_body),
    )
    .await;
    let replay_id = replay["result"]["task"]["id"]
        .as_str()
        .or_else(|| replay["result"]["id"].as_str())
        .unwrap_or_else(|| panic!("unexpected replay response: {replay}"));
    assert_eq!(replay_id, task_id);
    let after_restart =
        json(client.get(format!("http://127.0.0.1:{}/rest/tasks/{task_id}", a.port))).await;
    assert_eq!(after_restart["id"], task_id);
    b.command("STOP", "STOPPED replica-b");
    b.kill_and_reap();
    let other_still_usable =
        json(client.get(format!("http://127.0.0.1:{}/rest/tasks/{task_id}", a.port))).await;
    assert_eq!(other_still_usable["id"], task_id);
    a.command("STOP", "STOPPED replica-a-returned");
    a.kill_and_reap();

    // A transport-only subscriber process has no claimant; an independent winner
    // holds both receiver and outbox barriers while database-time renewals cross
    // the original expiry. A crash after receiver completion is reconciled by a
    // third independently opened process while the original SSE stream stays on A.
    let mut subscriber = Replica::spawn("subscriber-a", &schema, &admin, &runtime, None, true);
    let mut winner = Replica::spawn("winner-b", &schema, &admin, &runtime, Some("race"), false);
    subscriber.command("GO", "GO_ACK subscriber-a");
    winner.command("GO", "GO_ACK winner-b");
    let subscriber_base = format!("http://127.0.0.1:{}", subscriber.port);
    let barrier_send = serde_json::json!({
        "jsonrpc":"2.0","id":"barrier-send","method":a2a::jsonrpc::methods::SEND_MESSAGE,
        "params":{"message":{"messageId":"multi-process-barrier-message","role":"ROLE_USER","parts":[{"text":"barrier failover work"}]},"configuration":{"returnImmediately":true}}
    });
    let admitted = json(
        client
            .post(format!("{subscriber_base}/jsonrpc"))
            .json(&barrier_send),
    )
    .await;
    let barrier_task = admitted["result"]["task"]["id"]
        .as_str()
        .or_else(|| admitted["result"]["id"].as_str())
        .unwrap_or_else(|| panic!("unexpected barrier admission: {admitted}"))
        .to_owned();
    let sse_client = client.clone();
    let sse_url = format!("{subscriber_base}/rest/tasks/{barrier_task}:subscribe");
    let sse_reader = tokio::spawn(async move {
        let response = sse_client.get(sse_url).send().await.unwrap();
        assert!(response.status().is_success());
        response.text().await.unwrap()
    });
    winner.wait_checkpoint("CHECKPOINT winner-b before-effect");
    let mut competitor = Replica::spawn("competitor-c", &schema, &admin, &runtime, None, false);
    competitor.command("GO", "GO_ACK competitor-c");

    let pg = tokio_postgres::Config::from_str(&superuser).unwrap();
    let (super_client, connection) = pg.connect(tokio_postgres::NoTls).await.unwrap();
    let connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let receiver_sql = format!(
        "SELECT task_id,dispatch_id,payload_digest,sender_attempt_no,sender_lease_token,lease_owner,lease_token,lease_epoch,lease_until FROM {schema}.receiver_inbox WHERE tenant_scope='tenant-process' AND state='processing'"
    );
    let row = super_client.query_one(&receiver_sql, &[]).await.unwrap();
    let stale_receiver = ReceiverLease {
        tenant_scope: "tenant-process".into(),
        task_id: row.get(0),
        dispatch_id: row.get(1),
        payload_digest: row.get(2),
        sender_attempt_no: u32::try_from(row.get::<_, i64>(3)).unwrap(),
        sender_lease_token: row.get(4),
        lease_owner: row.get(5),
        lease_token: row.get(6),
        lease_epoch: u64::try_from(row.get::<_, i64>(7)).unwrap(),
        lease_until: row.get(8),
        execution_reservation: None,
    };
    assert!(
        stale_receiver
            .lease_owner
            .starts_with("winner-b#boot-sha256:"),
        "receiver lease must remain owned by the winner beyond original expiry"
    );
    tokio::time::timeout(WATCHDOG, async {
        loop {
            let row = super_client.query_one(
                &format!("SELECT lease_until,{schema}.db_millis() FROM {schema}.receiver_inbox WHERE tenant_scope='tenant-process' AND dispatch_id=$1"),
                &[&stale_receiver.dispatch_id],
            ).await.unwrap();
            let current: i64 = row.get(0);
            let database_now: i64 = row.get(1);
            if database_now > stale_receiver.lease_until && current > database_now { break; }
        }
    }).await.expect("receiver renewal must cross original lease expiry");
    let outbox_owner: String = super_client.query_one(
        &format!("SELECT lease_owner FROM {schema}.outbox WHERE tenant_scope='tenant-process' AND dispatch_id=$1"),
        &[&stale_receiver.dispatch_id],
    ).await.unwrap().get(0);
    assert!(
        outbox_owner.starts_with("winner-b#boot-sha256:"),
        "another replica cannot steal an actively renewed dispatch"
    );

    winner.command("RELEASE_PRE", "RELEASED pre");
    winner.wait_checkpoint("CHECKPOINT winner-b after-receiver-complete-before-delivery-commit");
    winner.kill_and_reap();
    let mut recovery = Replica::spawn("recovery-c", &schema, &admin, &runtime, None, false);
    recovery.command("GO", "GO_ACK recovery-c");
    let sse = tokio::time::timeout(WATCHDOG, sse_reader)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        sse.matches("TASK_STATE_COMPLETED").count(),
        1,
        "durable SSE closes with one terminal frame: {sse}"
    );
    let terminal = json(client.get(format!("{subscriber_base}/rest/tasks/{barrier_task}"))).await;
    assert_eq!(terminal["status"]["state"], "TASK_STATE_COMPLETED");

    let probe = PostgresTaskStore::open(cleanup.clone().with_test_only_parent_managed_cleanup())
        .await
        .unwrap();
    assert_eq!(
        probe.durable_effect_count().await.unwrap(),
        2,
        "one effect per distinct dispatch across both scenarios"
    );
    assert!(
        probe
            .complete_loopback_receive(
                &stale_receiver,
                &[MeshEvent::Completed {
                    summary: "stale completion".into()
                }],
                chrono::Utc::now().timestamp_millis(),
            )
            .await
            .is_err(),
        "stale first-process receiver fence must be rejected"
    );
    probe.shutdown().await.unwrap();
    subscriber.command("STOP", "STOPPED subscriber-a");
    subscriber.kill_and_reap();
    recovery.command("STOP", "STOPPED recovery-c");
    recovery.kill_and_reap();
    competitor.command("STOP", "STOPPED competitor-c");
    competitor.kill_and_reap();

    // Graceful shutdown after at least one applied sender renewal must join the
    // renewal owner and requeue with its latest fence, not the original expiry.
    let mut shutdown_subscriber =
        Replica::spawn("shutdown-subscriber", &schema, &admin, &runtime, None, true);
    let mut shutdown_winner = Replica::spawn(
        "shutdown-winner",
        &schema,
        &admin,
        &runtime,
        Some("race"),
        false,
    );
    shutdown_subscriber.command("GO", "GO_ACK shutdown-subscriber");
    shutdown_winner.command("GO", "GO_ACK shutdown-winner");
    let shutdown_send = serde_json::json!({
        "jsonrpc":"2.0","id":"shutdown-send","method":a2a::jsonrpc::methods::SEND_MESSAGE,
        "params":{"message":{"messageId":"multi-process-shutdown-message","role":"ROLE_USER","parts":[{"text":"graceful renewed shutdown"}]},"configuration":{"returnImmediately":true}}
    });
    let shutdown_admitted = json(
        client
            .post(format!(
                "http://127.0.0.1:{}/jsonrpc",
                shutdown_subscriber.port
            ))
            .json(&shutdown_send),
    )
    .await;
    let shutdown_task = shutdown_admitted["result"]["task"]["id"]
        .as_str()
        .or_else(|| shutdown_admitted["result"]["id"].as_str())
        .unwrap()
        .to_owned();
    shutdown_winner.wait_checkpoint("CHECKPOINT shutdown-winner before-effect");
    let shutdown_row = super_client.query_one(
        &format!("SELECT dispatch_id,lease_until FROM {schema}.outbox WHERE tenant_scope='tenant-process' AND task_id=$1"),
        &[&shutdown_task],
    ).await.unwrap();
    let shutdown_dispatch: String = shutdown_row.get(0);
    let original_shutdown_until: i64 = shutdown_row.get(1);
    tokio::time::timeout(WATCHDOG, async {
        loop {
            let row = super_client.query_one(
                &format!("SELECT lease_until,{schema}.db_millis() FROM {schema}.outbox WHERE tenant_scope='tenant-process' AND dispatch_id=$1"),
                &[&shutdown_dispatch],
            ).await.unwrap();
            let current: i64 = row.get(0);
            let database_now: i64 = row.get(1);
            if database_now > original_shutdown_until && current > database_now { break; }
        }
    }).await.expect("shutdown sender renewal must cross original expiry");
    shutdown_winner.command("STOP", "STOPPED shutdown-winner");
    shutdown_winner.kill_and_reap();
    let requeued = super_client.query_one(
        &format!("SELECT state,lease_owner,lease_token,lease_until,available_at<={schema}.db_millis() FROM {schema}.outbox WHERE tenant_scope='tenant-process' AND dispatch_id=$1"),
        &[&shutdown_dispatch],
    ).await.unwrap();
    assert_eq!(requeued.get::<_, String>(0), "pending");
    assert_eq!(requeued.get::<_, Option<String>>(1), None);
    assert_eq!(requeued.get::<_, Option<String>>(2), None);
    assert_eq!(requeued.get::<_, Option<i64>>(3), None);
    assert!(requeued.get::<_, bool>(4));
    let mut shutdown_recovery =
        Replica::spawn("shutdown-recovery", &schema, &admin, &runtime, None, false);
    shutdown_recovery.command("GO", "GO_ACK shutdown-recovery");
    let shutdown_replay = json(
        client
            .post(format!(
                "http://127.0.0.1:{}/jsonrpc",
                shutdown_recovery.port
            ))
            .json(&shutdown_send),
    )
    .await;
    assert_eq!(
        shutdown_replay["result"]["task"]["id"]
            .as_str()
            .or_else(|| shutdown_replay["result"]["id"].as_str()),
        Some(shutdown_task.as_str())
    );
    tokio::time::timeout(WATCHDOG, async {
        loop {
            let task = json(client.get(format!(
                "http://127.0.0.1:{}/rest/tasks/{shutdown_task}",
                shutdown_recovery.port
            )))
            .await;
            if task["status"]["state"] == "TASK_STATE_COMPLETED" {
                break;
            }
        }
    })
    .await
    .expect("shutdown recovery must finish before the outage scenario");
    shutdown_subscriber.command("STOP", "STOPPED shutdown-subscriber");
    shutdown_subscriber.kill_and_reap();
    shutdown_recovery.command("STOP", "STOPPED shutdown-recovery");
    shutdown_recovery.kill_and_reap();

    // Renewal outage is fatal and cannot commit through a lost fence. Recovery
    // is deliberately process-restart based, not an in-process unfenced retry.
    let mut outage_winner = Replica::spawn(
        "outage-winner",
        &schema,
        &admin,
        &runtime,
        Some("race"),
        false,
    );
    outage_winner.command("GO", "GO_ACK outage-winner");
    let outage_base = format!("http://127.0.0.1:{}", outage_winner.port);
    let outage_send = serde_json::json!({
        "jsonrpc":"2.0","id":"outage-send","method":a2a::jsonrpc::methods::SEND_MESSAGE,
        "params":{"message":{"messageId":"multi-process-outage-message","role":"ROLE_USER","parts":[{"text":"renewal outage work"}]},"configuration":{"returnImmediately":true}}
    });
    let outage_admitted = json(
        client
            .post(format!("{outage_base}/jsonrpc"))
            .json(&outage_send),
    )
    .await;
    let outage_task = outage_admitted["result"]["task"]["id"]
        .as_str()
        .or_else(|| outage_admitted["result"]["id"].as_str())
        .unwrap_or_else(|| panic!("unexpected outage admission: {outage_admitted}"))
        .to_owned();
    outage_winner.wait_checkpoint("CHECKPOINT outage-winner before-effect");
    let outage_row = super_client.query_one(
        &format!("SELECT r.dispatch_id,r.lease_until FROM {schema}.receiver_inbox r JOIN {schema}.outbox o USING(tenant_scope,dispatch_id) WHERE r.tenant_scope='tenant-process' AND r.task_id=$1 AND r.state='processing'"),
        &[&outage_task],
    ).await.unwrap();
    let outage_dispatch: String = outage_row.get(0);
    let outage_until: i64 = outage_row.get(1);
    let mut privilege_guard = SchemaPrivilegeGuard {
        superuser_url: superuser.clone(),
        schema: schema.clone(),
        armed: true,
    };
    super_client
        .batch_execute(&format!(
            "REVOKE USAGE ON SCHEMA {schema} FROM {schema}_runtime"
        ))
        .await
        .unwrap();
    super_client
        .query(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name=$1 AND pid<>pg_backend_pid()",
            &[&schema],
        )
        .await
        .unwrap();
    tokio::time::timeout(WATCHDOG, async {
        loop {
            let now: i64 = super_client
                .query_one(&format!("SELECT {schema}.db_millis()"), &[])
                .await
                .unwrap()
                .get(0);
            if now > outage_until + 500 {
                break;
            }
        }
    })
    .await
    .expect("database-time outage expiry watchdog");
    super_client
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA {schema} TO {schema}_runtime"
        ))
        .await
        .unwrap();
    privilege_guard.armed = false;
    outage_winner.command("RELEASE_PRE", "RELEASED pre");
    let outage_effects: i64 = super_client.query_one(
        &format!("SELECT count(*) FROM {schema}.loopback_effects WHERE tenant_scope='tenant-process' AND dispatch_id=$1"),
        &[&outage_dispatch],
    ).await.unwrap().get(0);
    assert_eq!(
        outage_effects, 0,
        "renewal outage cannot produce an unfenced effect"
    );
    let fatal = tokio::time::timeout(
        WATCHDOG,
        client
            .post(format!("{outage_base}/jsonrpc"))
            .json(&outage_send)
            .send(),
    )
    .await
    .unwrap();
    match fatal {
        Err(_) => {}
        Ok(response) if response.status().is_server_error() => {}
        Ok(response) => {
            let body: serde_json::Value = response.json().await.unwrap();
            assert!(
                body.get("error").is_some(),
                "outage must publish bounded failure: {body}"
            );
        }
    }
    let state: String = super_client.query_one(
        &format!("SELECT state FROM {schema}.outbox WHERE tenant_scope='tenant-process' AND dispatch_id=$1"),
        &[&outage_dispatch],
    ).await.unwrap().get(0);
    assert_eq!(
        state, "leased",
        "fatal process cannot commit or dead-letter after access returns"
    );
    outage_winner.kill_and_reap();
    let mut outage_recovery =
        Replica::spawn("outage-recovery", &schema, &admin, &runtime, None, false);
    outage_recovery.command("GO", "GO_ACK outage-recovery");
    let outage_replay = json(
        client
            .post(format!("http://127.0.0.1:{}/jsonrpc", outage_recovery.port))
            .json(&outage_send),
    )
    .await;
    let outage_replay_task = outage_replay["result"]["task"]["id"]
        .as_str()
        .or_else(|| outage_replay["result"]["id"].as_str())
        .unwrap_or_else(|| panic!("unexpected outage replay response: {outage_replay}"));
    assert_eq!(outage_replay_task, outage_task);
    let outage_terminal = tokio::time::timeout(WATCHDOG, async {
        loop {
            let task = json(client.get(format!(
                "http://127.0.0.1:{}/rest/tasks/{outage_task}",
                outage_recovery.port
            )))
            .await;
            if task["status"]["state"] == "TASK_STATE_COMPLETED" {
                break task;
            }
        }
    })
    .await
    .expect("outage restart reconciliation watchdog");
    assert_eq!(outage_terminal["status"]["state"], "TASK_STATE_COMPLETED");
    let outage_effects: i64 = super_client.query_one(
        &format!("SELECT count(*) FROM {schema}.loopback_effects WHERE tenant_scope='tenant-process' AND dispatch_id=$1"),
        &[&outage_dispatch],
    ).await.unwrap().get(0);
    assert_eq!(outage_effects, 1);
    outage_recovery.command("STOP", "STOPPED outage-recovery");
    outage_recovery.kill_and_reap();
    drop(super_client);
    connection.abort();
    PostgresTaskStore::drop_test_schema(&cleanup).await.unwrap();
    schema_cleanup.0 = None;
}

#[test]
fn multiprocess_fixture_panic_reaps_children_and_restores_postgres() {
    const PANIC_CHILD: &str = "SMESH_MULTI_PANIC_GUARD_CHILD";
    if std::env::var(PANIC_CHILD).as_deref() == Ok("1") {
        let admin = std::env::var("SMESH_TEST_POSTGRES_ADMIN_URL").unwrap();
        let runtime_base = std::env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap();
        let schema = std::env::var("SMESH_MULTI_PANIC_SCHEMA").unwrap();
        let mut runtime_url = url::Url::parse(&runtime_base).unwrap();
        runtime_url
            .query_pairs_mut()
            .append_pair("application_name", &schema);
        let runtime = runtime_url.to_string();
        let async_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        async_runtime.block_on(async {
            let config = PostgresStoreConfig::new(&admin, &runtime, &schema)
                .unwrap()
                .with_test_only_insecure_loopback(true)
                .with_test_only_parent_managed_cleanup();
            let store = PostgresTaskStore::open(config.clone()).await.unwrap();
            store.shutdown().await.unwrap();
            let _cleanup = SchemaCleanupGuard(Some(config));
            let mut replica = Replica::spawn(
                "panic-cleanup-replica",
                &schema,
                &admin,
                &runtime,
                None,
                false,
            );
            replica.command("GO", "GO_ACK panic-cleanup-replica");
            panic!("intentional multi-process fixture unwind probe");
        });
        return;
    }
    let Some(admin) = required("SMESH_TEST_POSTGRES_ADMIN_URL") else {
        return;
    };
    let Some(runtime) = required("SMESH_TEST_POSTGRES_RUNTIME_URL") else {
        return;
    };
    let Some(superuser) = required("SMESH_TEST_POSTGRES_SUPERUSER_URL") else {
        return;
    };
    let schema = format!("smesh_multi_{:016x}", rand::random::<u64>());
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "multiprocess_fixture_panic_reaps_children_and_restores_postgres",
            "--nocapture",
        ])
        .env(PANIC_CHILD, "1")
        .env("SMESH_MULTI_PANIC_SCHEMA", &schema)
        .env("SMESH_TEST_POSTGRES_ADMIN_URL", admin)
        .env("SMESH_TEST_POSTGRES_RUNTIME_URL", runtime)
        .env("SMESH_TEST_POSTGRES_SUPERUSER_URL", &superuser)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let status = child.wait_timeout(WATCHDOG).unwrap().unwrap_or_else(|| {
        let _ = child.kill();
        child.wait().unwrap()
    });
    assert!(!status.success());
    let async_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    async_runtime.block_on(async {
        let pg = tokio_postgres::Config::from_str(&superuser).unwrap();
        let (client, connection) = pg.connect(tokio_postgres::NoTls).await.unwrap();
        let driver = tokio::spawn(async move { let _ = connection.await; });
        let row = client.query_one(
            "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=$1),EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$2),(SELECT count(*) FROM pg_stat_activity WHERE application_name=$1),has_database_privilege('smesh_test_runtime',current_database(),'CONNECT')",
            &[&schema, &format!("{schema}_runtime")],
        ).await.unwrap();
        assert!(!row.get::<_, bool>(0));
        assert!(!row.get::<_, bool>(1));
        assert_eq!(row.get::<_, i64>(2), 0);
        assert!(row.get::<_, bool>(3));
        drop(client);
        driver.abort();
    });
}
