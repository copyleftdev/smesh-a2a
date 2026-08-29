#![cfg(all(unix, debug_assertions))]

use std::fmt::Write as _;
use std::io::{BufRead as _, BufReader};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr as _;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::StreamExt as _;
use smesh_a2a::{
    AuthorityShutdown, AuthorizationAuditInput, AuthorizationDecisionEffect, AuthorizedMutation,
    OwnedTaskScope, PostgresStoreConfig, PostgresTaskStore, QuotaPolicy, QuotaSubject,
    SendMessageAdmission, TaskAdmission, VisibilityScope, content_digest,
};
use wait_timeout::ChildExt as _;

const WATCHDOG: Duration = Duration::from_secs(15);
const TENANT_A: &str = "tenant-a";
const TENANT_B: &str = "tenant-b";
const ACCOUNT: &str = "agent-17";
const PRINCIPAL_ISSUER: &str = "mtls:test";
const PRINCIPAL_SUBJECT: &str = "agent-17";
const STREAM_MESSAGE: &str = "quota-process-stream";
const OUTPUT_OVER_MESSAGE: &str = "quota-process-output-over";
const OUTPUT_OVER_TEXT: &str = "exceed production output budget";

fn required_url(name: &str) -> String {
    match std::env::var(name) {
        Ok(value) => value,
        Err(error) => {
            panic!("{name} is required once the PostgreSQL process fixture is selected: {error}")
        }
    }
}

fn process_admin_url() -> Option<String> {
    match std::env::var("SMESH_TEST_POSTGRES_ADMIN_URL") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent)
            if std::env::var("SMESH_POSTGRES_TEST_REQUIRED").as_deref() == Ok("1") =>
        {
            panic!("SMESH_TEST_POSTGRES_ADMIN_URL is required")
        }
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => panic!("SMESH_TEST_POSTGRES_ADMIN_URL is invalid: {error}"),
    }
}

async fn postgres_db_millis(admin: &str) -> i64 {
    let (client, driver) = admin_client(admin).await;
    let now = client
        .query_one(
            "SELECT floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .expect("read PostgreSQL database time")
        .get(0);
    drop(client);
    driver.abort();
    now
}

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "smesh-quota-process-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        std::fs::create_dir(&root).expect("create process fixture");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("protect process fixture");
        Self { root }
    }

    fn write_files(&self, now: i64) -> (PathBuf, PathBuf, Arc<QuotaPolicy>) {
        let tls = self.root.join("tls");
        std::fs::create_dir(&tls).expect("create TLS fixture");
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls");
        for name in [
            "server.pem",
            "server.key",
            "server-ca.pem",
            "client-ca.pem",
            "client.pem",
            "client.key",
            "principals.json",
        ] {
            std::fs::copy(source.join(name), tls.join(name)).expect("copy TLS fixture");
        }
        for name in ["server.key", "client.key"] {
            std::fs::set_permissions(tls.join(name), std::fs::Permissions::from_mode(0o600))
                .expect("protect test key");
        }
        let authz = self.root.join("authorization.json");
        std::fs::write(
            &authz,
            br#"{
              "schemaVersion":"smesh-authz-policy/v1","policyId":"quota-process-authz","revision":14,
              "tenants":[{"id":"tenant-a","enabled":true},{"id":"tenant-b","enabled":true}],
              "accounts":[{"id":"agent-17","kind":"serviceAccount","memberships":[
                {"tenantId":"tenant-a","roles":["taskAgent"]},
                {"tenantId":"tenant-b","roles":["taskAgent"]}
              ]}],
              "principalBindings":[{"principal":{"issuer":"mtls:test","subject":"agent-17"},"accountId":"agent-17"}]
            }"#,
        )
        .expect("write authorization policy");
        let quota = self.root.join("quota.json");
        let over_admission = seeded_admission(OUTPUT_OVER_MESSAGE, OUTPUT_OVER_TEXT, false);
        let over_events = production_output_events(&over_admission);
        let output_limit = measured_output_bytes(&over_events)
            .checked_sub(1)
            .expect("nonempty output");
        let event_limit = u64::try_from(over_events.len() - 1).expect("event limit");
        let mut overrides = vec![serde_json::json!({
            "overrideId":"process-task-get-incident","actor":"operator-primary","reason":"ticket-14-process",
            "scopeKind":"principal","scopeId":principal_scope(),"operation":"taskGet","dimension":"requestCount",
            "oldLimit":20,"newLimit":1,"effectiveAt":now-60_000,"expiresAt":now+10_000
        })];
        for (scope_kind, scope_id) in [
            ("tenant", TENANT_A.to_owned()),
            ("tenant", TENANT_B.to_owned()),
            ("account", ACCOUNT.to_owned()),
            ("principal", principal_scope()),
        ] {
            for (dimension, old_limit, new_limit) in [
                ("outputBytes", output_limit, 67_108_864_u64),
                ("eventCount", event_limit, 65_536_u64),
            ] {
                overrides.push(serde_json::json!({
                    "overrideId":format!("process-egress-{scope_kind}-{scope_id}-{dimension}"),
                    "actor":"operator-primary","reason":"ticket-14-process-egress",
                    "scopeKind":scope_kind,"scopeId":scope_id,"operation":"publicEgress","dimension":dimension,
                    "oldLimit":old_limit,"newLimit":new_limit,"effectiveAt":now-60_000,"expiresAt":now+60_000
                }));
            }
        }
        let document = serde_json::json!({
          "schemaVersion":"smesh-quota-policy/v1","policyId":"quota-process-policy","revision":14,
          "requestWindowMillis":3_600_000,"reconnectWindowMillis":3_600_000,
          "limits":{
            "requestCount":{"tenant":20,"account":20,"principal":20},
            "concurrentActiveWork":{"tenant":8,"account":8,"principal":8},
            "inputBytes":{"tenant":16_777_216,"account":16_777_216,"principal":16_777_216},
            "outputBytes":{"tenant":output_limit,"account":output_limit,"principal":output_limit},
            "eventCount":{"tenant":event_limit,"account":event_limit,"principal":event_limit},
            "concurrentStreams":{"tenant":1,"account":1,"principal":1},
            "concurrentSubscriptions":{"tenant":1,"account":1,"principal":1},
            "reconnectCount":{"tenant":2,"account":2,"principal":2},
            "retainedAuthorityBytes":{"tenant":1_048_576,"account":1_048_576,"principal":1_048_576}
          },
          "overrides":overrides
        });
        let bytes = serde_json::to_vec(&document).expect("serialize quota policy");
        std::fs::write(&quota, &bytes).expect("write quota policy");
        let policy = Arc::new(QuotaPolicy::from_json(&bytes).expect("parse quota policy"));
        (tls, quota, policy)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

struct SchemaGuard {
    config: Option<PostgresStoreConfig>,
}

impl SchemaGuard {
    fn new(config: PostgresStoreConfig) -> Self {
        Self {
            config: Some(config),
        }
    }

    async fn cleanup(mut self) {
        let config = self.config.take().expect("schema cleanup config");
        tokio::time::timeout(WATCHDOG, PostgresTaskStore::drop_test_schema(&config))
            .await
            .expect("schema cleanup watchdog")
            .expect("drop test schema");
    }
}

impl Drop for SchemaGuard {
    fn drop(&mut self) {
        let Some(config) = self.config.take() else {
            return;
        };
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .and_then(|runtime| {
                    runtime
                        .block_on(PostgresTaskStore::drop_test_schema(&config))
                        .map_err(std::io::Error::other)
                });
            let _ = done_tx.send(result);
        });
        // Drop runs while a test panic may already be unwinding. Cleanup remains
        // watchdog-bounded, but must not double-panic and abort the entire test process.
        let _ = done_rx.recv_timeout(WATCHDOG);
    }
}

struct GatewayProcess {
    child: Option<Child>,
    logs: Arc<Mutex<String>>,
    reader: Option<std::thread::JoinHandle<()>>,
    reader_done: mpsc::Receiver<()>,
}

impl GatewayProcess {
    fn pid(&self) -> u32 {
        self.child.as_ref().expect("live child").id()
    }

    fn kill_and_reap(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.kill();
        if child.wait_timeout(WATCHDOG).expect("child wait").is_none() {
            let _ = child.kill();
            let _ = child.wait();
            panic!("gateway shutdown watchdog");
        }
        self.reader_done
            .recv_timeout(WATCHDOG)
            .expect("stderr completion watchdog");
        if let Some(reader) = self.reader.take() {
            reader.join().expect("stderr reader join");
        }
    }

    fn logs(&self) -> String {
        self.logs.lock().expect("logs mutex").clone()
    }
}

impl Drop for GatewayProcess {
    fn drop(&mut self) {
        self.kill_and_reap();
    }
}

fn free_address() -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve address");
    let address = listener.local_addr().expect("local address");
    drop(listener);
    address
}

#[allow(clippy::too_many_arguments)]
fn launch_gateway(
    fixture: &Fixture,
    tls: &Path,
    quota: &Path,
    admin: &str,
    runtime: &str,
    schema: &str,
    replica: &str,
    address: std::net::SocketAddr,
) -> GatewayProcess {
    let mut command = Command::new(env!("CARGO_BIN_EXE_smesh-a2a-gateway"));
    command
        .env_clear()
        .env("RUST_LOG", "info")
        .env("SMESH_A2A_AUTH_MODE", "disabled")
        .env("SMESH_A2A_CLIENT_AUTH_MODE", "required")
        .env("SMESH_A2A_MODE", "loopback")
        .env("SMESH_A2A_BIND", address.to_string())
        .env(
            "SMESH_A2A_PUBLIC_URL",
            format!("https://localhost:{}", address.port()),
        )
        .env("SMESH_A2A_DURABLE_BACKEND", "postgres")
        .env("SMESH_A2A_POSTGRES_MIGRATOR_URL", admin)
        .env("SMESH_A2A_POSTGRES_RUNTIME_URL", runtime)
        .env("SMESH_A2A_POSTGRES_SCHEMA", schema)
        .env("SMESH_A2A_QUOTA_POLICY_PATH", quota)
        .env("SMESH_A2A_REPLICA_ID", replica)
        .env("SMESH_TEST_POSTGRES_INSECURE_LOOPBACK", "1")
        .env("SMESH_TEST_POSTGRES_PARENT_MANAGED_CLEANUP", "1")
        .env(
            "SMESH_A2A_AUTHORIZATION_POLICY_PATH",
            fixture.root.join("authorization.json"),
        )
        .env("SMESH_A2A_TRANSPORT_MODE", "direct-tls")
        .env("SMESH_A2A_TLS_CERT_PATH", tls.join("server.pem"))
        .env("SMESH_A2A_TLS_KEY_PATH", tls.join("server.key"))
        .env("SMESH_A2A_TLS_CLIENT_CA_PATH", tls.join("client-ca.pem"))
        .env(
            "SMESH_A2A_TLS_PRINCIPAL_MAP_PATH",
            tls.join("principals.json"),
        )
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn gateway process");
    let stderr = child.stderr.take().expect("gateway stderr");
    let logs = Arc::new(Mutex::new(String::new()));
    let reader_logs = Arc::clone(&logs);
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let mut ready = false;
        for line in BufReader::new(stderr).lines() {
            match line {
                Ok(line) => {
                    let _ = writeln!(reader_logs.lock().expect("logs mutex"), "{line}");
                    if !ready && line.contains("gateway listening") {
                        ready = true;
                        let _ = ready_tx.send(Ok(()));
                    }
                }
                Err(error) => {
                    if !ready {
                        let _ = ready_tx.send(Err(format!("stderr read failed: {error}")));
                    }
                    let _ = done_tx.send(());
                    return;
                }
            }
        }
        if !ready {
            let captured = reader_logs.lock().expect("logs mutex").clone();
            let _ = ready_tx.send(Err(format!("gateway exited before READY: {captured}")));
        }
        let _ = done_tx.send(());
    });
    let mut process = GatewayProcess {
        child: Some(child),
        logs,
        reader: Some(reader),
        reader_done: done_rx,
    };
    match ready_rx.recv_timeout(WATCHDOG) {
        Ok(Ok(())) => process,
        Ok(Err(error)) => {
            process.kill_and_reap();
            panic!("{error}")
        }
        Err(error) => {
            process.kill_and_reap();
            panic!("gateway READY watchdog: {error}")
        }
    }
}

fn mtls_client(tls: &Path) -> reqwest::Client {
    let mut identity = std::fs::read(tls.join("client.pem")).expect("client cert");
    identity.extend(std::fs::read(tls.join("client.key")).expect("client key"));
    reqwest::Client::builder()
        .no_proxy()
        .tls_certs_only([reqwest::Certificate::from_pem(
            &std::fs::read(tls.join("server-ca.pem")).expect("server CA"),
        )
        .expect("server CA PEM")])
        .identity(reqwest::Identity::from_pem(&identity).expect("client identity"))
        .connect_timeout(Duration::from_secs(3))
        .timeout(WATCHDOG)
        .build()
        .expect("mTLS client")
}

fn principal_scope() -> String {
    content_digest(
        format!("quota-principal-v1\0{PRINCIPAL_ISSUER}\0{PRINCIPAL_SUBJECT}").as_bytes(),
    )
}

fn seeded_admission(message_id: &str, text: &str, streaming: bool) -> SendMessageAdmission {
    let mut message = a2a::Message::new(a2a::Role::User, vec![a2a::Part::text(text)]);
    message.message_id = message_id.into();
    let request = a2a::SendMessageRequest {
        message: message.clone(),
        configuration: None,
        metadata: None,
        tenant: None,
    };
    let identity =
        content_digest(format!("task-v2\0{TENANT_A}\0{ACCOUNT}\0{message_id}").as_bytes());
    let task = a2a::Task {
        id: format!("task-{}", &identity[..32]),
        context_id: format!("context-{}", &identity[32..]),
        status: a2a::TaskStatus {
            state: a2a::TaskState::Submitted,
            message: None,
            timestamp: chrono::DateTime::from_timestamp_millis(1_700_000_000_000),
        },
        artifacts: None,
        history: Some(vec![message]),
        metadata: None,
    };
    SendMessageAdmission {
        request,
        streaming,
        task: task.clone(),
        original_result: a2a::SendMessageResponse::Task(task),
        input_limits: smesh_a2a::InputLimits::default(),
        now: 1_700_000_000_000,
        max_attempts: 8,
    }
}

fn seeded_stream_admission(policy: &QuotaPolicy) -> (SendMessageAdmission, smesh_a2a::QuotaIntent) {
    let admission = seeded_admission(STREAM_MESSAGE, "hold production stream", true);
    let bytes = serde_json::to_vec(&admission.request)
        .expect("measure seed")
        .len() as u64;
    let subject = QuotaSubject::new(TENANT_A, ACCOUNT, principal_scope()).expect("quota subject");
    let intent = policy
        .operation_intent(
            &subject,
            smesh_a2a::QuotaOperation::SendStream,
            STREAM_MESSAGE,
            bytes,
        )
        .expect("seed quota intent");
    (admission, intent)
}

fn production_output_events(admission: &SendMessageAdmission) -> Vec<smesh_a2a::MeshEvent> {
    let content = serde_json::json!({
        "contextId": admission.task.context_id,
        "result": format!("SMESH accepted: {OUTPUT_OVER_TEXT}"),
        "taskId": admission.task.id,
    })
    .to_string();
    vec![
        smesh_a2a::MeshEvent::Progress("SMESH swarm is processing the durable dispatch".to_owned()),
        smesh_a2a::MeshEvent::Artifact {
            name: "smesh-result.json".to_owned(),
            media_type: "application/json".to_owned(),
            content,
        },
        smesh_a2a::MeshEvent::Completed {
            summary: "SMESH swarm completed the task".to_owned(),
        },
    ]
}

fn measured_output_bytes(events: &[smesh_a2a::MeshEvent]) -> u64 {
    events
        .iter()
        .map(|event| {
            serde_json::to_vec(event)
                .expect("serialize output event")
                .len() as u64
        })
        .sum()
}

async fn admin_client(admin: &str) -> (tokio_postgres::Client, tokio::task::JoinHandle<()>) {
    let config = tokio_postgres::Config::from_str(admin).expect("admin URL");
    let (client, connection) =
        tokio::time::timeout(WATCHDOG, config.connect(tokio_postgres::NoTls))
            .await
            .expect("admin connect watchdog")
            .expect("admin connect");
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    (client, driver)
}

async fn wait_for_no_active_lease(client: &tokio_postgres::Client, schema: &str, kind: &str) {
    let deadline = tokio::time::Instant::now() + WATCHDOG;
    loop {
        let count: i64 = tokio::time::timeout(
            WATCHDOG,
            client.query_one(
                &format!("SELECT count(*) FROM {schema}.quota_leases WHERE lease_kind=$1 AND state='active'"),
                &[&kind],
            ),
        )
        .await
        .expect("lease checkpoint watchdog")
        .expect("lease checkpoint")
        .get(0);
        if count == 0 {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "lease release checkpoint watchdog"
        );
    }
}

async fn body(response: reqwest::Response) -> Vec<u8> {
    tokio::time::timeout(WATCHDOG, response.bytes())
        .await
        .expect("response body watchdog")
        .expect("response body")
        .to_vec()
}

fn tenant(request: reqwest::RequestBuilder, value: &str) -> reqwest::RequestBuilder {
    request.header("x-smesh-tenant", value)
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn production_wire_multi_process_quota_abuse_outage_fairness_and_failover_matrix() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let Some(admin) = process_admin_url() else {
            return;
        };
        let runtime = required_url("SMESH_TEST_POSTGRES_RUNTIME_URL");
        let fixture = Fixture::new();
        let (tls, quota_path, policy) = fixture.write_files(postgres_db_millis(&admin).await);
        let schema = format!("smesh_quota_process_{:016x}", rand::random::<u64>());
        let config = PostgresStoreConfig::new(&admin, &runtime, &schema)
            .expect("PostgreSQL config")
            .with_test_only_insecure_loopback(true)
            .with_test_only_parent_managed_cleanup()
            .with_quota_policy(Arc::clone(&policy));
        let schema_guard = SchemaGuard::new(config.clone());

        // Seed one deliberately pending streaming task before replicas start. Its outbox
        // due time is moved beyond the test horizon, so subscriptions have a real open tail.
        let store = PostgresTaskStore::open(config.clone()).await.expect("seed store");
        let scope = OwnedTaskScope::new(TENANT_A, ACCOUNT, VisibilityScope::Own).expect("scope");
        let (admission, intent) = seeded_stream_admission(&policy);
        let task_id = admission.task.id.clone();
        let raw_message_id = admission.request.message.message_id.clone();
        let audit = AuthorizationAuditInput::new(
            "seed-process-audit", TENANT_A, ACCOUNT, "quota-process-authz", 14,
            "digest:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "TaskCreate", AuthorizationDecisionEffect::Allow, "policy_grant", "message",
            content_digest(STREAM_MESSAGE.as_bytes()), None, 1_700_000_000_000,
        ).expect("seed audit");
        store.authorize_and_admit_mutation(
            &scope, AuthorizedMutation::with_quota_intent(admission, intent), audit,
        ).await.expect("seed pending stream");

        let (admin_db, admin_driver) = admin_client(&admin).await;
        let (evidence_db, evidence_driver) = admin_client(&runtime).await;
        evidence_db.batch_execute(&format!("SET ROLE {schema}_runtime"))
            .await.expect("enter runtime evidence role");
        evidence_db.query_one(
            "SELECT set_config('smesh.tenant_scope',$1,false),set_config('smesh.account_id',$2,false)",
            &[&TENANT_A, &ACCOUNT],
        ).await.expect("bind runtime evidence scope");
        assert_eq!(evidence_db.execute(
            &format!("UPDATE {schema}.outbox SET available_at=253402300799000 WHERE tenant_scope=$1 AND task_id=$2"),
            &[&TENANT_A, &task_id],
        ).await.expect("hold outbox"), 1, "pending stream outbox must be held before replicas start");
        store.shutdown().await.expect("seed shutdown");

        let address_a = free_address();
        let address_b = free_address();
        let mut replica_a = launch_gateway(
            &fixture, &tls, &quota_path, &admin, &runtime, &schema, "quota-process-a", address_a,
        );
        let mut replica_b = launch_gateway(
            &fixture, &tls, &quota_path, &admin, &runtime, &schema, "quota-process-b", address_b,
        );
        assert_ne!(replica_a.pid(), replica_b.pid(), "replicas require distinct PIDs");
        assert_ne!(address_a, address_b, "replicas require distinct sockets");
        let client = mtls_client(&tls);
        let bases = [
            format!("https://localhost:{}", address_a.port()),
            format!("https://localhost:{}", address_b.port()),
        ];

        // A real, signed configuration override applies only to the named principal,
        // operation, and dimension. It is audited durably and cannot be selected by headers.
        let override_first = tenant(
            client.get(format!("{}/rest/tasks/{task_id}", bases[0])),
            TENANT_A,
        )
        .send()
        .await
        .expect("configured override first request");
        assert!(override_first.status().is_success());
        let _ = body(override_first).await;
        let override_denied = tenant(
            client.get(format!("{}/rest/tasks/{task_id}", bases[1])),
            TENANT_A,
        )
        .header("x-smesh-quota-override", "allow")
        .send()
        .await
        .expect("configured override boundary");
        assert_eq!(override_denied.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
        let _ = body(override_denied).await;
        let override_audit = evidence_db.query_one(
            &format!("SELECT count(*),min(old_limit),min(new_limit),min(expires_at),bool_and(policy_digest=$1) FROM {schema}.quota_override_audits WHERE tenant_scope=$2 AND override_id='process-task-get-incident'"),
            &[&policy.digest(), &TENANT_A],
        ).await.expect("configured override audit");
        assert_eq!(override_audit.get::<_, i64>(0), 1);
        assert_eq!((override_audit.get::<_, i64>(1), override_audit.get::<_, i64>(2)), (20, 1));
        assert!(override_audit.get::<_, bool>(4));
        let override_expires_at = override_audit.get::<_, i64>(3);
        let override_denials: i64 = evidence_db.query_one(
            &format!("SELECT count(*) FROM {schema}.quota_denial_audits WHERE tenant_scope=$1"),
            &[&TENANT_A],
        ).await.expect("configured override denial row scope").get(0);
        assert_eq!(override_denials, 1, "the exact principal task-get boundary emits one denial row");

        // Named GO barrier: 22 tenant-A requests storm two independent replicas while
        // tenant B enters at the same boundary. A has exactly 20 winners; B is independent.
        let go = Arc::new(tokio::sync::Barrier::new(24));
        let mut attempts = Vec::new();
        for index in 0..22 {
            let go = Arc::clone(&go);
            let client = client.clone();
            let base = bases[index % 2].clone();
            attempts.push(tokio::spawn(async move {
                go.wait().await;
                let request = tenant(client.get(format!("{base}/rest/tasks")), TENANT_A)
                    .header("x-smesh-quota-limit", "999999999")
                    .header("x-smesh-quota-principal", "attacker")
                    .header("x-smesh-quota-override", "allow")
                    .header("x-smesh-authenticated-principal", "attacker");
                tokio::time::timeout(WATCHDOG, request.send())
                    .await.expect("A request watchdog").expect("A request")
            }));
        }
        let go_b = Arc::clone(&go);
        let client_b = client.clone();
        let base_b = bases[1].clone();
        let tenant_b = tokio::spawn(async move {
            go_b.wait().await;
            tokio::time::timeout(
                WATCHDOG,
                tenant(client_b.get(format!("{base_b}/rest/tasks")), TENANT_B).send(),
            ).await.expect("B fairness watchdog").expect("B request")
        });
        go.wait().await;
        let mut statuses = Vec::new();
        for attempt in attempts {
            let response = attempt.await.expect("A request join");
            statuses.push(response.status());
            let _ = body(response).await;
        }
        let b_response = tenant_b.await.expect("B request join");
        assert!(b_response.status().is_success(), "tenant B must not wait behind A: {}", b_response.status());
        let _ = body(b_response).await;
        assert_eq!(statuses.iter().filter(|status| status.is_success()).count(), 20);
        assert_eq!(statuses.iter().filter(|status| **status == reqwest::StatusCode::TOO_MANY_REQUESTS).count(), 2);

        // Denial evidence is mandatory: forced denial-audit failure is unavailable, never allow.
        admin_db.batch_execute(&format!(
            "CREATE FUNCTION {schema}.fail_quota_denial() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'quota denial audit unavailable'; END $$; \
             CREATE TRIGGER fail_quota_denial BEFORE INSERT ON {schema}.quota_denial_audits FOR EACH ROW EXECUTE FUNCTION {schema}.fail_quota_denial()"
        )).await.expect("install denial outage");
        let unavailable = tenant(client.get(format!("{}/rest/tasks", bases[0])), TENANT_A)
            .send().await.expect("outage request");
        assert_eq!(unavailable.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        let unavailable_body = String::from_utf8_lossy(&body(unavailable).await).into_owned();
        assert!(unavailable_body.contains("\"reason\":\"UNAVAILABLE\""), "{unavailable_body}");
        admin_db.batch_execute(&format!(
            "DROP TRIGGER fail_quota_denial ON {schema}.quota_denial_audits; DROP FUNCTION {schema}.fail_quota_denial()"
        )).await.expect("restore denial audit");
        let exhausted = tenant(client.get(format!("{}/rest/tasks", bases[1])), TENANT_A)
            .send().await.expect("exhaustion request");
        assert_eq!(exhausted.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
        let retry_after = exhausted.headers().get(reqwest::header::RETRY_AFTER)
            .expect("Retry-After").to_str().expect("integer Retry-After").parse::<u64>().expect("integer Retry-After");
        assert!((1..=3600).contains(&retry_after));
        let exhausted_body = String::from_utf8_lossy(&body(exhausted).await).into_owned();
        assert!(exhausted_body.contains("\"reason\":\"RESOURCE_EXHAUSTED\""), "{exhausted_body}");
        assert!(!exhausted_body.contains(STREAM_MESSAGE));
        let denial = evidence_db.query_one(
            &format!("SELECT count(*),coalesce(bool_and(tenant_scope=$1 AND bucket_digest LIKE 'sha256:%' AND reason_digest LIKE 'sha256:%' AND content_digest LIKE 'sha256:%'),false),coalesce(bool_and(bucket_digest NOT LIKE '%quota-process-stream%' AND reason_digest NOT LIKE '%quota-process-stream%'),false) FROM {schema}.quota_denial_audits"),
            &[&TENANT_A],
        ).await.expect("denial audit checkpoint");
        assert_eq!(denial.get::<_, i64>(0), override_denials + 3);
        assert!(denial.get::<_, bool>(1));
        assert!(denial.get::<_, bool>(2));

        // Separate replicas compete for the final subscription slot before SSE headers.
        let subscribe_go = Arc::new(tokio::sync::Barrier::new(3));
        let mut subscribe_attempts = Vec::new();
        for base in &bases {
            let go = Arc::clone(&subscribe_go);
            let client = client.clone();
            let url = format!("{base}/rest/tasks/{task_id}:subscribe");
            subscribe_attempts.push(tokio::spawn(async move {
                go.wait().await;
                tokio::time::timeout(WATCHDOG, tenant(client.get(url), TENANT_A).send())
                    .await.expect("subscription watchdog").expect("subscription request")
            }));
        }
        subscribe_go.wait().await;
        let mut subscription_winner = None;
        let mut subscription_denials = 0;
        for attempt in subscribe_attempts {
            let response = attempt.await.expect("subscription join");
            if response.status().is_success() {
                assert!(subscription_winner.replace(response).is_none());
            } else {
                let status = response.status();
                let content_type = response.headers().get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok()).map(str::to_owned);
                let denied_body = String::from_utf8_lossy(&body(response).await).into_owned();
                assert_eq!(
                    status,
                    reqwest::StatusCode::TOO_MANY_REQUESTS,
                    "{denied_body}\nreplica-a:\n{}\nreplica-b:\n{}",
                    replica_a.logs(),
                    replica_b.logs(),
                );
                assert_eq!(content_type.as_deref(), Some("application/json"));
                subscription_denials += 1;
            }
        }
        assert_eq!(subscription_denials, 1);
        drop(subscription_winner.take());
        wait_for_no_active_lease(&evidence_db, &schema, "taskSubscription").await;
        let replacement = tenant(
            client.get(format!("{}/rest/tasks/{task_id}:subscribe", bases[1])), TENANT_A,
        ).send().await.expect("replacement subscription");
        assert!(replacement.status().is_success());
        drop(replacement);
        wait_for_no_active_lease(&evidence_db, &schema, "taskSubscription").await;

        // A killed holder cannot release. The slot remains active, then exact DB-time expiry
        // lets the other replica reclaim it without a wall-clock sleep.
        let crashed_holder = tenant(
            client.get(format!("{}/rest/tasks/{task_id}:subscribe", bases[1])), TENANT_A,
        ).send().await.expect("crash holder");
        assert!(crashed_holder.status().is_success(), "crash holder was {}", crashed_holder.status());
        replica_b.kill_and_reap();
        drop(crashed_holder);
        let blocked = tenant(
            client.get(format!("{}/rest/tasks/{task_id}:subscribe", bases[0])), TENANT_A,
        ).send().await.expect("blocked after crash");
        assert_eq!(blocked.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
        let _ = body(blocked).await;
        let lease_until: i64 = evidence_db.query_one(
            &format!("SELECT lease_until FROM {schema}.quota_leases WHERE lease_kind='taskSubscription' AND state='active'"),
            &[],
        ).await.expect("read crashed lease expiry").get(0);
        let expiry_watchdog = tokio::time::Instant::now() + Duration::from_secs(40);
        loop {
            let database_now: i64 = evidence_db.query_one(
                &format!("SELECT {schema}.db_millis()"),
                &[],
            ).await.expect("DB-time expiry checkpoint").get(0);
            if database_now >= lease_until {
                break;
            }
            assert!(tokio::time::Instant::now() < expiry_watchdog, "crashed lease DB-time expiry watchdog");
        }
        let reclaim_watchdog = tokio::time::Instant::now() + Duration::from_secs(10);
        let reclaimed = loop {
            let candidate = tenant(
                client.get(format!("{}/rest/tasks/{task_id}:subscribe", bases[0])), TENANT_A,
            ).send().await.expect("reclaimed subscription");
            if candidate.status().is_success() {
                break candidate;
            }
            let status = candidate.status();
            let denied = String::from_utf8_lossy(&body(candidate).await).into_owned();
            assert_eq!(status, reqwest::StatusCode::TOO_MANY_REQUESTS, "{denied}");
            assert!(tokio::time::Instant::now() < reclaim_watchdog, "expired slot reclaim watchdog: {denied}");
        };
        drop(reclaimed);
        wait_for_no_active_lease(&evidence_db, &schema, "taskSubscription").await;

        // Frozen replay input consumes the reconnect bucket exactly; changing quota metadata
        // cannot alter its scope. Each accepted replay is dropped and releases its stream slot.
        let stream_request = serde_json::json!({
            "jsonrpc":"2.0","id":"frozen-reconnect","method":a2a::jsonrpc::methods::SEND_STREAMING_MESSAGE,
            "params":{
                "message":{"messageId":raw_message_id,"role":"ROLE_USER","parts":[{"text":"hold production stream"}]}
            }
        });
        for accepted in 0..2 {
            let response = tenant(
                client.post(format!("{}/jsonrpc", bases[0])).json(&stream_request), TENANT_A,
            ).header("x-smesh-quota-limit", "999999").send().await.expect("reconnect");
            assert!(response.status().is_success(), "reconnect {accepted}: {}", response.status());
            let mut stream = response.bytes_stream();
            let first = tokio::time::timeout(WATCHDOG, stream.next()).await
                .expect("reconnect first-frame watchdog").expect("reconnect first frame")
                .expect("reconnect frame bytes");
            let first = String::from_utf8_lossy(&first);
            assert!(first.contains("task") && !first.contains("\"error\""), "reconnect {accepted} was not an accepted stream: {first}");
            drop(stream);
            wait_for_no_active_lease(&evidence_db, &schema, "messageStream").await;
        }
        let reconnect_before_denial: i64 = evidence_db.query_one(
            &format!("SELECT coalesce(sum(r.units),0)::bigint FROM {schema}.quota_receipts r JOIN {schema}.quota_intents i USING(tenant_scope,binding_digest) WHERE r.tenant_scope=$1 AND r.scope_kind='principal' AND r.scope_id=$2 AND i.operation='reconnect' AND r.dimension='reconnectCount'"),
            &[&TENANT_A, &principal_scope()],
        ).await.expect("reconnect pre-denial checkpoint").get(0);
        assert_eq!(reconnect_before_denial, 2, "accepted replay streams must charge reconnects");
        let reconnect_denied = tenant(
            client.post(format!("{}/jsonrpc", bases[0])).json(&stream_request), TENANT_A,
        ).send().await.expect("reconnect denial");
        let reconnect_status = reconnect_denied.status();
        if reconnect_status != reqwest::StatusCode::TOO_MANY_REQUESTS {
            let unexpected = String::from_utf8_lossy(&body(reconnect_denied).await).into_owned();
            panic!("reconnect denial was {reconnect_status}: {unexpected}");
        }
        assert_eq!(reconnect_denied.headers().get(reqwest::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()), Some("application/json"));
        let reconnect_body = String::from_utf8_lossy(&body(reconnect_denied).await).into_owned();
        assert!(reconnect_body.contains("-32010"), "{reconnect_body}");

        let reconnect_units: i64 = evidence_db.query_one(
            &format!("SELECT coalesce(sum(r.units),0)::bigint FROM {schema}.quota_receipts r JOIN {schema}.quota_intents i USING(tenant_scope,binding_digest) WHERE r.tenant_scope=$1 AND r.scope_kind='principal' AND r.scope_id=$2 AND i.operation='reconnect' AND r.dimension='reconnectCount'"),
            &[&TENANT_A, &principal_scope()],
        ).await.expect("reconnect receipt checkpoint").get(0);
        assert_eq!(reconnect_units, 2);
        let reconnect_state = evidence_db.query_one(
            &format!("SELECT used_units,available_tokens,capacity,refill_remainder FROM {schema}.quota_buckets WHERE tenant_scope=$1 AND policy_digest=$2 AND scope_kind='principal' AND scope_id=$3 AND operation='reconnect' AND dimension='reconnectCount' AND window_start=0"),
            &[&TENANT_A, &policy.digest(), &principal_scope()],
        ).await.expect("reconnect token state checkpoint");
        assert_eq!(reconnect_state.get::<_, i64>(0), 2);
        assert_eq!(reconnect_state.get::<_, Option<i64>>(1), Some(0));
        assert_eq!(reconnect_state.get::<_, i64>(2), 2);
        assert!((0..3_600_000).contains(&reconnect_state.get::<_, Option<i64>>(3).expect("token remainder")));

        let override_expiry_watchdog = tokio::time::Instant::now() + WATCHDOG;
        loop {
            let database_now: i64 = evidence_db
                .query_one(&format!("SELECT {schema}.db_millis()"), &[])
                .await
                .expect("override DB-time expiry checkpoint")
                .get(0);
            if database_now >= override_expires_at {
                break;
            }
            assert!(tokio::time::Instant::now() < override_expiry_watchdog, "configured override DB-time expiry watchdog");
        }
        evidence_db.batch_execute(&format!(r"
            DO $$ DECLARE i integer; BEGIN
              FOR i IN 1..10000 LOOP
                BEGIN
                  INSERT INTO {schema}.quota_denial_audits(
                    tenant_scope,decision_key,content_digest,policy_digest,bucket_digest,reason_digest,retry_after_seconds,denied_at
                  ) VALUES(
                    '{TENANT_A}','sha256:'||lpad(i::text,64,'0'),'sha256:'||repeat('a',64),
                    '{policy_digest}','sha256:'||repeat('b',64),'sha256:'||repeat('c',64),1,1
                  );
                EXCEPTION WHEN SQLSTATE '53000' THEN EXIT;
                END;
              END LOOP;
            END $$;
        ", policy_digest=policy.digest())).await.expect("fill retained authority to configured cap");
        let retained_full: i64 = evidence_db.query_one(
            &format!("SELECT retained_bytes FROM {schema}.retained_authority_usage WHERE tenant_scope=$1 AND scope_kind='tenant' AND scope_id=$1"),
            &[&TENANT_A],
        ).await.expect("retained cap checkpoint").get(0);
        assert!(retained_full <= 1_048_576 && retained_full > 1_047_500, "retained filler did not reach the configured boundary: {retained_full}");
        let retained_denied = tenant(
            client.get(format!("{}/rest/tasks/{task_id}", bases[0])), TENANT_A,
        ).send().await.expect("retained-cap request");
        assert!(matches!(retained_denied.status(), reqwest::StatusCode::TOO_MANY_REQUESTS | reqwest::StatusCode::SERVICE_UNAVAILABLE));
        let _ = body(retained_denied).await;
        let b_during_retained_pressure = tenant(
            client.get(format!("{}/rest/tasks", bases[0])), TENANT_B,
        ).send().await.expect("tenant-B retained-pressure progress");
        assert!(b_during_retained_pressure.status().is_success(), "tenant B blocked by tenant A retained cap: {}", b_during_retained_pressure.status());
        let _ = body(b_during_retained_pressure).await;

        let gc_now: i64 = evidence_db.query_one(&format!("SELECT {schema}.db_millis()"), &[])
            .await.expect("retained GC database time").get(0);
        let gc_store = PostgresTaskStore::open(config.clone()).await.expect("open concurrent GC store");
        let removed = gc_store.gc_quota_authority(gc_now, 1000).await.expect("bounded retained GC");
        assert_eq!(removed, 1000, "bounded GC must release an exact batch under pressure");
        gc_store.shutdown().await.expect("GC store shutdown");
        let retained_after_gc: i64 = evidence_db.query_one(
            &format!("SELECT retained_bytes FROM {schema}.retained_authority_usage WHERE tenant_scope=$1 AND scope_kind='tenant' AND scope_id=$1"),
            &[&TENANT_A],
        ).await.expect("retained recovery checkpoint").get(0);
        assert!(retained_after_gc < retained_full);

        let after_override = tenant(
            client.get(format!("{}/rest/tasks/{task_id}", bases[0])),
            TENANT_A,
        ).send().await.expect("post-override request");
        assert!(after_override.status().is_success(), "baseline must resume after the configured override expires: {}", after_override.status());
        let _ = body(after_override).await;

        let active: i64 = evidence_db.query_one(
            &format!("SELECT count(*) FROM {schema}.quota_leases WHERE state='active'"), &[],
        ).await.expect("active lease checkpoint").get(0);
        assert_eq!(active, 0, "drop/backpressure cleanup must not retain slots");

        replica_a.kill_and_reap();
        let logs = format!("{}{}", replica_a.logs(), replica_b.logs());
        for secret in [admin.as_str(), runtime.as_str(), STREAM_MESSAGE, "attacker"] {
            assert!(!logs.contains(secret), "stderr leaked protected value");
        }
        drop(admin_db);
        admin_driver.abort();
        let _ = admin_driver.await;
        drop(evidence_db);
        evidence_driver.abort();
        let _ = evidence_driver.await;
        schema_guard.cleanup().await;
    }).await.expect("full production-process quota matrix watchdog");
}

#[tokio::test]
async fn production_process_rejects_output_and_event_plus_one_before_effect_or_frame() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let Some(admin) = process_admin_url() else { return };
        let runtime = required_url("SMESH_TEST_POSTGRES_RUNTIME_URL");
        let fixture = Fixture::new();
        let (tls, quota_path, policy) = fixture.write_files(postgres_db_millis(&admin).await);
        let schema = format!("smesh_quota_process_output_{:016x}", rand::random::<u64>());
        let config = PostgresStoreConfig::new(&admin, &runtime, &schema).expect("PostgreSQL config")
            .with_test_only_insecure_loopback(true)
            .with_test_only_parent_managed_cleanup()
            .with_quota_policy(Arc::clone(&policy));
        let schema_guard = SchemaGuard::new(config.clone());
        let store = PostgresTaskStore::open(config).await.expect("output seed store");
        let scope = OwnedTaskScope::new(TENANT_A, ACCOUNT, VisibilityScope::Own).expect("scope");
        let admission = seeded_admission(OUTPUT_OVER_MESSAGE, OUTPUT_OVER_TEXT, false);
        let task_id = admission.task.id.clone();
        let events = production_output_events(&admission);
        let expected_bytes = i64::try_from(measured_output_bytes(&events)).expect("output bytes");
        let expected_events = i64::try_from(events.len()).expect("event count");
        let input = serde_json::to_vec(&admission.request).expect("measure input").len() as u64;
        let subject = QuotaSubject::new(TENANT_A, ACCOUNT, principal_scope()).expect("subject");
        let intent = policy.admission_intent(&subject, OUTPUT_OVER_MESSAGE, input, false).expect("intent");
        let audit = AuthorizationAuditInput::new(
            "process-output-over-audit", TENANT_A, ACCOUNT, "quota-process-authz", 14,
            "digest:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "TaskCreate", AuthorizationDecisionEffect::Allow, "policy_grant", "message",
            content_digest(OUTPUT_OVER_MESSAGE.as_bytes()), None, 1_700_000_000_000,
        ).expect("audit");
        store.authorize_and_admit_mutation(
            &scope, AuthorizedMutation::with_quota_intent(admission, intent), audit,
        ).await.expect("seed output-over task");
        store.shutdown().await.expect("seed shutdown");

        let address = free_address();
        let mut gateway = launch_gateway(
            &fixture, &tls, &quota_path, &admin, &runtime, &schema, "quota-process-output", address,
        );
        let (evidence, driver) = admin_client(&runtime).await;
        evidence.batch_execute(&format!("SET ROLE {schema}_runtime")).await.expect("runtime role");
        evidence.query_one(
            "SELECT set_config('smesh.tenant_scope',$1,false),set_config('smesh.account_id',$2,false)",
            &[&TENANT_A, &ACCOUNT],
        ).await.expect("scope evidence");
        let checkpoint = tokio::time::Instant::now() + WATCHDOG;
        loop {
            let count: i64 = evidence.query_one(
                &format!("SELECT count(*) FROM {schema}.receiver_inbox WHERE tenant_scope=$1 AND task_id=$2"),
                &[&TENANT_A, &task_id],
            ).await.expect("receiver checkpoint").get(0);
            if count > 0 { break; }
            assert!(tokio::time::Instant::now() < checkpoint, "output process watchdog");
        }
        let row = evidence.query_one(
            &format!("SELECT q.reserved_output_bytes,q.reserved_event_count,(SELECT count(*) FROM {schema}.loopback_effects e JOIN {schema}.receiver_inbox r USING(tenant_scope,dispatch_id) WHERE r.task_id=$2),(SELECT count(*) FROM {schema}.receiver_frames f JOIN {schema}.receiver_inbox r USING(tenant_scope,dispatch_id) WHERE r.task_id=$2),bool_and(r.state<>'completed') FROM {schema}.quota_execution_reservations q JOIN {schema}.receiver_inbox r ON r.tenant_scope=q.tenant_scope AND r.quota_reservation_id=q.reservation_id WHERE q.tenant_scope=$1 AND q.task_id=$2 GROUP BY q.reserved_output_bytes,q.reserved_event_count"),
            &[&TENANT_A, &task_id],
        ).await.expect("output process evidence");
        assert_eq!(row.get::<_, i64>(0) + 1, expected_bytes);
        assert_eq!(row.get::<_, i64>(1) + 1, expected_events);
        assert_eq!((row.get::<_, i64>(2), row.get::<_, i64>(3)), (0, 0));
        assert!(row.get::<_, bool>(4));
        gateway.kill_and_reap();
        drop(evidence);
        driver.abort();
        let _ = driver.await;
        schema_guard.cleanup().await;
    }).await.expect("production output/event process watchdog");
}
