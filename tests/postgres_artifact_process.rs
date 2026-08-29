#![cfg(all(unix, debug_assertions))]
#![allow(clippy::too_many_arguments, clippy::too_many_lines)]

mod support;

use std::fmt::Write as _;
use std::io::{BufRead as _, BufReader};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr as _;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use smesh_a2a::{
    ArtifactStoreConfig, AuthorityShutdown, PostgresStoreConfig, PostgresTaskStore, QuotaPolicy,
};
use support::artifact_test_root::ArtifactTestRoot;
use wait_timeout::ChildExt as _;

const WATCHDOG: Duration = Duration::from_secs(90);

const PRODUCTION_CRASH_CUTS: &[&str] = &[
    "publication_stage_before_receiver_transaction",
    "receiver_commit_before_physical_promotion",
    "promoter_claim_before_physical_promotion",
    "physical_promotion_before_upload_ack",
    "receiver_complete_before_sender_delivery_commit",
    "resolver_read_lease_before_blob_verify",
    "gc_tombstone_claim_before_unlink",
    "gc_physical_unlink_before_finalize",
    "gc_finalize_before_worker_ack",
    "reencryption_stage_registration_before_physical_promotion",
    "reencryption_physical_promotion_before_state_ack",
    "reencryption_promoted_before_metadata_swap",
    "reencryption_metadata_swap_before_old_delete",
    "reencryption_old_delete_before_complete",
    "backup_pin_snapshot_before_object_copy",
    "backup_object_copy_before_inventory_write",
    "backup_inventory_write_before_seal",
    "restore_ciphertext_stage_before_metadata",
    "restore_metadata_restoring_before_enable",
    "restore_atomic_enable_before_ack",
    "migration_stage_before_batch_transaction",
    "migration_batch_commit_before_checkpoint_ack",
];

fn required(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent)
            if std::env::var("SMESH_POSTGRES_TEST_REQUIRED").as_deref() == Ok("1") =>
        {
            panic!("{name} is required")
        }
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => panic!("{name} is invalid: {error}"),
    }
}

struct Fixture(ArtifactTestRoot);
impl Fixture {
    fn new() -> Self {
        Self(ArtifactTestRoot::new("postgres-artifact-process"))
    }

    fn prepare(&self) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
        let tls = self.0.join("tls");
        std::fs::create_dir(&tls).unwrap();
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
            std::fs::copy(source.join(name), tls.join(name)).unwrap();
        }
        for name in ["server.key", "client.key"] {
            std::fs::set_permissions(tls.join(name), std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        let authz = self.0.join("authorization.json");
        std::fs::write(
            &authz,
            br#"{"schemaVersion":"smesh-authz-policy/v1","policyId":"artifact-process","revision":1,"tenants":[{"id":"tenant-a","enabled":true}],"accounts":[{"id":"agent-17","kind":"serviceAccount","memberships":[{"tenantId":"tenant-a","roles":["taskAgent"]}]}],"principalBindings":[{"principal":{"issuer":"mtls:test","subject":"agent-17"},"accountId":"agent-17"}]}"#,
        )
        .unwrap();
        let quota = self.0.join("quota.json");
        std::fs::write(
            &quota,
            br#"{"schemaVersion":"smesh-quota-policy/v1","policyId":"artifact-process","revision":1,"requestWindowMillis":60000,"reconnectWindowMillis":60000,"limits":{"requestCount":{"tenant":10000,"account":10000,"principal":10000},"concurrentActiveWork":{"tenant":100,"account":100,"principal":100},"inputBytes":{"tenant":67108864,"account":67108864,"principal":67108864},"outputBytes":{"tenant":67108864,"account":67108864,"principal":67108864},"eventCount":{"tenant":10000,"account":10000,"principal":10000},"concurrentStreams":{"tenant":100,"account":100,"principal":100},"concurrentSubscriptions":{"tenant":100,"account":100,"principal":100},"reconnectCount":{"tenant":10000,"account":10000,"principal":10000},"retainedAuthorityBytes":{"tenant":67108864,"account":67108864,"principal":67108864}},"overrides":[]}"#,
        )
        .unwrap();
        let keyring = self.0.join("keys.json");
        std::fs::write(
            &keyring,
            br#"{"activeGeneration":"key-1","generations":{"key-1":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"}}"#,
        )
        .unwrap();
        std::fs::set_permissions(&keyring, std::fs::Permissions::from_mode(0o600)).unwrap();
        let cas = self.0.join("cas");
        std::fs::create_dir(&cas).unwrap();
        std::fs::set_permissions(&cas, std::fs::Permissions::from_mode(0o700)).unwrap();
        (tls, authz, quota, keyring)
    }
}

struct SchemaGuard(Option<PostgresStoreConfig>);
impl SchemaGuard {
    async fn cleanup(mut self) {
        let config = self.0.take().unwrap();
        tokio::time::timeout(WATCHDOG, PostgresTaskStore::drop_test_schema(&config))
            .await
            .expect("schema cleanup watchdog")
            .expect("drop artifact process schema");
    }
}
impl Drop for SchemaGuard {
    fn drop(&mut self) {
        let Some(config) = self.0.take() else { return };
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
        let _ = done_rx.recv_timeout(WATCHDOG);
    }
}

struct Gateway {
    child: Option<Child>,
    logs: Arc<Mutex<String>>,
    reader: Option<std::thread::JoinHandle<()>>,
    done: mpsc::Receiver<()>,
    checkpoint: Option<mpsc::Receiver<()>>,
    checkpoint_reader: Option<std::thread::JoinHandle<()>>,
    port: u16,
}
impl Gateway {
    fn spawn(
        fixture: &Fixture,
        tls: &Path,
        authz: &Path,
        quota: &Path,
        keyring: &Path,
        admin: &str,
        runtime: &str,
        schema: &str,
        replica: &str,
        checkpoint: Option<&str>,
    ) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut command = Command::new(env!("CARGO_BIN_EXE_smesh-a2a-gateway"));
        command
            .env_clear()
            .env("RUST_LOG", "info")
            .env("SMESH_A2A_AUTH_MODE", "disabled")
            .env("SMESH_A2A_CLIENT_AUTH_MODE", "required")
            .env("SMESH_A2A_MODE", "loopback")
            .env("SMESH_A2A_BIND", format!("127.0.0.1:{port}"))
            .env("SMESH_A2A_PUBLIC_URL", format!("https://localhost:{port}"))
            .env("SMESH_A2A_DURABLE_BACKEND", "postgres")
            .env("SMESH_A2A_POSTGRES_MIGRATOR_URL", admin)
            .env("SMESH_A2A_POSTGRES_RUNTIME_URL", runtime)
            .env("SMESH_A2A_POSTGRES_SCHEMA", schema)
            .env("SMESH_A2A_REPLICA_ID", replica)
            .env("SMESH_A2A_QUOTA_POLICY_PATH", quota)
            .env("SMESH_A2A_AUTHORIZATION_POLICY_PATH", authz)
            .env("SMESH_A2A_TRANSPORT_MODE", "direct-tls")
            .env("SMESH_A2A_TLS_CERT_PATH", tls.join("server.pem"))
            .env("SMESH_A2A_TLS_KEY_PATH", tls.join("server.key"))
            .env("SMESH_A2A_TLS_CLIENT_CA_PATH", tls.join("client-ca.pem"))
            .env(
                "SMESH_A2A_TLS_PRINCIPAL_MAP_PATH",
                tls.join("principals.json"),
            )
            .env("SMESH_A2A_ARTIFACT_ROOT", fixture.0.join("cas"))
            .env("SMESH_A2A_ARTIFACT_KEYRING_PATH", keyring)
            .env("SMESH_TEST_POSTGRES_INSECURE_LOOPBACK", "1")
            .env("SMESH_TEST_POSTGRES_PARENT_MANAGED_CLEANUP", "1")
            .stdin(if checkpoint.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(if checkpoint.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stderr(Stdio::piped());
        if let Some(checkpoint) = checkpoint {
            command.env("SMESH_TEST_ARTIFACT_CHECKPOINT", checkpoint);
        }
        let mut child = command.spawn().unwrap();
        let (checkpoint_rx, checkpoint_reader) = checkpoint.map_or((None, None), |checkpoint| {
            let stdout = child.stdout.take().unwrap();
            let expected = format!("SMESH_ARTIFACT_CHECKPOINT READY {checkpoint}");
            let (tx, rx) = mpsc::sync_channel(1);
            let reader = std::thread::spawn(move || {
                for line in BufReader::new(stdout).lines() {
                    if line.is_ok_and(|line| line == expected) {
                        let _ = tx.send(());
                        break;
                    }
                }
            });
            (Some(rx), Some(reader))
        });
        let stderr = child.stderr.take().unwrap();
        let logs = Arc::new(Mutex::new(String::new()));
        let shared = Arc::clone(&logs);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (done_tx, done) = mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || {
            let mut ready = false;
            for line in BufReader::new(stderr).lines() {
                let line = line.unwrap();
                writeln!(shared.lock().unwrap(), "{line}").unwrap();
                if !ready && line.contains("gateway listening") {
                    ready = true;
                    let _ = ready_tx.send(());
                }
            }
            let _ = done_tx.send(());
        });
        ready_rx.recv_timeout(WATCHDOG).unwrap_or_else(|error| {
            panic!(
                "{replica} readiness watchdog {error}: {}",
                logs.lock().unwrap()
            )
        });
        Self {
            child: Some(child),
            logs,
            reader: Some(reader),
            done,
            checkpoint: checkpoint_rx,
            checkpoint_reader,
            port,
        }
    }

    fn pid(&self) -> u32 {
        self.child.as_ref().unwrap().id()
    }

    fn replica_id(&self) -> String {
        let environment = std::fs::read(format!("/proc/{}/environ", self.pid())).unwrap();
        environment
            .split(|byte| *byte == 0)
            .find_map(|entry| {
                entry
                    .strip_prefix(b"SMESH_A2A_REPLICA_ID=")
                    .map(|value| String::from_utf8(value.to_vec()).unwrap())
            })
            .expect("gateway process replica identity")
    }

    fn wait_checkpoint(&self, checkpoint: &str) {
        self.checkpoint
            .as_ref()
            .unwrap_or_else(|| panic!("{checkpoint} was not armed"))
            .recv_timeout(WATCHDOG)
            .unwrap_or_else(|error| {
                panic!(
                    "{checkpoint} production READY watchdog: {error}; logs: {}",
                    self.logs.lock().unwrap()
                )
            });
    }

    fn kill_and_reap(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.kill();
        if child.wait_timeout(WATCHDOG).unwrap().is_none() {
            let _ = child.kill();
            let _ = child.wait();
            panic!("gateway reap watchdog: {}", self.logs.lock().unwrap());
        }
        self.done.recv_timeout(WATCHDOG).unwrap();
        if let Some(reader) = self.reader.take() {
            reader.join().unwrap();
        }
        if let Some(reader) = self.checkpoint_reader.take() {
            reader.join().unwrap();
        }
    }
}
impl Drop for Gateway {
    fn drop(&mut self) {
        self.kill_and_reap();
    }
}

fn client(tls: &Path) -> reqwest::Client {
    let mut identity = std::fs::read(tls.join("client.pem")).unwrap();
    identity.extend(std::fs::read(tls.join("client.key")).unwrap());
    reqwest::Client::builder()
        .no_proxy()
        .tls_certs_only([reqwest::Certificate::from_pem(
            &std::fs::read(tls.join("server-ca.pem")).unwrap(),
        )
        .unwrap()])
        .identity(reqwest::Identity::from_pem(&identity).unwrap())
        .connect_timeout(Duration::from_secs(2))
        .timeout(WATCHDOG)
        .build()
        .unwrap()
}

async fn json(request: reqwest::RequestBuilder) -> serde_json::Value {
    let deadline = tokio::time::Instant::now() + WATCHDOG;
    loop {
        match tokio::time::timeout_at(deadline, request.try_clone().unwrap().send()).await {
            Ok(Ok(response)) => {
                let status = response.status();
                let bytes = response.bytes().await.unwrap();
                assert!(
                    status.is_success(),
                    "{status}: {}",
                    String::from_utf8_lossy(&bytes)
                );
                return serde_json::from_slice(&bytes).unwrap();
            }
            Ok(Err(error)) if error.is_connect() && tokio::time::Instant::now() < deadline => {}
            Ok(Err(error)) => panic!("request failed: {error}"),
            Err(error) => panic!("request watchdog: {error}"),
        }
    }
}

async fn promoted_artifact(client: &reqwest::Client, resolver: &str) -> reqwest::Response {
    let deadline = tokio::time::Instant::now() + WATCHDOG;
    loop {
        let response = client.get(resolver).send().await.unwrap();
        if response.status() == reqwest::StatusCode::OK {
            return response;
        }
        assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
        assert!(
            tokio::time::Instant::now() < deadline,
            "artifact promotion watchdog"
        );
        // This is polling only; checkpoint channels remain the synchronization
        // mechanism for deterministic crash cuts.
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publication_stage_crash_has_no_authoritative_effect_and_restart_retries_once() {
    let Some(admin) = required("SMESH_TEST_POSTGRES_ADMIN_URL") else {
        return;
    };
    let Some(runtime) = required("SMESH_TEST_POSTGRES_RUNTIME_URL") else {
        return;
    };
    let Some(superuser) = required("SMESH_TEST_POSTGRES_SUPERUSER_URL") else {
        return;
    };
    let checkpoint = PRODUCTION_CRASH_CUTS[0];
    assert_eq!(checkpoint, "publication_stage_before_receiver_transaction");
    let fixture = Fixture::new();
    let (tls, authz, quota, keyring) = fixture.prepare();
    let schema = format!(
        "smesh_artcut_{}_{:016x}",
        std::process::id(),
        rand::random::<u64>()
    );
    let cleanup = PostgresStoreConfig::new(&admin, &runtime, &schema)
        .unwrap()
        .with_test_only_insecure_loopback(true)
        .with_test_only_parent_managed_cleanup()
        .with_quota_policy(Arc::new(
            QuotaPolicy::from_json(&std::fs::read(&quota).unwrap()).unwrap(),
        ))
        .with_artifact_store(ArtifactStoreConfig::new(fixture.0.join("cas"), &keyring).unwrap());
    let bootstrap = PostgresTaskStore::open(cleanup.clone()).await.unwrap();
    bootstrap.shutdown().await.unwrap();
    let schema_guard = SchemaGuard(Some(cleanup));
    let mut crashed = Gateway::spawn(
        &fixture,
        &tls,
        &authz,
        &quota,
        &keyring,
        &admin,
        &runtime,
        &schema,
        "publication-stage-crash",
        Some(checkpoint),
    );
    let http = client(&tls);
    let send = serde_json::json!({
        "jsonrpc":"2.0","id":"publication-stage-crash","method":a2a::jsonrpc::methods::SEND_MESSAGE,
        "params":{"message":{"messageId":"publication-stage-crash-message","role":"ROLE_USER","parts":[{"text":"publication-stage-crash-canary"}]},"configuration":{"returnImmediately":false}}
    });
    let request_http = http.clone();
    let request_url = format!("https://localhost:{}/jsonrpc", crashed.port);
    let request =
        tokio::spawn(async move { request_http.post(request_url).json(&send).send().await });
    crashed.wait_checkpoint(checkpoint);

    let pg = tokio_postgres::Config::from_str(&superuser).unwrap();
    let (db, connection) = pg.connect(tokio_postgres::NoTls).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let before = db.query_one(&format!("SELECT (SELECT count(*) FROM {schema}.artifact_manifests),(SELECT count(*) FROM {schema}.content_objects),(SELECT count(*) FROM {schema}.upload_intents),(SELECT count(*) FROM {schema}.loopback_effects)"), &[]).await.unwrap();
    for column in 0..4 {
        assert_eq!(
            before.get::<_, i64>(column),
            0,
            "{checkpoint} escaped durable effect column {column}"
        );
    }
    crashed.kill_and_reap();
    let _ = request.await;

    let mut restarted = Gateway::spawn(
        &fixture,
        &tls,
        &authz,
        &quota,
        &keyring,
        &admin,
        &runtime,
        &schema,
        "publication-stage-restart",
        None,
    );
    let replay = serde_json::json!({
        "jsonrpc":"2.0","id":"publication-stage-replay","method":a2a::jsonrpc::methods::SEND_MESSAGE,
        "params":{"message":{"messageId":"publication-stage-crash-message","role":"ROLE_USER","parts":[{"text":"publication-stage-crash-canary"}]},"configuration":{"returnImmediately":false}}
    });
    let completed = json(
        http.post(format!("https://localhost:{}/jsonrpc", restarted.port))
            .json(&replay),
    )
    .await;
    assert_eq!(
        completed["result"]["task"]["status"]["state"],
        "TASK_STATE_COMPLETED"
    );
    let after = db.query_one(&format!("SELECT (SELECT count(*) FROM {schema}.artifact_manifests),(SELECT count(*) FROM {schema}.content_objects),(SELECT COALESCE(sum(reference_count),0)::bigint FROM {schema}.content_objects),(SELECT count(*) FROM {schema}.loopback_effects)"), &[]).await.unwrap();
    assert_eq!(after.get::<_, i64>(0), 1);
    assert_eq!(after.get::<_, i64>(1), 1);
    assert_eq!(after.get::<_, Option<i64>>(2), Some(1));
    assert_eq!(after.get::<_, i64>(3), 1);
    restarted.kill_and_reap();
    drop(db);
    driver.abort();
    schema_guard.cleanup().await;
}

#[tokio::test]
async fn two_binary_artifact_publication_failover_is_manifest_only_and_exact() {
    let Some(admin) = required("SMESH_TEST_POSTGRES_ADMIN_URL") else {
        return;
    };
    let Some(runtime) = required("SMESH_TEST_POSTGRES_RUNTIME_URL") else {
        return;
    };
    let Some(superuser) = required("SMESH_TEST_POSTGRES_SUPERUSER_URL") else {
        return;
    };
    let fixture = Fixture::new();
    let (tls, authz, quota, keyring) = fixture.prepare();
    let schema = format!(
        "smesh_artp_{}_{:016x}",
        std::process::id(),
        rand::random::<u64>()
    );
    let cleanup = PostgresStoreConfig::new(&admin, &runtime, &schema)
        .unwrap()
        .with_test_only_insecure_loopback(true)
        .with_test_only_parent_managed_cleanup()
        .with_quota_policy(Arc::new(
            QuotaPolicy::from_json(&std::fs::read(&quota).unwrap()).unwrap(),
        ))
        .with_artifact_store(ArtifactStoreConfig::new(fixture.0.join("cas"), &keyring).unwrap());
    let bootstrap = PostgresTaskStore::open(cleanup.clone()).await.unwrap();
    bootstrap.shutdown().await.unwrap();
    let schema_guard = SchemaGuard(Some(cleanup.clone()));

    let mut a = Gateway::spawn(
        &fixture,
        &tls,
        &authz,
        &quota,
        &keyring,
        &admin,
        &runtime,
        &schema,
        "artifact-a",
        None,
    );
    let mut b = Gateway::spawn(
        &fixture,
        &tls,
        &authz,
        &quota,
        &keyring,
        &admin,
        &runtime,
        &schema,
        "artifact-b",
        None,
    );
    assert_ne!(a.pid(), b.pid());
    assert_ne!(a.port, b.port);
    assert_eq!(a.replica_id(), "artifact-a");
    assert_eq!(b.replica_id(), "artifact-b");
    assert_ne!(a.replica_id(), b.replica_id());
    let http = client(&tls);
    let base_a = format!("https://localhost:{}", a.port);
    let base_b = format!("https://localhost:{}", b.port);
    let canary = "héllo-🌍-BINARY-00-ff-https://127.0.0.1:9/file:data:";
    let artifact_canary = format!("SMESH accepted: {canary}");
    let send = serde_json::json!({
        "jsonrpc":"2.0","id":"artifact-send","method":a2a::jsonrpc::methods::SEND_MESSAGE,
        "params":{"message":{"messageId":"artifact-process-message","role":"ROLE_USER","parts":[{"text":canary}]},"configuration":{"returnImmediately":false}}
    });
    let admission = json(http.post(format!("{base_a}/jsonrpc")).json(&send)).await;
    let task = &admission["result"]["task"];
    let task_id = task["id"].as_str().unwrap().to_owned();
    let through_b = json(http.get(format!("{base_b}/rest/tasks/{task_id}"))).await;
    assert_eq!(through_b["status"]["state"], "TASK_STATE_COMPLETED");
    let artifact = &through_b["artifacts"][0];
    let projection = serde_json::to_string(artifact).unwrap();
    assert!(
        projection.contains("smesh-artifact-projection/v1"),
        "{projection}\nA logs:\n{}\nB logs:\n{}",
        a.logs.lock().unwrap(),
        b.logs.lock().unwrap()
    );
    assert!(!projection.contains(&artifact_canary));
    let artifact_id = artifact["artifactId"].as_str().unwrap();
    let expected = serde_json::json!({
        "taskId": task_id,
        "contextId": through_b["contextId"],
        "result": format!("SMESH accepted: {canary}"),
        "signalHash": through_b["artifacts"][0]["metadata"]["smesh.manifest"]["producer"]["dispatchId"]
    });
    let resolver = format!("{base_b}/artifacts/v1/{artifact_id}");
    let response = promoted_artifact(&http, &resolver).await;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.headers()[reqwest::header::CONTENT_TYPE],
        "application/json"
    );
    assert_eq!(
        response.headers()[reqwest::header::CONTENT_DISPOSITION],
        "attachment"
    );
    let bytes = response.bytes().await.unwrap();
    let actual: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(actual["taskId"], expected["taskId"]);
    assert_eq!(actual["contextId"], expected["contextId"]);
    assert_eq!(actual["result"], expected["result"]);
    let head = http.head(&resolver).send().await.unwrap();
    assert_eq!(head.status(), reqwest::StatusCode::OK);
    assert_eq!(head.content_length(), Some(bytes.len() as u64));
    assert!(head.bytes().await.unwrap().is_empty());

    let pg = tokio_postgres::Config::from_str(&superuser).unwrap();
    let (db, connection) = pg.connect(tokio_postgres::NoTls).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    for relation in [
        "tasks",
        "task_events",
        "idempotency_records",
        "receiver_inbox",
        "receiver_frames",
        "stream_frames",
    ] {
        let rows = db
            .query(
                &format!("SELECT row_to_json(t)::text FROM {schema}.{relation} t"),
                &[],
            )
            .await
            .unwrap();
        assert!(
            rows.iter()
                .all(|row| !row.get::<_, String>(0).contains(&artifact_canary)),
            "payload escaped into {relation}"
        );
    }
    let counts = db.query_one(&format!("SELECT (SELECT count(*) FROM {schema}.artifact_manifests),(SELECT count(*) FROM {schema}.content_objects),(SELECT COALESCE(sum(reference_count),0)::bigint FROM {schema}.content_objects)"), &[]).await.unwrap();
    assert_eq!(counts.get::<_, i64>(0), 1);
    assert_eq!(counts.get::<_, i64>(1), 1);
    assert_eq!(counts.get::<_, Option<i64>>(2), Some(1));
    let runtime_user = url::Url::parse(&runtime).unwrap().username().to_owned();
    let runtime_backends: i64 = db
        .query_one(
            "SELECT count(DISTINCT pid) FROM pg_stat_activity WHERE usename=$1 AND pid<>pg_backend_pid()",
            &[&runtime_user],
        )
        .await
        .unwrap()
        .get(0);
    assert!(
        runtime_backends >= 2,
        "two live gateway pools must own distinct PostgreSQL backends"
    );

    a.kill_and_reap();
    let replay = json(http.post(format!("{base_b}/jsonrpc")).json(&send)).await;
    assert_eq!(replay["result"]["task"]["id"], task_id);
    let after = db.query_one(&format!("SELECT count(*),(SELECT COALESCE(sum(reference_count),0)::bigint FROM {schema}.content_objects) FROM {schema}.artifact_manifests"), &[]).await.unwrap();
    assert_eq!(after.get::<_, i64>(0), 1);
    assert_eq!(after.get::<_, Option<i64>>(1), Some(1));
    b.kill_and_reap();
    drop(db);
    driver.abort();
    schema_guard.cleanup().await;
}
