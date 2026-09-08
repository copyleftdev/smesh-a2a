#![cfg(unix)]

use std::io::{BufRead as _, BufReader, Read as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
#[cfg(debug_assertions)]
use std::str::FromStr as _;
use std::sync::mpsc;
use std::time::Duration;

#[cfg(debug_assertions)]
use smesh_a2a::{
    AuthoritativeReviewCandidate, AuthorizationAuditInput, AuthorizationDecisionEffect,
    OutboxAuthority as _, OwnedTaskScope, PostgresStoreConfig, PostgresTaskStore,
    SendMessageAdmission, TaskAdmission as _, VisibilityScope,
};
use wait_timeout::ChildExt as _;

const WATCHDOG: Duration = Duration::from_secs(8);
const KEY_CANARY: &[u8; 32] = b"RATIFICATION-CANARY-123456789012";

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "smesh-ratification-process-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        copy_tls(&root);
        write_policy(&root.join("policy.json"));
        Self(root)
    }

    fn key(&self, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn copy_tls(root: &Path) {
    let output = root.join("tls");
    std::fs::create_dir(&output).unwrap();
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls");
    for name in [
        "server.pem",
        "server.key",
        "server-ca.pem",
        "client-ca.pem",
        "client.pem",
        "client.key",
        "unmapped-client.pem",
        "unmapped-client.key",
        "principals.json",
    ] {
        std::fs::copy(source.join(name), output.join(name)).unwrap();
    }
    for name in ["server.key", "client.key", "unmapped-client.key"] {
        std::fs::set_permissions(output.join(name), std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }
}

fn write_policy(path: &Path) {
    std::fs::write(
        path,
        br#"{"schemaVersion":"smesh-authz-policy/v1","policyId":"ratification-process","revision":1,"tenants":[{"id":"tenant-a","enabled":true},{"id":"tenant-b","enabled":true},{"id":"tenant-c","enabled":true}],"accounts":[{"id":"agent-17","kind":"human","memberships":[{"tenantId":"tenant-a","roles":["humanRatifier"]},{"tenantId":"tenant-b","roles":["humanRatifier"]},{"tenantId":"tenant-c","roles":["taskViewer"]}]}],"principalBindings":[{"principal":{"issuer":"mtls:test","subject":"agent-17"},"accountId":"agent-17"}]}"#,
    )
    .unwrap();
}

fn free_address(ip: &str) -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind(format!("{ip}:0")).unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    address
}

fn command(fixture: &Fixture, database: &Path, key: &Path, bind: std::net::SocketAddr) -> Command {
    let tls = fixture.0.join("tls");
    let mut command = Command::new(env!("CARGO_BIN_EXE_smesh-a2a-gateway"));
    command
        .env_clear()
        .env("RUST_LOG", "info")
        .env("SMESH_A2A_AUTH_MODE", "disabled")
        .env("SMESH_A2A_CLIENT_AUTH_MODE", "required")
        .env("SMESH_A2A_MODE", "loopback")
        .env("SMESH_A2A_BIND", bind.to_string())
        .env(
            "SMESH_A2A_PUBLIC_URL",
            format!("https://localhost:{}", bind.port()),
        )
        .env("SMESH_A2A_DURABLE_BACKEND", "sqlite")
        .env("SMESH_A2A_SQLITE_PATH", database)
        .env("SMESH_A2A_RATIFICATION_HMAC_KEY_PATH", key)
        .env(
            "SMESH_A2A_AUTHORIZATION_POLICY_PATH",
            fixture.0.join("policy.json"),
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
    command
}

fn failed(mut command: Command) -> String {
    let mut child = command.spawn().unwrap();
    let status = child.wait_timeout(WATCHDOG).unwrap().unwrap_or_else(|| {
        let _ = child.kill();
        let _ = child.wait();
        panic!("gateway startup failure watchdog expired")
    });
    assert!(!status.success());
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    stderr
}

struct Running {
    child: Child,
    complete: mpsc::Receiver<String>,
    reader: Option<std::thread::JoinHandle<()>>,
}

fn launch(mut command: Command) -> Running {
    let mut child = command.spawn().unwrap();
    let stderr = child.stderr.take().unwrap();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (complete_tx, complete_rx) = mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let mut captured = String::new();
        let mut announced = false;
        for line in BufReader::new(stderr).lines() {
            let line = line.unwrap();
            captured.push_str(&line);
            captured.push('\n');
            if !announced && line.contains("gateway listening") {
                ready_tx.send(()).unwrap();
                announced = true;
            }
        }
        let _ = complete_tx.send(captured);
    });
    ready_rx.recv_timeout(WATCHDOG).unwrap_or_else(|error| {
        let _ = child.kill();
        let _ = child.wait();
        let captured = complete_rx
            .recv_timeout(WATCHDOG)
            .unwrap_or_else(|_| "<stderr unavailable>".to_owned());
        panic!("gateway readiness watchdog failed: {error}: {captured}")
    });
    Running {
        child,
        complete: complete_rx,
        reader: Some(reader),
    }
}

impl Running {
    fn stop(mut self) -> String {
        assert!(
            Command::new("kill")
                .args(["-TERM", &self.child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        self.child
            .wait_timeout(WATCHDOG)
            .unwrap()
            .unwrap_or_else(|| {
                let _ = self.child.kill();
                self.child.wait().unwrap()
            });
        let captured = self.complete.recv_timeout(WATCHDOG).unwrap();
        self.reader.take().unwrap().join().unwrap();
        captured
    }
}

fn assert_database_absent(database: &Path) {
    for path in [
        database.to_path_buf(),
        PathBuf::from(format!("{}-wal", database.display())),
        PathBuf::from(format!("{}-shm", database.display())),
    ] {
        assert!(
            !path.exists(),
            "unexpected durable resource: {}",
            path.display()
        );
    }
}

#[test]
fn ratification_rejects_insecure_files_and_non_loopback_before_resources() {
    let fixture = Fixture::new();
    let database = fixture.0.join("must-not-exist.sqlite3");
    let insecure = fixture.key("PATH-CANARY", KEY_CANARY, 0o640);
    let stderr = failed(command(
        &fixture,
        &database,
        &insecure,
        free_address("127.0.0.1"),
    ));
    assert_database_absent(&database);
    assert!(!stderr.contains("PATH-CANARY"));
    assert!(!stderr.contains("RATIFICATION-CANARY"));
    assert!(!stderr.contains("gateway listening"));

    let secure = fixture.key("key", KEY_CANARY, 0o600);
    for bind in [
        free_address("0.0.0.0"),
        free_address("::"),
        "192.0.2.1:31027".parse().unwrap(),
    ] {
        let stderr = failed(command(&fixture, &database, &secure, bind));
        assert!(stderr.contains("ratification requires a loopback bind IP"));
        assert!(!stderr.contains("gateway listening"));
        assert_database_absent(&database);
    }

    if let Ok(listener) = std::net::TcpListener::bind("[::1]:0") {
        let bind = listener.local_addr().unwrap();
        let stderr = failed(command(&fixture, &database, &secure, bind));
        assert!(!stderr.contains("ratification requires a loopback bind IP"));
        assert_database_absent(&database);
    }
}

#[test]
fn occupied_bind_fails_before_database_telemetry_runtime_or_readiness() {
    let fixture = Fixture::new();
    let database = fixture.0.join("must-not-exist.sqlite3");
    let key = fixture.key("key", KEY_CANARY, 0o600);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let bind = listener.local_addr().unwrap();
    let mut disabled = command(&fixture, &database, &key, bind);
    disabled.env_remove("SMESH_A2A_RATIFICATION_HMAC_KEY_PATH");
    let disabled_stderr = failed(disabled);
    assert!(!disabled_stderr.contains("ratification requires"));
    assert_database_absent(&database);

    let mut process = command(&fixture, &database, &key, bind);
    process
        .env("SMESH_A2A_OTLP_MODE", "http-protobuf")
        .env("SMESH_A2A_OTLP_ENDPOINT", "http://127.0.0.1:9/")
        .env("SMESH_TEST_OTLP_INSECURE_LOOPBACK", "1");
    let stderr = failed(process);
    drop(listener);
    assert_database_absent(&database);
    assert!(!stderr.contains("gateway listening"));
    assert!(!stderr.contains("RATIFICATION-CANARY"));
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn production_binary_installs_authenticated_routes_and_binds_restart_key() {
    let fixture = Fixture::new();
    let database = fixture.0.join("tasks.sqlite3");
    let key = fixture.key("key", KEY_CANARY, 0o600);
    let bind = free_address("127.0.0.1");
    let mut startup = command(&fixture, &database, &key, bind);
    if cfg!(debug_assertions) {
        startup
            .env("SMESH_A2A_OTLP_MODE", "http-protobuf")
            .env("SMESH_A2A_OTLP_ENDPOINT", "http://127.0.0.1:9/")
            .env("SMESH_TEST_OTLP_INSECURE_LOOPBACK", "1")
            .env("SMESH_A2A_OTLP_EXPORT_TIMEOUT_MILLIS", "100")
            .env("SMESH_A2A_OTLP_SHUTDOWN_TIMEOUT_MILLIS", "1000");
    }
    let process = launch(startup);

    let tls = fixture.0.join("tls");
    let unauthenticated = reqwest::Client::builder()
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(tls.join("server-ca.pem")).unwrap())
                .unwrap(),
        )
        .build()
        .unwrap();
    let unauthenticated_result = tokio::time::timeout(
        WATCHDOG,
        unauthenticated
            .get(format!(
                "https://localhost:{}/ratification/v1/tasks/missing",
                bind.port()
            ))
            .send(),
    )
    .await
    .unwrap();
    assert!(unauthenticated_result.is_err());

    let mut identity = std::fs::read(tls.join("client.pem")).unwrap();
    identity.extend_from_slice(&std::fs::read(tls.join("client.key")).unwrap());
    let client = reqwest::Client::builder()
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(tls.join("server-ca.pem")).unwrap())
                .unwrap(),
        )
        .identity(reqwest::Identity::from_pem(&identity).unwrap())
        .build()
        .unwrap();
    let console = tokio::time::timeout(
        WATCHDOG,
        client
            .get(format!(
                "https://localhost:{}/ratification/console",
                bind.port()
            ))
            .send(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(console.status(), reqwest::StatusCode::OK);
    assert_eq!(console.headers()["cache-control"], "private, no-store");
    assert_eq!(console.headers()["referrer-policy"], "no-referrer");
    assert_eq!(
        console.headers()["content-security-policy"],
        "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; img-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    );
    let console_body = tokio::time::timeout(WATCHDOG, console.bytes())
        .await
        .unwrap()
        .unwrap();
    assert!(
        !console_body
            .windows(KEY_CANARY.len())
            .any(|window| window == KEY_CANARY)
    );
    assert!(
        !console_body
            .windows(b"missing".len())
            .any(|window| window == b"missing")
    );
    let response = tokio::time::timeout(
        WATCHDOG,
        client
            .post(format!(
                "https://localhost:{}/ratification/v1/tasks/missing/decision",
                bind.port()
            ))
            .header("x-smesh-tenant", "tenant-a")
            .header("origin", format!("https://localhost:{}", bind.port()))
            .header(
                "if-match",
                "\"sha256:0000000000000000000000000000000000000000000000000000000000000000:0\"",
            )
            .json(&serde_json::json!({}))
            .send(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()["cache-control"], "private, no-store");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert!(
        response
            .headers()
            .get("access-control-allow-origin")
            .is_none()
    );
    let response_body = tokio::time::timeout(WATCHDOG, response.bytes())
        .await
        .unwrap()
        .unwrap();
    assert!(
        !response_body
            .windows(KEY_CANARY.len())
            .any(|window| window == KEY_CANARY)
    );
    let stderr = process.stop();
    assert!(!stderr.contains("RATIFICATION-CANARY"));
    let database_view = rusqlite::Connection::open(&database).unwrap();
    assert_eq!(
        database_view
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='audit_projection_outbox'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    drop(database_view);

    let wrong = fixture.key("wrong", &[0x5a; 32], 0o600);
    let wrong_stderr = failed(command(&fixture, &database, &wrong, bind));
    assert!(!wrong_stderr.contains("RATIFICATION-CANARY"));
    assert!(!wrong_stderr.contains("gateway listening"));

    let restarted = launch(command(&fixture, &database, &key, bind));
    let stderr = restarted.stop();
    assert!(!stderr.contains("RATIFICATION-CANARY"));
    for path in [
        database.clone(),
        PathBuf::from(format!("{}-wal", database.display())),
        PathBuf::from(format!("{}-shm", database.display())),
    ] {
        if let Ok(bytes) = std::fs::read(path) {
            assert!(
                !bytes
                    .windows(KEY_CANARY.len())
                    .any(|window| window == KEY_CANARY)
            );
        }
    }
}

#[allow(clippy::too_many_lines)] // One production PostgreSQL lifecycle intentionally stays linear.
#[cfg(debug_assertions)]
async fn seed_postgres_packet(config: PostgresStoreConfig, policy_digest: String) -> String {
    let store =
        PostgresTaskStore::open(config.with_ratification_key(zeroize::Zeroizing::new(*KEY_CANARY)))
            .await
            .unwrap();
    let now = 1_700_000_020_000;
    let task_id = "production-postgres-ratification".to_owned();
    let mut message = a2a::Message::new(a2a::Role::User, vec![a2a::Part::text("qualify release")]);
    message.message_id = "production-postgres-message".into();
    let request = a2a::SendMessageRequest {
        message: message.clone(),
        configuration: None,
        metadata: None,
        tenant: None,
    };
    let task = a2a::Task {
        id: task_id.clone(),
        context_id: "production-postgres-context".into(),
        status: a2a::TaskStatus {
            state: a2a::TaskState::Submitted,
            message: None,
            timestamp: chrono::DateTime::from_timestamp_millis(now),
        },
        artifacts: None,
        history: Some(vec![message]),
        metadata: None,
    };
    let admission = SendMessageAdmission {
        request,
        streaming: false,
        task: task.clone(),
        original_result: a2a::SendMessageResponse::Task(task),
        input_limits: smesh_a2a::InputLimits::default(),
        now,
        max_attempts: 8,
    };
    let principal = smesh_a2a::content_digest(b"production-postgres-owner");
    let scope = OwnedTaskScope::new_with_principal_and_authentication(
        "tenant-a",
        "agent-17",
        principal,
        VisibilityScope::Own,
        "mtls",
    )
    .unwrap();
    let audit = AuthorizationAuditInput::new(
        "production-postgres-admission",
        "tenant-a",
        "agent-17",
        "ratification-process",
        1,
        policy_digest,
        "TaskSend",
        AuthorizationDecisionEffect::Allow,
        "production qualification",
        "task",
        smesh_a2a::content_digest(task_id.as_bytes()),
        Some(task_id.clone()),
        now,
    )
    .unwrap();
    store
        .authorize_and_admit(&scope, admission, audit)
        .await
        .unwrap();
    let lease = store
        .claim_outbox("production-postgres-worker", now + 1, 60_000)
        .await
        .unwrap()
        .unwrap();
    let initial = store.task_for_outbox(&lease).await.unwrap().unwrap();
    let mut approved = initial.clone();
    approved.status = a2a::TaskStatus {
        state: a2a::TaskState::Completed,
        message: Some(a2a::Message::new(
            a2a::Role::Agent,
            vec![a2a::Part::text("qualified candidate")],
        )),
        timestamp: chrono::DateTime::from_timestamp_millis(now + 2),
    };
    approved.artifacts = Some(vec![a2a::Artifact {
        artifact_id: "production-qualified-artifact".into(),
        name: Some("release.txt".into()),
        description: None,
        parts: vec![a2a::Part::text("private until approved")],
        metadata: None,
        extensions: None,
    }]);
    store
        .commit_delivery_for_ratification(
            &lease,
            approved.clone(),
            a2a::SendMessageResponse::Task(approved.clone()),
            &[
                a2a::StreamResponse::Task(initial),
                a2a::StreamResponse::Task(approved),
            ],
            AuthoritativeReviewCandidate::new(
                "production-release-policy",
                1,
                smesh_a2a::content_digest(b"production-release-policy-v1"),
                b"production-checkpoint".to_vec(),
                vec![b"production evidence".to_vec()],
                "production uncertainty",
            )
            .unwrap(),
            now + 2,
        )
        .await
        .unwrap();
    drop(store);
    task_id
}

#[tokio::test]
#[cfg(debug_assertions)]
#[allow(clippy::too_many_lines)]
async fn production_postgres_binary_qualifies_ratification_routes() {
    let admin = match std::env::var("SMESH_TEST_POSTGRES_ADMIN_URL") {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent)
            if std::env::var("SMESH_POSTGRES_TEST_REQUIRED").as_deref() == Ok("1") =>
        {
            panic!("SMESH_TEST_POSTGRES_ADMIN_URL is required")
        }
        Err(std::env::VarError::NotPresent) => return,
        Err(error) => panic!("SMESH_TEST_POSTGRES_ADMIN_URL is invalid: {error}"),
    };
    let runtime = std::env::var("SMESH_TEST_POSTGRES_RUNTIME_URL")
        .expect("SMESH_TEST_POSTGRES_RUNTIME_URL is required");
    tokio_postgres::Config::from_str(&admin).unwrap();
    tokio_postgres::Config::from_str(&runtime).unwrap();

    let fixture = Fixture::new();
    let database = fixture.0.join("unused.sqlite3");
    let key = fixture.key("key", KEY_CANARY, 0o600);
    let bind = free_address("127.0.0.1");
    let schema = format!("smesh_ratification_binary_{:016x}", rand::random::<u64>());
    let cleanup = PostgresStoreConfig::new(&admin, &runtime, &schema)
        .unwrap()
        .with_test_only_insecure_loopback(true);
    let seed_config = PostgresStoreConfig::new(&admin, &runtime, &schema)
        .unwrap()
        .with_test_only_insecure_loopback(true)
        .with_test_only_parent_managed_cleanup();
    let policy_digest =
        smesh_a2a::content_digest(&std::fs::read(fixture.0.join("policy.json")).unwrap());
    let task_id = seed_postgres_packet(seed_config, policy_digest).await;
    let mut startup = command(&fixture, &database, &key, bind);
    startup
        .env_remove("SMESH_A2A_SQLITE_PATH")
        .env("SMESH_A2A_DURABLE_BACKEND", "postgres")
        .env("SMESH_A2A_POSTGRES_MIGRATOR_URL", &admin)
        .env("SMESH_A2A_POSTGRES_RUNTIME_URL", &runtime)
        .env("SMESH_A2A_POSTGRES_SCHEMA", &schema)
        .env(
            "SMESH_A2A_QUOTA_POLICY_PATH",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/quota-policy.json"
            ),
        )
        .env("SMESH_A2A_REPLICA_ID", "ratification-binary-pg")
        .env("SMESH_TEST_POSTGRES_INSECURE_LOOPBACK", "1")
        .env("SMESH_TEST_POSTGRES_PARENT_MANAGED_CLEANUP", "1");
    let process = launch(startup);

    let tls = fixture.0.join("tls");
    let mut identity = std::fs::read(tls.join("client.pem")).unwrap();
    identity.extend_from_slice(&std::fs::read(tls.join("client.key")).unwrap());
    let client = reqwest::Client::builder()
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(tls.join("server-ca.pem")).unwrap())
                .unwrap(),
        )
        .identity(reqwest::Identity::from_pem(&identity).unwrap())
        .build()
        .unwrap();
    let base = format!("https://localhost:{}", bind.port());
    let console = tokio::time::timeout(
        WATCHDOG,
        client.get(format!("{base}/ratification/console")).send(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(console.status(), reqwest::StatusCode::OK);
    assert_eq!(console.headers()["cache-control"], "private, no-store");
    let bytes = tokio::time::timeout(WATCHDOG, console.bytes())
        .await
        .unwrap()
        .unwrap();
    assert!(
        !bytes
            .windows(KEY_CANARY.len())
            .any(|window| window == KEY_CANARY)
    );

    let get_view = |client: &reqwest::Client, base: &str, task_id: &str| {
        client
            .get(format!("{base}/ratification/v1/tasks/{task_id}"))
            .header("x-smesh-tenant", "tenant-a")
    };
    let view_response = tokio::time::timeout(WATCHDOG, get_view(&client, &base, &task_id).send())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(view_response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        view_response.headers()["cache-control"],
        "private, no-store"
    );
    let etag = view_response.headers()["etag"].to_str().unwrap().to_owned();
    assert!(etag.starts_with("\"ratification-v1:"));
    let view: serde_json::Value = view_response.json().await.unwrap();
    assert_eq!(view["phase"], "awaitingReview");
    assert_eq!(view["revision"], 0);
    let packet = &view["packet"];
    let mut unmapped_identity = std::fs::read(tls.join("unmapped-client.pem")).unwrap();
    unmapped_identity.extend_from_slice(&std::fs::read(tls.join("unmapped-client.key")).unwrap());
    let unauthenticated = reqwest::Client::builder()
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(tls.join("server-ca.pem")).unwrap())
                .unwrap(),
        )
        .identity(reqwest::Identity::from_pem(&unmapped_identity).unwrap())
        .build()
        .unwrap();
    for (name, request, expected) in [
        (
            "postgres-generation-success",
            client
                .get(format!(
                    "{base}/ratification/v1/tasks/{task_id}/generations/1"
                ))
                .header("x-smesh-tenant", "tenant-a"),
            reqwest::StatusCode::OK,
        ),
        (
            "postgres-generation-missing",
            client
                .get(format!(
                    "{base}/ratification/v1/tasks/{task_id}/generations/2"
                ))
                .header("x-smesh-tenant", "tenant-a"),
            reqwest::StatusCode::NOT_FOUND,
        ),
        (
            "postgres-generation-cross-tenant",
            client
                .get(format!(
                    "{base}/ratification/v1/tasks/{task_id}/generations/1"
                ))
                .header("x-smesh-tenant", "tenant-b"),
            reqwest::StatusCode::NOT_FOUND,
        ),
        (
            "postgres-generation-role-denied",
            client
                .get(format!(
                    "{base}/ratification/v1/tasks/{task_id}/generations/1"
                ))
                .header("x-smesh-tenant", "tenant-c"),
            reqwest::StatusCode::FORBIDDEN,
        ),
        (
            "postgres-generation-zero",
            client
                .get(format!(
                    "{base}/ratification/v1/tasks/{task_id}/generations/0"
                ))
                .header("x-smesh-tenant", "tenant-a"),
            reqwest::StatusCode::BAD_REQUEST,
        ),
        (
            "postgres-generation-overflow",
            client
                .get(format!(
                    "{base}/ratification/v1/tasks/{task_id}/generations/18446744073709551616"
                ))
                .header("x-smesh-tenant", "tenant-a"),
            reqwest::StatusCode::BAD_REQUEST,
        ),
        (
            "postgres-generation-unauthenticated",
            unauthenticated.get(format!(
                "{base}/ratification/v1/tasks/{task_id}/generations/1"
            )),
            reqwest::StatusCode::UNAUTHORIZED,
        ),
    ] {
        let response = tokio::time::timeout(WATCHDOG, request.send())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), expected, "{name}");
        assert_eq!(
            response.headers()["cache-control"],
            "private, no-store",
            "{name}"
        );
        assert_eq!(
            response.headers()["x-content-type-options"],
            "nosniff",
            "{name}"
        );
        assert_eq!(
            response.headers()["referrer-policy"],
            "no-referrer",
            "{name}"
        );
    }
    let fresh = tokio::time::timeout(WATCHDOG, get_view(&client, &base, &task_id).send())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fresh.status(), reqwest::StatusCode::OK);
    let etag = fresh.headers()["etag"].to_str().unwrap().to_owned();
    let review = tokio::time::timeout(
        WATCHDOG,
        client
            .post(format!("{base}/ratification/v1/tasks/{task_id}/review"))
            .header("x-smesh-tenant", "tenant-a")
            .header("origin", &base)
            .header("if-match", &etag)
            .header("idempotency-key", "production-review-nonce")
            .json(&serde_json::json!({
                "evidenceHashes": packet["evidenceHashes"],
                "artifactHashes": packet["artifacts"].as_array().unwrap().iter().map(|artifact| artifact["digest"].clone()).collect::<Vec<_>>(),
                "artifactManifestDigest": packet["artifactSetDigest"],
                "uncertaintyAcknowledged": true
            }))
            .send(),
    )
    .await
    .unwrap()
    .unwrap();
    let review_status = review.status();
    let review_text = review.text().await.unwrap();
    assert_eq!(
        review_status,
        reqwest::StatusCode::CREATED,
        "review body: {review_text}"
    );
    let review_receipt: serde_json::Value = serde_json::from_str(&review_text).unwrap();
    assert_eq!(review_receipt["revision"], 1);
    assert_eq!(review_receipt["action"]["kind"], "reviewAcknowledged");
    let reviewed_response =
        tokio::time::timeout(WATCHDOG, get_view(&client, &base, &task_id).send())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(reviewed_response.status(), reqwest::StatusCode::OK);
    let reviewed_etag = reviewed_response.headers()["etag"]
        .to_str()
        .unwrap()
        .to_owned();
    let reviewed: serde_json::Value = reviewed_response.json().await.unwrap();
    assert_eq!(reviewed["phase"], "reviewed");
    assert_eq!(reviewed["history"].as_array().unwrap().len(), 1);

    let decision = tokio::time::timeout(
        WATCHDOG,
        client
            .post(format!("{base}/ratification/v1/tasks/{task_id}/decision"))
            .header("x-smesh-tenant", "tenant-a")
            .header("origin", &base)
            .header("if-match", &reviewed_etag)
            .header("idempotency-key", "production-amend-nonce")
            .json(&serde_json::json!({
                "decision": "amend",
                "rationale": "production path qualified"
            }))
            .send(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(decision.status(), reqwest::StatusCode::CREATED);
    let decision_etag = decision.headers()["etag"].to_str().unwrap().to_owned();
    let decision_bytes = decision.bytes().await.unwrap();
    let decision_receipt: serde_json::Value = serde_json::from_slice(&decision_bytes).unwrap();
    assert_eq!(decision_receipt["revision"], 2);
    assert_eq!(decision_receipt["action"]["kind"], "decision");
    assert_eq!(decision_receipt["action"]["decision"], "amend");

    let audits_before_replay = {
        let (audit_client, audit_connection) =
            tokio_postgres::connect(&admin, tokio_postgres::NoTls)
                .await
                .unwrap();
        let audit_driver = tokio::spawn(audit_connection);
        audit_client
            .batch_execute("SET smesh.internal_global='diag-v1'")
            .await
            .unwrap();
        let count = audit_client
            .query_one(
                &format!("SELECT count(*) FROM {schema}.authorization_decisions"),
                &[],
            )
            .await
            .unwrap()
            .get::<_, i64>(0);
        drop(audit_client);
        audit_driver.abort();
        count
    };
    let replay = tokio::time::timeout(
        WATCHDOG,
        client
            .post(format!("{base}/ratification/v1/tasks/{task_id}/decision"))
            .header("x-smesh-tenant", "tenant-a")
            .header("origin", &base)
            .header("if-match", &reviewed_etag)
            .header("idempotency-key", "production-amend-nonce")
            .json(&serde_json::json!({
                "decision": "amend",
                "rationale": "production path qualified"
            }))
            .send(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(replay.status(), reqwest::StatusCode::CREATED);
    assert_eq!(replay.headers()["etag"], decision_etag);
    assert_eq!(replay.bytes().await.unwrap(), decision_bytes);
    let (audit_client, audit_connection) = tokio_postgres::connect(&admin, tokio_postgres::NoTls)
        .await
        .unwrap();
    let audit_driver = tokio::spawn(audit_connection);
    audit_client
        .batch_execute("SET smesh.internal_global='diag-v1'")
        .await
        .unwrap();
    assert_eq!(
        audit_client
            .query_one(
                &format!("SELECT count(*) FROM {schema}.authorization_decisions"),
                &[],
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        audits_before_replay + 1
    );
    drop(audit_client);
    audit_driver.abort();
    let decided_response =
        tokio::time::timeout(WATCHDOG, get_view(&client, &base, &task_id).send())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(decided_response.status(), reqwest::StatusCode::OK);
    let decided: serde_json::Value = decided_response.json().await.unwrap();
    assert_eq!(decided["phase"], "amended");
    assert_eq!(decided["revision"], 2);
    assert_eq!(decided["history"].as_array().unwrap().len(), 2);

    let stderr = process.stop();
    assert!(!stderr.contains("RATIFICATION-CANARY"));
    assert!(!database.exists());

    let mut restart = command(&fixture, &database, &key, bind);
    restart
        .env_remove("SMESH_A2A_SQLITE_PATH")
        .env("SMESH_A2A_DURABLE_BACKEND", "postgres")
        .env("SMESH_A2A_POSTGRES_MIGRATOR_URL", &admin)
        .env("SMESH_A2A_POSTGRES_RUNTIME_URL", &runtime)
        .env("SMESH_A2A_POSTGRES_SCHEMA", &schema)
        .env(
            "SMESH_A2A_QUOTA_POLICY_PATH",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/quota-policy.json"
            ),
        )
        .env("SMESH_A2A_REPLICA_ID", "ratification-binary-pg-restart")
        .env("SMESH_TEST_POSTGRES_INSECURE_LOOPBACK", "1")
        .env("SMESH_TEST_POSTGRES_PARENT_MANAGED_CLEANUP", "1");
    let restarted = launch(restart);
    let mut restart_identity = std::fs::read(tls.join("client.pem")).unwrap();
    restart_identity.extend_from_slice(&std::fs::read(tls.join("client.key")).unwrap());
    let restart_client = reqwest::Client::builder()
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(tls.join("server-ca.pem")).unwrap())
                .unwrap(),
        )
        .identity(reqwest::Identity::from_pem(&restart_identity).unwrap())
        .build()
        .unwrap();
    let persisted =
        tokio::time::timeout(WATCHDOG, get_view(&restart_client, &base, &task_id).send())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(persisted.status(), reqwest::StatusCode::OK);
    let persisted: serde_json::Value = persisted.json().await.unwrap();
    assert_eq!(persisted["phase"], "amended");
    assert_eq!(persisted["history"].as_array().unwrap().len(), 2);

    let (admin_client, admin_connection) = tokio_postgres::connect(&admin, tokio_postgres::NoTls)
        .await
        .unwrap();
    let admin_driver = tokio::spawn(admin_connection);
    admin_client
        .batch_execute("SET smesh.internal_global='diag-v1'")
        .await
        .unwrap();
    let effects = admin_client.query_one(
        &format!("SELECT (SELECT state='\"TASK_STATE_COMPLETED\"' FROM {schema}.tasks WHERE task_id=$1),(SELECT count(*) FROM {schema}.ratification_events WHERE task_id=$1),(SELECT EXISTS(SELECT 1 FROM {schema}.idempotency_records WHERE task_id=$1 AND final_result_json IS NOT NULL))"),
        &[&task_id],
    ).await.unwrap();
    assert_eq!(effects.get::<_, Option<bool>>(0), Some(false));
    assert_eq!(effects.get::<_, i64>(1), 2);
    assert!(effects.get::<_, bool>(2));
    drop(admin_client);
    admin_driver.abort();
    let restart_stderr = restarted.stop();
    assert!(!restart_stderr.contains("RATIFICATION-CANARY"));
    PostgresTaskStore::drop_test_schema(&cleanup).await.unwrap();
}
