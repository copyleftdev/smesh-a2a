#![cfg(unix)]

use std::io::{BufRead as _, BufReader};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use a2a::{Task, TaskState, TaskStatus};
use smesh_a2a::content_digest;
use wait_timeout::ChildExt as _;

const WATCHDOG: Duration = Duration::from_secs(8);

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "smesh-authorized-process-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct ChildGuard {
    child: Option<Child>,
    reader: Option<std::thread::JoinHandle<()>>,
    reader_done: mpsc::Receiver<()>,
}

impl ChildGuard {
    fn finish_reader(&mut self) {
        if self.reader.is_none() {
            return;
        }
        self.reader_done
            .recv_timeout(WATCHDOG)
            .expect("stderr reader completion watchdog");
        if let Some(reader) = self.reader.take() {
            reader.join().expect("join stderr reader");
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            if child
                .wait_timeout(Duration::from_secs(2))
                .ok()
                .flatten()
                .is_none()
            {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        self.finish_reader();
    }
}

fn copy_tls(root: &Path) -> PathBuf {
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
        "principals.json",
    ] {
        std::fs::copy(source.join(name), output.join(name)).unwrap();
    }
    for name in ["server.key", "client.key"] {
        std::fs::set_permissions(output.join(name), std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }
    output
}

fn policy(path: &Path) {
    std::fs::write(
        path,
        br#"{
          "schemaVersion":"smesh-authz-policy/v1",
          "policyId":"process-policy",
          "revision":13,
          "tenants":[{"id":"tenant-a","enabled":true}],
          "accounts":[{"id":"agent-17","kind":"serviceAccount","memberships":[{"tenantId":"tenant-a","roles":["taskAgent"]}]}],
          "principalBindings":[{"principal":{"issuer":"mtls:test","subject":"agent-17"},"accountId":"agent-17"}]
        }"#,
    )
    .unwrap();
}

fn create_legacy_v1(path: &Path) -> Task {
    const V1: &str = "CREATE TABLE store_metadata (
     singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
     schema_version INTEGER NOT NULL,
     migration_hash TEXT NOT NULL,
     cursor_key BLOB NOT NULL CHECK (length(cursor_key) = 32),
     receipt_key BLOB NOT NULL CHECK (length(receipt_key) = 32)
 );
 CREATE TABLE tasks (
     created_order INTEGER PRIMARY KEY AUTOINCREMENT,
     task_id TEXT NOT NULL UNIQUE,
     context_id TEXT NOT NULL,
     state TEXT NOT NULL,
     status_timestamp TEXT,
     revision INTEGER NOT NULL CHECK (revision > 0),
     task_json TEXT NOT NULL
 );
 CREATE INDEX tasks_context_state_time
     ON tasks(context_id, state, status_timestamp, task_id);";
    let task = Task {
        id: "legacy-visible".into(),
        context_id: "legacy-context".into(),
        status: TaskStatus {
            state: TaskState::Completed,
            message: None,
            timestamp: None,
        },
        artifacts: None,
        history: None,
        metadata: None,
    };
    let db = rusqlite::Connection::open(path).unwrap();
    db.execute_batch(V1).unwrap();
    db.execute(
        "INSERT INTO store_metadata(singleton,schema_version,migration_hash,cursor_key,receipt_key) VALUES(1,1,?1,?2,?3)",
        rusqlite::params![content_digest(V1.as_bytes()), [7_u8; 32], [9_u8; 32]],
    )
    .unwrap();
    db.execute(
        "INSERT INTO tasks(task_id,context_id,state,revision,task_json) VALUES(?1,?2,?3,4,?4)",
        rusqlite::params![
            task.id,
            task.context_id,
            serde_json::to_string(&TaskState::Completed).unwrap(),
            serde_json::to_string(&task).unwrap()
        ],
    )
    .unwrap();
    db.pragma_update(None, "application_id", 0x534D_4132_i64)
        .unwrap();
    db.pragma_update(None, "user_version", 1_i64).unwrap();
    task
}

fn free_address() -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    address
}

fn command(root: &Path, database: &Path, bind: std::net::SocketAddr) -> Command {
    let tls = root.join("tls");
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
        .env("SMESH_A2A_SQLITE_PATH", database)
        .env(
            "SMESH_A2A_AUTHORIZATION_POLICY_PATH",
            root.join("policy.json"),
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

fn launch(mut command: Command) -> ChildGuard {
    let mut child = command.spawn().unwrap();
    let stderr = child.stderr.take().unwrap();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let mut captured = String::new();
        let mut ready = false;
        for line in BufReader::new(stderr).lines() {
            match line {
                Ok(line) => {
                    captured.push_str(&line);
                    captured.push('\n');
                    if !ready && line.contains("gateway listening") {
                        let _ = ready_tx.send(Ok(captured.clone()));
                        ready = true;
                    }
                }
                Err(error) => {
                    if !ready {
                        let _ =
                            ready_tx.send(Err(format!("stderr read failed: {error}; {captured}")));
                    }
                    let _ = done_tx.send(());
                    return;
                }
            }
        }
        if !ready {
            let _ = ready_tx.send(Err(format!("gateway exited before readiness: {captured}")));
        }
        let _ = done_tx.send(());
    });
    let mut process = ChildGuard {
        child: Some(child),
        reader: Some(reader),
        reader_done: done_rx,
    };
    match ready_rx.recv_timeout(WATCHDOG) {
        Ok(Ok(_)) => process,
        Ok(Err(error)) => {
            if let Some(mut child) = process.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            process.finish_reader();
            panic!("{error}")
        }
        Err(error) => {
            if let Some(mut child) = process.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            process.finish_reader();
            panic!("gateway readiness watchdog: {error}")
        }
    }
}

fn bounded_failed_start(child: &mut Child, label: &str) -> std::process::ExitStatus {
    child
        .wait_timeout(WATCHDOG)
        .unwrap_or_else(|error| panic!("{label} wait failed: {error}"))
        .unwrap_or_else(|| {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{label} did not fail within watchdog")
        })
}

fn stop(mut child: ChildGuard) {
    let process = child.child.as_mut().unwrap();
    let status = Command::new("kill")
        .args(["-TERM", &process.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let exit = process.wait_timeout(WATCHDOG).unwrap().unwrap_or_else(|| {
        let _ = process.kill();
        process.wait().expect("reap gateway after shutdown timeout")
    });
    assert!(exit.success(), "gateway did not shut down cleanly: {exit}");
    child.child = None;
    child.finish_reader();
}

fn mtls_client(tls: &Path) -> reqwest::Client {
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
    let response = loop {
        let attempt = request.try_clone().expect("request body is replayable");
        match tokio::time::timeout_at(deadline, attempt.send()).await {
            Ok(Ok(response)) => break response,
            Ok(Err(error)) if error.is_connect() && tokio::time::Instant::now() < deadline => {
                // A successful readiness log precedes the server accept future by a few
                // instructions. Retry only after a completed connection event; no polling pause.
            }
            Ok(Err(error)) => panic!("network request failed: {error:?}"),
            Err(error) => panic!("network watchdog expired: {error}"),
        }
    };
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
#[allow(clippy::too_many_lines)]
async fn production_mtls_gateway_migrates_restarts_and_serves_both_protocols() {
    let fixture = Fixture::new();
    let tls = copy_tls(&fixture.0);
    policy(&fixture.0.join("policy.json"));
    let database = fixture.0.join("tasks.sqlite3");
    let legacy = create_legacy_v1(&database);

    // No implicit legacy authority: startup fails before listening and leaves v1 unchanged.
    let address = free_address();
    let mut refused = command(&fixture.0, &database, address)
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let status = bounded_failed_start(&mut refused, "legacy refusal");
    assert!(!status.success());
    let db = rusqlite::Connection::open(&database).unwrap();
    assert_eq!(
        db.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM tasks", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
    drop(db);

    // A mismatched explicit binding is rejected by policy resolution and is equally atomic.
    let address = free_address();
    let mut mismatch = command(&fixture.0, &database, address);
    mismatch
        .env("SMESH_A2A_LEGACY_TENANT_ID", "tenant-a")
        .env("SMESH_A2A_LEGACY_OWNER_ACCOUNT_ID", "foreign-owner")
        .stderr(Stdio::null());
    let mut mismatch = mismatch.spawn().unwrap();
    let status = bounded_failed_start(&mut mismatch, "legacy mismatch");
    assert!(!status.success());
    let db = rusqlite::Connection::open(&database).unwrap();
    assert_eq!(
        db.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM tasks", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
    drop(db);

    let address = free_address();
    let mut enrolled = command(&fixture.0, &database, address);
    enrolled
        .env("SMESH_A2A_LEGACY_TENANT_ID", "tenant-a")
        .env("SMESH_A2A_LEGACY_OWNER_ACCOUNT_ID", "agent-17");
    let child = launch(enrolled);
    let client = mtls_client(&tls);
    let base = format!("https://localhost:{}", address.port());

    let migrated = json(client.get(format!("{base}/rest/tasks/{}", legacy.id))).await;
    assert_eq!(migrated["id"], legacy.id);

    let rpc_send = json(
        client.post(format!("{base}/jsonrpc")).json(&serde_json::json!({
            "jsonrpc":"2.0","id":"send","method":a2a::jsonrpc::methods::SEND_MESSAGE,"params":{
                "message":{"messageId":"process-rpc-message","role":"ROLE_USER","parts":[{"text":"rpc work"}]},
                "configuration":{"returnImmediately":false}
            }
        })),
    )
    .await;
    let rpc_task = rpc_send["result"]["task"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("unexpected JSON-RPC send response: {rpc_send}"))
        .to_owned();
    let rpc_get = json(
        client.post(format!("{base}/jsonrpc")).json(&serde_json::json!({
            "jsonrpc":"2.0","id":"get","method":a2a::jsonrpc::methods::GET_TASK,"params":{"id":rpc_task}
        })),
    )
    .await;
    assert_eq!(rpc_get["result"]["id"], rpc_task);

    let rest_send = json(
        client.post(format!("{base}/rest/message:send")).json(&serde_json::json!({
            "message":{"messageId":"process-rest-message","role":"ROLE_USER","parts":[{"text":"rest work"}]},
            "configuration":{"returnImmediately":false}
        })),
    )
    .await;
    let rest_task = rest_send["task"]["id"].as_str().unwrap().to_owned();
    let listed = json(client.get(format!("{base}/rest/tasks"))).await;
    assert_eq!(listed["totalSize"], 3);
    stop(child);

    let reopened = rusqlite::Connection::open(&database).unwrap();
    assert_eq!(
        reopened
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        6
    );
    drop(reopened);

    let address = free_address();
    let restarted = launch(command(&fixture.0, &database, address));
    let base = format!("https://localhost:{}", address.port());
    let after_restart = json(client.get(format!("{base}/rest/tasks/{rest_task}"))).await;
    assert_eq!(after_restart["id"], rest_task);
    let rpc_list = json(
        client
            .post(format!("{base}/jsonrpc"))
            .json(&serde_json::json!({
                "jsonrpc":"2.0","id":"list","method":a2a::jsonrpc::methods::LIST_TASKS,"params":{}
            })),
    )
    .await;
    assert_eq!(rpc_list["result"]["totalSize"], 3);
    stop(restarted);
}
