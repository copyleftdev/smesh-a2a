#![cfg(all(unix, debug_assertions))]
#![allow(clippy::too_many_lines)]

use std::fmt::Write as _;
use std::io::{BufRead as _, BufReader};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use axum::{
    Router,
    body::Bytes,
    extract::{Path as AxumPath, State},
    http::StatusCode,
    routing::post,
};
use opentelemetry_proto::tonic::collector::{
    logs::v1::ExportLogsServiceRequest, metrics::v1::ExportMetricsServiceRequest,
    trace::v1::ExportTraceServiceRequest,
};
use prost::Message as _;
use smesh_a2a::{PostgresStoreConfig, PostgresTaskStore};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use wait_timeout::ChildExt as _;

const WATCHDOG: Duration = Duration::from_secs(10);
const EXPORT_WATCHDOG: Duration = Duration::from_secs(20);

struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "smesh-pg-observability-process-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct SchemaGuard(Option<PostgresStoreConfig>);
impl SchemaGuard {
    async fn cleanup(mut self) {
        let config = self.0.take().unwrap();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    }
}
impl Drop for SchemaGuard {
    fn drop(&mut self) {
        let Some(config) = self.0.take() else {
            return;
        };
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(PostgresTaskStore::drop_test_schema(&config))
                .unwrap();
        })
        .join()
        .unwrap();
    }
}

struct Gateway {
    child: Option<Child>,
    stderr: Arc<Mutex<String>>,
    reader: Option<std::thread::JoinHandle<()>>,
}
impl Gateway {
    fn terminate(&mut self) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        assert!(
            Command::new("kill")
                .args(["-TERM", &child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        let status = child.wait_timeout(WATCHDOG).unwrap().unwrap_or_else(|| {
            let _ = child.kill();
            child.wait().unwrap()
        });
        assert!(
            status.success(),
            "gateway shutdown failed: {status}; {}",
            self.stderr.lock().unwrap()
        );
        self.child = None;
        if let Some(reader) = self.reader.take() {
            reader.join().unwrap();
        }
    }
}
impl Drop for Gateway {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait_timeout(Duration::from_secs(2));
            let _ = child.wait();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

#[derive(Clone)]
struct CollectorState {
    mode: Arc<AtomicU8>,
    release: Arc<Notify>,
    payloads: CapturedPayloads,
}

type CapturedPayloads = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

async fn collect(
    AxumPath(signal): AxumPath<String>,
    State(state): State<CollectorState>,
    body: Bytes,
) -> (StatusCode, [(&'static str, &'static str); 1], Vec<u8>) {
    if state.mode.load(Ordering::SeqCst) == 1 {
        state.release.notified().await;
    }
    let status = match state.mode.load(Ordering::SeqCst) {
        2 => StatusCode::UNAUTHORIZED,
        3 => StatusCode::FORBIDDEN,
        4 => StatusCode::TOO_MANY_REQUESTS,
        5 => StatusCode::INTERNAL_SERVER_ERROR,
        _ => {
            state.payloads.lock().unwrap().push((signal, body.to_vec()));
            StatusCode::OK
        }
    };
    (
        status,
        [("content-type", "application/x-protobuf")],
        Vec::new(),
    )
}

struct Collector {
    state: CollectorState,
    stop: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}
impl Collector {
    async fn start(address: std::net::SocketAddr) -> Self {
        let listener = tokio::net::TcpListener::bind(address).await.unwrap();
        let state = CollectorState {
            mode: Arc::new(AtomicU8::new(0)),
            release: Arc::new(Notify::new()),
            payloads: Arc::new(Mutex::new(Vec::new())),
        };
        let stop = CancellationToken::new();
        let server_state = state.clone();
        let server_stop = stop.clone();
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/v1/{signal}", post(collect))
                    .with_state(server_state),
            )
            .with_graceful_shutdown(server_stop.cancelled_owned())
            .await
            .unwrap();
        });
        Self { state, stop, task }
    }
    fn mode(&self, value: u8) {
        self.state.mode.store(value, Ordering::SeqCst);
        if value != 1 {
            self.state.release.notify_waiters();
        }
    }
    async fn shutdown(self) {
        self.stop.cancel();
        tokio::time::timeout(WATCHDOG, self.task)
            .await
            .unwrap()
            .unwrap();
    }
}

fn free_address() -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
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

fn write_policy(root: &Path) {
    std::fs::write(root.join("policy.json"), br#"{
      "schemaVersion":"smesh-authz-policy/v1","policyId":"observability-process-policy","revision":16,
      "tenants":[{"id":"tenant-a","enabled":true}],
      "accounts":[{"id":"agent-17","kind":"serviceAccount","memberships":[{"tenantId":"tenant-a","roles":["taskAgent"]}]}],
      "principalBindings":[{"principal":{"issuer":"mtls:test","subject":"agent-17"},"accountId":"agent-17"}]
    }"#).unwrap();
}

fn launch(
    root: &Path,
    address: std::net::SocketAddr,
    collector: std::net::SocketAddr,
    schema: &str,
    admin: &str,
    runtime: &str,
    replica: &str,
) -> Gateway {
    let tls = root.join("tls");
    let mut command = Command::new(env!("CARGO_BIN_EXE_smesh-a2a-gateway"));
    command
        .env_clear()
        .env("RUST_LOG", "info")
        .env("SMESH_A2A_AUTH_MODE", "disabled")
        .env("SMESH_A2A_CLIENT_AUTH_MODE", "required")
        .env(
            "SMESH_A2A_AUTHORIZATION_POLICY_PATH",
            root.join("policy.json"),
        )
        .env("SMESH_A2A_MODE", "loopback")
        .env("SMESH_A2A_BIND", address.to_string())
        .env(
            "SMESH_A2A_PUBLIC_URL",
            format!("https://localhost:{}", address.port()),
        )
        .env("SMESH_A2A_TRANSPORT_MODE", "direct-tls")
        .env("SMESH_A2A_TLS_CERT_PATH", tls.join("server.pem"))
        .env("SMESH_A2A_TLS_KEY_PATH", tls.join("server.key"))
        .env("SMESH_A2A_TLS_CLIENT_CA_PATH", tls.join("client-ca.pem"))
        .env(
            "SMESH_A2A_TLS_PRINCIPAL_MAP_PATH",
            tls.join("principals.json"),
        )
        .env("SMESH_A2A_DURABLE_BACKEND", "postgres")
        .env("SMESH_A2A_POSTGRES_MIGRATOR_URL", admin)
        .env("SMESH_A2A_POSTGRES_RUNTIME_URL", runtime)
        .env("SMESH_A2A_POSTGRES_SCHEMA", schema)
        .env(
            "SMESH_A2A_QUOTA_POLICY_PATH",
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/quota-policy.json"),
        )
        .env("SMESH_A2A_REPLICA_ID", replica)
        .env("SMESH_TEST_POSTGRES_INSECURE_LOOPBACK", "1")
        .env("SMESH_TEST_POSTGRES_PARENT_MANAGED_CLEANUP", "1")
        .env("SMESH_A2A_OTLP_MODE", "http-protobuf")
        .env("SMESH_A2A_OTLP_ENDPOINT", format!("http://{collector}/"))
        .env("SMESH_TEST_OTLP_INSECURE_LOOPBACK", "1")
        .env("SMESH_A2A_OTLP_TRACE_QUEUE", "64")
        .env("SMESH_A2A_OTLP_LOG_QUEUE", "64")
        .env("SMESH_A2A_OTLP_METRIC_QUEUE", "64")
        .env("SMESH_A2A_OTLP_BATCH_SIZE", "1")
        .env("SMESH_A2A_OTLP_SCHEDULE_MILLIS", "50")
        .env("SMESH_A2A_OTLP_EXPORT_TIMEOUT_MILLIS", "200")
        .env("SMESH_A2A_OTLP_METRIC_INTERVAL_MILLIS", "1000")
        .env("SMESH_A2A_OTLP_SHUTDOWN_TIMEOUT_MILLIS", "500")
        .env("SMESH_A2A_OTLP_TRACE_SAMPLE_RATIO", "1")
        .env("SMESH_A2A_AUDIT_PROJECTOR_POLL_MS", "10")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let stderr_pipe = child.stderr.take().unwrap();
    let stderr = Arc::new(Mutex::new(String::new()));
    let output = Arc::clone(&stderr);
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stderr_pipe).lines() {
            let line = line.unwrap();
            let _ = writeln!(output.lock().unwrap(), "{line}");
            if line.contains("gateway listening") {
                let _ = ready_tx.try_send(());
            }
        }
    });
    ready_rx.recv_timeout(WATCHDOG).unwrap_or_else(|error| {
        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "gateway readiness watchdog: {error}; {}",
            stderr.lock().unwrap()
        )
    });
    Gateway {
        child: Some(child),
        stderr,
        reader: Some(reader),
    }
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

async fn send(client: &reqwest::Client, base: &str, message_id: &str) -> serde_json::Value {
    let response = tokio::time::timeout(WATCHDOG, client.post(format!("{base}/jsonrpc")).json(&serde_json::json!({
        "jsonrpc":"2.0","id":message_id,"method":a2a::jsonrpc::methods::SEND_MESSAGE,
        "params":{"message":{"messageId":message_id,"role":"ROLE_USER","parts":[{"text":"bounded process work"}]},"configuration":{"returnImmediately":false}}
    })).send()).await.unwrap().unwrap();
    let status = response.status();
    let bytes = tokio::time::timeout(WATCHDOG, response.bytes())
        .await
        .unwrap()
        .unwrap();
    assert!(
        status.is_success(),
        "{status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_postgres_gateways_fail_open_and_resume_otlp_without_restart() {
    let required = std::env::var("SMESH_POSTGRES_TEST_REQUIRED").as_deref() == Ok("1");
    let admin = match std::env::var("SMESH_TEST_POSTGRES_ADMIN_URL") {
        Ok(value) => value,
        Err(error) if required => panic!("SMESH_TEST_POSTGRES_ADMIN_URL is required: {error}"),
        Err(_) => return,
    };
    let runtime = std::env::var("SMESH_TEST_POSTGRES_RUNTIME_URL")
        .expect("SMESH_TEST_POSTGRES_RUNTIME_URL is required");
    let root = Root::new();
    let tls = copy_tls(&root.0);
    write_policy(&root.0);
    let schema = format!("smesh_obs_process_{:016x}", rand::random::<u64>());
    let cleanup = SchemaGuard(Some(
        PostgresStoreConfig::new(&admin, &runtime, &schema)
            .unwrap()
            .with_test_only_insecure_loopback(true),
    ));
    let collector_address = free_address();
    let address_a = free_address();
    let mut gateway_a = launch(
        &root.0,
        address_a,
        collector_address,
        &schema,
        &admin,
        &runtime,
        "obs-a",
    );
    let client = mtls_client(&tls);
    let base_a = format!("https://localhost:{}", address_a.port());

    // Optional collector absence never prevents readiness or authoritative completion.
    let first = send(&client, &base_a, "collector-absent").await;
    let task_id = first["result"]["task"]["id"].as_str().unwrap().to_owned();

    let collector = Collector::start(collector_address).await;
    let address_b = free_address();
    let mut gateway_b = launch(
        &root.0,
        address_b,
        collector_address,
        &schema,
        &admin,
        &runtime,
        "obs-b",
    );
    let base_b = format!("https://localhost:{}", address_b.port());
    let replay = send(&client, &base_b, "collector-absent").await;
    assert_eq!(replay["result"]["task"]["id"], task_id);
    let second = send(&client, &base_b, "collector-success").await;
    assert!(
        second["result"]["task"]["id"].is_string() || second["error"].is_object(),
        "unexpected second authoritative response: {second}"
    );

    let initial_exports = tokio::time::timeout(EXPORT_WATCHDOG, async {
        loop {
            let complete = {
                let payloads = collector.state.payloads.lock().unwrap();
                let signals: std::collections::BTreeSet<_> =
                    payloads.iter().map(|(s, _)| s.as_str()).collect();
                signals.contains("logs")
                    && signals.contains("traces")
                    && signals.contains("metrics")
            };
            if complete {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        initial_exports.is_ok(),
        "all OTLP signals were not exported: {:?}; gateway stderr: {}",
        collector
            .state
            .payloads
            .lock()
            .unwrap()
            .iter()
            .map(|(signal, _)| signal.as_str())
            .collect::<Vec<_>>(),
        gateway_b.stderr.lock().unwrap()
    );

    // Decode actual production-process OTLP and keep identifiers out of metric attributes.
    let payloads = collector.state.payloads.lock().unwrap().clone();
    let mut decoded = [false; 3];
    for (signal, body) in &payloads {
        match signal.as_str() {
            "logs" => {
                ExportLogsServiceRequest::decode(body.as_slice()).unwrap();
                decoded[0] = true;
            }
            "traces" => {
                ExportTraceServiceRequest::decode(body.as_slice()).unwrap();
                decoded[1] = true;
            }
            "metrics" => {
                let export = ExportMetricsServiceRequest::decode(body.as_slice()).unwrap();
                for resource in export.resource_metrics {
                    for scope in resource.scope_metrics {
                        for metric in scope.metrics {
                            let debug = format!("{metric:?}");
                            for forbidden in [
                                "task.id",
                                "context.id",
                                "dispatch.id",
                                "request.id",
                                "tenant.id",
                            ] {
                                assert!(
                                    !debug.contains(forbidden),
                                    "metric label leaked {forbidden}: {debug}"
                                );
                            }
                        }
                    }
                }
                decoded[2] = true;
            }
            other => panic!("unexpected OTLP signal {other}"),
        }
    }
    assert_eq!(decoded, [true, true, true]);

    // A hung collector and saturated tiny queues cannot hold request latency or SIGTERM.
    collector.mode(1);
    let started = Instant::now();
    for n in 0..12 {
        let _ = send(&client, &base_b, &format!("hung-{n}")).await;
    }
    assert!(
        started.elapsed() < WATCHDOG,
        "authoritative requests blocked on OTLP"
    );
    gateway_a.terminate();

    // Exercise closed HTTP failure classes, then restore success at the same endpoint.
    for mode in [2, 3, 4, 5] {
        collector.mode(mode);
        let _ = send(&client, &base_b, &format!("collector-status-{mode}")).await;
    }
    collector.mode(0);
    let before = collector.state.payloads.lock().unwrap().len();
    tokio::time::timeout(EXPORT_WATCHDOG, async {
        let mut n = 0_u64;
        while collector.state.payloads.lock().unwrap().len() <= before {
            let _ = send(&client, &base_b, &format!("recovered-{n}")).await;
            n += 1;
        }
    })
    .await
    .expect("exports did not resume after collector recovery");

    gateway_b.terminate();
    let stderr = format!(
        "{}{}",
        gateway_a.stderr.lock().unwrap(),
        gateway_b.stderr.lock().unwrap()
    );
    for secret in ["smesh-ci-migrator", "smesh-ci-runtime", "postgresql://"] {
        assert!(
            !stderr.contains(secret),
            "secret leaked to gateway stderr: {secret}"
        );
    }
    collector.shutdown().await;
    cleanup.cleanup().await;
}
