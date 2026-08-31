#![cfg(all(unix, debug_assertions))]

use std::collections::HashSet;
use std::fmt::Write as _;
use std::io::{BufRead as _, BufReader, Write as IoWrite};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    Router,
    body::Bytes as AxumBytes,
    extract::{Path as AxumPath, State},
    http::StatusCode,
    routing::post,
};
use http_body_util::{BodyExt as _, Full};
use hyper::{
    Request, Response,
    body::{Bytes, Incoming},
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use opentelemetry_proto::tonic::collector::{
    logs::v1::ExportLogsServiceRequest, metrics::v1::ExportMetricsServiceRequest,
};
use opentelemetry_proto::tonic::common::v1::any_value::Value as OtlpValue;
use prost::Message as _;
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject as _},
};
use smesh_a2a::{
    PostgresStoreConfig, PostgresTaskStore, QuotaPolicy,
    push::{CallbackSigner, PushPolicy},
};
use tokio_rustls::TlsAcceptor;
use wait_timeout::ChildExt as _;

const WATCHDOG: Duration = Duration::from_secs(20);
const TENANT: &str = "tenant-a";
const ACCOUNT: &str = "agent-17";
const ENDPOINT: &str = "push-process-endpoint";
const CONFIG_ID: &str = "push-process-config";
const KEY_GENERATION: &str = "generation-17";
const SECRET: &[u8] = b"issue-17-process-secret-material-32-bytes-minimum";
const CHECKPOINT: &str = "after_http_2xx_before_authority_commit";

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

fn required_url(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|error| panic!("{name} is required: {error}"))
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "smesh-push-process-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(root)
    }
    fn private(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct SchemaGuard(Option<PostgresStoreConfig>);
impl SchemaGuard {
    async fn cleanup(mut self) {
        let config = self.0.take().unwrap();
        tokio::time::timeout(WATCHDOG, PostgresTaskStore::drop_test_schema(&config))
            .await
            .unwrap()
            .unwrap();
    }
}
impl Drop for SchemaGuard {
    fn drop(&mut self) {
        let Some(config) = self.0.take() else { return };
        let (tx, rx) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .and_then(|rt| {
                    rt.block_on(PostgresTaskStore::drop_test_schema(&config))
                        .map_err(std::io::Error::other)
                });
            let _ = tx.send(result);
        });
        let _ = rx.recv_timeout(WATCHDOG);
    }
}

#[derive(Clone)]
struct CertPair {
    cert_pem: String,
    key_pem: String,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
}
fn ca() -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let key = KeyPair::generate().unwrap();
    (params.self_signed(&key).unwrap(), key)
}
fn signed_pair(
    names: &[&str],
    issuer: &rcgen::Certificate,
    issuer_key: &KeyPair,
    client: bool,
) -> CertPair {
    let mut params =
        CertificateParams::new(names.iter().map(|v| (*v).to_owned()).collect::<Vec<_>>()).unwrap();
    params.extended_key_usages = vec![if client {
        ExtendedKeyUsagePurpose::ClientAuth
    } else {
        ExtendedKeyUsagePurpose::ServerAuth
    }];
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, issuer, issuer_key).unwrap();
    CertPair {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
        cert_der: cert.der().as_ref().to_vec(),
        key_der: key.serialize_der(),
    }
}

#[derive(Clone, Debug)]
struct Seen {
    headers: hyper::HeaderMap,
    body: Vec<u8>,
    peer_cert: bool,
}
struct Receiver {
    address: std::net::SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    effects: Arc<Mutex<HashSet<String>>>,
    connections: Arc<AtomicUsize>,
    tls_connections: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Receiver {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn receiver_config(server: &CertPair, client_ca_pem: &str) -> ServerConfig {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(client_ca_pem.as_bytes()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();
    ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![CertificateDer::from(server.cert_der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server.key_der.clone())),
        )
        .unwrap()
}

async fn start_receiver(config: ServerConfig) -> Receiver {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let effects = Arc::new(Mutex::new(HashSet::new()));
    let connections = Arc::new(AtomicUsize::new(0));
    let tls_connections = Arc::new(AtomicUsize::new(0));
    let seen_out = Arc::clone(&seen);
    let effects_out = Arc::clone(&effects);
    let connections_out = Arc::clone(&connections);
    let tls_connections_out = Arc::clone(&tls_connections);
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let task = tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            connections_out.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            let seen = Arc::clone(&seen_out);
            let effects = Arc::clone(&effects_out);
            let tls_connections = Arc::clone(&tls_connections_out);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                tls_connections.fetch_add(1, Ordering::SeqCst);
                let peer_cert = tls
                    .get_ref()
                    .1
                    .peer_certificates()
                    .is_some_and(|v| !v.is_empty());
                let service = service_fn(move |request: Request<Incoming>| {
                    let seen = Arc::clone(&seen);
                    let effects = Arc::clone(&effects);
                    async move {
                        let (parts, body) = request.into_parts();
                        let body = body.collect().await.unwrap().to_bytes().to_vec();
                        let event = parts
                            .headers
                            .get("x-smesh-callback-event-id")
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .to_owned();
                        let request_number = {
                            let mut requests = seen.lock().unwrap();
                            requests.push(Seen {
                                headers: parts.headers,
                                body,
                                peer_cert,
                            });
                            requests.len()
                        };
                        let mut response = Response::builder();
                        if request_number == 1 {
                            response = response.status(503).header("retry-after", "1");
                        } else {
                            effects.lock().unwrap().insert(event);
                            response = response.status(204);
                        }
                        Ok::<_, std::convert::Infallible>(
                            response.body(Full::new(Bytes::new())).unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    Receiver {
        address,
        seen,
        effects,
        connections,
        tls_connections,
        task,
    }
}

struct Gateway {
    child: Option<Child>,
    logs: Arc<Mutex<String>>,
    stderr_reader: Option<std::thread::JoinHandle<()>>,
    stderr_done: mpsc::Receiver<()>,
    stdout_reader: Option<std::thread::JoinHandle<()>>,
    stdout_done: mpsc::Receiver<()>,
    checkpoint: mpsc::Receiver<()>,
}
impl Gateway {
    fn pid(&self) -> u32 {
        self.child.as_ref().unwrap().id()
    }
    async fn wait_checkpoint(&self) -> bool {
        let deadline = tokio::time::Instant::now() + WATCHDOG;
        loop {
            match self.checkpoint.try_recv() {
                Ok(()) => return true,
                Err(mpsc::TryRecvError::Disconnected) => return false,
                Err(mpsc::TryRecvError::Empty) => {
                    if tokio::time::Instant::now() >= deadline {
                        return false;
                    }
                    tokio::task::yield_now().await;
                }
            }
        }
    }
    fn checkpoint_ready(&self) -> bool {
        self.checkpoint.try_recv().is_ok()
    }
    fn release_checkpoint(&mut self) {
        writeln!(
            self.child.as_mut().unwrap().stdin.as_mut().unwrap(),
            "GO {CHECKPOINT}"
        )
        .unwrap();
    }
    fn kill_and_reap(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        child.kill().unwrap();
        assert!(
            child.wait_timeout(WATCHDOG).unwrap().is_some(),
            "gateway reap watchdog"
        );
        self.finish_readers();
    }
    fn terminate_and_reap(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let status = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success(), "SIGTERM delivery failed");
        let exit = child
            .wait_timeout(WATCHDOG)
            .unwrap()
            .expect("gateway did not reap within SIGTERM watchdog");
        assert!(exit.success(), "gateway SIGTERM was not graceful: {exit}");
        self.finish_readers();
        assert!(
            self.logs()
                .contains("smesh.callback.worker_shutdown outcome=joined"),
            "callback workers did not report a complete join: {}",
            self.logs()
        );
    }
    fn terminate_fatal_and_reap(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let status = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success(), "SIGTERM delivery failed");
        let exit = child
            .wait_timeout(WATCHDOG)
            .unwrap()
            .expect("fatal gateway did not reap within SIGTERM watchdog");
        assert!(
            exit.success(),
            "contained callback fatal must not turn graceful SIGTERM into process failure: {exit}"
        );
        self.finish_readers();
        assert!(
            self.logs()
                .contains("smesh.callback.worker_shutdown outcome=failed"),
            "fatal callback worker shutdown outcome was not observed: {}",
            self.logs()
        );
    }
    fn finish_readers(&mut self) {
        let _ = self.stderr_done.recv_timeout(WATCHDOG);
        let _ = self.stdout_done.recv_timeout(WATCHDOG);
        if let Some(v) = self.stderr_reader.take() {
            v.join().unwrap();
        }
        if let Some(v) = self.stdout_reader.take() {
            v.join().unwrap();
        }
    }
    fn logs(&self) -> String {
        self.logs.lock().unwrap().clone()
    }
}
impl Drop for Gateway {
    fn drop(&mut self) {
        self.kill_and_reap();
    }
}

fn free_address() -> std::net::SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    a
}

type OtlpPayloads = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

async fn collect_otlp(
    AxumPath(signal): AxumPath<String>,
    State(payloads): State<OtlpPayloads>,
    body: AxumBytes,
) -> (StatusCode, [(&'static str, &'static str); 1], Vec<u8>) {
    payloads.lock().unwrap().push((signal, body.to_vec()));
    (
        StatusCode::OK,
        [("content-type", "application/x-protobuf")],
        Vec::new(),
    )
}

async fn start_otlp_collector() -> (
    std::net::SocketAddr,
    OtlpPayloads,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let payloads = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/v1/{signal}", post(collect_otlp))
        .with_state(Arc::clone(&payloads));
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (address, payloads, task)
}

#[allow(clippy::too_many_arguments)]
fn launch_gateway(
    root: &Path,
    gateway_tls: &Path,
    push: &Path,
    quota: &Path,
    dns: &Path,
    admin: &str,
    runtime: &str,
    schema: &str,
    replica: &str,
    address: std::net::SocketAddr,
    collector: std::net::SocketAddr,
    checkpoint: bool,
    worker_fatal: bool,
) -> Gateway {
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
        .env("SMESH_A2A_PUSH_CONFIG_PATH", push)
        .env("SMESH_A2A_REPLICA_ID", replica)
        .env("SMESH_TEST_POSTGRES_INSECURE_LOOPBACK", "1")
        .env("SMESH_TEST_POSTGRES_PARENT_MANAGED_CLEANUP", "1")
        .env("SMESH_TEST_PUSH_DNS_MAP_ENABLE", "1")
        .env("SMESH_TEST_PUSH_DNS_MAP_PATH", dns)
        .env("SMESH_A2A_OTLP_MODE", "http-protobuf")
        .env("SMESH_A2A_OTLP_ENDPOINT", format!("http://{collector}/"))
        .env("SMESH_TEST_OTLP_INSECURE_LOOPBACK", "1")
        .env("SMESH_A2A_OTLP_BATCH_SIZE", "1")
        .env("SMESH_A2A_OTLP_SCHEDULE_MILLIS", "50")
        .env("SMESH_A2A_OTLP_METRIC_INTERVAL_MILLIS", "1000")
        .env("SMESH_A2A_OTLP_EXPORT_TIMEOUT_MILLIS", "100")
        .env("SMESH_A2A_OTLP_SHUTDOWN_TIMEOUT_MILLIS", "1000")
        .env(
            "SMESH_A2A_AUTHORIZATION_POLICY_PATH",
            root.join("authorization.json"),
        )
        .env("SMESH_A2A_TRANSPORT_MODE", "direct-tls")
        .env("SMESH_A2A_TLS_CERT_PATH", gateway_tls.join("server.pem"))
        .env("SMESH_A2A_TLS_KEY_PATH", gateway_tls.join("server.key"))
        .env(
            "SMESH_A2A_TLS_CLIENT_CA_PATH",
            gateway_tls.join("client-ca.pem"),
        )
        .env(
            "SMESH_A2A_TLS_PRINCIPAL_MAP_PATH",
            gateway_tls.join("principals.json"),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if checkpoint {
        command.env("SMESH_TEST_PUSH_CHECKPOINT", CHECKPOINT);
    }
    if worker_fatal {
        command.env("SMESH_TEST_PUSH_WORKER_FATAL", "1");
    }
    let mut child = command.spawn().unwrap();
    let stderr = child.stderr.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let logs = Arc::new(Mutex::new(String::new()));
    let stderr_logs = Arc::clone(&logs);
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (stderr_done_tx, stderr_done) = mpsc::sync_channel(1);
    let stderr_reader = std::thread::spawn(move || {
        let mut ready = false;
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let _ = writeln!(stderr_logs.lock().unwrap(), "{line}");
            if !ready && line.contains("gateway listening") {
                ready = true;
                let _ = ready_tx.send(());
            }
        }
        let _ = stderr_done_tx.send(());
    });
    let (checkpoint_tx, checkpoint_rx) = mpsc::sync_channel(1);
    let (stdout_done_tx, stdout_done) = mpsc::sync_channel(1);
    let stdout_logs = Arc::clone(&logs);
    let stdout_reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = writeln!(stdout_logs.lock().unwrap(), "{line}");
            if line == format!("SMESH_PUSH_CHECKPOINT READY {CHECKPOINT}") {
                let _ = checkpoint_tx.send(());
            }
        }
        let _ = stdout_done_tx.send(());
    });
    let mut gateway = Gateway {
        child: Some(child),
        logs,
        stderr_reader: Some(stderr_reader),
        stderr_done,
        stdout_reader: Some(stdout_reader),
        stdout_done,
        checkpoint: checkpoint_rx,
    };
    if ready_rx.recv_timeout(WATCHDOG).is_err() {
        gateway.kill_and_reap();
        let logs = gateway.logs();
        panic!("gateway readiness watchdog replica={replica} schema={schema}: {logs}");
    }
    gateway
}

fn gateway_tls(fixture: &Fixture) -> PathBuf {
    let out = fixture.0.join("gateway-tls");
    std::fs::create_dir(&out).unwrap();
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
        std::fs::copy(source.join(name), out.join(name)).unwrap();
    }
    for name in ["server.key", "client.key", "principals.json"] {
        std::fs::set_permissions(out.join(name), std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    out
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
        .connect_timeout(Duration::from_secs(3))
        .timeout(WATCHDOG)
        .build()
        .unwrap()
}
async fn json(request: reqwest::RequestBuilder) -> serde_json::Value {
    let response = request.send().await.unwrap();
    let status = response.status();
    let body = response.bytes().await.unwrap();
    assert!(
        status.is_success(),
        "{status}: {}",
        String::from_utf8_lossy(&body)
    );
    serde_json::from_slice(&body).unwrap()
}
async fn wait_seen(receiver: &Receiver, count: usize) {
    let deadline = tokio::time::Instant::now() + WATCHDOG;
    loop {
        if receiver.seen.lock().unwrap().len() >= count {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "callback receiver watchdog"
        );
        tokio::task::yield_now().await;
    }
}
async fn admin_client(url: &str) -> (tokio_postgres::Client, tokio::task::JoinHandle<()>) {
    let config = tokio_postgres::Config::from_str(url).unwrap();
    let (client, connection) = config.connect(tokio_postgres::NoTls).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    (client, driver)
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn production_two_gateway_signed_callback_crash_failover_is_deduplicated() {
    tokio::time::timeout(Duration::from_secs(90), async {
        let Some(admin) = process_admin_url() else { return };
        let runtime = required_url("SMESH_TEST_POSTGRES_RUNTIME_URL");
        let (collector_address, otlp_payloads, collector_task) = start_otlp_collector().await;
        let fixture = Fixture::new();
        let gateway_tls = gateway_tls(&fixture);
        fixture.private("authorization.json", br#"{"schemaVersion":"smesh-authz-policy/v1","policyId":"push-process-authz","revision":17,"tenants":[{"id":"tenant-a","enabled":true}],"accounts":[{"id":"agent-17","kind":"serviceAccount","memberships":[{"tenantId":"tenant-a","roles":["taskAgent"]}]}],"principalBindings":[{"principal":{"issuer":"mtls:test","subject":"agent-17"},"accountId":"agent-17"}]}"#);
        let quota = fixture.private("quota.json", include_bytes!("fixtures/quota-policy.json"));
        let (server_ca, server_ca_key) = ca();
        let (client_ca, client_ca_key) = ca();
        let callback_server = signed_pair(&["callback.test"], &server_ca, &server_ca_key, false);
        let callback_client = signed_pair(&["push-process-client"], &client_ca, &client_ca_key, true);
        let ca_path = fixture.private("callback-ca.pem", server_ca.pem().as_bytes());
        let client_cert = fixture.private("callback-client.pem", callback_client.cert_pem.as_bytes());
        let client_key = fixture.private("callback-client.key", callback_client.key_pem.as_bytes());
        let secret = fixture.private("callback-secret.key", SECRET);
        let receiver = start_receiver(receiver_config(&callback_server, &client_ca.pem())).await;
        let dns = fixture.private("callback-dns.json", br#"{"callback.test":["127.0.0.1"]}"#);
        let canonical_url = format!("https://callback.test:{}/a2a/callback", receiver.address.port());
        let push_document = format!(r#"schema = "smesh-push/1"
enabled = true
policy_id = "push-process-policy"
policy_revision = 17
policy_digest = "sha256:1717171717171717171717171717171717171717171717171717171717171717"
max_pending = 100
max_configs_per_task = 4
max_configs_per_tenant = 100
worker_count = 3
claim_batch = 1
claim_lease_ms = 1000
dns_timeout_ms = 500
max_dns_answers = 4
connect_timeout_ms = 1000
request_timeout_ms = 3000
max_response_bytes = 4096
max_attempts = 4
base_retry_ms = 10
max_retry_ms = 100
max_delivery_age_ms = 60000
[[enrollments]]
tenant = "{TENANT}"
endpoint_id = "{ENDPOINT}"
url = "{canonical_url}"
event = "terminal"
auth = "hmac-sha256"
key_generation = "{KEY_GENERATION}"
secret_file = "{}"
ca_file = "{}"
mtls_cert_file = "{}"
mtls_key_file = "{}"
"#, secret.display(), ca_path.display(), client_cert.display(), client_key.display());
        let push = fixture.private("push.toml", push_document.as_bytes());
        let schema = format!("spush_{:016x}", rand::random::<u64>());
        let config = PostgresStoreConfig::new(&admin, &runtime, &schema).unwrap()
            .with_test_only_insecure_loopback(true).with_test_only_parent_managed_cleanup()
            .with_quota_policy(Arc::new(QuotaPolicy::load(&quota).unwrap()))
            .with_push_policy(PushPolicy::load(&push).unwrap());
        let schema_guard = SchemaGuard(Some(config));
        let address_a = free_address();
        let mut a = launch_gateway(&fixture.0, &gateway_tls, &push, &quota, &dns, &admin, &runtime, &schema, "push-process-a", address_a, collector_address, true, false);
        let address_b = free_address();
        let mut b = launch_gateway(&fixture.0, &gateway_tls, &push, &quota, &dns, &admin, &runtime, &schema, "push-process-b", address_b, collector_address, true, false);
        assert_ne!(a.pid(), b.pid()); assert_ne!(address_a, address_b);
        let client = mtls_client(&gateway_tls);
        let base_a = format!("https://localhost:{}", address_a.port());
        let base_b = format!("https://localhost:{}", address_b.port());
        let card_a = json(client.get(format!("{base_a}/.well-known/agent-card.json"))).await;
        assert_eq!(card_a["capabilities"]["pushNotifications"], true);
        let card_b = json(client.get(format!("{base_b}/.well-known/agent-card.json"))).await;
        assert_eq!(card_b["capabilities"]["pushNotifications"], true);
        let send = serde_json::json!({"jsonrpc":"2.0","id":"push-send","method":"SendMessage","params":{
            "message":{"messageId":"push-process-message","role":"ROLE_USER","parts":[{"text":"signed callback process evidence"}],"metadata":{"privateCanary":"must-not-leak"}},
            "configuration":{"returnImmediately":false,"taskPushNotificationConfig":{"url":canonical_url,"id":CONFIG_ID,"taskId":""}}
        }});
        let first = json(client.post(format!("{base_a}/jsonrpc")).header("x-smesh-tenant", TENANT).json(&send)).await;
        let task_id = first["result"]["task"]["id"].as_str().unwrap().to_owned();
        wait_seen(&receiver, 1).await;
        let (debug_db, debug_driver) = admin_client(&admin).await;
        debug_db.batch_execute("SELECT set_config('smesh.internal_global','callback-worker-v1',false)").await.unwrap();
        let retry_deadline = tokio::time::Instant::now() + WATCHDOG;
        let retry_values = loop {
            let row = debug_db.query_one(&format!("SELECT state,attempt_count,available_at,(SELECT max(finished_at) FROM {schema}.callback_attempts a WHERE a.tenant_scope=d.tenant_scope AND a.event_id=d.event_id AND a.config_id=d.config_id),(SELECT count(*) FROM {schema}.callback_attempts a WHERE a.tenant_scope=d.tenant_scope AND a.event_id=d.event_id AND a.config_id=d.config_id),(SELECT state FROM {schema}.callback_configs c WHERE c.tenant_scope=d.tenant_scope AND c.task_id=d.task_id AND c.config_id=d.config_id) FROM {schema}.callback_deliveries d WHERE tenant_scope=$1"), &[&TENANT]).await.unwrap();
            let state = row.get::<_, String>(0);
            let committed_attempts = row.get::<_, i64>(4);
            if committed_attempts == 1 && matches!(state.as_str(), "retry" | "leased") {
                break (row.get::<_,i32>(1),row.get::<_,i64>(2),row.get::<_,Option<i64>>(3).expect("committed retry finished_at"),committed_attempts,row.get::<_,String>(5),state);
            }
            assert!(tokio::time::Instant::now() < retry_deadline, "retry evidence commit watchdog");
            tokio::task::yield_now().await;
        };
        assert!((1..=2).contains(&retry_values.0), "the next attempt may already be leased: {retry_values:?}");
        assert!((0..=100).contains(&retry_values.1.saturating_sub(retry_values.2)), "Retry-After due time must be policy-clamped from the committed attempt time: {retry_values:?}");
        assert_eq!(retry_values.3, 1, "failed attempt fact commits exactly once");
        assert_eq!(retry_values.4, "terminal_closed");
        drop(debug_db); debug_driver.abort(); let _ = debug_driver.await;
        let deadline = tokio::time::Instant::now() + WATCHDOG;
        let first_was_a = loop {
            if a.checkpoint_ready() { break true; }
            if b.checkpoint_ready() { break false; }
            assert!(tokio::time::Instant::now() < deadline, "production push checkpoint missing; retry={retry_values:?} receiver={} tcp={} tls={} logs={}{}", receiver.seen.lock().unwrap().len(), receiver.connections.load(Ordering::SeqCst), receiver.tls_connections.load(Ordering::SeqCst), a.logs(), b.logs());
            tokio::task::yield_now().await;
        };
        wait_seen(&receiver, 2).await;

        let healthy_base = if first_was_a { &base_b } else { &base_a };
        let get = json(client.get(format!("{healthy_base}/rest/tasks/{task_id}/pushNotificationConfigs/{CONFIG_ID}")).header("x-smesh-tenant", TENANT)).await;
        assert_eq!(get["url"], canonical_url); assert!(get.get("token").is_none()); assert!(get.get("authentication").is_none());
        let listed = json(client.post(format!("{healthy_base}/jsonrpc")).header("x-smesh-tenant", TENANT).json(&serde_json::json!({"jsonrpc":"2.0","id":"push-list","method":"ListTaskPushNotificationConfigs","params":{"taskId":task_id}}))).await;
        assert_eq!(listed["result"]["configs"].as_array().unwrap().len(), 1);

        let survivor_base = if first_was_a {
            a.kill_and_reap();
            assert!(b.wait_checkpoint().await, "replica B did not retry at production checkpoint");
            b.release_checkpoint();
            base_b.clone()
        } else {
            b.kill_and_reap();
            assert!(a.wait_checkpoint().await, "replica A did not retry at production checkpoint");
            a.release_checkpoint();
            base_a.clone()
        };
        wait_seen(&receiver, 3).await;
        let seen = receiver.seen.lock().unwrap().clone();
        assert!(seen.iter().all(|request| request.peer_cert));
        let event_id = seen[0].headers["x-smesh-callback-event-id"].to_str().unwrap().to_owned();
        assert!(seen.iter().all(|request| request.headers["idempotency-key"] == event_id.as_str()));
        assert_eq!(seen[0].body, seen[1].body);
        assert_eq!(seen[1].body, seen[2].body);
        assert_eq!(receiver.effects.lock().unwrap().len(), 1, "receiver dedupe effect");
        let body_json: serde_json::Value = serde_json::from_slice(&seen[0].body).unwrap();
        assert_eq!(seen[0].headers["content-type"], "application/a2a+json");
        assert!(body_json.to_string().contains("TASK_STATE_COMPLETED"));
        assert!(!body_json.to_string().contains("privateCanary"));
        assert_eq!(seen[0].headers["content-digest"], smesh_a2a::push::content_digest_header(&seen[0].body));
        assert_eq!(seen[0].headers["x-smesh-callback-endpoint-id"], ENDPOINT);
        assert_eq!(seen[0].headers["x-smesh-callback-key-generation"], KEY_GENERATION);
        assert_eq!(seen[0].headers["x-smesh-callback-attempt"], "1");
        assert_eq!(seen[1].headers["x-smesh-callback-attempt"], "2");
        assert_eq!(seen[2].headers["x-smesh-callback-attempt"], "3");
        let signer = CallbackSigner::new(SECRET).unwrap();
        for request in &seen {
            let timestamp = request.headers["x-smesh-callback-timestamp"].to_str().unwrap().parse().unwrap();
            let attempt = request.headers["x-smesh-callback-attempt"].to_str().unwrap().parse().unwrap();
            assert!(signer.verify(&canonical_url, ENDPOINT, &event_id, timestamp, attempt, KEY_GENERATION, &request.body, request.headers["x-smesh-callback-signature"].to_str().unwrap()));
            assert!(request.headers.get("authorization").is_none());
            assert!(request.headers.get("cookie").is_none());
        }

        let replay = json(client.post(format!("{survivor_base}/jsonrpc")).header("x-smesh-tenant", TENANT).json(&send)).await;
        assert_eq!(replay["result"], first["result"]);
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(receiver.seen.lock().unwrap().len(), 3, "replay must not enqueue or deliver again");

        let rejected = client.post(format!("{survivor_base}/jsonrpc")).header("x-smesh-tenant", TENANT).json(&serde_json::json!({"jsonrpc":"2.0","id":"push-secret-reject","method":"SendMessage","params":{"message":{"messageId":"push-secret-reject","role":"ROLE_USER","parts":[{"text":"reject client credentials"}]},"configuration":{"returnImmediately":true,"taskPushNotificationConfig":{"url":canonical_url,"id":"bad-config","taskId":"","token":"caller-token","authentication":{"schemes":["Bearer"],"credentials":"caller-secret"}}}}})).send().await.unwrap();
        let rejected_body = rejected.text().await.unwrap();
        assert!(rejected_body.contains("invalid") || rejected_body.contains("INVALID"), "unexpected credential rejection: {rejected_body}"); assert!(!rejected_body.contains("caller-secret"));

        let (db, db_driver) = admin_client(&admin).await;
        db.batch_execute("SELECT set_config('smesh.internal_global','callback-worker-v1',false)").await.unwrap();
        db.query_one("SELECT set_config('smesh.tenant_scope',$1,false),set_config('smesh.account_id',$2,false)", &[&TENANT, &ACCOUNT]).await.unwrap();
        let delivery = db.query_one(&format!("SELECT state,attempt_count,(SELECT count(*) FROM {schema}.callback_attempts a WHERE a.tenant_scope=d.tenant_scope AND a.event_id=d.event_id AND a.config_id=d.config_id) FROM {schema}.callback_deliveries d WHERE tenant_scope=$1 AND event_id=$2"), &[&TENANT, &event_id]).await.unwrap();
        assert_eq!(delivery.get::<_, String>(0), "delivered"); assert_eq!(delivery.get::<_, i32>(1), 3); assert_eq!(delivery.get::<_, i64>(2), 2);
        let audits = db.query_one(&format!("SELECT count(*),bool_and(source_pk_digest ~ '^sha256:[0-9a-f]{{64}}$') FROM {schema}.callback_audits WHERE tenant_scope=$1"), &[&TENANT]).await.unwrap();
        assert!(audits.get::<_, i64>(0) >= 4); assert!(audits.get::<_, bool>(1));
        db.query_one("SELECT set_config('smesh.internal_global','audit-projector-v1',false)", &[]).await.unwrap();
        let projection_kinds: Vec<String> = db.query(&format!("SELECT DISTINCT event_kind FROM {schema}.audit_projection_outbox WHERE tenant_scope=$1 AND event_kind LIKE 'callback_%' ORDER BY event_kind"), &[&TENANT]).await.unwrap().into_iter().map(|r| r.get(0)).collect();
        for expected in ["callback_config_created","callback_delivered","callback_delivery_attempted","callback_event_enqueued","callback_policy_reconciled"] { assert!(projection_kinds.iter().any(|v| v == expected), "missing {expected}: {projection_kinds:?}"); }
        let primary_projection_event_id: String = db.query_one(&format!("SELECT event_id FROM {schema}.audit_projection_outbox WHERE tenant_scope=$1 AND event_kind='callback_event_enqueued' ORDER BY occurred_at,event_id LIMIT 1"), &[&TENANT]).await.unwrap().get(0);
        db.query_one("SELECT set_config('smesh.internal_global','callback-worker-v1',false)", &[]).await.unwrap();
        let text_rows: String = db.query_one(&format!("SELECT coalesce(string_agg(to_jsonb(x)::text,' '),'') FROM (SELECT * FROM {schema}.callback_audits UNION ALL SELECT tenant_scope,audit_order,event_kind,source_kind,source_pk_digest,occurred_at FROM {schema}.callback_audits) x"), &[]).await.unwrap().get(0);
        let logs = format!("{}{}{}{}", a.logs(), b.logs(), rejected_body, text_rows);
        for canary in [SECRET, admin.as_bytes(), runtime.as_bytes(), canonical_url.as_bytes(), b"privateCanary", b"caller-token", b"caller-secret"] { assert!(!logs.as_bytes().windows(canary.len()).any(|w| w == canary), "protected canary leaked"); }

        if first_was_a { b.terminate_and_reap(); } else { a.terminate_and_reap(); }
        let active_sessions: i64 = db.query_one(&format!("SELECT count(*) FROM {schema}.callback_worker_sessions s JOIN pg_stat_activity a ON a.pid=s.backend_pid"), &[]).await.unwrap().get(0);
        assert_eq!(active_sessions, 0, "graceful shutdown must release callback worker sessions");
        drop(db); db_driver.abort(); let _ = db_driver.await;
        schema_guard.cleanup().await;

        // Both primary gateways are now reaped and their telemetry owners have
        // flushed. Keep this authority's exports separate: the fatal-schema
        // scenario below legitimately projects a different callback event.
        let primary_exports = {
            let mut payloads = otlp_payloads.lock().unwrap();
            let exports = payloads.clone();
            payloads.clear();
            exports
        };

        let fatal_schema = format!("spush_fatal_{:016x}", rand::random::<u64>());
        let fatal_config = PostgresStoreConfig::new(&admin, &runtime, &fatal_schema).unwrap()
            .with_test_only_insecure_loopback(true).with_test_only_parent_managed_cleanup()
            .with_quota_policy(Arc::new(QuotaPolicy::load(&quota).unwrap()))
            .with_push_policy(PushPolicy::load(&push).unwrap());
        let fatal_guard = SchemaGuard(Some(fatal_config));
        let fatal_address = free_address();
        let mut fatal = launch_gateway(&fixture.0, &gateway_tls, &push, &quota, &dns, &admin, &runtime, &fatal_schema, "push-process-fatal", fatal_address, collector_address, false, true);
        let fatal_base = format!("https://localhost:{}", fatal_address.port());
        let initially_ready = json(client.get(format!("{fatal_base}/.well-known/agent-card.json"))).await;
        assert_eq!(initially_ready["capabilities"]["pushNotifications"], true);
        let seeded = json(client.post(format!("{fatal_base}/jsonrpc")).header("x-smesh-tenant", TENANT).json(&send)).await;
        let fatal_task = seeded["result"]["task"]["id"].as_str().unwrap().to_owned();
        let fatal_deadline = tokio::time::Instant::now() + WATCHDOG;
        loop {
            let card = json(client.get(format!("{fatal_base}/.well-known/agent-card.json"))).await;
            if card["capabilities"]["pushNotifications"] == false { break; }
            assert!(tokio::time::Instant::now() < fatal_deadline, "fatal worker did not flip live card: {}", fatal.logs());
            tokio::task::yield_now().await;
        }
        assert!(fatal.child.as_mut().unwrap().try_wait().unwrap().is_none(), "worker panic must not exit gateway");
        let safe_get = json(client.get(format!("{fatal_base}/rest/tasks/{fatal_task}/pushNotificationConfigs/{CONFIG_ID}")).header("x-smesh-tenant", TENANT)).await;
        assert_eq!(safe_get["id"], CONFIG_ID);
        let safe_list = json(client.post(format!("{fatal_base}/jsonrpc")).header("x-smesh-tenant", TENANT).json(&serde_json::json!({"jsonrpc":"2.0","id":"fatal-list","method":"ListTaskPushNotificationConfigs","params":{"taskId":fatal_task}}))).await;
        assert_eq!(safe_list["result"]["configs"].as_array().unwrap().len(), 1);
        let unavailable_create = json(client.post(format!("{fatal_base}/jsonrpc")).header("x-smesh-tenant", TENANT).json(&serde_json::json!({"jsonrpc":"2.0","id":"fatal-create","method":"SendMessage","params":{"message":{"messageId":"fatal-create-message","role":"ROLE_USER","parts":[{"text":"must fail closed"}]},"configuration":{"returnImmediately":true,"taskPushNotificationConfig":{"url":canonical_url,"id":"fatal-config","taskId":""}}}}))).await;
        assert!(unavailable_create.get("error").is_some(), "create must fail closed after worker fatal: {unavailable_create}");
        let deleted = client.delete(format!("{fatal_base}/rest/tasks/{fatal_task}/pushNotificationConfigs/{CONFIG_ID}")).header("x-smesh-tenant", TENANT).send().await.unwrap();
        assert!(deleted.status().is_success(), "safe delete remains available: {}", deleted.status());
        fatal.terminate_fatal_and_reap();
        let (fatal_db, fatal_db_driver) = admin_client(&admin).await;
        let fatal_active: i64 = fatal_db.query_one(&format!("SELECT count(*) FROM {fatal_schema}.callback_worker_sessions s JOIN pg_stat_activity a ON a.pid=s.backend_pid"), &[]).await.unwrap().get(0);
        assert_eq!(fatal_active, 0);
        let fatal_leases: i64 = fatal_db.query_one(&format!("SELECT count(*) FROM {fatal_schema}.callback_deliveries WHERE state='leased' AND lease_owner LIKE 'push-process-fatal-%'"), &[]).await.unwrap().get(0);
        assert_eq!(fatal_leases, 0, "graceful fatal shutdown must leave no process-owned callback lease");
        fatal_db.query_one("SELECT set_config('smesh.internal_global','audit-projector-v1',false)", &[]).await.unwrap();
        let fatal_projection_event_id: String = fatal_db.query_one(&format!("SELECT event_id FROM {fatal_schema}.audit_projection_outbox WHERE tenant_scope=$1 AND event_kind='callback_event_enqueued' ORDER BY occurred_at,event_id LIMIT 1"), &[&TENANT]).await.unwrap().get(0);
        drop(fatal_db); fatal_db_driver.abort(); let _ = fatal_db_driver.await;
        fatal_guard.cleanup().await;

        let fatal_exports = tokio::time::timeout(WATCHDOG, async {
            loop {
                let signals = otlp_payloads.lock().unwrap().iter().map(|(signal, _)| signal.clone()).collect::<HashSet<_>>();
                if signals.contains("logs") && signals.contains("metrics") { break otlp_payloads.lock().unwrap().clone(); }
                tokio::task::yield_now().await;
            }
        }).await.expect("callback OTLP export watchdog");
        let exports = primary_exports
            .into_iter()
            .chain(fatal_exports)
            .collect::<Vec<_>>();
        let mut callback_logs = String::new();
        let mut callback_metrics = String::new();
        let mut callback_event_projection_ids = Vec::new();
        for (signal, body) in exports {
            match signal.as_str() {
                "logs" => {
                    let export = ExportLogsServiceRequest::decode(body.as_slice()).unwrap();
                    for record in export
                        .resource_logs
                        .iter()
                        .flat_map(|resource| &resource.scope_logs)
                        .flat_map(|scope| &scope.log_records)
                    {
                        let attribute = |key: &str| {
                            record.attributes.iter().find_map(|attribute| {
                                (attribute.key == key)
                                    .then(|| attribute.value.as_ref()?.value.as_ref())
                                    .flatten()
                                    .and_then(|value| match value {
                                        OtlpValue::StringValue(value) => Some(value.as_str()),
                                        _ => None,
                                    })
                            })
                        };
                        if attribute("smesh.operation") == Some("callback_event_enqueued") {
                            callback_event_projection_ids.push(
                                attribute("event.id")
                                    .expect("callback projection event.id")
                                    .to_owned(),
                            );
                        }
                    }
                    let _ = write!(callback_logs, "{export:?}");
                }
                "metrics" => {
                    let export = ExportMetricsServiceRequest::decode(body.as_slice()).unwrap();
                    for resource in export.resource_metrics {
                        for scope in resource.scope_metrics {
                            for metric in scope.metrics {
                                if metric.name == "smesh.a2a.push.delivery" {
                                    let _ = write!(callback_metrics, "{metric:?}");
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        for operation in ["callback_config_created", "callback_event_enqueued", "callback_delivery_attempted", "callback_retry_scheduled", "callback_delivered", "callback_worker"] {
            assert!(callback_logs.contains(operation), "missing live callback log {operation}: {callback_logs}");
        }
        assert!(callback_logs.contains("worker_panic"), "fatal callback worker log missing: {callback_logs}");
        assert!(callback_metrics.contains("smesh.a2a.push.delivery"), "live PushDelivery metric missing: {callback_metrics}");
        for forbidden in [canonical_url.as_str(), "callback.test", "127.0.0.1", CONFIG_ID, event_id.as_str(), TENANT, std::str::from_utf8(SECRET).unwrap(), "privateCanary", "caller-secret"] {
            assert!(!callback_logs.contains(forbidden), "callback OTLP log leaked {forbidden}");
            assert!(!callback_metrics.contains(forbidden), "callback OTLP metric leaked {forbidden}");
        }
        for forbidden_key in ["url", "host", "ip", "config.id", "event.id", "tenant.id", "secret", "error.message", "error.body"] {
            assert!(!callback_metrics.contains(&format!("key: \"{forbidden_key}\"")), "high-cardinality PushDelivery metric attribute leaked: {forbidden_key}");
        }
        let expected_projection_ids = HashSet::from([
            primary_projection_event_id.as_str(),
            fatal_projection_event_id.as_str(),
        ]);
        assert!(!callback_event_projection_ids.is_empty(), "missing live callback event projection");
        assert!(callback_event_projection_ids.iter().all(|event| expected_projection_ids.contains(event.as_str())), "OTLP exported an event.id not bound to either durable callback projection: expected={expected_projection_ids:?} actual={callback_event_projection_ids:?}");
        collector_task.abort();
        let _ = collector_task.await;
    }).await.expect("two-gateway push process watchdog");
}

#[test]
fn conflicting_push_config_names_fail_before_listener_or_network_startup() {
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let mut child = Command::new(env!("CARGO_BIN_EXE_smesh-a2a-gateway"))
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("SMESH_A2A_AUTH_MODE", "disabled")
        .env("SMESH_A2A_MODE", "loopback")
        .env("SMESH_A2A_BIND", address.to_string())
        .env("SMESH_A2A_PUBLIC_URL", format!("http://{address}"))
        .env("SMESH_A2A_PUSH_CONFIG_PATH", "/not/read/canonical.toml")
        .env("SMESH_A2A_PUSH_POLICY_PATH", "/not/read/deprecated.toml")
        .spawn()
        .unwrap();
    let status = child
        .wait_timeout(Duration::from_secs(5))
        .unwrap()
        .expect("gateway startup watchdog expired");
    assert!(!status.success());
    drop(std::net::TcpListener::bind(address).expect("push config conflict must precede listener"));
}
