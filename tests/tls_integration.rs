#![cfg(unix)]

use std::{
    io::{BufRead as _, BufReader},
    net::SocketAddr,
    os::unix::{fs::PermissionsExt as _, process::ExitStatusExt as _},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex, mpsc},
    thread::JoinHandle,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use futures::stream::BoxStream;
use smesh_a2a::auth::{
    AuthState, AuthenticationError, AuthenticationMethod, BearerVerifier, PresentedBearer,
    Principal, PrincipalLimits, current_principal,
};
use smesh_a2a::transport::{
    ClientAuthMode, TlsIdentityAcceptor, TlsMaterialPaths, TlsSnapshotManager, load_tls_snapshot,
};
use smesh_a2a::{
    DispatchError, GatewayConfig, MeshDispatcher, MeshEvent, MeshRequest, RuntimeEventCapture,
    build_authenticated_router,
};

const WATCHDOG: Duration = Duration::from_secs(8);
const RPC_BODY: &str = r#"{"jsonrpc":"2.0","id":"tls","method":"SendMessage","params":{"message":{"messageId":"tls-message","role":"ROLE_USER","parts":[{"text":"real socket tls"}]}}}"#;
const REST_BODY: &str = r#"{"message":{"messageId":"tls-rest","role":"ROLE_USER","parts":[{"text":"real socket tls"}]}}"#;

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "smesh-a2a-tls-{label}-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("create isolated TLS test directory");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("secure isolated TLS test directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct GatewayProcess {
    child: Option<Child>,
    stderr: Arc<Mutex<String>>,
    events: mpsc::Receiver<String>,
    reader: Option<JoinHandle<()>>,
    reader_done: Option<mpsc::Receiver<()>>,
}

impl GatewayProcess {
    fn signal(&self, signal: i32) {
        let pid = self.child.as_ref().expect("live child").id().to_string();
        let status = Command::new("kill")
            .args([format!("-{signal}"), pid])
            .status()
            .expect("invoke kill");
        assert!(status.success(), "send signal {signal}");
    }

    fn stderr(&self) -> String {
        self.stderr.lock().expect("stderr lock").clone()
    }

    fn wait_for_stderr(&self, needle: &str) {
        let deadline = std::time::Instant::now() + WATCHDOG;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let line = self.events.recv_timeout(remaining).unwrap_or_else(|error| {
                panic!(
                    "stderr event {needle:?} not observed: {error}; stderr: {}",
                    self.stderr()
                )
            });
            if line.contains(needle) {
                return;
            }
        }
    }

    fn shutdown(mut self, signal: i32) -> String {
        self.signal(signal);
        let child = self.child.as_mut().expect("live child");
        let status = wait_timeout::ChildExt::wait_timeout(child, WATCHDOG)
            .expect("wait for gateway")
            .unwrap_or_else(|| {
                child.kill().expect("kill gateway after shutdown timeout");
                wait_timeout::ChildExt::wait_timeout(child, WATCHDOG)
                    .expect("wait for killed gateway")
                    .expect("killed gateway exits within watchdog")
            });
        assert!(
            status.success() || status.signal() == Some(signal),
            "gateway shutdown status {status:?}; stderr: {}",
            self.stderr()
        );
        self.child.take();
        if let (Some(done), Some(reader)) = (self.reader_done.take(), self.reader.take()) {
            done.recv_timeout(WATCHDOG)
                .expect("stderr reader completion watchdog");
            reader.join().expect("join completed stderr reader");
        }
        self.stderr()
    }
}

impl Drop for GatewayProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = wait_timeout::ChildExt::wait_timeout(&mut child, WATCHDOG);
        }
        if let (Some(done), Some(reader)) = (self.reader_done.take(), self.reader.take())
            && done.recv_timeout(WATCHDOG).is_ok()
        {
            let _ = reader.join();
        }
    }
}

fn unused_address() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve test address");
    let address = listener.local_addr().expect("test address");
    drop(listener);
    address
}

fn copy_material(root: &Path) -> TempDir {
    let temp = TempDir::new("material");
    for name in [
        "server.pem",
        "server.key",
        "server-ca.pem",
        "server2.pem",
        "server2.key",
        "server2-ca.pem",
        "evil-server.pem",
        "evil-server.key",
        "client-ca.pem",
        "client.pem",
        "client.key",
        "unmapped-client.pem",
        "unmapped-client.key",
        "untrusted-client.pem",
        "untrusted-client.key",
        "client2-ca.pem",
        "client2.pem",
        "client2.key",
        "principals.json",
        "principals2.json",
    ] {
        std::fs::copy(root.join(name), temp.path().join(name)).expect("copy TLS fixture");
    }
    for name in [
        "server.key",
        "server2.key",
        "evil-server.key",
        "client.key",
        "unmapped-client.key",
        "untrusted-client.key",
        "client2.key",
    ] {
        std::fs::set_permissions(
            temp.path().join(name),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("secure copied key");
    }
    temp
}

fn start_required_gateway_with_env(
    material: &Path,
    address: SocketAddr,
    max_connections: usize,
    extra_environment: &[(&str, &Path)],
) -> GatewayProcess {
    let mut command = Command::new(env!("CARGO_BIN_EXE_smesh-a2a-gateway"));
    command
        .env_clear()
        .env("RUST_LOG", "info")
        .env("SMESH_A2A_AUTH_MODE", "disabled")
        .env("SMESH_A2A_MODE", "loopback")
        .env("SMESH_A2A_BIND", address.to_string())
        .env(
            "SMESH_A2A_PUBLIC_URL",
            format!("https://localhost:{}", address.port()),
        )
        .env("SMESH_A2A_TRANSPORT_MODE", "direct-tls")
        .env("SMESH_A2A_CLIENT_AUTH_MODE", "required")
        .env("SMESH_A2A_TLS_CERT_PATH", material.join("server.pem"))
        .env("SMESH_A2A_TLS_KEY_PATH", material.join("server.key"))
        .env(
            "SMESH_A2A_TLS_CLIENT_CA_PATH",
            material.join("client-ca.pem"),
        )
        .env(
            "SMESH_A2A_TLS_PRINCIPAL_MAP_PATH",
            material.join("principals.json"),
        )
        .env("SMESH_A2A_TLS_HANDSHAKE_TIMEOUT_SECONDS", "1")
        .env("SMESH_A2A_MAX_CONNECTIONS", max_connections.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for (name, value) in extra_environment {
        command.env(name, value);
    }
    let mut child = command.spawn().expect("start direct-TLS gateway");
    let stderr_pipe = child.stderr.take().expect("capture gateway stderr");
    let stderr = Arc::new(Mutex::new(String::new()));
    let captured = Arc::clone(&stderr);
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (event_tx, event_rx) = mpsc::channel();
    let (reader_done_tx, reader_done_rx) = mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        use std::fmt::Write as _;
        let mut ready_tx = Some(ready_tx);
        for line in BufReader::new(stderr_pipe).lines() {
            match line {
                Ok(line) => {
                    let _ = writeln!(captured.lock().expect("stderr lock"), "{line}");
                    let _ = event_tx.send(line.clone());
                    if line.contains("server control signals armed")
                        && let Some(sender) = ready_tx.take()
                    {
                        let _ = sender.send(Ok(()));
                    }
                }
                Err(error) => {
                    if let Some(sender) = ready_tx.take() {
                        let _ = sender.send(Err(error.to_string()));
                    }
                    break;
                }
            }
        }
        if let Some(sender) = ready_tx.take() {
            let _ = sender.send(Err("stderr closed before readiness".to_owned()));
        }
        let _ = reader_done_tx.send(());
    });
    let process = GatewayProcess {
        child: Some(child),
        stderr,
        events: event_rx,
        reader: Some(reader),
        reader_done: Some(reader_done_rx),
    };
    ready_rx
        .recv_timeout(WATCHDOG)
        .unwrap_or_else(|error| {
            panic!(
                "TLS gateway readiness timeout: {error}; stderr: {}",
                process.stderr()
            )
        })
        .unwrap_or_else(|error| {
            panic!(
                "TLS gateway readiness failed: {error}; stderr: {}",
                process.stderr()
            )
        });
    process
}

fn start_required_gateway(
    material: &Path,
    address: SocketAddr,
    max_connections: usize,
) -> GatewayProcess {
    start_required_gateway_with_env(material, address, max_connections, &[])
}

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls")
}

fn identity(material: &Path, cert: &str, key: &str) -> reqwest::Identity {
    let mut pem = std::fs::read(material.join(cert)).expect("read identity certificate");
    pem.extend(std::fs::read(material.join(key)).expect("read identity key"));
    reqwest::Identity::from_pem(&pem).expect("parse test client identity")
}

fn root_certificate(path: &Path) -> reqwest::Certificate {
    reqwest::Certificate::from_pem(&std::fs::read(path).expect("read root certificate"))
        .expect("parse root certificate")
}

async fn raw_mtls_connection(
    material: &Path,
    address: SocketAddr,
    server_ca: &str,
    client_cert: &str,
    client_key: &str,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    use a2a_server::tls::rustls;
    use rustls::pki_types::pem::PemObject as _;

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    for certificate in rustls::pki_types::CertificateDer::pem_file_iter(material.join(server_ca))
        .expect("open raw-client server CA")
    {
        roots
            .add(certificate.expect("parse raw-client server CA"))
            .expect("trust raw-client server CA");
    }
    let certificates = rustls::pki_types::CertificateDer::pem_file_iter(material.join(client_cert))
        .expect("open raw-client certificate")
        .collect::<Result<Vec<_>, _>>()
        .expect("parse raw-client certificate");
    let mut keys = rustls::pki_types::PrivateKeyDer::pem_file_iter(material.join(client_key))
        .expect("open raw-client private key")
        .collect::<Result<Vec<_>, _>>()
        .expect("parse raw-client private key");
    let key = keys.pop().expect("one raw-client private key");
    assert!(keys.is_empty(), "exactly one raw-client private key");
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certificates, key)
        .expect("raw mTLS client config");
    let tcp = tokio::time::timeout(WATCHDOG, tokio::net::TcpStream::connect(address))
        .await
        .expect("raw TCP connect watchdog")
        .expect("raw TCP connect");
    tokio::time::timeout(
        WATCHDOG,
        tokio_rustls::TlsConnector::from(Arc::new(config)).connect(
            rustls::pki_types::ServerName::try_from("localhost")
                .expect("localhost server name")
                .to_owned(),
            tcp,
        ),
    )
    .await
    .expect("raw TLS handshake watchdog")
    .expect("raw TLS handshake")
}

fn replace_file(source: &Path, destination: &Path, private: bool) {
    let temporary = destination.with_extension("next");
    std::fs::copy(source, &temporary).expect("stage complete TLS material component");
    if private {
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))
            .expect("secure staged private key");
    }
    std::fs::rename(temporary, destination).expect("publish complete TLS material component");
}

fn client_builder_with_identity(
    material: &Path,
    certificate: Option<(&str, &str)>,
) -> reqwest::ClientBuilder {
    let builder = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(2))
        .timeout(WATCHDOG)
        .tls_certs_only([root_certificate(&material.join("server-ca.pem"))]);
    if let Some((cert, key)) = certificate {
        builder.identity(identity(material, cert, key))
    } else {
        builder
    }
}

fn client_builder(material: &Path) -> reqwest::ClientBuilder {
    client_builder_with_identity(material, Some(("client.pem", "client.key")))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PrincipalObservation {
    issuer: String,
    subject: String,
    method: AuthenticationMethod,
}

#[derive(Clone, Default)]
struct PrincipalRecordingDispatcher(Arc<Mutex<Vec<PrincipalObservation>>>);

#[async_trait]
impl MeshDispatcher for PrincipalRecordingDispatcher {
    fn dispatch(
        &self,
        _request: MeshRequest,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        let principal = current_principal().expect("authenticated dispatcher principal");
        self.0
            .lock()
            .expect("observation lock")
            .push(PrincipalObservation {
                issuer: principal.issuer().to_owned(),
                subject: principal.subject().to_owned(),
                method: principal.authentication_method(),
            });
        Box::pin(futures::stream::iter([Ok(MeshEvent::Completed {
            summary: "principal observed".to_owned(),
        })]))
    }

    async fn cancel(&self, _task_id: &str) -> Result<(), DispatchError> {
        Ok(())
    }
}

struct DeterministicBearerVerifier;

#[async_trait]
impl BearerVerifier for DeterministicBearerVerifier {
    async fn verify(&self, token: PresentedBearer<'_>) -> Result<Principal, AuthenticationError> {
        let subject = match token.as_str() {
            "same-principal-token" => "agent-17",
            "conflicting-principal-token" => "other-agent",
            _ => return Err(AuthenticationError::InvalidToken),
        };
        // AuthenticationMethod differs, but the authoritative identity tuple is
        // intentionally identical to the mapped certificate for the same case.
        Principal::bearer_for_verifier(
            "mtls:test".to_owned(),
            subject.to_owned(),
            PrincipalLimits::default(),
        )
        .map_err(|_| AuthenticationError::InvalidToken)
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn real_optional_and_required_mtls_bearer_matrix_preserves_exact_downstream_principal() {
    fn start(
        material: &Path,
        mode: ClientAuthMode,
    ) -> (
        SocketAddr,
        a2a_server::tls::axum_server::Handle<SocketAddr>,
        tokio::task::JoinHandle<std::io::Result<()>>,
        PrincipalRecordingDispatcher,
    ) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind matrix server");
        let address = listener.local_addr().expect("matrix address");
        listener
            .set_nonblocking(true)
            .expect("nonblocking matrix listener");
        let paths = TlsMaterialPaths {
            cert: material.join("server.pem"),
            key: material.join("server.key"),
            client_ca: Some(material.join("client-ca.pem")),
            principal_map: Some(material.join("principals.json")),
        };
        let snapshot = load_tls_snapshot(&paths, mode, 1).expect("matrix TLS snapshot");
        let manager = Arc::new(TlsSnapshotManager::new(
            snapshot,
            paths,
            mode,
            "https://localhost".to_owned(),
        ));
        let acceptor = TlsIdentityAcceptor::new(manager, WATCHDOG, 16);
        let dispatcher = PrincipalRecordingDispatcher::default();
        let base_auth = AuthState::new(Arc::new(DeterministicBearerVerifier), [91; 32]);
        let auth = if mode == ClientAuthMode::Required {
            base_auth.with_required_mutual_tls()
        } else {
            base_auth.with_mutual_tls()
        };
        let app = build_authenticated_router(
            GatewayConfig::new(format!("https://localhost:{}", address.port()), "matrix"),
            dispatcher.clone(),
            auth,
        );
        let handle = a2a_server::tls::axum_server::Handle::<SocketAddr>::new();
        let server = a2a_server::tls::axum_server::from_tcp(listener)
            .expect("matrix TLS server")
            .acceptor(acceptor)
            .handle(handle.clone());
        let task = tokio::spawn(async move { server.serve(app.into_make_service()).await });
        (address, handle, task, dispatcher)
    }

    async fn stop(
        handle: a2a_server::tls::axum_server::Handle<SocketAddr>,
        task: tokio::task::JoinHandle<std::io::Result<()>>,
    ) {
        handle.graceful_shutdown(Some(Duration::from_secs(1)));
        tokio::time::timeout(WATCHDOG, task)
            .await
            .expect("matrix server shutdown watchdog")
            .expect("join matrix server")
            .expect("matrix server result");
    }

    async fn request_response(
        client: &reqwest::Client,
        address: SocketAddr,
        protocol: &str,
        case: &str,
        bearer: Option<&str>,
    ) -> reqwest::Response {
        let base = format!("https://localhost:{}", address.port());
        let (path, body) = if protocol == "jsonrpc" {
            (
                "/jsonrpc",
                serde_json::json!({
                    "jsonrpc":"2.0", "id":case, "method":"SendMessage",
                    "params":{"message":{"messageId":format!("{case}-rpc"),"role":"ROLE_USER","parts":[{"text":case}]}}
                })
                .to_string(),
            )
        } else {
            (
                "/rest/message:send",
                serde_json::json!({
                    "message":{"messageId":format!("{case}-rest"),"role":"ROLE_USER","parts":[{"text":case}]}
                })
                .to_string(),
            )
        };
        let mut request = client
            .post(format!("{base}{path}"))
            .header("content-type", "application/json")
            .body(body);
        if let Some(token) = bearer {
            request = request.bearer_auth(token);
        }
        request.send().await.expect("real matrix HTTPS request")
    }

    async fn request(
        client: &reqwest::Client,
        address: SocketAddr,
        protocol: &str,
        case: &str,
        bearer: Option<&str>,
    ) -> reqwest::StatusCode {
        let response = request_response(client, address, protocol, case, bearer).await;
        let status = response.status();
        let _ = response
            .bytes()
            .await
            .expect("bounded matrix response body");
        status
    }

    let material = copy_material(&fixture_root());
    let mapped = client_builder_with_identity(material.path(), Some(("client.pem", "client.key")))
        .build()
        .expect("mapped matrix client");
    let unmapped = client_builder_with_identity(
        material.path(),
        Some(("unmapped-client.pem", "unmapped-client.key")),
    )
    .build()
    .expect("unmapped matrix client");
    let no_certificate = client_builder_with_identity(material.path(), None)
        .build()
        .expect("bearer-only matrix client");
    let untrusted = client_builder_with_identity(
        material.path(),
        Some(("untrusted-client.pem", "untrusted-client.key")),
    )
    .build()
    .expect("untrusted optional-mTLS client");

    let (address, handle, task, dispatcher) = start(material.path(), ClientAuthMode::Optional);
    let unmapped_response = request_response(
        &unmapped,
        address,
        "jsonrpc",
        "optional-unmapped-no-challenge",
        Some("same-principal-token"),
    )
    .await;
    assert_eq!(
        unmapped_response.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    assert!(
        !unmapped_response
            .headers()
            .contains_key(reqwest::header::WWW_AUTHENTICATE),
        "an unmapped verified certificate is a certificate-identity failure, not a Bearer failure"
    );
    assert!(
        untrusted
            .get(format!("https://localhost:{}/", address.port()))
            .send()
            .await
            .is_err(),
        "optional mTLS must reject a presented certificate issued by an untrusted CA"
    );
    for protocol in ["jsonrpc", "rest"] {
        assert_eq!(
            request(
                &no_certificate,
                address,
                protocol,
                &format!("optional-bearer-{protocol}"),
                Some("same-principal-token"),
            )
            .await,
            reqwest::StatusCode::OK,
            "no certificate plus valid bearer"
        );
        assert_eq!(
            request(
                &mapped,
                address,
                protocol,
                &format!("optional-mapped-{protocol}"),
                None,
            )
            .await,
            reqwest::StatusCode::OK,
            "mapped certificate without bearer"
        );
        assert_eq!(
            request(
                &unmapped,
                address,
                protocol,
                &format!("optional-unmapped-{protocol}"),
                Some("same-principal-token"),
            )
            .await,
            reqwest::StatusCode::UNAUTHORIZED,
            "same-CA unmapped certificate must never fall back to bearer"
        );
        assert_eq!(
            request(
                &mapped,
                address,
                protocol,
                &format!("optional-same-{protocol}"),
                Some("same-principal-token"),
            )
            .await,
            reqwest::StatusCode::OK,
            "mapped certificate plus same bearer"
        );
        assert_eq!(
            request(
                &mapped,
                address,
                protocol,
                &format!("optional-conflict-{protocol}"),
                Some("conflicting-principal-token"),
            )
            .await,
            reqwest::StatusCode::UNAUTHORIZED,
            "mapped certificate plus conflicting bearer"
        );
    }
    stop(handle, task).await;
    let optional = dispatcher.0.lock().expect("optional observations").clone();
    assert_eq!(
        optional,
        [
            PrincipalObservation {
                issuer: "mtls:test".to_owned(),
                subject: "agent-17".to_owned(),
                method: AuthenticationMethod::BearerJwt
            },
            PrincipalObservation {
                issuer: "mtls:test".to_owned(),
                subject: "agent-17".to_owned(),
                method: AuthenticationMethod::MutualTls
            },
            PrincipalObservation {
                issuer: "mtls:test".to_owned(),
                subject: "agent-17".to_owned(),
                method: AuthenticationMethod::MutualTls
            },
            PrincipalObservation {
                issuer: "mtls:test".to_owned(),
                subject: "agent-17".to_owned(),
                method: AuthenticationMethod::BearerJwt
            },
            PrincipalObservation {
                issuer: "mtls:test".to_owned(),
                subject: "agent-17".to_owned(),
                method: AuthenticationMethod::MutualTls
            },
            PrincipalObservation {
                issuer: "mtls:test".to_owned(),
                subject: "agent-17".to_owned(),
                method: AuthenticationMethod::MutualTls
            },
        ],
        "only successful JSON-RPC then REST cases reach the dispatcher with the exact authoritative principal"
    );

    let (address, handle, task, dispatcher) = start(material.path(), ClientAuthMode::Required);
    for protocol in ["jsonrpc", "rest"] {
        assert_eq!(
            request(
                &mapped,
                address,
                protocol,
                &format!("required-same-{protocol}"),
                Some("same-principal-token"),
            )
            .await,
            reqwest::StatusCode::OK
        );
        assert_eq!(
            request(
                &mapped,
                address,
                protocol,
                &format!("required-conflict-{protocol}"),
                Some("conflicting-principal-token"),
            )
            .await,
            reqwest::StatusCode::UNAUTHORIZED
        );
    }
    stop(handle, task).await;
    assert_eq!(
        dispatcher
            .0
            .lock()
            .expect("required observations")
            .as_slice(),
        [
            PrincipalObservation {
                issuer: "mtls:test".to_owned(),
                subject: "agent-17".to_owned(),
                method: AuthenticationMethod::MutualTls
            },
            PrincipalObservation {
                issuer: "mtls:test".to_owned(),
                subject: "agent-17".to_owned(),
                method: AuthenticationMethod::MutualTls
            },
        ]
    );
}

#[tokio::test]
async fn direct_tls_real_socket_serves_jsonrpc_and_rest_over_http1_and_http2() {
    let material = copy_material(&fixture_root());
    let address = unused_address();
    let gateway = start_required_gateway(material.path(), address, 16);
    let base = format!("https://localhost:{}", address.port());

    for (builder, expected) in [
        (
            client_builder(material.path()).http1_only(),
            reqwest::Version::HTTP_11,
        ),
        (
            client_builder(material.path()).http2_prior_knowledge(),
            reqwest::Version::HTTP_2,
        ),
    ] {
        let client = builder.build().expect("build protocol-pinned client");
        let rpc = client
            .post(format!("{base}/jsonrpc"))
            .header("content-type", "application/json")
            .body(RPC_BODY)
            .send()
            .await
            .expect("real HTTPS JSON-RPC request");
        assert_eq!(rpc.status(), reqwest::StatusCode::OK);
        assert_eq!(rpc.version(), expected, "negotiated HTTP version");
        let rpc_json: serde_json::Value = rpc.json().await.expect("JSON-RPC response JSON");
        assert!(
            rpc_json.get("error").is_none(),
            "JSON-RPC error: {rpc_json}"
        );

        let rest = client
            .post(format!("{base}/rest/message:send"))
            .header("content-type", "application/json")
            .body(REST_BODY)
            .send()
            .await
            .expect("real HTTPS REST request");
        assert_eq!(rest.status(), reqwest::StatusCode::OK);
        assert_eq!(rest.version(), expected, "negotiated REST HTTP version");
    }

    let stderr = gateway.shutdown(15);
    assert!(!stderr.contains("PRIVATE KEY"));
}

#[tokio::test]
async fn direct_tls_rejects_bad_transport_and_enforces_required_mtls_mapping() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let material = copy_material(&fixture_root());
    let address = unused_address();
    let gateway = start_required_gateway(material.path(), address, 16);
    let base = format!("https://localhost:{}", address.port());

    let no_certificate = client_builder_with_identity(material.path(), None)
        .build()
        .expect("client without certificate");
    assert!(
        no_certificate.get(&base).send().await.is_err(),
        "required mTLS must fail the TLS handshake when no certificate is presented"
    );

    let untrusted = client_builder_with_identity(
        material.path(),
        Some(("untrusted-client.pem", "untrusted-client.key")),
    )
    .build()
    .expect("untrusted identity client");
    assert!(
        untrusted.get(&base).send().await.is_err(),
        "a separately issued client must fail the TLS handshake"
    );

    let unmapped = client_builder_with_identity(
        material.path(),
        Some(("unmapped-client.pem", "unmapped-client.key")),
    )
    .build()
    .expect("same-CA unmapped client");
    let unmapped_response = unmapped
        .post(format!("{base}/jsonrpc"))
        .header("content-type", "application/json")
        .body(RPC_BODY)
        .send()
        .await
        .expect("same-CA certificate completes TLS");
    assert_eq!(
        unmapped_response.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    assert!(
        !unmapped_response
            .headers()
            .contains_key(reqwest::header::WWW_AUTHENTICATE),
        "mTLS-only rejection must not advertise an unusable Bearer challenge"
    );

    let unknown_ca = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(2))
        .timeout(WATCHDOG)
        .identity(identity(material.path(), "client.pem", "client.key"))
        .build()
        .expect("system-roots-only client");
    assert!(
        unknown_ca.get(&base).send().await.is_err(),
        "unknown serving CA must fail"
    );

    let mismatch = client_builder(material.path())
        .resolve("not-localhost.invalid", address)
        .build()
        .expect("hostname-mismatch client");
    assert!(
        mismatch
            .get(format!("https://not-localhost.invalid:{}", address.port()))
            .send()
            .await
            .is_err(),
        "hostname mismatch must fail"
    );

    let mut plaintext = tokio::time::timeout(WATCHDOG, tokio::net::TcpStream::connect(address))
        .await
        .expect("plaintext connect watchdog")
        .expect("plaintext TCP connection");
    plaintext
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("write plaintext probe");
    let mut reply = [0_u8; 64];
    let read = tokio::time::timeout(WATCHDOG, plaintext.read(&mut reply))
        .await
        .expect("plaintext rejection watchdog");
    if let Ok(count) = read {
        assert!(
            !reply[..count].starts_with(b"HTTP/"),
            "TLS port returned plaintext HTTP"
        );
    }

    let mut stalled = tokio::time::timeout(WATCHDOG, tokio::net::TcpStream::connect(address))
        .await
        .expect("stalled connect watchdog")
        .expect("stalled TCP connection");
    let stalled_read = tokio::time::timeout(WATCHDOG, stalled.read(&mut reply))
        .await
        .expect("server handshake deadline watchdog");
    assert!(
        matches!(stalled_read, Ok(0) | Err(_)),
        "stalled TLS handshake was not closed at the server deadline"
    );

    gateway.shutdown(15);
}

#[tokio::test]
async fn mapped_identity_ignores_spoofable_forwarding_and_principal_headers() {
    let material = copy_material(&fixture_root());
    let address = unused_address();
    let gateway = start_required_gateway(material.path(), address, 16);
    let client = client_builder(material.path())
        .build()
        .expect("mapped client");
    let response = client
        .post(format!("https://localhost:{}/jsonrpc", address.port()))
        .header("content-type", "application/json")
        .header("forwarded", "for=attacker;proto=https")
        .header("x-forwarded-client-cert", "By=attacker;Hash=forged")
        .header("x-client-cert", "forged-client-certificate")
        .header("x-smesh-principal", "forged-principal")
        .body(RPC_BODY)
        .send()
        .await
        .expect("spoof-attempt request over mapped mTLS");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body = response.text().await.expect("spoof response body");
    assert!(!body.contains("attacker"));
    assert!(!body.contains("forged"));
    gateway.shutdown(15);
}

#[test]
#[allow(clippy::too_many_lines)]
fn invalid_tls_material_fails_before_listener_or_durable_resource_acquisition_and_redacts_canaries()
{
    let fixture = fixture_root();
    for case in [
        "missing-cert",
        "bad-cert",
        "bad-key",
        "mismatched-key",
        "bad-ca",
        "bad-map",
        "insecure-key",
    ] {
        let material = copy_material(&fixture);
        let canary = format!("ISSUE12-{case}-TLS-CERT-KEY-TOKEN-CANARY");
        match case {
            "missing-cert" => std::fs::remove_file(material.path().join("server.pem")).unwrap(),
            "bad-cert" => {
                std::fs::write(material.path().join("server.pem"), canary.as_bytes()).unwrap();
            }
            "bad-key" => {
                std::fs::write(material.path().join("server.key"), canary.as_bytes()).unwrap();
                std::fs::set_permissions(
                    material.path().join("server.key"),
                    std::fs::Permissions::from_mode(0o600),
                )
                .unwrap();
            }
            "mismatched-key" => replace_file(
                &material.path().join("server2.key"),
                &material.path().join("server.key"),
                true,
            ),
            "bad-ca" => {
                std::fs::write(material.path().join("client-ca.pem"), canary.as_bytes()).unwrap();
            }
            "bad-map" => std::fs::write(
                material.path().join("principals.json"),
                format!(r#"{{"{canary}":{{}}}}"#),
            )
            .unwrap(),
            "insecure-key" => std::fs::set_permissions(
                material.path().join("server.key"),
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap(),
            _ => unreachable!(),
        }
        let address = unused_address();
        let database = material.path().join("must-not-exist.sqlite");
        let trace = material.path().join("must-not-exist.trace.json");
        let mut child = Command::new(env!("CARGO_BIN_EXE_smesh-a2a-gateway"))
            .env_clear()
            .env("RUST_LOG", "trace")
            .env("SMESH_A2A_AUTH_MODE", "disabled")
            .env("SMESH_A2A_MODE", "loopback")
            .env("SMESH_A2A_BIND", address.to_string())
            .env(
                "SMESH_A2A_PUBLIC_URL",
                format!("https://localhost:{}", address.port()),
            )
            .env("SMESH_A2A_TRANSPORT_MODE", "direct-tls")
            .env("SMESH_A2A_CLIENT_AUTH_MODE", "required")
            .env(
                "SMESH_A2A_TLS_CERT_PATH",
                material.path().join("server.pem"),
            )
            .env("SMESH_A2A_TLS_KEY_PATH", material.path().join("server.key"))
            .env(
                "SMESH_A2A_TLS_CLIENT_CA_PATH",
                material.path().join("client-ca.pem"),
            )
            .env(
                "SMESH_A2A_TLS_PRINCIPAL_MAP_PATH",
                material.path().join("principals.json"),
            )
            .env("SMESH_A2A_SQLITE_PATH", &database)
            .env("SMESH_RUNTIME_TRACE_PATH", &trace)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn invalid material process");
        let Some(status) = wait_timeout::ChildExt::wait_timeout(&mut child, WATCHDOG)
            .expect("invalid material child wait")
        else {
            child.kill().expect("kill hung invalid material child");
            wait_timeout::ChildExt::wait_timeout(&mut child, WATCHDOG)
                .expect("wait for killed invalid material child")
                .expect("killed invalid material child exits within watchdog");
            panic!("invalid TLS case {case} did not fail within watchdog");
        };
        assert!(
            !status.success(),
            "invalid TLS case {case} unexpectedly started"
        );
        let output = child
            .wait_with_output()
            .expect("collect reaped invalid material output");
        let mut evidence = output.stdout;
        evidence.extend(output.stderr);
        assert!(
            !evidence
                .windows(canary.len())
                .any(|window| window == canary.as_bytes()),
            "{case} leaked canary"
        );
        assert!(
            !database.exists(),
            "{case} acquired SQLite before TLS validation"
        );
        assert!(
            !PathBuf::from(format!("{}.lock", database.display())).exists(),
            "{case} left a lock"
        );
        assert!(!trace.exists(), "{case} created a runtime trace");
        let rebound = std::net::TcpListener::bind(address)
            .unwrap_or_else(|error| panic!("{case} acquired listener: {error}"));
        drop(rebound);
    }
}

#[test]
fn invalid_tls_material_precedes_runtime_and_reserved_mesh_address_acquisition() {
    let material = copy_material(&fixture_root());
    std::fs::write(
        material.path().join("server.pem"),
        b"invalid TLS certificate",
    )
    .expect("corrupt runtime TLS certificate");
    let http_address = unused_address();
    let mesh_address = unused_address();
    let trace = material.path().join("must-not-exist-runtime.trace.json");
    let mut child = Command::new(env!("CARGO_BIN_EXE_smesh-a2a-gateway"))
        .env_clear()
        .env("RUST_LOG", "trace")
        .env("SMESH_A2A_AUTH_MODE", "disabled")
        .env("SMESH_A2A_MODE", "runtime")
        .env("SMESH_A2A_MESH_BIND", mesh_address.to_string())
        .env("SMESH_RUNTIME_TRACE_PATH", &trace)
        .env("SMESH_A2A_BIND", http_address.to_string())
        .env(
            "SMESH_A2A_PUBLIC_URL",
            format!("https://localhost:{}", http_address.port()),
        )
        .env("SMESH_A2A_TRANSPORT_MODE", "direct-tls")
        .env("SMESH_A2A_CLIENT_AUTH_MODE", "required")
        .env(
            "SMESH_A2A_TLS_CERT_PATH",
            material.path().join("server.pem"),
        )
        .env("SMESH_A2A_TLS_KEY_PATH", material.path().join("server.key"))
        .env(
            "SMESH_A2A_TLS_CLIENT_CA_PATH",
            material.path().join("client-ca.pem"),
        )
        .env(
            "SMESH_A2A_TLS_PRINCIPAL_MAP_PATH",
            material.path().join("principals.json"),
        )
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn invalid runtime TLS process");
    let Some(status) = wait_timeout::ChildExt::wait_timeout(&mut child, WATCHDOG)
        .expect("invalid runtime material child wait")
    else {
        child.kill().expect("kill hung invalid runtime process");
        wait_timeout::ChildExt::wait_timeout(&mut child, WATCHDOG)
            .expect("wait for killed invalid runtime process")
            .expect("killed invalid runtime process exits within watchdog");
        panic!("invalid runtime TLS material did not fail within watchdog");
    };
    assert!(
        !status.success(),
        "invalid runtime TLS unexpectedly started"
    );
    assert!(
        !trace.exists(),
        "TLS validation must precede runtime trace creation"
    );
    let mesh = std::net::TcpListener::bind(mesh_address)
        .expect("TLS validation must precede mesh listener acquisition");
    drop(mesh);
    let http = std::net::TcpListener::bind(http_address)
        .expect("TLS validation must precede HTTP listener acquisition");
    drop(http);
}

#[test]
fn direct_tls_durable_and_runtime_sigint_sigterm_release_locks_and_persist_replayable_traces() {
    for signal in [2, 15] {
        let material = copy_material(&fixture_root());
        let database = material.path().join(format!("durable-{signal}.sqlite"));
        let address = unused_address();
        let gateway = start_required_gateway_with_env(
            material.path(),
            address,
            16,
            &[("SMESH_A2A_SQLITE_PATH", database.as_path())],
        );
        let held_database = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&database)
            .unwrap();
        assert!(
            fs2::FileExt::try_lock_exclusive(&held_database).is_err(),
            "durable process must hold database ownership lock"
        );
        let stderr = gateway.shutdown(signal);
        fs2::FileExt::try_lock_exclusive(&held_database)
            .expect("shutdown releases database ownership lock");
        fs2::FileExt::unlock(&held_database).expect("release test ownership lock");
        assert!(!stderr.contains("PRIVATE KEY"));
        let reopened = start_required_gateway_with_env(
            material.path(),
            unused_address(),
            16,
            &[("SMESH_A2A_SQLITE_PATH", database.as_path())],
        );
        reopened.shutdown(if signal == 2 { 15 } else { 2 });
        fs2::FileExt::try_lock_exclusive(&held_database)
            .expect("reopened process also releases ownership lock");
        fs2::FileExt::unlock(&held_database).expect("release reopened test lock");

        let trace = material.path().join(format!("runtime-{signal}.trace.json"));
        let address = unused_address();
        let runtime = start_required_gateway_with_env(
            material.path(),
            address,
            16,
            &[
                ("SMESH_A2A_MODE", Path::new("runtime")),
                ("SMESH_A2A_MESH_BIND", Path::new("127.0.0.1:0")),
                ("SMESH_RUNTIME_TRACE_PATH", trace.as_path()),
            ],
        );
        runtime.shutdown(signal);
        let bytes = std::fs::read(&trace).expect("persisted direct-TLS runtime trace");
        RuntimeEventCapture::replay(&bytes).expect("replay direct-TLS shutdown trace");
        assert!(!PathBuf::from(format!("{}.tmp", trace.display())).exists());
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn tls_certificate_key_and_token_canaries_never_cross_response_log_trace_or_sqlite_boundaries()
 {
    const CERT_CANARY: &str = "ISSUE12_TLS_CERT_CANARY_NEVER_DISCLOSE";
    const KEY_CANARY: &str = "ISSUE12_TLS_KEY_CANARY_NEVER_DISCLOSE";
    const TOKEN_CANARY: &str = "ISSUE12_TLS_TOKEN_CANARY_NEVER_DISCLOSE";

    fn prefix(path: &Path, canary: &str, private: bool) {
        let original = std::fs::read(path).expect("read canary material");
        let mut decorated = format!("# {canary}\n").into_bytes();
        decorated.extend(original);
        std::fs::write(path, decorated).expect("decorate canary material");
        if private {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .expect("secure decorated key");
        }
    }

    async fn reject(address: SocketAddr, material: &Path) -> Vec<u8> {
        let client = client_builder(material)
            .build()
            .expect("canary mTLS client");
        let response = client
            .post(format!("https://localhost:{}/jsonrpc", address.port()))
            .header("content-type", "application/json")
            .bearer_auth(TOKEN_CANARY)
            .body(RPC_BODY)
            .send()
            .await
            .expect("canary request");
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
        response
            .bytes()
            .await
            .expect("canary response body")
            .to_vec()
    }

    fn assert_redacted(bytes: &[u8], surface: &str) {
        for canary in [CERT_CANARY, KEY_CANARY, TOKEN_CANARY] {
            assert!(
                !bytes
                    .windows(canary.len())
                    .any(|window| window == canary.as_bytes()),
                "{surface} leaked {canary}"
            );
        }
    }

    let durable_material = copy_material(&fixture_root());
    prefix(
        &durable_material.path().join("server.pem"),
        CERT_CANARY,
        false,
    );
    prefix(
        &durable_material.path().join("server.key"),
        KEY_CANARY,
        true,
    );
    let database = durable_material.path().join("canary.sqlite");
    let address = unused_address();
    let durable = start_required_gateway_with_env(
        durable_material.path(),
        address,
        16,
        &[("SMESH_A2A_SQLITE_PATH", database.as_path())],
    );
    assert_redacted(
        &reject(address, durable_material.path()).await,
        "HTTP response",
    );
    let stderr = durable.shutdown(15);
    assert_redacted(stderr.as_bytes(), "durable stderr");
    for suffix in ["", "-wal", "-shm"] {
        let path = PathBuf::from(format!("{}{suffix}", database.display()));
        if let Ok(bytes) = std::fs::read(&path) {
            assert_redacted(&bytes, "SQLite");
        }
    }

    let runtime_material = copy_material(&fixture_root());
    prefix(
        &runtime_material.path().join("server.pem"),
        CERT_CANARY,
        false,
    );
    prefix(
        &runtime_material.path().join("server.key"),
        KEY_CANARY,
        true,
    );
    let trace = runtime_material.path().join("canary.trace.json");
    let address = unused_address();
    let runtime = start_required_gateway_with_env(
        runtime_material.path(),
        address,
        16,
        &[
            ("SMESH_A2A_MODE", Path::new("runtime")),
            ("SMESH_A2A_MESH_BIND", Path::new("127.0.0.1:0")),
            ("SMESH_RUNTIME_TRACE_PATH", trace.as_path()),
        ],
    );
    assert_redacted(
        &reject(address, runtime_material.path()).await,
        "runtime HTTP response",
    );
    let stderr = runtime.shutdown(2);
    assert_redacted(stderr.as_bytes(), "runtime stderr");
    let trace_bytes = std::fs::read(&trace).expect("canary runtime trace");
    RuntimeEventCapture::replay(&trace_bytes).expect("replay canary runtime trace");
    assert_redacted(&trace_bytes, "runtime trace");
}

#[test]
fn official_a2a_client_custom_root_support_is_checked_and_its_factory_limitation_is_documented() {
    let root = std::fs::read(fixture_root().join("server-ca.pem")).expect("SDK test root");
    let sdk_http = a2a_client::default_reqwest_client(Some(&root))
        .expect("official SDK low-level helper accepts an extra root PEM");
    let _resolver = a2a_client::agent_card::AgentCardResolver::new(Some(sdk_http.clone()));
    let _factory = a2a_client::A2AClientFactory::builder()
        .no_defaults()
        .register(Arc::new(a2a_client::jsonrpc::JsonRpcTransportFactory::new(
            Some(sdk_http),
        )))
        .build();

    let readme = include_str!("../README.md");
    assert!(readme.contains("A2A client SDK TLS limitation (a2a-client-lf 0.2.2)"));
    assert!(readme.contains("does not expose a custom `reqwest::Client`"));
    assert!(readme.contains("does not provide client-identity (mTLS) configuration"));
}

#[tokio::test]
async fn production_socket_limiter_queues_then_recovers_with_the_reloaded_generation() {
    let material = copy_material(&fixture_root());
    let address = unused_address();
    let gateway = start_required_gateway(material.path(), address, 1);

    // A completed TLS handshake consumes the sole production permit while the
    // resulting connection remains alive, without relying on request timing.
    let held = raw_mtls_connection(
        material.path(),
        address,
        "server-ca.pem",
        "client.pem",
        "client.key",
    )
    .await;

    let material_path = material.path().to_owned();
    let mut queued = tokio::spawn(async move {
        raw_mtls_connection(
            &material_path,
            address,
            "server2-ca.pem",
            "client2.pem",
            "client2.key",
        )
        .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut queued)
            .await
            .is_err(),
        "the second real socket must remain queued while max_connections=1 is occupied"
    );

    replace_file(
        &material.path().join("server2.pem"),
        &material.path().join("server.pem"),
        false,
    );
    replace_file(
        &material.path().join("server2.key"),
        &material.path().join("server.key"),
        true,
    );
    replace_file(
        &material.path().join("client2-ca.pem"),
        &material.path().join("client-ca.pem"),
        false,
    );
    replace_file(
        &material.path().join("principals2.json"),
        &material.path().join("principals.json"),
        false,
    );
    gateway.signal(1);
    gateway.wait_for_stderr("TLS snapshot reloaded");
    drop(held);

    let current_generation = tokio::time::timeout(WATCHDOG, queued)
        .await
        .expect("queued real socket recovery watchdog")
        .expect("queued real socket task");
    drop(current_generation);

    // Releasing the queued connection returns the permit; another connection
    // using only generation-two trust must now complete within the bound.
    let recovered = raw_mtls_connection(
        material.path(),
        address,
        "server2-ca.pem",
        "client2.pem",
        "client2.key",
    )
    .await;
    drop(recovered);
    gateway.shutdown(15);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn sighup_atomically_rotates_tls_trust_map_and_preserves_old_keepalive_generation() {
    let material = copy_material(&fixture_root());
    let address = unused_address();
    let gateway = start_required_gateway(material.path(), address, 16);
    let endpoint = format!("https://localhost:{}/jsonrpc", address.port());

    let old = client_builder(material.path())
        .http1_only()
        .pool_max_idle_per_host(1)
        .build()
        .expect("old-generation keepalive client");
    let request = || {
        old.post(&endpoint)
            .header("content-type", "application/json")
            .body(RPC_BODY)
    };
    assert_eq!(
        request()
            .send()
            .await
            .expect("prime old TLS connection")
            .status(),
        reqwest::StatusCode::OK
    );

    replace_file(
        &material.path().join("server2.pem"),
        &material.path().join("server.pem"),
        false,
    );
    replace_file(
        &material.path().join("server2.key"),
        &material.path().join("server.key"),
        true,
    );
    replace_file(
        &material.path().join("client2-ca.pem"),
        &material.path().join("client-ca.pem"),
        false,
    );
    replace_file(
        &material.path().join("principals2.json"),
        &material.path().join("principals.json"),
        false,
    );
    gateway.signal(1);
    gateway.wait_for_stderr("TLS snapshot reloaded");

    assert_eq!(
        request()
            .send()
            .await
            .expect("old keepalive retains accepted identity")
            .status(),
        reqwest::StatusCode::OK
    );

    let rotated = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(2))
        .timeout(WATCHDOG)
        .tls_certs_only([root_certificate(&material.path().join("server2-ca.pem"))])
        .identity(identity(material.path(), "client2.pem", "client2.key"))
        .build()
        .expect("rotated trust client");
    assert_eq!(
        rotated
            .post(&endpoint)
            .header("content-type", "application/json")
            .body(RPC_BODY)
            .send()
            .await
            .expect("new connection observes rotated certificate, root, and map")
            .status(),
        reqwest::StatusCode::OK
    );

    replace_file(
        &material.path().join("evil-server.pem"),
        &material.path().join("server.pem"),
        false,
    );
    replace_file(
        &material.path().join("evil-server.key"),
        &material.path().join("server.key"),
        true,
    );
    gateway.signal(1);
    gateway.wait_for_stderr("TLS snapshot reload rejected");
    let after_bad_san = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(2))
        .timeout(WATCHDOG)
        .tls_certs_only([root_certificate(&material.path().join("server2-ca.pem"))])
        .identity(identity(material.path(), "client2.pem", "client2.key"))
        .build()
        .expect("fresh client after rejected SAN reload");
    assert_eq!(
        after_bad_san
            .post(&endpoint)
            .header("content-type", "application/json")
            .body(RPC_BODY)
            .send()
            .await
            .expect("bad-SAN reload retains last-good serving certificate")
            .status(),
        reqwest::StatusCode::OK
    );

    let stale_identity = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(2))
        .timeout(WATCHDOG)
        .tls_certs_only([root_certificate(&material.path().join("server2-ca.pem"))])
        .identity(identity(material.path(), "client.pem", "client.key"))
        .build()
        .expect("stale identity client");
    assert!(
        stale_identity
            .post(&endpoint)
            .body(RPC_BODY)
            .send()
            .await
            .is_err(),
        "new connections must not retain the old client trust root"
    );

    std::fs::write(
        material.path().join("server.key"),
        b"TLS-KEY-CANARY-DO-NOT-LOG",
    )
    .expect("stage torn reload");
    std::fs::set_permissions(
        material.path().join("server.key"),
        std::fs::Permissions::from_mode(0o600),
    )
    .expect("secure torn key");
    gateway.signal(1);
    gateway.wait_for_stderr("reload rejected");
    assert_eq!(
        rotated
            .post(&endpoint)
            .header("content-type", "application/json")
            .body(RPC_BODY)
            .send()
            .await
            .expect("failed reload retains last-good generation")
            .status(),
        reqwest::StatusCode::OK
    );

    let stderr = gateway.shutdown(15);
    assert!(!stderr.contains("TLS-KEY-CANARY-DO-NOT-LOG"));
}
