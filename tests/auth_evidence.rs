use async_trait::async_trait;
use axum::{
    body::Body,
    http::{HeaderValue, Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use smesh_a2a::auth::{
    AuthClock, AuthState, AuthenticationError, BearerVerifier, JwksFetch, JwksProvider,
    JwtBearerVerifier, JwtVerifierConfig, PresentedBearer, Principal, RESERVED_PRINCIPAL_HEADER,
};
use smesh_a2a::{
    DurableLoopbackEndpoint, GatewayConfig, InjectedClock, LoopbackDispatcher, RuntimeEventCapture,
    SqliteTaskStore, build_authenticated_durable_loopback_gateway,
    build_authenticated_router_with_trace,
};
use std::{
    collections::BTreeMap,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tower::ServiceExt;

const WATCHDOG: Duration = Duration::from_secs(5);
const CANARY: &str = "ISSUE12_AUTH_CANARY_7f4d9c_never_persist_return_log_trace";

struct ProbeDirectory(PathBuf);

impl ProbeDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "smesh-auth-probe-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock after epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).expect("create auth probe directory");
        Self(path)
    }
}

impl Drop for ProbeDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Reject;
#[async_trait]
impl BearerVerifier for Reject {
    async fn verify(&self, _: PresentedBearer<'_>) -> Result<Principal, AuthenticationError> {
        Err(AuthenticationError::InvalidToken)
    }
}

#[derive(Clone, Default)]
struct LogSink(Arc<Mutex<Vec<u8>>>);
struct LogWriter(Arc<Mutex<Vec<u8>>>);
impl Write for LogWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogSink {
    type Writer = LogWriter;
    fn make_writer(&'a self) -> Self::Writer {
        LogWriter(self.0.clone())
    }
}

#[derive(Clone)]
struct Op {
    name: &'static str,
    rpc: &'static str,
    rest_method: Method,
    rest_path: &'static str,
    rest_body: &'static str,
}
fn ops() -> Vec<Op> {
    vec![
        Op {
            name: "unary",
            rpc: "SendMessage",
            rest_method: Method::POST,
            rest_path: "/rest/message:send",
            rest_body: "{}",
        },
        Op {
            name: "stream",
            rpc: "SendStreamingMessage",
            rest_method: Method::POST,
            rest_path: "/rest/message:stream",
            rest_body: "{}",
        },
        Op {
            name: "get",
            rpc: "GetTask",
            rest_method: Method::GET,
            rest_path: "/rest/tasks/canary-task",
            rest_body: "",
        },
        Op {
            name: "list",
            rpc: "ListTasks",
            rest_method: Method::GET,
            rest_path: "/rest/tasks",
            rest_body: "",
        },
        Op {
            name: "subscribe",
            rpc: "SubscribeToTask",
            rest_method: Method::GET,
            rest_path: "/rest/tasks/canary-task:subscribe",
            rest_body: "",
        },
        Op {
            name: "cancel",
            rpc: "CancelTask",
            rest_method: Method::POST,
            rest_path: "/rest/tasks/canary-task:cancel",
            rest_body: "",
        },
        Op {
            name: "push-create",
            rpc: "CreateTaskPushNotificationConfig",
            rest_method: Method::POST,
            rest_path: "/rest/tasks/canary-task/pushNotificationConfigs",
            rest_body: "{}",
        },
        Op {
            name: "push-get",
            rpc: "GetTaskPushNotificationConfig",
            rest_method: Method::GET,
            rest_path: "/rest/tasks/canary-task/pushNotificationConfigs/canary-config",
            rest_body: "",
        },
        Op {
            name: "push-list",
            rpc: "ListTaskPushNotificationConfigs",
            rest_method: Method::GET,
            rest_path: "/rest/tasks/canary-task/pushNotificationConfigs",
            rest_body: "",
        },
        Op {
            name: "push-delete",
            rpc: "DeleteTaskPushNotificationConfig",
            rest_method: Method::DELETE,
            rest_path: "/rest/tasks/canary-task/pushNotificationConfigs/canary-config",
            rest_body: "",
        },
        Op {
            name: "extended",
            rpc: "GetExtendedAgentCard",
            rest_method: Method::GET,
            rest_path: "/rest/extendedAgentCard",
            rest_body: "",
        },
    ]
}

#[derive(Clone, Copy)]
enum Cred {
    Missing,
    Invalid,
    Duplicate,
    Oversized,
}
impl Cred {
    fn name(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Invalid => "invalid",
            Self::Duplicate => "duplicate",
            Self::Oversized => "oversized",
        }
    }
}
fn decorate(mut req: Request<Body>, cred: Cred) -> Request<Body> {
    req.headers_mut()
        .insert(RESERVED_PRINCIPAL_HEADER, HeaderValue::from_static(CANARY));
    req.headers_mut()
        .insert("x-principal", HeaderValue::from_static(CANARY));
    match cred {
        Cred::Missing => {}
        Cred::Invalid => {
            req.headers_mut().insert(
                "authorization",
                HeaderValue::from_str(&format!("Bearer {CANARY}")).unwrap(),
            );
        }
        Cred::Duplicate => {
            req.headers_mut().append(
                "authorization",
                HeaderValue::from_str(&format!("Bearer {CANARY}-a")).unwrap(),
            );
            req.headers_mut().append(
                "authorization",
                HeaderValue::from_str(&format!("Bearer {CANARY}-b")).unwrap(),
            );
        }
        Cred::Oversized => {
            let value = format!("Bearer {CANARY}{}", "x".repeat(17 * 1024));
            req.headers_mut()
                .insert("authorization", HeaderValue::from_str(&value).unwrap());
        }
    }
    req
}

fn table_counts(path: &Path) -> BTreeMap<String, i64> {
    let db = rusqlite::Connection::open(path).unwrap();
    let mut stmt=db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").unwrap();
    let names = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect::<Vec<_>>();
    names
        .into_iter()
        .map(|n| {
            let q = format!("SELECT COUNT(*) FROM \"{}\"", n.replace('"', "\"\""));
            let c = db.query_row(&q, [], |r| r.get(0)).unwrap();
            (n, c)
        })
        .collect()
}
fn scan_file(path: &Path) -> bool {
    std::fs::read(path).is_ok_and(|b| b.windows(CANARY.len()).any(|w| w == CANARY.as_bytes()))
}

const RSA_N: &str = "p26N-Nwoj5-nUmncx2MHcT01-VCtp6LLQaOPv6tFIE4J3GS6Acccllk_QqMUamBnfwzgFErmBznMY8MfqZUM1-HNd_9GgvlJHIJUbYrU5Jbn1QnkY51GW5L4BXpyMeovuTPOjyKuAgRuAlaRI0W8JjZXGZt6stPFyofx-wZLT5eM0_ppclD-jJUQ_yt5tmkidf7SeXE7zDt8eg1aR2wolmhYfVzELkPRLYF4mLcMWXK7eV5Oc9L_u4NobVqAMlFX309TALcS_zrs7EbY9aB7m75RAhLjhPw8F-f_CLpvw5XMQ9OACg5NDqXEfTQUzHf9GWIHCC8JmJufvAn9jJI04Q";
fn jwks(kid: &str) -> Vec<u8> {
    format!(r#"{{"keys":[{{"kty":"RSA","kid":"{kid}","use":"sig","alg":"RS256","n":"{RSA_N}","e":"AQAB"}}]}}"#).into_bytes()
}
struct Clock {
    unix: std::sync::atomic::AtomicI64,
    mono: std::sync::atomic::AtomicU64,
}
impl AuthClock for Clock {
    fn unix_seconds(&self) -> i64 {
        self.unix.load(std::sync::atomic::Ordering::SeqCst)
    }
    fn monotonic_seconds(&self) -> u64 {
        self.mono.load(std::sync::atomic::Ordering::SeqCst)
    }
}
struct Provider {
    q: tokio::sync::Mutex<std::collections::VecDeque<Result<Vec<u8>, AuthenticationError>>>,
    calls: std::sync::atomic::AtomicUsize,
    ttl: u64,
}
#[async_trait]
impl JwksProvider for Provider {
    async fn fetch(&self, _: usize) -> Result<JwksFetch, AuthenticationError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let body = self.q.lock().await.pop_front().expect("provider script")?;
        Ok(JwksFetch {
            body,
            fresh_for: Duration::from_secs(self.ttl),
        })
    }
}
#[derive(serde::Serialize)]
struct Claims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    exp: i64,
    nbf: i64,
    iat: i64,
    client_id: &'a str,
    jti: &'a str,
}
fn token(kid: &str, exp: i64, nbf: i64, iat: i64) -> String {
    let mut h = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    h.kid = Some(kid.into());
    h.typ = Some("at+jwt".into());
    jsonwebtoken::encode(
        &h,
        &Claims {
            iss: "https://issuer.example",
            sub: "probe",
            aud: "smesh-api",
            exp,
            nbf,
            iat,
            client_id: "probe-client",
            jti: "probe-jti",
        },
        &jsonwebtoken::EncodingKey::from_rsa_pem(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/issue12-test-private.pem"
        )))
        .unwrap(),
    )
    .unwrap()
}
#[allow(clippy::too_many_lines)]
async fn probe_rotation_concurrency_skew_outage() {
    let now = 1_800_000_000;
    let p = Arc::new(Provider {
        q: tokio::sync::Mutex::new(std::collections::VecDeque::from([
            Ok(jwks("a")),
            Ok(jwks("b")),
            Ok(jwks("b")),
        ])),
        calls: std::sync::atomic::AtomicUsize::new(0),
        ttl: 300,
    });
    let clock = Arc::new(Clock {
        unix: std::sync::atomic::AtomicI64::new(now),
        mono: std::sync::atomic::AtomicU64::new(0),
    });
    let v = Arc::new(
        JwtBearerVerifier::new(
            JwtVerifierConfig::strict("https://issuer.example", "smesh-api"),
            p.clone(),
            clock,
        )
        .await
        .unwrap(),
    );
    let t = token("b", now + 60, now - 1, now - 1);
    let mut joins = Vec::new();
    for _ in 0..32 {
        let v = v.clone();
        let t = t.clone();
        joins.push(tokio::spawn(async move {
            tokio::time::timeout(WATCHDOG, v.verify(PresentedBearer::new(&t).unwrap()))
                .await
                .unwrap()
        }));
    }
    for j in joins {
        j.await.unwrap().unwrap();
    }
    assert_eq!(
        p.calls.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "rotation must singleflight"
    );
    let unknown = token("c", now + 60, now - 1, now - 1);
    assert_eq!(
        v.verify(PresentedBearer::new(&unknown).unwrap()).await,
        Err(AuthenticationError::UnknownKeyId)
    );
    assert_eq!(
        v.verify(PresentedBearer::new(&unknown).unwrap()).await,
        Err(AuthenticationError::UnknownKeyId)
    );
    assert_eq!(
        p.calls.load(std::sync::atomic::Ordering::SeqCst),
        3,
        "only the second genuinely unknown kid request is throttled"
    );
    let p = Arc::new(Provider {
        q: tokio::sync::Mutex::new(std::collections::VecDeque::from([
            Ok(jwks("a")),
            Err(AuthenticationError::ProviderUnavailable),
        ])),
        calls: std::sync::atomic::AtomicUsize::new(0),
        ttl: 1,
    });
    let c = Arc::new(Clock {
        unix: std::sync::atomic::AtomicI64::new(now),
        mono: std::sync::atomic::AtomicU64::new(0),
    });
    let v = JwtBearerVerifier::new(
        JwtVerifierConfig::strict("https://issuer.example", "smesh-api"),
        p,
        c.clone(),
    )
    .await
    .unwrap();
    let t = token("a", now + 60, now - 1, now - 1);
    assert!(v.verify(PresentedBearer::new(&t).unwrap()).await.is_ok());
    c.mono.store(2, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        v.verify(PresentedBearer::new(&t).unwrap()).await,
        Err(AuthenticationError::ProviderUnavailable)
    );
    let p = Arc::new(Provider {
        q: tokio::sync::Mutex::new(std::collections::VecDeque::from([Ok(jwks("a"))])),
        calls: std::sync::atomic::AtomicUsize::new(0),
        ttl: 300,
    });
    let c = Arc::new(Clock {
        unix: std::sync::atomic::AtomicI64::new(now),
        mono: std::sync::atomic::AtomicU64::new(0),
    });
    let v = JwtBearerVerifier::new(
        JwtVerifierConfig::strict("https://issuer.example", "smesh-api"),
        p,
        c,
    )
    .await
    .unwrap();
    for (t, ok) in [
        (token("a", now + 60, now + 30, now + 30), true),
        (token("a", now + 60, now + 31, now + 31), false),
        (token("a", now - 30, now - 100, now - 100), false),
    ] {
        assert_eq!(
            v.verify(PresentedBearer::new(&t).unwrap()).await.is_ok(),
            ok
        );
    }
}

#[test]
fn probe_directory_cleanup_runs_on_success_and_panic() {
    let success_path = {
        let directory = ProbeDirectory::new();
        directory.0.clone()
    };
    assert!(!success_path.exists());

    let panic_path = Arc::new(Mutex::new(None));
    let captured = Arc::clone(&panic_path);
    let _ = std::panic::catch_unwind(move || {
        let directory = ProbeDirectory::new();
        *captured.lock().unwrap() = Some(directory.0.clone());
        panic!("cleanup probe");
    });
    let panic_path = panic_path.lock().unwrap().clone().unwrap();
    assert!(!panic_path.exists());
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn authenticated_protocol_rejection_and_redaction_evidence() {
    let logs = LogSink::default();
    let _ = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_max_level(tracing::Level::TRACE)
        .try_init();
    let root = ProbeDirectory::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let dbpath = root.0.join("probe.sqlite");
    let store = tokio::time::timeout(WATCHDOG, SqliteTaskStore::open(&dbpath, 128))
        .await
        .unwrap()
        .unwrap();
    let auth = AuthState::new(Arc::new(Reject), [23; 32]);
    let gateway = build_authenticated_durable_loopback_gateway(
        GatewayConfig::new("http://127.0.0.1:1", "probe"),
        store,
        DurableLoopbackEndpoint::new(),
        InjectedClock::new(1_700_000_000_000),
        auth,
    )
    .unwrap();
    let before = table_counts(&dbpath);
    let mut outputs = Vec::new();
    let mut assertions = 0usize;
    for op in ops() {
        for cred in [
            Cred::Missing,
            Cred::Invalid,
            Cred::Duplicate,
            Cred::Oversized,
        ] {
            let rpc_body = serde_json::json!({"jsonrpc":"2.0","id":format!("{}-{}",op.name,cred.name()),"method":op.rpc,"params":{"id":"canary-task","taskId":"canary-task","metadata":{"principal":CANARY},"message":{"messageId":"canary-message","role":"ROLE_USER","parts":[]}}});
            let req = decorate(
                Request::post("/jsonrpc")
                    .header("content-type", "application/json")
                    .body(Body::from(rpc_body.to_string()))
                    .unwrap(),
                cred,
            );
            let resp = tokio::time::timeout(WATCHDOG, gateway.router().oneshot(req))
                .await
                .unwrap()
                .unwrap();
            let status = resp.status();
            let headers = format!("{:?}", resp.headers());
            let body = tokio::time::timeout(WATCHDOG, resp.into_body().collect())
                .await
                .unwrap()
                .unwrap()
                .to_bytes();
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "rpc {} {}",
                op.name,
                cred.name()
            );
            outputs.extend_from_slice(headers.as_bytes());
            outputs.extend_from_slice(&body);
            assertions += 1;
            let req = decorate(
                Request::builder()
                    .method(op.rest_method.clone())
                    .uri(op.rest_path)
                    .header("content-type", "application/json")
                    .body(Body::from(op.rest_body))
                    .unwrap(),
                cred,
            );
            let resp = tokio::time::timeout(WATCHDOG, gateway.router().oneshot(req))
                .await
                .unwrap()
                .unwrap();
            let status = resp.status();
            let headers = format!("{:?}", resp.headers());
            let body = tokio::time::timeout(WATCHDOG, resp.into_body().collect())
                .await
                .unwrap()
                .unwrap()
                .to_bytes();
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "rest {} {}",
                op.name,
                cred.name()
            );
            outputs.extend_from_slice(headers.as_bytes());
            outputs.extend_from_slice(&body);
            assertions += 1;
        }
    }
    assert_eq!(gateway.durable_effect_count().await.unwrap(), 0);
    let after = table_counts(&dbpath);
    assert_eq!(before, after, "SQLite table counts mutated");
    assert!(
        !outputs
            .windows(CANARY.len())
            .any(|w| w == CANARY.as_bytes()),
        "response/error leak"
    );

    let vp = Arc::new(Provider {
        q: tokio::sync::Mutex::new(std::collections::VecDeque::from([Ok(jwks("valid"))])),
        calls: std::sync::atomic::AtomicUsize::new(0),
        ttl: 300,
    });
    let vc = Arc::new(Clock {
        unix: std::sync::atomic::AtomicI64::new(1_800_000_000),
        mono: std::sync::atomic::AtomicU64::new(0),
    });
    let vv = JwtBearerVerifier::new(
        JwtVerifierConfig::strict("https://issuer.example", "smesh-api"),
        vp,
        vc,
    )
    .await
    .unwrap();
    let valid_token = token("valid", 1_800_000_060, 1_799_999_999, 1_799_999_999);
    let valid_router = smesh_a2a::build_authenticated_router(
        GatewayConfig::new("http://127.0.0.1:1", "valid-probe"),
        LoopbackDispatcher,
        AuthState::new(Arc::new(vv), [31; 32]),
    );
    let mut valid_assertions = 0usize;
    for op in ops() {
        let rpc_body = serde_json::json!({"jsonrpc":"2.0","id":op.name,"method":op.rpc,"params":{"id":"probe-task","taskId":"probe-task","metadata":{"principal":CANARY}}});
        let mut req = Request::post("/jsonrpc")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {valid_token}"))
            .body(Body::from(rpc_body.to_string()))
            .unwrap();
        req.headers_mut()
            .insert(RESERVED_PRINCIPAL_HEADER, HeaderValue::from_static(CANARY));
        let resp = tokio::time::timeout(WATCHDOG, valid_router.clone().oneshot(req))
            .await
            .unwrap()
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "valid rpc {}",
            op.name
        );
        valid_assertions += 1;
        let mut req = Request::builder()
            .method(op.rest_method.clone())
            .uri(op.rest_path)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {valid_token}"))
            .body(Body::from(op.rest_body))
            .unwrap();
        req.headers_mut()
            .insert(RESERVED_PRINCIPAL_HEADER, HeaderValue::from_static(CANARY));
        let resp = tokio::time::timeout(WATCHDOG, valid_router.clone().oneshot(req))
            .await
            .unwrap()
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "valid rest {}",
            op.name
        );
        valid_assertions += 1;
    }

    let trace = Arc::new(RuntimeEventCapture::new(128, 128));
    let trace_router = build_authenticated_router_with_trace(
        GatewayConfig::new("http://127.0.0.1:1", "trace-probe"),
        LoopbackDispatcher,
        AuthState::new(Arc::new(Reject), [29; 32]),
        trace.clone(),
    );
    let req=decorate(Request::post("/jsonrpc").header("content-type","application/json").body(Body::from(format!(r#"{{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{{"metadata":{{"principal":"{CANARY}"}}}}}}"#))).unwrap(),Cred::Invalid);
    let resp = tokio::time::timeout(WATCHDOG, trace_router.oneshot(req))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let trace_json = serde_json::to_vec(&trace.snapshot().await).unwrap();
    assert!(
        !trace_json
            .windows(CANARY.len())
            .any(|w| w == CANARY.as_bytes())
    );
    assert!(trace.snapshot().await.events.is_empty());

    tokio::time::timeout(WATCHDOG, gateway.shutdown())
        .await
        .unwrap()
        .unwrap();
    let mut scanned = Vec::new();
    for suffix in ["", "-wal", "-shm"] {
        let p = PathBuf::from(format!("{}{}", dbpath.display(), suffix));
        scanned.push((p.display().to_string(), scan_file(&p)));
    }
    assert!(
        scanned.iter().all(|(_, found)| !*found),
        "canary persisted: {scanned:?}"
    );
    let log_bytes = logs.0.lock().unwrap().clone();
    assert!(
        !log_bytes
            .windows(CANARY.len())
            .any(|w| w == CANARY.as_bytes()),
        "log leak"
    );
    probe_rotation_concurrency_skew_outage().await;
    assert_eq!(assertions, 88);
    assert_eq!(valid_assertions, 22);
}
