use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use axum::{body::Body, http::Request};
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;

use smesh_a2a::{
    AuthorizationMiddlewareState, AuthorizationPolicy, DurableLoopbackEndpoint, GatewayConfig,
    InjectedClock, IntoDurableAuthority, PollInterval, SqliteTaskStore,
    build_durable_loopback_gateway,
};

mod support;
use support::durable_authority_conformance::{
    RecordingAuthority, run_durable_authority_fixture_conformance,
};

#[test]
fn sqlite_middleware_compatibility_constructor_is_externally_callable() {
    let _: fn(
        std::sync::Arc<AuthorizationPolicy>,
        SqliteTaskStore,
        InjectedClock,
    ) -> AuthorizationMiddlewareState = AuthorizationMiddlewareState::with_sqlite;
}

#[test]
fn poll_interval_rejects_values_outside_operational_bounds() {
    assert!(PollInterval::new(std::time::Duration::ZERO).is_err());
    assert!(PollInterval::new(std::time::Duration::from_millis(9)).is_err());
    assert!(PollInterval::new(std::time::Duration::from_millis(10)).is_ok());
    assert!(PollInterval::new(std::time::Duration::from_secs(5)).is_ok());
    assert!(PollInterval::new(std::time::Duration::from_millis(5_001)).is_err());
}

/// SQLite/local JSON-RPC compatibility tracer. This is intentionally separate
/// from backend-neutral command conformance.
async fn rpc(router: axum::Router, value: serde_json::Value) -> serde_json::Value {
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        router.oneshot(
            Request::builder()
                .method("POST")
                .uri("/jsonrpc")
                .header("content-type", "application/json")
                .body(Body::from(value.to_string()))
                .unwrap(),
        ),
    )
    .await
    .expect("conformance request watchdog")
    .expect("conformance response");
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).expect("JSON-RPC response")
}

async fn run_sqlite_local_gateway_compatibility(authority: impl IntoDurableAuthority) {
    let gateway = build_durable_loopback_gateway(
        GatewayConfig::new("https://example.invalid", "conformance-node"),
        authority,
        DurableLoopbackEndpoint::new(),
        InjectedClock::new(1_700_000_000_000),
    )
    .expect("backend-neutral gateway construction");
    let router = gateway.router();
    let sent = rpc(
        router.clone(),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "SendMessage",
            "params": {
                "message": {
                    "messageId": "authority-conformance-message",
                    "role": "ROLE_USER",
                    "parts": [{"text": "exercise every durable transition"}]
                }
            }
        }),
    )
    .await;
    let task_id = sent["result"]["task"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("admission returns a task id: {sent}"))
        .to_owned();
    assert_eq!(
        sent["result"]["task"]["status"]["state"],
        "TASK_STATE_COMPLETED"
    );
    assert!(gateway.durable_effect_count().await.unwrap() >= 1);

    let fetched = rpc(
        router.clone(),
        serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "GetTask",
            "params": {"id": &task_id}
        }),
    )
    .await;
    assert_eq!(fetched["result"]["id"], task_id);
    let listed = rpc(
        router,
        serde_json::json!({
            "jsonrpc": "2.0", "id": 3, "method": "ListTasks", "params": {}
        }),
    )
    .await;
    assert!(
        listed["result"]["tasks"]
            .as_array()
            .is_some_and(|tasks| tasks.iter().any(|task| task["id"] == task_id))
    );

    gateway.shutdown().await.expect("joinable shutdown");
}

struct SecureTempDir(PathBuf);

impl SecureTempDir {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "smesh-authority-conformance-{}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&directory).expect("create authority test directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
                .expect("secure authority test directory");
        }
        Self(directory)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for SecureTempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn sqlite_authority_conforms_to_gateway_surface() {
    let directory = SecureTempDir::new();
    let path = directory.path().join("tasks.sqlite3");
    let store = SqliteTaskStore::open(&path, 8)
        .await
        .expect("open sqlite authority");
    run_sqlite_local_gateway_compatibility(store).await;
}

#[tokio::test]
async fn recording_fake_conforms_to_every_backend_neutral_command() {
    let recording = RecordingAuthority::new();
    let factory_recording = recording.clone();
    run_durable_authority_fixture_conformance(
        move || async move {
            let authority: std::sync::Arc<dyn smesh_a2a::DurableAuthority> =
                factory_recording.clone();
            (authority, factory_recording)
        },
        |fixture| async move { fixture.assert_complete() },
    )
    .await;
}

#[tokio::test]
async fn sqlite_runs_the_same_backend_neutral_command_conformance() {
    run_durable_authority_fixture_conformance(
        || async {
            let directory = SecureTempDir::new();
            let store =
                SqliteTaskStore::open(directory.path().join("command-conformance.sqlite3"), 8)
                    .await
                    .expect("open sqlite command authority");
            let authority: std::sync::Arc<dyn smesh_a2a::DurableAuthority> =
                std::sync::Arc::new(store);
            (authority, directory)
        },
        |directory| async move { drop(directory) },
    )
    .await;
}
