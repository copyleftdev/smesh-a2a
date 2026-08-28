#![cfg(unix)]

use std::future::Future;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use a2a::{
    GetTaskRequest, ListTasksRequest, Message, Part, Role, SendMessageConfiguration,
    SendMessageRequest, SendMessageResponse, Task, TaskState,
};
use async_trait::async_trait;
use axum::{
    body::Body,
    http::{HeaderMap, Request, StatusCode},
};
use http_body_util::BodyExt as _;
use smesh_a2a::auth::{
    AuthState, AuthenticationError, BearerVerifier, PresentedBearer, Principal, PrincipalLimits,
};
use smesh_a2a::{
    AuthorizationPolicy, DurableLoopbackEndpoint, GatewayConfig, InjectedClock, SqliteTaskStore,
    build_authorized_durable_loopback_gateway,
};
use tower::ServiceExt as _;

const WATCHDOG: Duration = Duration::from_secs(5);
const TOKEN_CANARY: &str = "issue13-raw-token-canary-never-persist";

async fn bounded<F: Future>(label: &str, future: F) -> F::Output {
    tokio::time::timeout(WATCHDOG, future)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {label}"))
}

struct FixturePath(PathBuf);
impl FixturePath {
    fn new(label: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "smesh-authorized-protocol-{label}-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(root.join("tasks.sqlite3"))
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for FixturePath {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm", ".lock"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.0.display()));
        }
        if let Some(parent) = self.0.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }
}

/// Selects a synthetic principal without retaining, formatting, or returning a token.
struct TokenPrincipalVerifier;
#[async_trait]
impl BearerVerifier for TokenPrincipalVerifier {
    async fn verify(&self, token: PresentedBearer<'_>) -> Result<Principal, AuthenticationError> {
        let subject = match token.as_str() {
            "agent-a" | "agent-a-second-binding" => "agent-a",
            "agent-b" => "agent-b",
            "operator" => "operator",
            "viewer" => "viewer",
            "admin" => "admin",
            "multi" => "multi",
            TOKEN_CANARY => "unenrolled",
            _ => return Err(AuthenticationError::InvalidToken),
        };
        Principal::bearer_for_verifier(
            "https://issuer.example".into(),
            subject.into(),
            PrincipalLimits::default(),
        )
        .map_err(|_| AuthenticationError::InvalidToken)
    }
}

fn policy(revision: u64) -> AuthorizationPolicy {
    AuthorizationPolicy::from_json(
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion":"smesh-authz-policy/v1",
            "policyId":"gateway-main",
            "revision":revision,
            "tenants":[
                {"id":"tenant-a","enabled":true},
                {"id":"tenant-b","enabled":true}
            ],
            "accounts":[
                {"id":"agent-a","kind":"serviceAccount","memberships":[{"tenantId":"tenant-a","roles":["taskAgent"]}]},
                {"id":"agent-b","kind":"serviceAccount","memberships":[{"tenantId":"tenant-b","roles":["taskAgent"]}]},
                {"id":"operator","kind":"human","memberships":[{"tenantId":"tenant-a","roles":["taskOperator"]}]},
                {"id":"viewer","kind":"human","memberships":[{"tenantId":"tenant-a","roles":["taskViewer"]}]},
                {"id":"admin","kind":"human","memberships":[{"tenantId":"tenant-a","roles":["tenantAdmin"]}]},
                {"id":"multi","kind":"human","memberships":[
                    {"tenantId":"tenant-a","roles":["taskViewer"]},
                    {"tenantId":"tenant-b","roles":["taskViewer"]}
                ]}
            ],
            "principalBindings":[
                {"principal":{"issuer":"https://issuer.example","subject":"agent-a"},"accountId":"agent-a"},
                {"principal":{"issuer":"https://issuer.example","subject":"agent-b"},"accountId":"agent-b"},
                {"principal":{"issuer":"https://issuer.example","subject":"operator"},"accountId":"operator"},
                {"principal":{"issuer":"https://issuer.example","subject":"viewer"},"accountId":"viewer"},
                {"principal":{"issuer":"https://issuer.example","subject":"admin"},"accountId":"admin"},
                {"principal":{"issuer":"https://issuer.example","subject":"multi"},"accountId":"multi"}
            ]
        }))
        .unwrap()
        .as_slice(),
    )
    .unwrap()
}

async fn gateway(
    path: &Path,
    endpoint: DurableLoopbackEndpoint,
    revision: u64,
) -> (smesh_a2a::DurableGateway, SqliteTaskStore) {
    let store = SqliteTaskStore::open(path, 64).await.unwrap();
    let gateway = build_authorized_durable_loopback_gateway(
        GatewayConfig::new("http://127.0.0.1:1", "authorized-test"),
        store.clone(),
        endpoint,
        InjectedClock::new(1_700_000_000_000),
        AuthState::new(Arc::new(TokenPrincipalVerifier), [41; 32]),
        Arc::new(policy(revision)),
    )
    .unwrap();
    (gateway, store)
}

struct WireResponse {
    status: StatusCode,
    headers: HeaderMap,
    bytes: Vec<u8>,
}
impl WireResponse {
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.bytes).unwrap_or_else(|error| {
            panic!(
                "response is not JSON: {error}; {}",
                String::from_utf8_lossy(&self.bytes)
            )
        })
    }
}

fn stable_error(mut value: serde_json::Value) -> serde_json::Value {
    fn strip(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(object) => {
                if let Some(serde_json::Value::Object(metadata)) = object.get_mut("metadata") {
                    metadata.remove("timestamp");
                }
                for child in object.values_mut() {
                    strip(child);
                }
            }
            serde_json::Value::Array(values) => values.iter_mut().for_each(strip),
            _ => {}
        }
    }
    strip(&mut value);
    value
}

async fn wire(
    router: axum::Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    selectors: &[&str],
    body: Option<serde_json::Value>,
) -> WireResponse {
    bounded("authorized wire request", async {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        for selector in selectors {
            builder = builder.header("x-smesh-tenant", *selector);
        }
        let body = if let Some(body) = body {
            builder = builder.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&body).unwrap())
        } else {
            Body::empty()
        };
        let response = router.oneshot(builder.body(body).unwrap()).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        WireResponse {
            status,
            headers,
            bytes,
        }
    })
    .await
}

async fn rpc(
    router: axum::Router,
    token: &str,
    selectors: &[&str],
    method: &str,
    params: serde_json::Value,
) -> WireResponse {
    wire(
        router,
        "POST",
        "/jsonrpc",
        Some(token),
        selectors,
        Some(serde_json::json!({
            "jsonrpc":"2.0", "id":"fixed-probe", "method":method, "params":params
        })),
    )
    .await
}

fn send_request(message_id: &str, text: &str, immediate: bool) -> SendMessageRequest {
    let mut message = Message::new(Role::User, vec![Part::text(text)]);
    message_id.clone_into(&mut message.message_id);
    SendMessageRequest {
        message,
        configuration: Some(SendMessageConfiguration {
            accepted_output_modes: None,
            task_push_notification_config: None,
            history_length: None,
            return_immediately: Some(immediate),
        }),
        metadata: None,
        tenant: None,
    }
}

fn rpc_result_task(response: &WireResponse) -> Task {
    let body = response.json();
    assert_eq!(response.status, StatusCode::OK, "{body}");
    assert!(body.get("error").is_none(), "{body}");
    let result: SendMessageResponse = serde_json::from_value(body["result"].clone()).unwrap();
    let SendMessageResponse::Task(task) = result else {
        panic!("expected task: {body}")
    };
    task
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn selector_and_role_matrix_fail_closed_with_identical_transport_errors() {
    let path = FixturePath::new("selectors");
    let (gateway, store) = gateway(path.path(), DurableLoopbackEndpoint::new(), 7).await;
    let params = serde_json::to_value(send_request("selector-message", "work", true)).unwrap();

    // A sole membership needs no selector.
    let allowed = rpc(
        gateway.router(),
        "agent-a",
        &[],
        a2a::jsonrpc::methods::SEND_MESSAGE,
        params.clone(),
    )
    .await;
    assert!(allowed.json().get("error").is_none(), "{}", allowed.json());

    let mut denied = Vec::new();
    denied.push(
        rpc(
            gateway.router(),
            "multi",
            &[],
            a2a::jsonrpc::methods::SEND_MESSAGE,
            params.clone(),
        )
        .await,
    );
    denied.push(
        rpc(
            gateway.router(),
            "multi",
            &["tenant-a", "tenant-b"],
            a2a::jsonrpc::methods::SEND_MESSAGE,
            params.clone(),
        )
        .await,
    );
    denied.push(
        rpc(
            gateway.router(),
            "multi",
            &["tenant-a,tenant-b"],
            a2a::jsonrpc::methods::SEND_MESSAGE,
            params.clone(),
        )
        .await,
    );
    denied.push(
        rpc(
            gateway.router(),
            "multi",
            &["Tenant-A"],
            a2a::jsonrpc::methods::SEND_MESSAGE,
            params.clone(),
        )
        .await,
    );
    denied.push(
        rpc(
            gateway.router(),
            "multi",
            &["tenant-missing"],
            a2a::jsonrpc::methods::SEND_MESSAGE,
            params.clone(),
        )
        .await,
    );
    denied.push(
        rpc(
            gateway.router(),
            TOKEN_CANARY,
            &["tenant-a"],
            a2a::jsonrpc::methods::SEND_MESSAGE,
            params.clone(),
        )
        .await,
    );
    for response in &denied {
        assert_eq!(response.status, StatusCode::FORBIDDEN);
        assert_eq!(response.bytes.as_slice(), b"forbidden");
        assert!(response.headers.get("www-authenticate").is_none());
    }

    let before = store.authorization_decision_count().await.unwrap();
    let viewer = rpc(
        gateway.router(),
        "viewer",
        &[],
        a2a::jsonrpc::methods::SEND_MESSAGE,
        serde_json::to_value(send_request("viewer-denied", "must not admit", true)).unwrap(),
    )
    .await;
    assert_eq!(viewer.status, StatusCode::OK);
    assert_eq!(viewer.json()["error"]["code"], serde_json::json!(-32600));
    assert_eq!(
        store.authorization_decision_count().await.unwrap(),
        before + 1,
        "role denial must be durable-audited"
    );

    let missing_auth = wire(gateway.router(), "GET", "/rest/tasks/nope", None, &[], None).await;
    assert_eq!(missing_auth.status, StatusCode::UNAUTHORIZED);
    assert!(missing_auth.headers.get("www-authenticate").is_some());
    assert!(!String::from_utf8_lossy(&missing_auth.bytes).contains(TOKEN_CANARY));

    bounded("selector gateway shutdown", gateway.shutdown())
        .await
        .unwrap();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn two_tenant_send_replay_visibility_existence_and_audit_are_exact() {
    let path = FixturePath::new("matrix");
    let (gateway, store) = gateway(path.path(), DurableLoopbackEndpoint::new(), 7).await;
    let request_a = send_request("shared-message", "tenant A work", false);
    let task_a = rpc_result_task(
        &rpc(
            gateway.router(),
            "agent-a",
            &[],
            a2a::jsonrpc::methods::SEND_MESSAGE,
            serde_json::to_value(&request_a).unwrap(),
        )
        .await,
    );
    assert_eq!(task_a.status.state, TaskState::Completed);

    // A second credential representation resolving to the same account replays exactly.
    let replay = rpc(
        gateway.router(),
        "agent-a-second-binding",
        &[],
        a2a::jsonrpc::methods::SEND_MESSAGE,
        serde_json::to_value(&request_a).unwrap(),
    )
    .await;
    assert_eq!(rpc_result_task(&replay).id, task_a.id);
    let mut conflict = request_a.clone();
    conflict.message.parts = vec![Part::text("changed semantics")];
    let conflict = rpc(
        gateway.router(),
        "agent-a",
        &[],
        a2a::jsonrpc::methods::SEND_MESSAGE,
        serde_json::to_value(conflict).unwrap(),
    )
    .await;
    assert_eq!(conflict.json()["error"]["code"], serde_json::json!(-32600));

    // The same public messageId belongs to a different idempotency scope in tenant B.
    let request_b = send_request("shared-message", "tenant B work", false);
    let task_b = rpc_result_task(
        &rpc(
            gateway.router(),
            "agent-b",
            &[],
            a2a::jsonrpc::methods::SEND_MESSAGE,
            serde_json::to_value(&request_b).unwrap(),
        )
        .await,
    );
    assert_ne!(task_a.id, task_b.id);

    for token in ["operator", "viewer"] {
        let visible = rpc(
            gateway.router(),
            token,
            &[],
            a2a::jsonrpc::methods::GET_TASK,
            serde_json::to_value(GetTaskRequest {
                id: task_a.id.clone(),
                history_length: Some(1),
                tenant: None,
            })
            .unwrap(),
        )
        .await;
        assert_eq!(visible.status, StatusCode::OK);
        assert!(visible.json().get("error").is_none(), "{}", visible.json());
        assert_eq!(
            visible.json()["result"]["history"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            visible.json()["result"]["artifacts"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    let foreign = rpc(
        gateway.router(),
        "agent-b",
        &[],
        a2a::jsonrpc::methods::GET_TASK,
        serde_json::json!({"id":task_a.id}),
    )
    .await;
    let missing = rpc(
        gateway.router(),
        "agent-b",
        &[],
        a2a::jsonrpc::methods::GET_TASK,
        serde_json::json!({"id":"missing-task"}),
    )
    .await;
    assert_eq!(
        stable_error(foreign.json()["error"].clone()),
        stable_error(missing.json()["error"].clone())
    );
    assert_eq!(foreign.json()["error"]["code"], serde_json::json!(-32001));
    assert!(!String::from_utf8_lossy(&foreign.bytes).contains(&task_a.id));

    let rest_foreign = wire(
        gateway.router(),
        "GET",
        &format!("/rest/tasks/{}", task_a.id),
        Some("agent-b"),
        &[],
        None,
    )
    .await;
    let rest_missing = wire(
        gateway.router(),
        "GET",
        "/rest/tasks/missing-task",
        Some("agent-b"),
        &[],
        None,
    )
    .await;
    assert_eq!(rest_foreign.status, rest_missing.status);
    assert_eq!(
        stable_error(rest_foreign.json()),
        stable_error(rest_missing.json())
    );
    assert_eq!(
        rest_foreign.headers.get("content-type"),
        rest_missing.headers.get("content-type")
    );
    assert_eq!(
        rest_foreign.headers.get("www-authenticate"),
        rest_missing.headers.get("www-authenticate")
    );
    assert_ne!(
        rest_foreign
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("text/event-stream")
    );

    let sub_foreign = wire(
        gateway.router(),
        "GET",
        &format!("/rest/tasks/{}:subscribe", task_a.id),
        Some("agent-b"),
        &[],
        None,
    )
    .await;
    let sub_missing = wire(
        gateway.router(),
        "GET",
        "/rest/tasks/missing-task:subscribe",
        Some("agent-b"),
        &[],
        None,
    )
    .await;
    assert_eq!(sub_foreign.status, sub_missing.status);
    assert_eq!(
        stable_error(sub_foreign.json()),
        stable_error(sub_missing.json())
    );
    assert_ne!(
        sub_foreign
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("text/event-stream")
    );

    let rpc_sub_foreign = rpc(
        gateway.router(),
        "agent-b",
        &[],
        a2a::jsonrpc::methods::SUBSCRIBE_TO_TASK,
        serde_json::json!({"id":task_a.id}),
    )
    .await;
    let rpc_sub_missing = rpc(
        gateway.router(),
        "agent-b",
        &[],
        a2a::jsonrpc::methods::SUBSCRIBE_TO_TASK,
        serde_json::json!({"id":"missing-task"}),
    )
    .await;
    assert_eq!(rpc_sub_foreign.status, rpc_sub_missing.status);
    assert_eq!(
        stable_error(rpc_sub_foreign.json()["error"].clone()),
        stable_error(rpc_sub_missing.json()["error"].clone())
    );
    assert_ne!(
        rpc_sub_foreign
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("text/event-stream")
    );

    let mut foreign_continuation = send_request("foreign-continuation", "continue", true);
    foreign_continuation.message.task_id = Some(task_a.id.clone());
    foreign_continuation.message.context_id = Some(task_a.context_id.clone());
    let mut missing_continuation = foreign_continuation.clone();
    missing_continuation.message.message_id = "missing-continuation".into();
    missing_continuation.message.task_id = Some("missing-task".into());
    let rpc_stream_foreign = rpc(
        gateway.router(),
        "agent-b",
        &[],
        a2a::jsonrpc::methods::SEND_STREAMING_MESSAGE,
        serde_json::to_value(foreign_continuation).unwrap(),
    )
    .await;
    let rpc_stream_missing = rpc(
        gateway.router(),
        "agent-b",
        &[],
        a2a::jsonrpc::methods::SEND_STREAMING_MESSAGE,
        serde_json::to_value(missing_continuation).unwrap(),
    )
    .await;
    assert_eq!(rpc_stream_foreign.status, rpc_stream_missing.status);
    assert_eq!(
        stable_error(rpc_stream_foreign.json()["error"].clone()),
        stable_error(rpc_stream_missing.json()["error"].clone())
    );
    assert_ne!(
        rpc_stream_foreign
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("text/event-stream")
    );
    let mut rest_foreign_request = send_request("rest-foreign-continuation", "continue", true);
    rest_foreign_request.message.task_id = Some(task_a.id.clone());
    rest_foreign_request.message.context_id = Some(task_a.context_id.clone());
    let rest_stream_foreign = wire(
        gateway.router(),
        "POST",
        "/rest/message:stream",
        Some("agent-b"),
        &[],
        Some(serde_json::to_value(&rest_foreign_request).unwrap()),
    )
    .await;
    let mut missing_rest = rest_foreign_request;
    missing_rest.message.message_id = "rest-missing-continuation".into();
    missing_rest.message.task_id = Some("missing-task".into());
    let rest_stream_missing = wire(
        gateway.router(),
        "POST",
        "/rest/message:stream",
        Some("agent-b"),
        &[],
        Some(serde_json::to_value(&missing_rest).unwrap()),
    )
    .await;
    assert_eq!(rest_stream_foreign.status, rest_stream_missing.status);
    assert_eq!(
        stable_error(rest_stream_foreign.json()),
        stable_error(rest_stream_missing.json())
    );
    assert_ne!(
        rest_stream_foreign
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("text/event-stream")
    );

    let effects_before_foreign_cancel = store.durable_effect_count().await.unwrap();
    let audits_before_foreign_cancel = store.authorization_decision_count().await.unwrap();
    let rpc_cancel_foreign = rpc(
        gateway.router(),
        "agent-b",
        &[],
        a2a::jsonrpc::methods::CANCEL_TASK,
        serde_json::json!({"id":task_a.id}),
    )
    .await;
    let rpc_cancel_missing = rpc(
        gateway.router(),
        "agent-b",
        &[],
        a2a::jsonrpc::methods::CANCEL_TASK,
        serde_json::json!({"id":"missing-task"}),
    )
    .await;
    assert_eq!(
        stable_error(rpc_cancel_foreign.json()["error"].clone()),
        stable_error(rpc_cancel_missing.json()["error"].clone())
    );
    let rest_cancel_foreign = wire(
        gateway.router(),
        "POST",
        &format!("/rest/tasks/{}:cancel", task_a.id),
        Some("agent-b"),
        &[],
        None,
    )
    .await;
    let rest_cancel_missing = wire(
        gateway.router(),
        "POST",
        "/rest/tasks/missing-task:cancel",
        Some("agent-b"),
        &[],
        None,
    )
    .await;
    assert_eq!(rest_cancel_foreign.status, rest_cancel_missing.status);
    assert_eq!(
        stable_error(rest_cancel_foreign.json()),
        stable_error(rest_cancel_missing.json())
    );
    assert_eq!(
        store.durable_effect_count().await.unwrap(),
        effects_before_foreign_cancel
    );
    assert_eq!(
        store.authorization_decision_count().await.unwrap(),
        audits_before_foreign_cancel + 4
    );
    let still_completed = rpc(
        gateway.router(),
        "operator",
        &[],
        a2a::jsonrpc::methods::GET_TASK,
        serde_json::json!({"id":task_a.id}),
    )
    .await;
    assert_eq!(
        still_completed.json()["result"]["status"]["state"],
        serde_json::json!("TASK_STATE_COMPLETED")
    );

    bounded("matrix gateway shutdown", gateway.shutdown())
        .await
        .unwrap();

    let db = rusqlite::Connection::open(path.path()).unwrap();
    let raw: Vec<(String, Option<String>)> = db
        .prepare("SELECT resource_digest, task_id FROM authorization_decisions WHERE effect='deny'")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(
        raw.iter()
            .all(|(digest, _)| digest.starts_with("hmac-sha256:"))
    );
    let foreign_id = task_a.id.as_str();
    assert!(
        raw.iter()
            .all(|(digest, task)| digest != foreign_id && task.as_deref() != Some(foreign_id)),
        "foreign deny audit persisted raw inaccessible id"
    );
    let file = std::fs::read(path.path()).unwrap();
    assert!(
        !file
            .windows(TOKEN_CANARY.len())
            .any(|window| window == TOKEN_CANARY.as_bytes())
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn visible_list_totals_pagination_and_cursors_are_scope_bound_across_restart() {
    let path = FixturePath::new("list-restart");
    let (first_gateway, _) = gateway(path.path(), DurableLoopbackEndpoint::new(), 7).await;
    for (token, id, text) in [
        ("agent-a", "list-a-1", "A one"),
        ("agent-a", "list-a-2", "A two"),
        ("agent-b", "list-b-1", "B one"),
    ] {
        let response = rpc(
            first_gateway.router(),
            token,
            &[],
            a2a::jsonrpc::methods::SEND_MESSAGE,
            serde_json::to_value(send_request(id, text, false)).unwrap(),
        )
        .await;
        assert!(
            response.json().get("error").is_none(),
            "{}",
            response.json()
        );
    }
    let page = ListTasksRequest {
        context_id: None,
        status: Some(TaskState::Completed),
        page_size: Some(1),
        page_token: None,
        history_length: Some(0),
        status_timestamp_after: None,
        include_artifacts: Some(false),
        tenant: None,
    };
    let first = rpc(
        first_gateway.router(),
        "operator",
        &[],
        a2a::jsonrpc::methods::LIST_TASKS,
        serde_json::to_value(&page).unwrap(),
    )
    .await;
    let first_body = first.json();
    assert_eq!(first_body["result"]["totalSize"], 2);
    assert_eq!(first_body["result"]["tasks"].as_array().unwrap().len(), 1);
    assert!(first_body["result"]["tasks"][0].get("history").is_none());
    assert!(first_body["result"]["tasks"][0].get("artifacts").is_none());
    let cursor = first_body["result"]["nextPageToken"]
        .as_str()
        .unwrap()
        .to_owned();

    let mut second_page = page.clone();
    second_page.page_token = Some(cursor.clone());
    let second = rpc(
        first_gateway.router(),
        "operator",
        &[],
        a2a::jsonrpc::methods::LIST_TASKS,
        serde_json::to_value(&second_page).unwrap(),
    )
    .await;
    assert_eq!(second.json()["result"]["totalSize"], 2);

    let cross_tenant = rpc(
        first_gateway.router(),
        "agent-b",
        &[],
        a2a::jsonrpc::methods::LIST_TASKS,
        serde_json::to_value(&second_page).unwrap(),
    )
    .await;
    assert_eq!(
        cross_tenant.json()["error"]["code"],
        serde_json::json!(-32602)
    );
    let mut forged = second_page.clone();
    forged.page_token = Some("not-a-cursor".into());
    let invalid = rpc(
        first_gateway.router(),
        "operator",
        &[],
        a2a::jsonrpc::methods::LIST_TASKS,
        serde_json::to_value(forged).unwrap(),
    )
    .await;
    assert_eq!(
        stable_error(cross_tenant.json()["error"].clone()),
        stable_error(invalid.json()["error"].clone())
    );

    bounded("first list gateway shutdown", first_gateway.shutdown())
        .await
        .unwrap();
    let (restarted, _) = gateway(path.path(), DurableLoopbackEndpoint::new(), 8).await;
    let revision_changed = rpc(
        restarted.router(),
        "operator",
        &[],
        a2a::jsonrpc::methods::LIST_TASKS,
        serde_json::to_value(second_page).unwrap(),
    )
    .await;
    assert_eq!(
        stable_error(revision_changed.json()["error"].clone()),
        stable_error(invalid.json()["error"].clone())
    );
    let visible = rpc(
        restarted.router(),
        "operator",
        &[],
        a2a::jsonrpc::methods::LIST_TASKS,
        serde_json::to_value(page).unwrap(),
    )
    .await;
    assert_eq!(visible.json()["result"]["totalSize"], 2);
    bounded("restarted list gateway shutdown", restarted.shutdown())
        .await
        .unwrap();
}

#[tokio::test]
async fn push_and_extended_operations_are_closed_and_durably_audited_on_both_bindings() {
    let path = FixturePath::new("closed-operations");
    let (gateway, store) = gateway(path.path(), DurableLoopbackEndpoint::new(), 1).await;
    let operations = [
        (
            "CreateTaskPushNotificationConfig",
            serde_json::json!({"taskId":"opaque-task","url":"https://callback.invalid"}),
        ),
        (
            "GetTaskPushNotificationConfig",
            serde_json::json!({"taskId":"opaque-task","id":"config"}),
        ),
        (
            "ListTaskPushNotificationConfigs",
            serde_json::json!({"taskId":"opaque-task"}),
        ),
        (
            "DeleteTaskPushNotificationConfig",
            serde_json::json!({"taskId":"opaque-task","id":"config"}),
        ),
    ];
    for role in ["viewer", "operator", "admin"] {
        for (method, params) in &operations {
            let response = rpc(gateway.router(), role, &[], method, params.clone()).await;
            assert!(
                response.json().get("error").is_some(),
                "{}",
                response.json()
            );
        }
        let response = rpc(
            gateway.router(),
            role,
            &[],
            "GetExtendedAgentCard",
            serde_json::json!({}),
        )
        .await;
        assert!(
            response.json().get("error").is_some(),
            "{}",
            response.json()
        );
    }
    for (method, path, body) in [
        (
            "POST",
            "/rest/tasks/opaque-task/pushNotificationConfigs",
            Some(serde_json::json!({"taskId":"opaque-task","url":"https://callback.invalid"})),
        ),
        (
            "GET",
            "/rest/tasks/opaque-task/pushNotificationConfigs/config",
            None,
        ),
        (
            "GET",
            "/rest/tasks/opaque-task/pushNotificationConfigs",
            None,
        ),
        (
            "DELETE",
            "/rest/tasks/opaque-task/pushNotificationConfigs/config",
            None,
        ),
        ("GET", "/rest/extendedAgentCard", None),
    ] {
        let response = wire(gateway.router(), method, path, Some("viewer"), &[], body).await;
        assert!(
            response.status.is_client_error(),
            "{path}: {}",
            response.status
        );
    }
    assert_eq!(store.authorization_decision_count().await.unwrap(), 20);
    bounded("closed operations shutdown", gateway.shutdown())
        .await
        .unwrap();
}

#[tokio::test]
async fn deferred_stream_retains_owner_scope_after_authorization_middleware_returns() {
    let path = FixturePath::new("deferred-stream");
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let endpoint = DurableLoopbackEndpoint::with_completion_barrier(
        Arc::clone(&started),
        Arc::clone(&release),
    );
    let (gateway, _) = gateway(path.path(), endpoint, 7).await;
    let request = send_request("scoped-stream", "stream work", false);
    let response = bounded("stream establishment", async {
        gateway
            .router()
            .oneshot(
                Request::post("/rest/message:stream")
                    .header("authorization", "Bearer agent-a")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap()
    })
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("text/event-stream")
    );
    bounded("receiver barrier", started.notified()).await;
    release.notify_one();
    let bytes = bounded(
        "scoped stream terminal closure",
        response.into_body().collect(),
    )
    .await
    .unwrap()
    .to_bytes();
    let wire = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(wire.contains("scoped-stream"));
    assert!(wire.contains("completed"));
    assert!(!wire.contains("agent-a"));
    bounded("stream gateway shutdown", gateway.shutdown())
        .await
        .unwrap();
}
