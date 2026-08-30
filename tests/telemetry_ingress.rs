use axum::{Router, middleware, routing::get};
use http_body_util::BodyExt as _;
use smesh_a2a::{
    auth::{AuthState, AuthenticationError, BearerVerifier, PresentedBearer},
    telemetry::{
        EventName, RequestTelemetryContext, TelemetryHandle, capture_request_telemetry_context,
        current_request_telemetry_context, instrument_router, instrument_router_with_telemetry,
    },
};
use tower::ServiceExt as _;

#[tokio::test]
async fn ingress_replaces_all_remote_correlation_authority() {
    async fn handler(axum::Extension(context): axum::Extension<RequestTelemetryContext>) -> String {
        context.request_id().to_owned()
    }
    let app = instrument_router(Router::new().route("/", get(handler)));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/")
                .header("x-request-id", "attacker")
                .header(
                    "traceparent",
                    "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01",
                )
                .header("tracestate", "secret=canary")
                .header("baggage", "tenant=evil")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let header = response
        .headers()
        .get("x-request-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body = std::str::from_utf8(&body).unwrap();
    assert_eq!(header, body);
    assert_ne!(header, "attacker");
    assert_eq!(header.len(), 32);
    assert!(header.bytes().all(|byte| byte.is_ascii_hexdigit()));
}

struct RejectVerifier;
#[async_trait::async_trait]
impl BearerVerifier for RejectVerifier {
    async fn verify(
        &self,
        _token: PresentedBearer<'_>,
    ) -> Result<smesh_a2a::auth::Principal, AuthenticationError> {
        Err(AuthenticationError::InvalidToken)
    }
}

#[tokio::test]
async fn authentication_denial_uses_server_request_context_and_required_log_queue() {
    let (telemetry, receiver) = TelemetryHandle::log_capture_for_test(8);
    let auth = AuthState::new(std::sync::Arc::new(RejectVerifier), [7; 32])
        .with_telemetry(telemetry.clone());
    let protected = Router::new()
        .route("/", get(|| async { "unreachable" }))
        .layer(middleware::from_fn_with_state(
            auth,
            smesh_a2a::auth::authenticate_request,
        ));
    let app = instrument_router_with_telemetry(protected, Some(telemetry));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    let record = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap();
    assert_eq!(record.name(), EventName::AuthenticationDecided.as_str());
    assert!(record.required());
    assert!(record.attributes().iter().any(|attribute| {
        attribute.key() == "smesh.request.id" && attribute.value().len() == 32
    }));
}

#[tokio::test]
async fn task_local_request_context_is_isolated_and_capturable_for_deferred_work() {
    async fn handler() -> String {
        let current = current_request_telemetry_context().expect("request context");
        let captured = capture_request_telemetry_context().expect("captured context");
        tokio::task::yield_now().await;
        assert_eq!(current, current_request_telemetry_context().unwrap());
        assert_eq!(current, captured);
        current.request_id().to_owned()
    }
    let app = instrument_router(Router::new().route("/", get(handler)));
    let (first, second) = tokio::join!(
        app.clone().oneshot(
            axum::http::Request::builder()
                .uri("/")
                .body(axum::body::Body::empty())
                .unwrap(),
        ),
        app.oneshot(
            axum::http::Request::builder()
                .uri("/")
                .body(axum::body::Body::empty())
                .unwrap(),
        ),
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_ne!(
        first.headers()["x-request-id"],
        second.headers()["x-request-id"]
    );
    assert!(current_request_telemetry_context().is_none());
}
