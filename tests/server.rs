use std::sync::Arc;

use a2a::AgentCard;
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use smesh_a2a::auth::{AuthState, AuthenticationError, BearerVerifier, PresentedBearer, Principal};
use smesh_a2a::{GatewayConfig, LoopbackDispatcher, build_authenticated_router, build_router};
use tower::ServiceExt;

const TOKEN_CANARY: &str = "issue12-token-canary-never-persist-or-return";

struct RejectingVerifier;

#[async_trait]
impl BearerVerifier for RejectingVerifier {
    async fn verify(&self, _token: PresentedBearer<'_>) -> Result<Principal, AuthenticationError> {
        Err(AuthenticationError::InvalidToken)
    }
}

#[tokio::test]
async fn authenticated_router_keeps_card_public_and_rejects_protocol_without_bearer() {
    let config = GatewayConfig::new("http://127.0.0.1:3000", "gateway-node");
    let auth = AuthState::new(Arc::new(RejectingVerifier), [3; 32]);
    let app = build_authenticated_router(config, LoopbackDispatcher, auth);
    let public = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/agent-card.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(public.status(), StatusCode::OK);
    let public_body = public.into_body().collect().await.unwrap().to_bytes();
    let authenticated_card: AgentCard = serde_json::from_slice(&public_body).unwrap();
    assert!(authenticated_card.security_schemes.is_some());
    assert!(authenticated_card.security_requirements.is_some());
    let denied = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/jsonrpc")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        denied.headers()["www-authenticate"],
        "Bearer realm=\"smesh-a2a\""
    );

    let invalid = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/rest/message:send")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {TOKEN_CANARY}"))
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
    assert!(
        invalid.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .contains("invalid_token")
    );
    let body = invalid.into_body().collect().await.unwrap().to_bytes();
    assert!(!String::from_utf8_lossy(&body).contains(TOKEN_CANARY));
}

#[tokio::test]
async fn router_serves_the_public_agent_card() {
    let config = GatewayConfig::new("http://127.0.0.1:3000", "gateway-node");
    let app = build_router(config, LoopbackDispatcher);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/agent-card.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let card: AgentCard = serde_json::from_slice(&body).unwrap();
    assert_eq!(card.name, "SMESH Swarm");
    assert!(card.security_schemes.is_none());
    assert!(card.security_requirements.is_none());
}

#[tokio::test]
async fn router_rejects_http_bodies_over_the_gateway_limit() {
    let mut config = GatewayConfig::new("http://127.0.0.1:3000", "gateway-node");
    config.max_body_bytes = 16;
    let app = build_router(config, LoopbackDispatcher);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/jsonrpc")
                .header("content-type", "application/json")
                .body(Body::from(vec![b'x'; 17]))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
