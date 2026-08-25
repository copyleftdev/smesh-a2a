use a2a::AgentCard;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use smesh_a2a::{GatewayConfig, LoopbackDispatcher, build_router};
use tower::ServiceExt;

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
