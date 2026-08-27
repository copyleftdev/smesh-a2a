use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use smesh_a2a::auth::{
    AuthClock, AuthState, AuthenticationError, JwksFetch, JwksProvider, JwtBearerVerifier,
    JwtVerifierConfig,
};
use smesh_a2a::{GatewayConfig, LoopbackDispatcher, build_authenticated_router};
use tower::ServiceExt;

const RSA_N: &str = "p26N-Nwoj5-nUmncx2MHcT01-VCtp6LLQaOPv6tFIE4J3GS6Acccllk_QqMUamBnfwzgFErmBznMY8MfqZUM1-HNd_9GgvlJHIJUbYrU5Jbn1QnkY51GW5L4BXpyMeovuTPOjyKuAgRuAlaRI0W8JjZXGZt6stPFyofx-wZLT5eM0_ppclD-jJUQ_yt5tmkidf7SeXE7zDt8eg1aR2wolmhYfVzELkPRLYF4mLcMWXK7eV5Oc9L_u4NobVqAMlFX309TALcS_zrs7EbY9aB7m75RAhLjhPw8F-f_CLpvw5XMQ9OACg5NDqXEfTQUzHf9GWIHCC8JmJufvAn9jJI04Q";

struct FixedClock(i64);
impl AuthClock for FixedClock {
    fn unix_seconds(&self) -> i64 {
        self.0
    }
    fn monotonic_seconds(&self) -> u64 {
        0
    }
}

struct StaticJwks(Vec<u8>);
#[async_trait]
impl JwksProvider for StaticJwks {
    async fn fetch(&self, _max_bytes: usize) -> Result<JwksFetch, AuthenticationError> {
        Ok(JwksFetch {
            body: self.0.clone(),
            fresh_for: std::time::Duration::from_secs(300),
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

async fn auth_and_token() -> (AuthState, String) {
    let now = 1_800_000_000;
    let jwks = format!(r#"{{"keys":[{{"kty":"RSA","kid":"key-a","use":"sig","alg":"RS256","n":"{RSA_N}","e":"AQAB"}}]}}"#).into_bytes();
    let verifier = JwtBearerVerifier::new(
        JwtVerifierConfig::strict("https://issuer.example", "smesh-api"),
        Arc::new(StaticJwks(jwks)),
        Arc::new(FixedClock(now)),
    )
    .await
    .unwrap();
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("key-a".to_owned());
    header.typ = Some("at+jwt".to_owned());
    let token = jsonwebtoken::encode(
        &header,
        &Claims {
            iss: "https://issuer.example",
            sub: "agent-17",
            aud: "smesh-api",
            exp: now + 60,
            nbf: now - 1,
            iat: now - 1,
            client_id: "client-17",
            jti: "token-17",
        },
        &jsonwebtoken::EncodingKey::from_rsa_pem(include_bytes!(
            "fixtures/issue12-test-private.pem"
        ))
        .unwrap(),
    )
    .unwrap();
    (AuthState::new(Arc::new(verifier), [4; 32]), token)
}

#[tokio::test]
async fn signed_bearer_reaches_official_jsonrpc_and_rest_unary_routes() {
    let (auth, token) = auth_and_token().await;
    let app = build_authenticated_router(
        GatewayConfig::new("http://127.0.0.1:3000", "gateway-node"),
        LoopbackDispatcher,
        auth,
    );
    let send = a2a::SendMessageRequest {
        message: a2a::Message::new(a2a::Role::User, vec![a2a::Part::text("authenticated")]),
        configuration: None,
        metadata: Some(std::collections::HashMap::from([(
            "principal".to_owned(),
            serde_json::json!("caller-forgery"),
        )])),
        tenant: None,
    };
    let rpc_body = serde_json::json!({
        "jsonrpc": "2.0", "id": "auth-rpc",
        "method": a2a::jsonrpc::methods::SEND_MESSAGE,
        "params": send,
    });
    let rpc = app
        .clone()
        .oneshot(
            Request::post("/jsonrpc")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&rpc_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rpc.status(), StatusCode::OK);
    let bytes = rpc.into_body().collect().await.unwrap().to_bytes();
    assert!(
        serde_json::from_slice::<serde_json::Value>(&bytes)
            .unwrap()
            .get("error")
            .is_none()
    );

    let rest = app
        .oneshot(
            Request::post("/rest/message:send")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&send).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rest.status(), StatusCode::OK);
}
