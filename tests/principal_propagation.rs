use std::sync::{Arc, Mutex};

use a2a_server::RequestHandler;
use async_trait::async_trait;
use axum::{Router, body::Body, http::Request, middleware};
use http_body_util::BodyExt as _;
use smesh_a2a::auth::{AuthState, AuthenticationError, authenticate_request, current_principal};
use tower::ServiceExt;

#[derive(Default)]
struct RecordingHandler {
    observations: Arc<Mutex<Vec<Observation>>>,
    requests: Arc<Mutex<Vec<(&'static str, serde_json::Value)>>>,
}

type Observation = (&'static str, String, String);

impl RecordingHandler {
    fn record(&self, method: &'static str) -> Result<(), a2a::A2AError> {
        let principal = current_principal()
            .ok_or_else(|| a2a::A2AError::internal("principal task-local missing"))?;
        self.observations.lock().unwrap().push((
            method,
            principal.issuer().to_owned(),
            principal.subject().to_owned(),
        ));
        Ok(())
    }

    fn recorded_request_error<T, R: serde::Serialize>(
        &self,
        method: &'static str,
        request: &R,
    ) -> Result<T, a2a::A2AError> {
        self.record(method)?;
        self.requests
            .lock()
            .unwrap()
            .push((method, serde_json::to_value(request).unwrap()));
        Err(a2a::A2AError::internal("recorded"))
    }

    fn recorded_stream(
        &self,
        method: &'static str,
        request: &a2a::SendMessageRequest,
    ) -> Result<
        futures::stream::BoxStream<'static, Result<a2a::StreamResponse, a2a::A2AError>>,
        a2a::A2AError,
    > {
        self.record(method)?;
        self.requests
            .lock()
            .unwrap()
            .push((method, serde_json::to_value(request).unwrap()));
        let observations = Arc::clone(&self.observations);
        let mut polls = 0;
        Ok(Box::pin(futures::stream::poll_fn(move |_| {
            let principal = current_principal()
                .expect("every deferred handler stream poll must restore the principal");
            observations.lock().unwrap().push((
                if method == "stream" {
                    "stream-poll"
                } else {
                    "subscribe-poll"
                },
                principal.issuer().to_owned(),
                principal.subject().to_owned(),
            ));
            polls += 1;
            if polls <= 2 {
                std::task::Poll::Ready(Some(Ok(a2a::StreamResponse::Message(a2a::Message::new(
                    a2a::Role::Agent,
                    vec![a2a::Part::text("poll")],
                )))))
            } else {
                std::task::Poll::Ready(None)
            }
        })))
    }
}

#[async_trait]
impl RequestHandler for RecordingHandler {
    async fn send_message(
        &self,
        _: &a2a_server::ServiceParams,
        request: a2a::SendMessageRequest,
    ) -> Result<a2a::SendMessageResponse, a2a::A2AError> {
        self.recorded_request_error("send", &request)
    }
    async fn send_streaming_message(
        &self,
        _: &a2a_server::ServiceParams,
        request: a2a::SendMessageRequest,
    ) -> Result<
        futures::stream::BoxStream<'static, Result<a2a::StreamResponse, a2a::A2AError>>,
        a2a::A2AError,
    > {
        self.recorded_stream("stream", &request)
    }
    async fn get_task(
        &self,
        _: &a2a_server::ServiceParams,
        request: a2a::GetTaskRequest,
    ) -> Result<a2a::Task, a2a::A2AError> {
        self.recorded_request_error("get", &request)
    }
    async fn list_tasks(
        &self,
        _: &a2a_server::ServiceParams,
        request: a2a::ListTasksRequest,
    ) -> Result<a2a::ListTasksResponse, a2a::A2AError> {
        self.recorded_request_error("list", &request)
    }
    async fn cancel_task(
        &self,
        _: &a2a_server::ServiceParams,
        request: a2a::CancelTaskRequest,
    ) -> Result<a2a::Task, a2a::A2AError> {
        self.recorded_request_error("cancel", &request)
    }
    async fn subscribe_to_task(
        &self,
        _: &a2a_server::ServiceParams,
        request: a2a::SubscribeToTaskRequest,
    ) -> Result<
        futures::stream::BoxStream<'static, Result<a2a::StreamResponse, a2a::A2AError>>,
        a2a::A2AError,
    > {
        self.record("subscribe")?;
        self.requests
            .lock()
            .unwrap()
            .push(("subscribe", serde_json::to_value(&request).unwrap()));
        let observations = Arc::clone(&self.observations);
        let mut polls = 0;
        Ok(Box::pin(futures::stream::poll_fn(move |_| {
            let principal = current_principal()
                .expect("every deferred handler stream poll must restore the principal");
            observations.lock().unwrap().push((
                "subscribe-poll",
                principal.issuer().to_owned(),
                principal.subject().to_owned(),
            ));
            polls += 1;
            if polls <= 2 {
                std::task::Poll::Ready(Some(Ok(a2a::StreamResponse::Message(a2a::Message::new(
                    a2a::Role::Agent,
                    vec![a2a::Part::text("poll")],
                )))))
            } else {
                std::task::Poll::Ready(None)
            }
        })))
    }
    async fn create_push_config(
        &self,
        _: &a2a_server::ServiceParams,
        request: a2a::TaskPushNotificationConfig,
    ) -> Result<a2a::TaskPushNotificationConfig, a2a::A2AError> {
        self.recorded_request_error("push-create", &request)
    }
    async fn get_push_config(
        &self,
        _: &a2a_server::ServiceParams,
        request: a2a::GetTaskPushNotificationConfigRequest,
    ) -> Result<a2a::TaskPushNotificationConfig, a2a::A2AError> {
        self.recorded_request_error("push-get", &request)
    }
    async fn list_push_configs(
        &self,
        _: &a2a_server::ServiceParams,
        request: a2a::ListTaskPushNotificationConfigsRequest,
    ) -> Result<a2a::ListTaskPushNotificationConfigsResponse, a2a::A2AError> {
        self.recorded_request_error("push-list", &request)
    }
    async fn delete_push_config(
        &self,
        _: &a2a_server::ServiceParams,
        request: a2a::DeleteTaskPushNotificationConfigRequest,
    ) -> Result<(), a2a::A2AError> {
        self.recorded_request_error("push-delete", &request)
    }
    async fn get_extended_agent_card(
        &self,
        _: &a2a_server::ServiceParams,
        request: a2a::GetExtendedAgentCardRequest,
    ) -> Result<a2a::AgentCard, a2a::A2AError> {
        self.recorded_request_error("extended", &request)
    }
}

struct FixedClock;
impl smesh_a2a::auth::AuthClock for FixedClock {
    fn unix_seconds(&self) -> i64 {
        1_800_000_000
    }
    fn monotonic_seconds(&self) -> u64 {
        0
    }
}
struct StaticJwks;
#[async_trait]
impl smesh_a2a::auth::JwksProvider for StaticJwks {
    async fn fetch(&self, _: usize) -> Result<smesh_a2a::auth::JwksFetch, AuthenticationError> {
        const N: &str = "p26N-Nwoj5-nUmncx2MHcT01-VCtp6LLQaOPv6tFIE4J3GS6Acccllk_QqMUamBnfwzgFErmBznMY8MfqZUM1-HNd_9GgvlJHIJUbYrU5Jbn1QnkY51GW5L4BXpyMeovuTPOjyKuAgRuAlaRI0W8JjZXGZt6stPFyofx-wZLT5eM0_ppclD-jJUQ_yt5tmkidf7SeXE7zDt8eg1aR2wolmhYfVzELkPRLYF4mLcMWXK7eV5Oc9L_u4NobVqAMlFX309TALcS_zrs7EbY9aB7m75RAhLjhPw8F-f_CLpvw5XMQ9OACg5NDqXEfTQUzHf9GWIHCC8JmJufvAn9jJI04Q";
        Ok(smesh_a2a::auth::JwksFetch { body: format!(r#"{{"keys":[{{"kty":"RSA","kid":"k","use":"sig","alg":"RS256","n":"{N}","e":"AQAB"}}]}}"#).into_bytes(), fresh_for: std::time::Duration::from_secs(300) })
    }
}

fn token() -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("k".to_owned());
    header.typ = Some("at+jwt".to_owned());
    jsonwebtoken::encode(
        &header,
        &serde_json::json!({"iss":"https://issuer.example","sub":"authoritative-agent","aud":"smesh-api","exp":1_800_000_060_i64,"iat":1_799_999_999_i64,"client_id":"client","jti":"jti"}),
        &jsonwebtoken::EncodingKey::from_rsa_pem(include_bytes!("fixtures/issue12-test-private.pem")).unwrap(),
    ).unwrap()
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn authoritative_principal_reaches_every_handler_method() {
    let verifier = smesh_a2a::auth::JwtBearerVerifier::new(
        smesh_a2a::auth::JwtVerifierConfig::strict("https://issuer.example", "smesh-api"),
        Arc::new(StaticJwks),
        Arc::new(FixedClock),
    )
    .await
    .unwrap();
    let auth = AuthState::new(Arc::new(verifier), [44; 32]);
    let recorder = Arc::new(RecordingHandler::default());
    let handler: Arc<dyn RequestHandler> = recorder.clone();
    let protected = Router::new()
        .nest(
            "/jsonrpc",
            a2a_server::jsonrpc::jsonrpc_router(auth.wrap_handler(handler)),
        )
        .layer(middleware::from_fn_with_state(auth, authenticate_request));
    let cases = [
        (
            "SendMessage",
            serde_json::json!({"message":{"messageId":"m","role":"ROLE_USER","parts":[{"text":"x"}]},"metadata":{"principal":"caller-forgery"}}),
        ),
        (
            "SendStreamingMessage",
            serde_json::json!({"message":{"messageId":"m","role":"ROLE_USER","parts":[{"text":"x"}]},"metadata":{"principal":"caller-forgery"}}),
        ),
        ("GetTask", serde_json::json!({"id":"t"})),
        ("ListTasks", serde_json::json!({})),
        (
            "CancelTask",
            serde_json::json!({"id":"t","metadata":{"principal":"caller-forgery"}}),
        ),
        ("SubscribeToTask", serde_json::json!({"id":"t"})),
        (
            "CreateTaskPushNotificationConfig",
            serde_json::json!({"url":"https://callback.invalid","id":"c","taskId":"t"}),
        ),
        (
            "GetTaskPushNotificationConfig",
            serde_json::json!({"taskId":"t","id":"c"}),
        ),
        (
            "ListTaskPushNotificationConfigs",
            serde_json::json!({"taskId":"t"}),
        ),
        (
            "DeleteTaskPushNotificationConfig",
            serde_json::json!({"taskId":"t","id":"c"}),
        ),
        ("GetExtendedAgentCard", serde_json::json!({})),
    ];
    let bearer = token();
    for (index, (method, params)) in cases.into_iter().enumerate() {
        let body = serde_json::json!({"jsonrpc":"2.0","id":index,"method":method,"params":params});
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            protected.clone().oneshot(
                Request::post("/jsonrpc")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {bearer}"))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_ne!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            response.into_body().collect(),
        )
        .await
        .expect("bounded response body")
        .expect("response body");
    }
    let observations = recorder.observations.lock().unwrap();
    assert_eq!(
        observations
            .iter()
            .filter(|(method, _, _)| !method.ends_with("-poll"))
            .count(),
        11,
        "every official method must enter the inner handler"
    );
    for (_, issuer, subject) in observations.iter() {
        assert_eq!(issuer, "https://issuer.example");
        assert_eq!(subject, "authoritative-agent");
        assert_ne!(subject, "caller-forgery");
    }
    assert_eq!(
        observations
            .iter()
            .filter(|(method, _, _)| *method == "stream-poll")
            .count(),
        3
    );
    assert_eq!(
        observations
            .iter()
            .filter(|(method, _, _)| *method == "subscribe-poll")
            .count(),
        3
    );
    assert!(current_principal().is_none());
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn authoritative_principal_reaches_every_rest_handler_method() {
    let verifier = smesh_a2a::auth::JwtBearerVerifier::new(
        smesh_a2a::auth::JwtVerifierConfig::strict("https://issuer.example", "smesh-api"),
        Arc::new(StaticJwks),
        Arc::new(FixedClock),
    )
    .await
    .unwrap();
    let auth = AuthState::new(Arc::new(verifier), [45; 32]);
    let recorder = Arc::new(RecordingHandler::default());
    let handler: Arc<dyn RequestHandler> = recorder.clone();
    let protected = Router::new()
        .nest(
            "/rest",
            a2a_server::rest::rest_router(auth.wrap_handler(handler)),
        )
        .layer(middleware::from_fn_with_state(auth, authenticate_request));
    let cases = [
        (
            "POST",
            "/rest/message:send",
            r#"{"message":{"messageId":"rest-message","role":"ROLE_USER","parts":[{"text":"rest send"}]},"metadata":{"principal":"caller-forgery"}}"#,
        ),
        (
            "POST",
            "/rest/message:stream",
            r#"{"message":{"messageId":"rest-message","role":"ROLE_USER","parts":[{"text":"rest stream"}]},"metadata":{"principal":"caller-forgery"}}"#,
        ),
        ("GET", "/rest/tasks/task?historyLength=3", ""),
        (
            "GET",
            "/rest/tasks?contextId=context&pageSize=7&includeArtifacts=true",
            "",
        ),
        ("POST", "/rest/tasks/task:cancel", ""),
        ("GET", "/rest/tasks/task:subscribe", ""),
        (
            "POST",
            "/rest/tasks/task/pushNotificationConfigs",
            r#"{"taskId":"task","id":"config","url":"https://callback.invalid/events"}"#,
        ),
        ("GET", "/rest/tasks/task/pushNotificationConfigs/config", ""),
        (
            "GET",
            "/rest/tasks/task/pushNotificationConfigs?pageSize=5&pageToken=next",
            "",
        ),
        (
            "DELETE",
            "/rest/tasks/task/pushNotificationConfigs/config",
            "",
        ),
        ("GET", "/rest/extendedAgentCard", ""),
    ];
    let bearer = token();
    for (method, uri, body) in cases {
        if uri.starts_with("/rest/message:") {
            let payload: serde_json::Value = serde_json::from_str(body).unwrap();
            assert_eq!(
                payload.pointer("/message/messageId"),
                Some(&serde_json::json!("rest-message"))
            );
            assert_eq!(
                payload.pointer("/message/role"),
                Some(&serde_json::json!("ROLE_USER"))
            );
            assert!(payload.pointer("/message/parts/0/text").is_some());
        }
        if method == "POST" && uri.contains("pushNotificationConfigs") {
            let payload: serde_json::Value = serde_json::from_str(body).unwrap();
            assert_eq!(payload.get("id"), Some(&serde_json::json!("config")));
            assert_eq!(
                payload.get("url"),
                Some(&serde_json::json!("https://callback.invalid/events"))
            );
        }
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            protected.clone().oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {bearer}"))
                    .body(Body::from(body))
                    .unwrap(),
            ),
        )
        .await
        .expect("bounded REST request")
        .expect("REST response");
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            response.into_body().collect(),
        )
        .await
        .expect("bounded REST response body")
        .expect("REST response body");
    }

    let observations = recorder.observations.lock().unwrap();
    let entered = observations
        .iter()
        .filter_map(|(method, _, _)| (!method.ends_with("-poll")).then_some(*method))
        .collect::<Vec<_>>();
    assert_eq!(
        entered,
        [
            "send",
            "stream",
            "get",
            "list",
            "cancel",
            "subscribe",
            "push-create",
            "push-get",
            "push-list",
            "push-delete",
            "extended",
        ],
        "all 11 REST operations must enter their exact recording handler method"
    );
    let requests = recorder.requests.lock().unwrap();
    assert_eq!(
        requests.as_slice(),
        [
            (
                "send",
                serde_json::json!({"message":{"messageId":"rest-message","role":"ROLE_USER","parts":[{"text":"rest send"}]},"metadata":{"principal":"caller-forgery"}}),
            ),
            (
                "stream",
                serde_json::json!({"message":{"messageId":"rest-message","role":"ROLE_USER","parts":[{"text":"rest stream"}]},"metadata":{"principal":"caller-forgery"}}),
            ),
            ("get", serde_json::json!({"id":"task","historyLength":3})),
            (
                "list",
                serde_json::json!({"contextId":"context","pageSize":7,"includeArtifacts":true}),
            ),
            ("cancel", serde_json::json!({"id":"task"})),
            ("subscribe", serde_json::json!({"id":"task"})),
            (
                "push-create",
                serde_json::json!({"url":"https://callback.invalid/events","id":"config","taskId":"task"}),
            ),
            (
                "push-get",
                serde_json::json!({"taskId":"task","id":"config"}),
            ),
            (
                "push-list",
                serde_json::json!({"taskId":"task","pageSize":5,"pageToken":"next"}),
            ),
            (
                "push-delete",
                serde_json::json!({"taskId":"task","id":"config"}),
            ),
            ("extended", serde_json::json!({})),
        ],
        "REST paths, bodies, and query strings must parse into the exact operation requests"
    );
    for (method, issuer, subject) in observations.iter() {
        assert_eq!(issuer, "https://issuer.example", "REST {method} issuer");
        assert_eq!(subject, "authoritative-agent", "REST {method} subject");
        assert_ne!(subject, "caller-forgery", "REST {method} trusted body data");
    }
    assert_eq!(
        observations
            .iter()
            .filter(|(method, _, _)| *method == "stream-poll")
            .count(),
        3,
        "REST streaming response must preserve the principal on every deferred poll"
    );
    assert_eq!(
        observations
            .iter()
            .filter(|(method, _, _)| *method == "subscribe-poll")
            .count(),
        3,
        "REST subscription must preserve the principal on every deferred poll"
    );
    assert!(current_principal().is_none());
}
