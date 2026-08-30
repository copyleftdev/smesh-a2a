use http_body_util::BodyExt as _;
use smesh_a2a::{
    DurableLoopbackEndpoint, GatewayConfig, InjectedClock, SqliteTaskStore,
    build_durable_loopback_gateway_with_telemetry,
    telemetry::{AttributeKey, Signal, TelemetryHandle, instrument_router_with_telemetry},
};
use tower::ServiceExt as _;

fn normalized_value(key: &str, value: &str) -> String {
    match AttributeKey::parse(key).ok() {
        Some(AttributeKey::RequestId) => "<request-id>".into(),
        Some(AttributeKey::TaskId) => "<task-id>".into(),
        Some(AttributeKey::ContextId) => "<context-id>".into(),
        Some(AttributeKey::MessageId) => "<message-id>".into(),
        Some(AttributeKey::DispatchId) => "<dispatch-id>".into(),
        Some(AttributeKey::SignalHash) => "<signal-hash>".into(),
        Some(AttributeKey::ArtifactId) => "<artifact-id>".into(),
        Some(AttributeKey::AuditDecisionId) => "<audit-decision-id>".into(),
        Some(AttributeKey::EventId) => "<event-id>".into(),
        _ => value.to_owned(),
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One live production capture remains linear and auditable.
async fn normalized_golden_is_captured_from_the_live_production_sqlite_path() {
    let root =
        std::env::temp_dir().join(format!("smesh-telemetry-golden-{}", rand::random::<u64>()));
    std::fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let store = SqliteTaskStore::open(root.join("golden.sqlite"), 8)
        .await
        .unwrap();
    let (telemetry, receiver) = TelemetryHandle::multisignal_capture_for_test(512, 1.0);
    let gateway = build_durable_loopback_gateway_with_telemetry(
        GatewayConfig::new("http://127.0.0.1:1", "telemetry-golden"),
        store,
        DurableLoopbackEndpoint::new(),
        InjectedClock::new(1_700_000_000_000),
        Some(telemetry.clone()),
    )
    .unwrap();
    let app = instrument_router_with_telemetry(gateway.router(), Some(telemetry));
    let request = serde_json::json!({
        "jsonrpc":"2.0","id":"golden","method":a2a::jsonrpc::methods::SEND_MESSAGE,
        "params":{"message":{"messageId":"golden-message","role":"ROLE_USER","parts":[{"text":"work"}]},"configuration":{"returnImmediately":false}}
    });
    let response = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/jsonrpc")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&request).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let task_id = json["result"]["task"]["id"].as_str().unwrap();
    for (id, method, params) in [
        (
            "get",
            a2a::jsonrpc::methods::GET_TASK,
            serde_json::json!({"id":task_id}),
        ),
        (
            "list",
            a2a::jsonrpc::methods::LIST_TASKS,
            serde_json::json!({}),
        ),
        (
            "replay",
            a2a::jsonrpc::methods::SEND_MESSAGE,
            request["params"].clone(),
        ),
    ] {
        let body = serde_json::to_vec(
            &serde_json::json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}),
        )
        .unwrap();
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/jsonrpc")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(response.status().is_success());
    }
    gateway.shutdown().await.unwrap();
    let mut normalized: Vec<_> = receiver.try_iter().map(|record| {
        let signal = match record.signal() { Signal::Log => "log", Signal::Span => "span", Signal::Metric => "metric" };
        let mut attributes: Vec<_> = record.attributes().iter()
            .map(|attribute| [attribute.key().to_owned(), normalized_value(attribute.key(), attribute.value())])
            .collect();
        attributes.sort();
        serde_json::json!({"signal":signal,"name":record.name(),"required":record.required(),"attributes":attributes})
    }).collect();
    normalized.sort_by_key(|record| serde_json::to_string(record).unwrap());
    let actual = serde_json::to_string_pretty(&normalized).unwrap() + "\n";
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("observability/fixtures/normalized-otlp-golden.json");
    if std::env::var_os("SMESH_UPDATE_TELEMETRY_GOLDEN").is_some() {
        std::fs::write(&fixture, &actual).unwrap();
    }
    let expected = std::fs::read_to_string(&fixture).unwrap();
    assert_eq!(
        actual,
        expected,
        "live normalized telemetry changed; inspect and update {}",
        fixture.display()
    );
    std::fs::remove_dir_all(root).unwrap();
}
