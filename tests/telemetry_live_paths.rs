use http_body_util::BodyExt as _;
use smesh_a2a::{
    DurableLoopbackEndpoint, GatewayConfig, InjectedClock, SqliteTaskStore,
    build_durable_loopback_gateway_with_telemetry,
    telemetry::{
        EventName, MetricName, Signal, SpanName, TelemetryHandle, instrument_router_with_telemetry,
    },
};
use tower::ServiceExt as _;

#[tokio::test]
async fn ordinary_streaming_admission_uses_the_authoritative_task_context_and_message() {
    let root = std::env::temp_dir().join(format!(
        "smesh-telemetry-stream-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let store = SqliteTaskStore::open(root.join("stream.sqlite"), 8)
        .await
        .unwrap();
    let (telemetry, receiver) = TelemetryHandle::multisignal_capture_for_test(128, 0.0);
    let gateway = build_durable_loopback_gateway_with_telemetry(
        GatewayConfig::new("http://127.0.0.1:1", "telemetry-stream"),
        store,
        DurableLoopbackEndpoint::new(),
        InjectedClock::new(1_700_000_000_000),
        Some(telemetry.clone()),
    )
    .unwrap();
    let app = instrument_router_with_telemetry(gateway.router(), Some(telemetry));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/jsonrpc")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "jsonrpc":"2.0","id":"stream","method":a2a::jsonrpc::methods::SEND_STREAMING_MESSAGE,
                        "params":{"message":{"messageId":"stream-message","role":"ROLE_USER","parts":[{"text":"work"}]}}
                    })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success());
    let admitted = (0..128)
        .filter_map(|_| {
            receiver
                .recv_timeout(std::time::Duration::from_millis(50))
                .ok()
        })
        .find(|record| record.name() == EventName::TaskAdmitted.as_str())
        .unwrap();
    for key in ["a2a.task.id", "a2a.context.id", "a2a.message.id"] {
        assert!(
            admitted
                .attributes()
                .iter()
                .any(|attribute| attribute.key() == key)
        );
    }
    assert!(admitted.attributes().iter().any(|attribute| {
        attribute.key() == "a2a.message.id" && attribute.value() == "stream-message"
    }));
    drop(response);
    gateway.shutdown().await.unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One end-to-end production correlation chain stays linear.
async fn live_sqlite_request_dispatch_and_terminal_commit_emit_one_correlated_chain() {
    let root = std::env::temp_dir().join(format!(
        "smesh-telemetry-live-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let store = SqliteTaskStore::open(root.join("live.sqlite"), 8)
        .await
        .unwrap();
    let (telemetry, receiver) = TelemetryHandle::multisignal_capture_for_test(256, 1.0);
    let gateway = build_durable_loopback_gateway_with_telemetry(
        GatewayConfig::new("http://127.0.0.1:1", "telemetry-live"),
        store,
        DurableLoopbackEndpoint::new(),
        InjectedClock::new(1_700_000_000_000),
        Some(telemetry.clone()),
    )
    .unwrap();
    let app = instrument_router_with_telemetry(gateway.router(), Some(telemetry));
    let response = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/jsonrpc")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": "live",
                        "method": a2a::jsonrpc::methods::SEND_MESSAGE,
                        "params": {
                            "message": {
                                "messageId": "telemetry-live-message",
                                "role": "ROLE_USER",
                                "parts": [{"text": "work"}]
                            },
                            "configuration": {"returnImmediately": false}
                        }
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["result"]["task"]["id"].is_string(), "{json}");
    let task_id = json["result"]["task"]["id"].as_str().unwrap();

    for (id, method, params) in [
        (
            "get",
            a2a::jsonrpc::methods::GET_TASK,
            serde_json::json!({"id": task_id}),
        ),
        (
            "list",
            a2a::jsonrpc::methods::LIST_TASKS,
            serde_json::json!({}),
        ),
        (
            "replay",
            a2a::jsonrpc::methods::SEND_MESSAGE,
            serde_json::json!({
                "message": {
                    "messageId": "telemetry-live-message",
                    "role": "ROLE_USER",
                    "parts": [{"text": "work"}]
                },
                "configuration": {"returnImmediately": false}
            }),
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/jsonrpc")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "jsonrpc": "2.0", "id": id, "method": method, "params": params
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(response.status().is_success());
    }

    let mut records = Vec::new();
    while let Ok(record) = receiver.recv_timeout(std::time::Duration::from_millis(100)) {
        records.push(record);
    }
    let names: Vec<_> = records
        .iter()
        .map(|record| record.name().to_owned())
        .collect();
    for required in [
        EventName::DispatchClaimed.as_str(),
        EventName::ReceiverAdmitted.as_str(),
        EventName::ReceiverCompleted.as_str(),
        EventName::TaskTerminal.as_str(),
    ] {
        assert_eq!(
            names
                .iter()
                .filter(|name| name.as_str() == required)
                .count(),
            1,
            "duplicate or missing {required}: {names:?}"
        );
    }
    assert_eq!(
        names
            .iter()
            .filter(|name| name.as_str() == EventName::TaskAdmitted.as_str())
            .count(),
        1
    );
    assert_eq!(
        names
            .iter()
            .filter(|name| name.as_str() == EventName::RequestCompleted.as_str())
            .count(),
        4
    );
    for operation in ["get_task", "list_tasks"] {
        assert!(
            records.iter().any(|record| {
                record.name() == EventName::TaskTransitioned.as_str()
                    && record.attributes().iter().any(|attribute| {
                        attribute.key() == "smesh.operation" && attribute.value() == operation
                    })
            }),
            "missing durable read outcome for {operation}"
        );
    }
    assert!(records.iter().any(|record| {
        record.signal() == Signal::Metric && record.name() == MetricName::DurableOperation.as_str()
    }));
    assert!(records.iter().any(|record| {
        record.signal() == Signal::Metric && record.name() == MetricName::A2aRequest.as_str()
    }));
    let emitted_identities: std::collections::HashSet<_> = records
        .iter()
        .filter_map(smesh_a2a::telemetry::TelemetryRecord::span_identity_for_test)
        .collect();
    for background_span in [
        SpanName::OutboxClaim,
        SpanName::OutboxAttempt,
        SpanName::ReceiverAdmit,
        SpanName::ReceiverExecute,
    ] {
        let record = records
            .iter()
            .find(|record| {
                record.signal() == Signal::Span && record.name() == background_span.as_str()
            })
            .unwrap_or_else(|| panic!("missing background span {}", background_span.as_str()));
        let expected_links = usize::from(background_span != SpanName::OutboxClaim);
        assert_eq!(record.link_count_for_test(), expected_links);
        for target in record.span_links_for_test() {
            assert!(
                emitted_identities.contains(&target),
                "{} linked to a span identity that was never emitted",
                background_span.as_str()
            );
        }
    }
    assert!(
        records
            .iter()
            .filter(|record| record.required())
            .all(|record| record.signal() == Signal::Log)
    );
    assert!(SpanName::HttpRequest.as_str().starts_with("smesh."));
    gateway.shutdown().await.unwrap();
    std::fs::remove_dir_all(root).unwrap();
}
