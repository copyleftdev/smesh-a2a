use http_body_util::BodyExt as _;
use smesh_a2a::{
    DurableInterruptionKind, DurableLoopbackEndpoint, GatewayConfig, InjectedClock,
    SqliteTaskStore, build_durable_loopback_gateway_with_telemetry,
    telemetry::{
        EventName, MetricName, Signal, SpanName, TelemetryHandle, instrument_router_with_telemetry,
    },
};
use tokio::sync::Notify;
use tower::ServiceExt as _;

async fn post_json(app: &axum::Router, value: serde_json::Value) -> axum::response::Response {
    app.clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/jsonrpc")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(&value).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

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
        SpanName::DurableCommit,
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
    let terminal_commit = records
        .iter()
        .find(|record| {
            record.signal() == Signal::Span
                && record.attributes().iter().any(|attribute| {
                    attribute.key() == "smesh.operation" && attribute.value() == "terminal_commit"
                })
        })
        .expect("terminal commit span");
    assert_eq!(terminal_commit.name(), SpanName::DurableCommit.as_str());
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

#[tokio::test]
#[allow(clippy::too_many_lines)] // Two termination variants plus immediate-cancel telemetry stay auditable together.
async fn interrupted_receivers_emit_nonterminal_transition_without_task_terminal() {
    for (index, (kind, expected_state)) in [
        (DurableInterruptionKind::InputRequired, "input_required"),
        (DurableInterruptionKind::AuthRequired, "auth_required"),
    ]
    .into_iter()
    .enumerate()
    {
        let root = std::env::temp_dir().join(format!(
            "smesh-telemetry-interruption-{}-{}-{index}",
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
        let endpoint = DurableLoopbackEndpoint::with_interruption_for_text(
            "interrupt",
            kind,
            "continue later",
        );
        let gateway = build_durable_loopback_gateway_with_telemetry(
            GatewayConfig::new("http://127.0.0.1:1", "telemetry-interruption"),
            store,
            endpoint,
            InjectedClock::new(1_700_000_000_000),
            Some(telemetry.clone()),
        )
        .unwrap();
        let app = instrument_router_with_telemetry(gateway.router(), Some(telemetry));
        let response = app.clone().oneshot(
            axum::http::Request::builder().method("POST").uri("/jsonrpc")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(&serde_json::json!({
                    "jsonrpc":"2.0", "id":"interrupt", "method":a2a::jsonrpc::methods::SEND_MESSAGE,
                    "params":{"message":{"messageId":format!("interrupt-{index}"),"role":"ROLE_USER","parts":[{"text":"interrupt"}]},"configuration":{"returnImmediately":false}}
                })).unwrap())).unwrap()
        ).await.unwrap();
        assert!(response.status().is_success());
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let response_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let task_id = response_json["result"]["task"]["id"].as_str().unwrap();
        let records: Vec<_> = receiver.try_iter().collect();
        let logs: Vec<_> = records
            .iter()
            .filter(|record| record.signal() == Signal::Log)
            .collect();
        assert_eq!(
            logs.iter()
                .filter(|record| record.name() == EventName::TaskTerminal.as_str())
                .count(),
            0
        );
        for expected in [EventName::TaskTransitioned, EventName::ReceiverCompleted] {
            let matching: Vec<_> = logs
                .iter()
                .filter(|record| record.name() == expected.as_str())
                .collect();
            assert_eq!(matching.len(), 1, "{expected_state} {expected:?}");
            assert!(matching[0].attributes().iter().any(|attribute| {
                attribute.key() == "smesh.task.state" && attribute.value() == expected_state
            }));
        }
        let commit_metrics = records
            .iter()
            .filter(|record| {
                record.signal() == Signal::Metric
                    && record.name() == MetricName::DurableOperation.as_str()
                    && record.attributes().iter().any(|attribute| {
                        attribute.key() == "smesh.operation"
                            && matches!(attribute.value(), "receiver_execute" | "task_transition")
                    })
            })
            .count();
        assert_eq!(
            commit_metrics, 2,
            "one metric per transition/completion log"
        );

        let canceled = app.clone().oneshot(
            axum::http::Request::builder().method("POST").uri("/jsonrpc")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(&serde_json::json!({
                    "jsonrpc":"2.0", "id":"cancel", "method":a2a::jsonrpc::methods::CANCEL_TASK,
                    "params":{"id":task_id}
                })).unwrap())).unwrap()
        ).await.unwrap();
        assert!(canceled.status().is_success());
        let _ = canceled.into_body().collect().await.unwrap();
        gateway.shutdown().await.unwrap();
        let cancellation_records: Vec<_> = receiver.try_iter().collect();
        for expected in [
            EventName::CancellationRequested,
            EventName::CancellationAcknowledged,
            EventName::TaskTerminal,
        ] {
            assert_eq!(
                cancellation_records
                    .iter()
                    .filter(|record| {
                        record.signal() == Signal::Log && record.name() == expected.as_str()
                    })
                    .count(),
                1,
                "missing immediate cancellation event {expected:?}"
            );
        }
        assert_eq!(
            cancellation_records
                .iter()
                .filter(|record| {
                    record.signal() == Signal::Log
                        && record.name() == EventName::CancellationStopped.as_str()
                })
                .count(),
            0,
            "immediate durable cancellation did not join an active receiver"
        );
        let terminal_span = cancellation_records
            .iter()
            .find(|record| {
                record.signal() == Signal::Span
                    && record.attributes().iter().any(|attribute| {
                        attribute.key() == "smesh.operation"
                            && attribute.value() == "terminal_commit"
                    })
            })
            .expect("immediate cancellation terminal commit span");
        assert_eq!(terminal_span.name(), SpanName::DurableCommit.as_str());
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[tokio::test]
async fn cooperative_cancellation_emits_stopped_after_joining_active_receiver() {
    let root = std::env::temp_dir().join(format!(
        "smesh-telemetry-cooperative-cancel-{}-{}",
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
    let started = std::sync::Arc::new(Notify::new());
    let release = std::sync::Arc::new(Notify::new());
    let endpoint = DurableLoopbackEndpoint::with_completion_barrier(started.clone(), release);
    let (telemetry, receiver) = TelemetryHandle::multisignal_capture_for_test(256, 1.0);
    let gateway = build_durable_loopback_gateway_with_telemetry(
        GatewayConfig::new("http://127.0.0.1:1", "telemetry-cooperative-cancel"),
        store,
        endpoint,
        InjectedClock::new(1_700_000_000_000),
        Some(telemetry.clone()),
    )
    .unwrap();
    let app = instrument_router_with_telemetry(gateway.router(), Some(telemetry));
    let admitted = post_json(&app, serde_json::json!({
        "jsonrpc":"2.0", "id":"send", "method":a2a::jsonrpc::methods::SEND_MESSAGE,
        "params":{"message":{"messageId":"cooperative-cancel","role":"ROLE_USER","parts":[{"text":"work"}]},"configuration":{"returnImmediately":true}}
    })).await;
    let admitted_body = admitted.into_body().collect().await.unwrap().to_bytes();
    let admitted_json: serde_json::Value = serde_json::from_slice(&admitted_body).unwrap();
    let task_id = admitted_json["result"]["task"]["id"].as_str().unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), started.notified())
        .await
        .unwrap();
    let canceled = post_json(
        &app,
        serde_json::json!({
            "jsonrpc":"2.0", "id":"cancel", "method":a2a::jsonrpc::methods::CANCEL_TASK,
            "params":{"id":task_id}
        }),
    )
    .await;
    assert!(canceled.status().is_success());
    let _ = canceled.into_body().collect().await.unwrap();
    gateway.shutdown().await.unwrap();
    let records: Vec<_> = receiver.try_iter().collect();
    for expected in [
        EventName::CancellationRequested,
        EventName::CancellationAcknowledged,
        EventName::CancellationStopped,
        EventName::TaskTerminal,
    ] {
        assert_eq!(
            records
                .iter()
                .filter(|record| {
                    record.signal() == Signal::Log && record.name() == expected.as_str()
                })
                .count(),
            1,
            "cooperative cancellation event {expected:?}"
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}
