#![cfg(debug_assertions)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use axum::{Router, body::Bytes, extract::State, http::StatusCode, routing::post};
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use prost::Message as _;
use smesh_a2a::telemetry::{
    Attribute, AttributeKey, EventName, OtlpConfig, OtlpOwner, TelemetryRecord,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[cfg(debug_assertions)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_http_protobuf_collector_decodes_closed_log_record() {
    async fn collect(
        State(sender): State<Arc<mpsc::Sender<Vec<u8>>>>,
        body: Bytes,
    ) -> (StatusCode, [(&'static str, &'static str); 1], Vec<u8>) {
        sender.send(body.to_vec()).await.unwrap();
        (
            StatusCode::OK,
            [("content-type", "application/x-protobuf")],
            Vec::new(),
        )
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, mut receiver) = mpsc::channel(4);
    let stop = CancellationToken::new();
    let app = Router::new()
        .route("/v1/logs", post(collect))
        .with_state(Arc::new(sender));
    let server_stop = stop.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(server_stop.cancelled_owned())
            .await
            .unwrap();
    });

    let config = OtlpConfig::parse(BTreeMap::from([
        ("SMESH_A2A_OTLP_MODE".to_owned(), "http-protobuf".to_owned()),
        (
            "SMESH_A2A_OTLP_ENDPOINT".to_owned(),
            format!("http://{address}/"),
        ),
        (
            "SMESH_TEST_OTLP_INSECURE_LOOPBACK".to_owned(),
            "1".to_owned(),
        ),
        ("SMESH_A2A_OTLP_TRACE_QUEUE".to_owned(), "64".to_owned()),
        ("SMESH_A2A_OTLP_LOG_QUEUE".to_owned(), "64".to_owned()),
    ]))
    .unwrap();
    let owner = OtlpOwner::start(config).unwrap().unwrap();
    let record = TelemetryRecord::log(
        EventName::TaskTerminal,
        vec![
            Attribute::new(AttributeKey::TaskId, "task-17").unwrap(),
            Attribute::new(AttributeKey::ContextId, "context-3").unwrap(),
            Attribute::new(AttributeKey::MessageId, "message-17").unwrap(),
            Attribute::new(AttributeKey::Outcome, "ok").unwrap(),
            Attribute::new(AttributeKey::Reason, "committed").unwrap(),
            Attribute::new(AttributeKey::Operation, "terminal_commit").unwrap(),
        ],
    )
    .unwrap();
    assert!(owner.try_emit(record));
    assert!(owner.shutdown(Duration::from_secs(3)));

    let bytes = tokio::time::timeout(Duration::from_secs(3), receiver.recv())
        .await
        .unwrap()
        .unwrap();
    let export = ExportLogsServiceRequest::decode(bytes.as_slice()).unwrap();
    let log = &export.resource_logs[0].scope_logs[0].log_records[0];
    assert_eq!(log.event_name, "smesh.task.terminal");
    let keys: Vec<_> = log
        .attributes
        .iter()
        .map(|attribute| attribute.key.as_str())
        .collect();
    assert!(keys.contains(&"a2a.task.id"));
    assert!(keys.contains(&"a2a.context.id"));
    assert!(
        !keys
            .iter()
            .any(|key| key.contains("tenant") || key.contains("principal"))
    );

    stop.cancel();
    tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap();
}

#[cfg(debug_assertions)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_grpc_collector_decodes_closed_log_record() {
    use opentelemetry_proto::tonic::collector::logs::v1::{
        ExportLogsServiceResponse,
        logs_service_server::{LogsService, LogsServiceServer},
    };
    use tokio_stream::wrappers::TcpListenerStream;

    struct Collector(mpsc::Sender<ExportLogsServiceRequest>);
    #[tonic::async_trait]
    impl LogsService for Collector {
        async fn export(
            &self,
            request: tonic::Request<ExportLogsServiceRequest>,
        ) -> Result<tonic::Response<ExportLogsServiceResponse>, tonic::Status> {
            self.0
                .send(request.into_inner())
                .await
                .map_err(|_| tonic::Status::unavailable("closed"))?;
            Ok(tonic::Response::new(ExportLogsServiceResponse {
                partial_success: None,
            }))
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, mut receiver) = mpsc::channel(4);
    let stop = CancellationToken::new();
    let server_stop = stop.clone();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(LogsServiceServer::new(Collector(sender)))
            .serve_with_incoming_shutdown(
                TcpListenerStream::new(listener),
                server_stop.cancelled_owned(),
            )
            .await
            .unwrap();
    });
    let config = OtlpConfig::parse(BTreeMap::from([
        ("SMESH_A2A_OTLP_MODE".to_owned(), "grpc".to_owned()),
        (
            "SMESH_A2A_OTLP_ENDPOINT".to_owned(),
            format!("http://{address}/"),
        ),
        (
            "SMESH_TEST_OTLP_INSECURE_LOOPBACK".to_owned(),
            "1".to_owned(),
        ),
        ("SMESH_A2A_OTLP_TRACE_QUEUE".to_owned(), "64".to_owned()),
        ("SMESH_A2A_OTLP_LOG_QUEUE".to_owned(), "64".to_owned()),
    ]))
    .unwrap();
    let owner = OtlpOwner::start(config).unwrap().unwrap();
    assert!(
        owner.try_emit(
            TelemetryRecord::log(
                EventName::AuthorizationDecided,
                vec![
                    Attribute::new(AttributeKey::Outcome, "denied").unwrap(),
                    Attribute::new(AttributeKey::Reason, "role_denied").unwrap(),
                    Attribute::new(AttributeKey::Operation, "authorize").unwrap(),
                    Attribute::new(AttributeKey::RequestId, "0123456789abcdef0123456789abcdef")
                        .unwrap(),
                ]
            )
            .unwrap()
        )
    );
    assert!(owner.shutdown(Duration::from_secs(3)));
    let export = tokio::time::timeout(Duration::from_secs(3), receiver.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        export.resource_logs[0].scope_logs[0].log_records[0].event_name,
        "smesh.authorization.decided"
    );
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_batch_size_combines_logs_into_one_export_request() {
    async fn collect(
        State(sender): State<Arc<mpsc::Sender<Vec<u8>>>>,
        body: Bytes,
    ) -> (StatusCode, [(&'static str, &'static str); 1], Vec<u8>) {
        sender.send(body.to_vec()).await.unwrap();
        (
            StatusCode::OK,
            [("content-type", "application/x-protobuf")],
            Vec::new(),
        )
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, mut receiver) = mpsc::channel(4);
    let stop = CancellationToken::new();
    let server_stop = stop.clone();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/v1/logs", post(collect))
                .with_state(Arc::new(sender)),
        )
        .with_graceful_shutdown(server_stop.cancelled_owned())
        .await
        .unwrap();
    });
    let config = OtlpConfig::parse(BTreeMap::from([
        ("SMESH_A2A_OTLP_MODE".to_owned(), "http-protobuf".to_owned()),
        (
            "SMESH_A2A_OTLP_ENDPOINT".to_owned(),
            format!("http://{address}/"),
        ),
        (
            "SMESH_TEST_OTLP_INSECURE_LOOPBACK".to_owned(),
            "1".to_owned(),
        ),
        ("SMESH_A2A_OTLP_TRACE_QUEUE".to_owned(), "64".to_owned()),
        ("SMESH_A2A_OTLP_LOG_QUEUE".to_owned(), "64".to_owned()),
        ("SMESH_A2A_OTLP_METRIC_QUEUE".to_owned(), "64".to_owned()),
        ("SMESH_A2A_OTLP_BATCH_SIZE".to_owned(), "3".to_owned()),
        (
            "SMESH_A2A_OTLP_SCHEDULE_MILLIS".to_owned(),
            "10000".to_owned(),
        ),
    ]))
    .unwrap();
    let owner = OtlpOwner::start(config).unwrap().unwrap();
    for task in ["task-1", "task-2", "task-3"] {
        assert!(
            owner.try_emit(
                TelemetryRecord::log(
                    EventName::TaskTerminal,
                    vec![
                        Attribute::new(AttributeKey::TaskId, task).unwrap(),
                        Attribute::new(AttributeKey::ContextId, "context-1").unwrap(),
                        Attribute::new(AttributeKey::MessageId, format!("message-{task}")).unwrap(),
                        Attribute::new(AttributeKey::Outcome, "ok").unwrap(),
                        Attribute::new(AttributeKey::Reason, "committed").unwrap(),
                        Attribute::new(AttributeKey::Operation, "terminal_commit").unwrap(),
                    ],
                )
                .unwrap()
            )
        );
    }
    assert!(owner.shutdown(Duration::from_secs(3)));
    let bytes = tokio::time::timeout(Duration::from_secs(3), receiver.recv())
        .await
        .unwrap()
        .unwrap();
    let export = ExportLogsServiceRequest::decode(bytes.as_slice()).unwrap();
    assert_eq!(export.resource_logs[0].scope_logs[0].log_records.len(), 3);
    assert!(
        receiver.try_recv().is_err(),
        "one batch must produce one request"
    );
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap();
}

#[test]
fn shutdown_health_remains_observable_after_owner_is_consumed() {
    let owner = OtlpOwner::blocked_for_test(1);
    let health = owner.health_snapshot();
    assert!(!health.shutdown_started());
    assert!(!owner.shutdown(Duration::ZERO));
    assert!(health.shutdown_started());
    assert!(!health.shutdown_completed());
    assert_eq!(health.shutdown_timed_out_count(), 1);
    assert_eq!(health.worker_alive_count(), 0);
    assert_eq!(health.last_shutdown_outcome().as_str(), "timed_out");
}
