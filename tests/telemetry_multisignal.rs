#![cfg(debug_assertions)]
#![allow(clippy::too_many_lines, clippy::type_complexity)]

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use axum::{
    Router,
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    routing::post,
};
use opentelemetry_proto::tonic::collector::{
    logs::v1::ExportLogsServiceRequest, metrics::v1::ExportMetricsServiceRequest,
    trace::v1::ExportTraceServiceRequest,
};
use prost::Message as _;
use smesh_a2a::telemetry::{
    Attribute, AttributeKey, ClosedSpan, EventName, MetricName, MetricPoint, OtlpConfig, OtlpOwner,
    SpanLink, SpanName, TelemetryRecord,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

fn terminal_attributes() -> Vec<Attribute> {
    vec![
        Attribute::new(AttributeKey::TaskId, "task-1").unwrap(),
        Attribute::new(AttributeKey::ContextId, "context-1").unwrap(),
        Attribute::new(AttributeKey::MessageId, "message-1").unwrap(),
        Attribute::new(AttributeKey::Outcome, "ok").unwrap(),
        Attribute::new(AttributeKey::Reason, "committed").unwrap(),
        Attribute::new(AttributeKey::Operation, "terminal_commit").unwrap(),
    ]
}

fn admission_span_attributes() -> Vec<Attribute> {
    vec![
        Attribute::new(AttributeKey::Outcome, "ok").unwrap(),
        Attribute::new(AttributeKey::Reason, "admitted").unwrap(),
        Attribute::new(AttributeKey::Operation, "send_message").unwrap(),
        Attribute::new(AttributeKey::TaskId, "task-1").unwrap(),
        Attribute::new(AttributeKey::ContextId, "context-1").unwrap(),
        Attribute::new(AttributeKey::MessageId, "message-1").unwrap(),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_protobuf_exports_closed_trace_cumulative_metric_and_required_log() {
    async fn collect(
        Path(signal): Path<String>,
        State(sender): State<Arc<mpsc::Sender<(String, Vec<u8>)>>>,
        body: Bytes,
    ) -> (StatusCode, [(&'static str, &'static str); 1], Vec<u8>) {
        sender.send((signal, body.to_vec())).await.unwrap();
        (
            StatusCode::OK,
            [("content-type", "application/x-protobuf")],
            Vec::new(),
        )
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, mut receiver) = mpsc::channel(8);
    let stop = CancellationToken::new();
    let server_stop = stop.clone();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/v1/{signal}", post(collect))
                .with_state(Arc::new(sender)),
        )
        .with_graceful_shutdown(server_stop.cancelled_owned())
        .await
        .unwrap();
    });

    let config = OtlpConfig::parse(BTreeMap::from([
        ("SMESH_A2A_OTLP_MODE".into(), "http-protobuf".into()),
        (
            "SMESH_A2A_OTLP_ENDPOINT".into(),
            format!("http://{address}/"),
        ),
        ("SMESH_TEST_OTLP_INSECURE_LOOPBACK".into(), "1".into()),
        ("SMESH_A2A_OTLP_TRACE_QUEUE".into(), "64".into()),
        ("SMESH_A2A_OTLP_LOG_QUEUE".into(), "64".into()),
        ("SMESH_A2A_OTLP_METRIC_QUEUE".into(), "64".into()),
        (
            "SMESH_A2A_OTLP_METRIC_INTERVAL_MILLIS".into(),
            "1000".into(),
        ),
        ("SMESH_A2A_OTLP_EXPORT_TIMEOUT_MILLIS".into(), "100".into()),
    ]))
    .unwrap();
    let owner = OtlpOwner::start(config).unwrap().unwrap();

    let span = ClosedSpan::new(
        SpanName::DurableAdmission,
        [0x11; 16],
        [0x22; 8],
        Some([0x33; 8]),
        vec![SpanLink::new([0x44; 16], [0x55; 8])],
        1_000,
        1_900,
        admission_span_attributes(),
    )
    .unwrap();
    assert_eq!(span.duration_nanos(), 900);
    assert!(owner.try_emit(TelemetryRecord::span(span)));
    let metric_record = || {
        TelemetryRecord::metric(
            MetricPoint::new(
                MetricName::TaskAdmitted,
                7,
                vec![Attribute::new(AttributeKey::Outcome, "ok").unwrap()],
            )
            .unwrap(),
        )
    };
    assert!(owner.try_emit(metric_record()));
    let required = TelemetryRecord::log(EventName::TaskTerminal, terminal_attributes()).unwrap();
    assert!(required.required());
    assert!(owner.try_emit(required));

    let mut payloads = BTreeMap::new();
    let mut metric_payloads = Vec::new();
    while metric_payloads.is_empty() {
        let (signal, bytes) = tokio::time::timeout(Duration::from_secs(3), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        if signal == "metrics" {
            metric_payloads.push(bytes);
        } else {
            payloads.insert(signal, bytes);
        }
    }
    assert!(owner.try_emit(metric_record()));
    assert!(owner.shutdown(Duration::from_secs(3)));
    while metric_payloads.len() < 2
        || !payloads.contains_key("traces")
        || !payloads.contains_key("logs")
    {
        let (signal, bytes) = tokio::time::timeout(Duration::from_secs(3), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        if signal == "metrics" {
            metric_payloads.push(bytes);
        } else {
            payloads.insert(signal, bytes);
        }
    }
    let traces = ExportTraceServiceRequest::decode(payloads["traces"].as_slice()).unwrap();
    let wire_span = &traces.resource_spans[0].scope_spans[0].spans[0];
    assert_eq!(wire_span.trace_id, vec![0x11; 16]);
    assert_eq!(wire_span.span_id, vec![0x22; 8]);
    assert_eq!(wire_span.parent_span_id, vec![0x33; 8]);
    assert_eq!(wire_span.links[0].trace_id, vec![0x44; 16]);
    assert_eq!(wire_span.start_time_unix_nano, 1_000);
    assert_eq!(wire_span.end_time_unix_nano, 1_900);

    let first_metrics = ExportMetricsServiceRequest::decode(metric_payloads[0].as_slice()).unwrap();
    let second_metrics =
        ExportMetricsServiceRequest::decode(metric_payloads[1].as_slice()).unwrap();
    let metric = &second_metrics.resource_metrics[0].scope_metrics[0].metrics[0];
    assert_eq!(metric.name, "smesh.a2a.task.admitted");
    assert_eq!(metric.unit, "{task}");
    let sum_value = |request: &ExportMetricsServiceRequest| {
        let metric = &request.resource_metrics[0].scope_metrics[0].metrics[0];
        let opentelemetry_proto::tonic::metrics::v1::metric::Data::Sum(sum) =
            metric.data.as_ref().unwrap()
        else {
            panic!("counter was not a sum")
        };
        let point = &sum.data_points[0];
        let opentelemetry_proto::tonic::metrics::v1::number_data_point::Value::AsInt(value) =
            point.value.unwrap()
        else {
            panic!("counter was not an integer")
        };
        (value, point.start_time_unix_nano)
    };
    let first = sum_value(&first_metrics);
    let second = sum_value(&second_metrics);
    assert_eq!((first.0, second.0), (7, 14));
    assert_eq!(first.1, second.1, "cumulative series start time reset");
    let logs = ExportLogsServiceRequest::decode(payloads["logs"].as_slice()).unwrap();
    assert_eq!(
        logs.resource_logs[0].scope_logs[0].log_records[0].event_name,
        "smesh.task.terminal"
    );

    stop.cancel();
    tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_mtls_collector_requires_client_identity_and_secret_header() {
    use opentelemetry_proto::tonic::collector::logs::v1::{
        ExportLogsServiceResponse,
        logs_service_server::{LogsService, LogsServiceServer},
    };
    use smesh_a2a::telemetry::DropReason;
    use tokio_stream::wrappers::TcpListenerStream;

    #[derive(Clone)]
    struct Collector(mpsc::Sender<()>);
    #[tonic::async_trait]
    impl LogsService for Collector {
        async fn export(
            &self,
            request: tonic::Request<ExportLogsServiceRequest>,
        ) -> Result<tonic::Response<ExportLogsServiceResponse>, tonic::Status> {
            assert_eq!(
                request
                    .metadata()
                    .get("authorization")
                    .and_then(|value| value.to_str().ok()),
                Some("Bearer OTLP_HEADER_CANARY")
            );
            self.0.send(()).await.unwrap();
            Ok(tonic::Response::new(ExportLogsServiceResponse {
                partial_success: None,
            }))
        }
    }

    struct PrivateRoot(std::path::PathBuf);
    impl Drop for PrivateRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls");
    let root = PrivateRoot(std::env::temp_dir().join(format!(
        "smesh-otlp-mtls-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    )));
    std::fs::create_dir(&root.0).unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    let private_copy = |name: &str| {
        let destination = root.0.join(name);
        std::fs::copy(fixtures.join(name), &destination).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o600)).unwrap();
        destination
    };
    let ca = private_copy("server-ca.pem");
    let client_cert = private_copy("client.pem");
    let client_key = private_copy("client.key");
    let headers = root.0.join("headers");
    std::fs::write(&headers, "authorization: Bearer OTLP_HEADER_CANARY\n").unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(&headers, std::fs::Permissions::from_mode(0o600)).unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, mut receiver) = mpsc::channel(4);
    let stop = CancellationToken::new();
    let server_stop = stop.clone();
    let identity = tonic::transport::Identity::from_pem(
        std::fs::read(fixtures.join("server.pem")).unwrap(),
        std::fs::read(fixtures.join("server.key")).unwrap(),
    );
    let client_ca = tonic::transport::Certificate::from_pem(
        std::fs::read(fixtures.join("client-ca.pem")).unwrap(),
    );
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .tls_config(
                tonic::transport::ServerTlsConfig::new()
                    .identity(identity)
                    .client_ca_root(client_ca),
            )
            .unwrap()
            .add_service(LogsServiceServer::new(Collector(sender)))
            .serve_with_incoming_shutdown(
                TcpListenerStream::new(listener),
                server_stop.cancelled_owned(),
            )
            .await
            .unwrap();
    });

    let base = BTreeMap::from([
        ("SMESH_A2A_OTLP_MODE".to_owned(), "grpc".to_owned()),
        (
            "SMESH_A2A_OTLP_ENDPOINT".to_owned(),
            format!("https://localhost:{}/", address.port()),
        ),
        (
            "SMESH_A2A_OTLP_CA_PATH".to_owned(),
            ca.display().to_string(),
        ),
        (
            "SMESH_A2A_OTLP_HEADERS_PATH".to_owned(),
            headers.display().to_string(),
        ),
        ("SMESH_A2A_OTLP_TRACE_QUEUE".to_owned(), "64".to_owned()),
        ("SMESH_A2A_OTLP_LOG_QUEUE".to_owned(), "64".to_owned()),
        ("SMESH_A2A_OTLP_METRIC_QUEUE".to_owned(), "64".to_owned()),
        (
            "SMESH_A2A_OTLP_EXPORT_TIMEOUT_MILLIS".to_owned(),
            "1000".to_owned(),
        ),
    ]);
    let mut success = base.clone();
    success.insert(
        "SMESH_A2A_OTLP_CLIENT_CERT_PATH".to_owned(),
        client_cert.display().to_string(),
    );
    success.insert(
        "SMESH_A2A_OTLP_CLIENT_KEY_PATH".to_owned(),
        client_key.display().to_string(),
    );
    let owner = OtlpOwner::start(OtlpConfig::parse(success).unwrap())
        .unwrap()
        .unwrap();
    assert!(
        owner.try_emit(
            TelemetryRecord::log(EventName::TaskTerminal, terminal_attributes()).unwrap()
        )
    );
    assert!(owner.shutdown(Duration::from_secs(3)));
    tokio::time::timeout(Duration::from_secs(3), receiver.recv())
        .await
        .unwrap()
        .unwrap();

    let owner = OtlpOwner::start(OtlpConfig::parse(base).unwrap())
        .unwrap()
        .unwrap();
    let snapshot = owner.health_snapshot();
    assert!(
        owner.try_emit(
            TelemetryRecord::log(EventName::TaskTerminal, terminal_attributes()).unwrap()
        )
    );
    assert!(owner.shutdown(Duration::from_secs(3)));
    assert_eq!(snapshot.drop_count(DropReason::Transport), 1);
    assert!(receiver.try_recv().is_err());

    stop.cancel();
    tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_collector_decodes_all_three_signal_services() {
    use opentelemetry_proto::tonic::collector::{
        logs::v1::{
            ExportLogsServiceResponse,
            logs_service_server::{LogsService, LogsServiceServer},
        },
        metrics::v1::{
            ExportMetricsServiceResponse,
            metrics_service_server::{MetricsService, MetricsServiceServer},
        },
        trace::v1::{
            ExportTraceServiceResponse,
            trace_service_server::{TraceService, TraceServiceServer},
        },
    };
    use tokio_stream::wrappers::TcpListenerStream;
    #[derive(Clone)]
    struct Collector(mpsc::Sender<&'static str>);
    #[tonic::async_trait]
    impl TraceService for Collector {
        async fn export(
            &self,
            request: tonic::Request<ExportTraceServiceRequest>,
        ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
            assert_eq!(
                request.get_ref().resource_spans[0].scope_spans[0].spans[0].trace_id,
                vec![1; 16]
            );
            self.0.send("traces").await.unwrap();
            Ok(tonic::Response::new(ExportTraceServiceResponse {
                partial_success: None,
            }))
        }
    }
    #[tonic::async_trait]
    impl MetricsService for Collector {
        async fn export(
            &self,
            request: tonic::Request<ExportMetricsServiceRequest>,
        ) -> Result<tonic::Response<ExportMetricsServiceResponse>, tonic::Status> {
            assert_eq!(
                request.get_ref().resource_metrics[0].scope_metrics[0].metrics[0].name,
                "smesh.a2a.task.admitted"
            );
            self.0.send("metrics").await.unwrap();
            Ok(tonic::Response::new(ExportMetricsServiceResponse {
                partial_success: None,
            }))
        }
    }
    #[tonic::async_trait]
    impl LogsService for Collector {
        async fn export(
            &self,
            request: tonic::Request<ExportLogsServiceRequest>,
        ) -> Result<tonic::Response<ExportLogsServiceResponse>, tonic::Status> {
            assert_eq!(
                request.get_ref().resource_logs[0].scope_logs[0].log_records[0].event_name,
                "smesh.task.terminal"
            );
            self.0.send("logs").await.unwrap();
            Ok(tonic::Response::new(ExportLogsServiceResponse {
                partial_success: None,
            }))
        }
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, mut receiver) = mpsc::channel(8);
    let collector = Collector(sender);
    let stop = CancellationToken::new();
    let server_stop = stop.clone();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(TraceServiceServer::new(collector.clone()))
            .add_service(MetricsServiceServer::new(collector.clone()))
            .add_service(LogsServiceServer::new(collector))
            .serve_with_incoming_shutdown(
                TcpListenerStream::new(listener),
                server_stop.cancelled_owned(),
            )
            .await
            .unwrap();
    });
    let owner = OtlpOwner::start(
        OtlpConfig::parse(BTreeMap::from([
            ("SMESH_A2A_OTLP_MODE".into(), "grpc".into()),
            (
                "SMESH_A2A_OTLP_ENDPOINT".into(),
                format!("http://{address}/"),
            ),
            ("SMESH_TEST_OTLP_INSECURE_LOOPBACK".into(), "1".into()),
            ("SMESH_A2A_OTLP_TRACE_QUEUE".into(), "64".into()),
            ("SMESH_A2A_OTLP_LOG_QUEUE".into(), "64".into()),
            ("SMESH_A2A_OTLP_METRIC_QUEUE".into(), "64".into()),
        ]))
        .unwrap(),
    )
    .unwrap()
    .unwrap();
    assert!(
        owner.try_emit(TelemetryRecord::span(
            ClosedSpan::new(
                SpanName::DurableAdmission,
                [1; 16],
                [2; 8],
                None,
                vec![],
                1,
                2,
                admission_span_attributes(),
            )
            .unwrap()
        ))
    );
    assert!(owner.try_emit(TelemetryRecord::metric(
        MetricPoint::new(MetricName::TaskAdmitted, 1, vec![]).unwrap()
    )));
    assert!(
        owner.try_emit(
            TelemetryRecord::log(EventName::TaskTerminal, terminal_attributes()).unwrap()
        )
    );
    assert!(owner.shutdown(Duration::from_secs(3)));
    let mut seen = Vec::new();
    for _ in 0..3 {
        seen.push(
            tokio::time::timeout(Duration::from_secs(3), receiver.recv())
                .await
                .unwrap()
                .unwrap(),
        );
    }
    seen.sort_unstable();
    assert_eq!(seen, ["logs", "metrics", "traces"]);
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap();
}
