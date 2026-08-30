use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use smesh_a2a::telemetry::{
    Attribute, AttributeKey, CircuitBreaker, DropReason, EventName, OtlpConfig, OtlpMode,
    OtlpOwner, TelemetryRecord,
};

fn terminal_record() -> TelemetryRecord {
    TelemetryRecord::log(
        EventName::TaskTerminal,
        vec![
            Attribute::new(AttributeKey::TaskId, "task-1").unwrap(),
            Attribute::new(AttributeKey::ContextId, "context-1").unwrap(),
            Attribute::new(AttributeKey::MessageId, "message-1").unwrap(),
            Attribute::new(AttributeKey::Outcome, "ok").unwrap(),
            Attribute::new(AttributeKey::Reason, "committed").unwrap(),
            Attribute::new(AttributeKey::Operation, "terminal_commit").unwrap(),
        ],
    )
    .unwrap()
}

#[test]
fn try_emit_is_nonblocking_when_the_queue_is_full() {
    let owner = OtlpOwner::blocked_for_test(1);
    let record = terminal_record();
    assert!(owner.try_emit(record.clone()));
    let started = Instant::now();
    assert!(!owner.try_emit(record));
    assert!(started.elapsed() < Duration::from_millis(20));
    assert_eq!(owner.drop_count(DropReason::QueueFull), 1);
    assert!(!owner.shutdown(Duration::ZERO));
}

#[test]
fn shutdown_closes_every_preexisting_handle_atomically() {
    let config = OtlpConfig::parse(BTreeMap::from([
        ("SMESH_A2A_OTLP_MODE".into(), "http-protobuf".into()),
        (
            "SMESH_A2A_OTLP_ENDPOINT".into(),
            "https://127.0.0.1:9/".into(),
        ),
        ("SMESH_A2A_OTLP_TRACE_QUEUE".into(), "64".into()),
        ("SMESH_A2A_OTLP_LOG_QUEUE".into(), "64".into()),
        ("SMESH_A2A_OTLP_METRIC_QUEUE".into(), "64".into()),
        ("SMESH_A2A_OTLP_EXPORT_TIMEOUT_MILLIS".into(), "100".into()),
        (
            "SMESH_A2A_OTLP_METRIC_INTERVAL_MILLIS".into(),
            "1000".into(),
        ),
    ]))
    .unwrap();
    let owner = OtlpOwner::start(config).unwrap().unwrap();
    let first = owner.handle();
    let second = first.clone();
    let record = terminal_record;
    assert!(first.try_emit(record()));
    assert!(owner.shutdown(Duration::from_secs(1)));
    assert!(!first.try_emit(record()));
    assert!(!second.try_emit(record()));
}

#[test]
fn shutdown_linearizes_after_an_emitter_that_passed_the_gate_precheck() {
    use std::sync::{Arc, Barrier, mpsc};

    let config = OtlpConfig::parse(BTreeMap::from([
        ("SMESH_A2A_OTLP_MODE".into(), "http-protobuf".into()),
        (
            "SMESH_A2A_OTLP_ENDPOINT".into(),
            "https://127.0.0.1:9/".into(),
        ),
        ("SMESH_A2A_OTLP_TRACE_QUEUE".into(), "64".into()),
        ("SMESH_A2A_OTLP_LOG_QUEUE".into(), "64".into()),
        ("SMESH_A2A_OTLP_METRIC_QUEUE".into(), "64".into()),
        ("SMESH_A2A_OTLP_EXPORT_TIMEOUT_MILLIS".into(), "100".into()),
        (
            "SMESH_A2A_OTLP_METRIC_INTERVAL_MILLIS".into(),
            "1000".into(),
        ),
    ]))
    .unwrap();
    let owner = OtlpOwner::start(config).unwrap().unwrap();
    let health = owner.health_snapshot();
    let handle = owner.handle();
    let emitter = handle.clone();
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let emit_entered = Arc::clone(&entered);
    let emit_release = Arc::clone(&release);
    let emission = std::thread::spawn(move || {
        emitter.try_emit_with_overlap_barrier_for_test(
            terminal_record(),
            &emit_entered,
            &emit_release,
        )
    });
    entered.wait();
    let (shutdown_tx, shutdown_rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = owner.shutdown(Duration::from_secs(1));
        let _ = shutdown_tx.send(result);
    });
    assert!(shutdown_rx.recv_timeout(Duration::from_millis(20)).is_err());
    release.wait();
    assert!(emission.join().unwrap());
    assert!(shutdown_rx.recv_timeout(Duration::from_secs(2)).unwrap());
    assert_eq!(health.worker_alive_count(), 0);
    assert!(health.drop_count(DropReason::Transport) > 0);
    assert!(!handle.try_emit(terminal_record()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hung_collector_obeys_the_absolute_shutdown_deadline_and_leaves_no_worker() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let server_requests = Arc::clone(&requests);
    let server = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            server_requests.fetch_add(1, Ordering::SeqCst);
            held.push(socket);
        }
    });
    let config = OtlpConfig::parse(BTreeMap::from([
        ("SMESH_A2A_OTLP_MODE".into(), "http-protobuf".into()),
        (
            "SMESH_A2A_OTLP_ENDPOINT".into(),
            format!("https://{address}/"),
        ),
        ("SMESH_A2A_OTLP_TRACE_QUEUE".into(), "64".into()),
        ("SMESH_A2A_OTLP_LOG_QUEUE".into(), "64".into()),
        ("SMESH_A2A_OTLP_METRIC_QUEUE".into(), "64".into()),
        (
            "SMESH_A2A_OTLP_EXPORT_TIMEOUT_MILLIS".into(),
            "10000".into(),
        ),
        (
            "SMESH_A2A_OTLP_METRIC_INTERVAL_MILLIS".into(),
            "300000".into(),
        ),
    ]))
    .unwrap();
    let owner = OtlpOwner::start(config).unwrap().unwrap();
    let health = owner.health_snapshot();
    let handle = owner.handle();
    assert!(handle.try_emit(terminal_record()));
    let started = Instant::now();
    assert!(!owner.shutdown(Duration::from_millis(100)));
    assert!(started.elapsed() < Duration::from_millis(300));
    assert_eq!(health.worker_alive_count(), 0);
    assert_eq!(health.shutdown_timed_out_count(), 1);
    assert!(!handle.try_emit(terminal_record()));
    let after = requests.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        requests.load(Ordering::SeqCst),
        after,
        "network activity continued after shutdown returned"
    );
    server.abort();
    let _ = server.await;
}

#[test]
fn live_metric_enqueue_rejects_new_series_before_the_queue() {
    use smesh_a2a::telemetry::{Attribute, AttributeKey, MetricName, MetricPoint};

    let owner = OtlpOwner::blocked_metrics_for_test(8, 1, 8);
    let metric = |operation: &str| {
        TelemetryRecord::metric(
            MetricPoint::new(
                MetricName::A2aRequest,
                1,
                vec![Attribute::new(AttributeKey::Operation, operation).unwrap()],
            )
            .unwrap(),
        )
    };
    assert!(owner.try_emit(metric("get")));
    assert!(!owner.try_emit(metric("list")));
    assert_eq!(owner.drop_count(DropReason::SeriesLimit), 1);
    assert_eq!(owner.drop_count(DropReason::QueueFull), 0);
    assert!(!owner.shutdown(Duration::ZERO));
}

#[test]
fn exporter_circuit_opens_after_exactly_three_failures_and_resets_on_success() {
    let mut circuit = CircuitBreaker::new();
    assert!(circuit.allow(0));
    circuit.failure(0);
    circuit.failure(0);
    assert!(circuit.allow(0));
    circuit.failure(0);
    assert!(!circuit.allow(999));
    assert!(circuit.allow(1_000));

    circuit.success();
    circuit.failure(2_000);
    circuit.failure(2_000);
    assert!(circuit.allow(2_000));
    circuit.failure(2_000);
    assert!(!circuit.allow(2_999));
    assert!(circuit.allow(3_000));
}

#[test]
fn disabled_is_default_and_rejects_ignored_export_configuration() {
    assert_eq!(
        OtlpConfig::parse(BTreeMap::<String, String>::new())
            .unwrap()
            .mode,
        OtlpMode::Disabled
    );
    let env = BTreeMap::from([(
        "SMESH_A2A_OTLP_ENDPOINT".to_owned(),
        "https://collector.example".to_owned(),
    )]);
    assert!(OtlpConfig::parse(env).is_err());
}

#[test]
fn enabled_endpoint_is_strict_and_bounded() {
    for endpoint in [
        "http://collector.example",
        "https://user:secret@collector.example",
        "https://collector.example/v1/traces",
        "https://collector.example/?secret=yes",
        "https://collector.example/#fragment",
        "ftp://collector.example",
    ] {
        let env = BTreeMap::from([
            ("SMESH_A2A_OTLP_MODE".to_owned(), "http-protobuf".to_owned()),
            ("SMESH_A2A_OTLP_ENDPOINT".to_owned(), endpoint.to_owned()),
        ]);
        assert!(OtlpConfig::parse(env).is_err(), "accepted {endpoint}");
    }
    let env = BTreeMap::from([
        ("SMESH_A2A_OTLP_MODE".to_owned(), "grpc".to_owned()),
        (
            "SMESH_A2A_OTLP_ENDPOINT".to_owned(),
            "https://collector.example:4317/".to_owned(),
        ),
        ("SMESH_A2A_OTLP_TRACE_QUEUE".to_owned(), "64".to_owned()),
        ("SMESH_A2A_OTLP_LOG_QUEUE".to_owned(), "64".to_owned()),
    ]);
    let config = OtlpConfig::parse(env).unwrap();
    assert_eq!(config.mode, OtlpMode::Grpc);
    assert_eq!(config.trace_queue, 64);
}

#[test]
fn insecure_debug_collector_requires_literal_loopback_and_explicit_gate() {
    let env = BTreeMap::from([
        ("SMESH_A2A_OTLP_MODE".to_owned(), "http-protobuf".to_owned()),
        (
            "SMESH_A2A_OTLP_ENDPOINT".to_owned(),
            "http://127.0.0.1:4318/".to_owned(),
        ),
        (
            "SMESH_TEST_OTLP_INSECURE_LOOPBACK".to_owned(),
            "1".to_owned(),
        ),
    ]);
    if cfg!(debug_assertions) {
        assert!(OtlpConfig::parse(env).is_ok());
    } else {
        assert!(OtlpConfig::parse(env).is_err());
    }
}

#[cfg(unix)]
#[test]
fn tls_and_secret_header_material_is_snapshotted_privately_and_redacted() {
    use std::os::unix::fs::PermissionsExt as _;
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls");
    let root = std::env::temp_dir().join(format!("smesh-otlp-secret-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let copy = |name: &str, source: &str| {
        let path = root.join(name);
        std::fs::copy(fixture.join(source), &path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    };
    let ca = copy("ca.pem", "server-ca.pem");
    let cert = copy("client.pem", "client.pem");
    let key = copy("client.key", "client.key");
    let headers = root.join("headers");
    std::fs::write(
        &headers,
        "authorization: Bearer OTLP_HEADER_CANARY\nx-api-key: second\n",
    )
    .unwrap();
    std::fs::set_permissions(&headers, std::fs::Permissions::from_mode(0o600)).unwrap();
    let config = OtlpConfig::parse(BTreeMap::from([
        ("SMESH_A2A_OTLP_MODE".into(), "grpc".into()),
        (
            "SMESH_A2A_OTLP_ENDPOINT".into(),
            "https://collector.example:4317/".into(),
        ),
        ("SMESH_A2A_OTLP_CA_PATH".into(), ca.display().to_string()),
        (
            "SMESH_A2A_OTLP_CLIENT_CERT_PATH".into(),
            cert.display().to_string(),
        ),
        (
            "SMESH_A2A_OTLP_CLIENT_KEY_PATH".into(),
            key.display().to_string(),
        ),
        (
            "SMESH_A2A_OTLP_HEADERS_PATH".into(),
            headers.display().to_string(),
        ),
    ]))
    .unwrap();
    let debug = format!("{config:?}");
    assert!(!debug.contains("OTLP_HEADER_CANARY"));
    assert!(!debug.contains("second"));
    std::fs::remove_dir_all(root).unwrap();
}
