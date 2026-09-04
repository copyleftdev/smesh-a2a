use std::io::Cursor;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use a2a_server::{CallContext, CallInterceptor, ServiceParams};
use serde_json::json;
use smesh_a2a::{
    A2aCaptureAdapter, ArtifactCaptureAdapter, CanonicalCapture, CaptureError, CaptureFailure,
    CaptureGapReason, CaptureKind, CaptureParent, CaptureStream, HumanConsoleCaptureAdapter,
    ProducerIdentity, ProducerKind, SmeshJournalCaptureAdapter, ToolMcpCaptureAdapter,
};
use smesh_runtime::{JournalEvent, RuntimeEvent};
use wait_timeout::ChildExt as _;

const MISSING_EVENT_ID: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

struct FailingInput;

impl std::io::Read for FailingInput {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("sabotaged read"))
    }
}

impl std::io::BufRead for FailingInput {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        Err(std::io::Error::other("sabotaged read"))
    }

    fn consume(&mut self, _amount: usize) {}
}

struct FailingOutput;

impl std::io::Write for FailingOutput {
    fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("sabotaged write"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other("sabotaged flush"))
    }
}

#[test]
fn adapter_rejects_deserialized_invalid_identity_without_capture_effect() {
    let capture = Arc::new(CanonicalCapture::new("run-invalid-identity", 4).unwrap());
    let invalid_id: ProducerIdentity = serde_json::from_value(json!({
        "kind": "a2a",
        "id": "invalid id",
        "instanceId": "process"
    }))
    .unwrap();
    let oversized_instance: ProducerIdentity = serde_json::from_value(json!({
        "kind": "a2a",
        "id": "gateway",
        "instanceId": "x".repeat(257)
    }))
    .unwrap();

    assert!(matches!(
        A2aCaptureAdapter::new(Arc::clone(&capture), invalid_id),
        Err(CaptureError::InvalidIdentifier)
    ));
    assert!(matches!(
        A2aCaptureAdapter::new(Arc::clone(&capture), oversized_instance),
        Err(CaptureError::InvalidIdentifier)
    ));
    for (kind, id, instance_id) in [
        (
            ProducerKind::Smesh,
            "runtime".to_owned(),
            "bad instance".to_owned(),
        ),
        (ProducerKind::Tool, "x".repeat(257), "process".to_owned()),
        (
            ProducerKind::Artifact,
            "bad artifact".to_owned(),
            "process".to_owned(),
        ),
        (ProducerKind::Human, "reviewer".to_owned(), "x".repeat(257)),
    ] {
        let identity = ProducerIdentity {
            kind,
            id,
            instance_id,
        };
        let rejected = match kind {
            ProducerKind::Smesh => {
                SmeshJournalCaptureAdapter::new(Arc::clone(&capture), identity).err()
            }
            ProducerKind::Tool => ToolMcpCaptureAdapter::new(Arc::clone(&capture), identity).err(),
            ProducerKind::Artifact => {
                ArtifactCaptureAdapter::new(Arc::clone(&capture), identity).err()
            }
            ProducerKind::Human => {
                HumanConsoleCaptureAdapter::new(Arc::clone(&capture), identity).err()
            }
            ProducerKind::A2a => unreachable!(),
        };
        assert_eq!(rejected, Some(CaptureError::InvalidIdentifier));
    }
    assert!(capture.snapshot().unwrap().events.is_empty());
    assert!(capture.snapshot().unwrap().capture_valid);
}

#[test]
fn a2a_send_and_receive_share_interaction_with_producer_sequences() {
    let capture = Arc::new(CanonicalCapture::new("run-23", 16).unwrap());
    let sender = A2aCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::A2a, "director", "director-process").unwrap(),
    )
    .unwrap();
    let receiver = A2aCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::A2a, "atlas-gateway", "atlas-process").unwrap(),
    )
    .unwrap();

    let sent = sender
        .send(
            "interaction-1",
            "atlas-gateway",
            Some("task-1"),
            Some("context-1"),
            b"private request body",
            CaptureParent::Root,
        )
        .unwrap();
    receiver
        .receive(
            "interaction-1",
            "director",
            Some("task-1"),
            Some("context-1"),
            b"private request body",
            CaptureParent::Event(sent.event_id().to_owned()),
        )
        .unwrap();

    let stream = capture.snapshot().unwrap();
    assert!(stream.capture_valid);
    assert_eq!(stream.events.len(), 2);
    assert_eq!(stream.events[0].sequence, 0);
    assert_eq!(stream.events[1].sequence, 1);
    assert_eq!(stream.events[0].producer.sequence, 0);
    assert_eq!(stream.events[1].producer.sequence, 0);
    assert_eq!(stream.events[0].kind, CaptureKind::A2aSend);
    assert_eq!(stream.events[1].kind, CaptureKind::A2aReceive);
    assert_eq!(
        stream.events[0].interaction_id,
        stream.events[1].interaction_id
    );
    assert_eq!(
        stream.events[1].parent,
        CaptureParent::Event(stream.events[0].event_id.clone())
    );
    assert_eq!(stream.events[0].content, stream.events[1].content);

    let encoded = serde_json::to_vec(&stream).unwrap();
    assert!(
        !encoded
            .windows(b"private request body".len())
            .any(|window| window == b"private request body")
    );
}

#[tokio::test]
async fn a2a_server_interceptor_captures_before_and_after_with_one_interaction() {
    let capture = Arc::new(CanonicalCapture::new("run-23", 8).unwrap());
    let interceptor = A2aCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::A2a, "atlas-gateway", "atlas-process").unwrap(),
    )
    .unwrap();
    let mut context = CallContext::new("message/send", ServiceParams::new());
    let request = json!({"message": {"messageId": "message-1", "parts": ["private"]}});

    interceptor.before(&mut context, &request).await.unwrap();
    interceptor
        .after(&context, &Ok(json!({"task": {"id": "task-1"}})))
        .await
        .unwrap();

    let stream = capture.snapshot().unwrap();
    assert_eq!(stream.events.len(), 2);
    assert_eq!(stream.events[0].kind, CaptureKind::A2aReceive);
    assert_eq!(stream.events[1].kind, CaptureKind::A2aSend);
    assert_eq!(
        stream.events[0].interaction_id,
        stream.events[1].interaction_id
    );
    assert_eq!(
        stream.events[1].parent,
        CaptureParent::Event(stream.events[0].event_id.clone())
    );
}

#[tokio::test]
async fn a2a_wrapper_preserves_terminal_capacity_while_nested_observations_are_captured() {
    let root = CaptureTempRoot(std::env::temp_dir().join(format!(
        "smesh-a2a-nested-capture-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )));
    std::fs::create_dir(&root.0).unwrap();
    let path = root.0.join("capture.jsonl");
    let capture = Arc::new(CanonicalCapture::create_spool("run-a2a-nested", 7, &path).unwrap());
    let interceptor = A2aCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::A2a, "gateway", "gateway-process").unwrap(),
    )
    .unwrap();
    let independent_a2a = A2aCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::A2a, "worker", "worker-process").unwrap(),
    )
    .unwrap();
    let smesh = SmeshJournalCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::Smesh, "runtime", "runtime-process").unwrap(),
    )
    .unwrap();
    let artifact = ArtifactCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::Artifact, "store", "store-process").unwrap(),
    )
    .unwrap();
    let tool = ToolMcpCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::Tool, "tool", "tool-process").unwrap(),
    )
    .unwrap();
    let mut context = CallContext::new("message/send", ServiceParams::new());

    interceptor
        .capture_unary(&mut context, &json!({"request": true}), async {
            tool.execute(
                "nested-tool",
                "lookup",
                None,
                None,
                b"input",
                CaptureParent::Root,
                || Ok::<_, std::convert::Infallible>(b"output".to_vec()),
            )
            .unwrap();
            smesh
                .record(
                    "nested-smesh",
                    None,
                    None,
                    RuntimeEvent::SignalEmitted {
                        hash: "signal".to_owned(),
                    },
                    CaptureParent::Root,
                )
                .unwrap();
            artifact
                .produced(
                    "nested-artifact",
                    "artifact",
                    None,
                    None,
                    b"artifact",
                    CaptureParent::Root,
                )
                .unwrap();
            independent_a2a
                .send(
                    "independent-interaction",
                    "peer",
                    None,
                    None,
                    b"message",
                    CaptureParent::Root,
                )
                .unwrap();
            Ok(json!({"result": true}))
        })
        .await
        .unwrap();

    let expected = capture.snapshot().unwrap();
    assert!(expected.capture_valid);
    assert_eq!(expected.events.len(), 7);
    assert_eq!(expected.events.last().unwrap().kind, CaptureKind::A2aSend);
    capture.complete().unwrap();
    assert_eq!(
        CanonicalCapture::replay_jsonl(&std::fs::read(path).unwrap()).unwrap(),
        expected
    );
}

#[tokio::test]
async fn a2a_server_interceptor_overwrites_hostile_capture_metadata() {
    let capture = Arc::new(CanonicalCapture::new("run-a2a-hostile", 2).unwrap());
    let interceptor = A2aCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::A2a, "gateway", "process").unwrap(),
    )
    .unwrap();
    let mut params = ServiceParams::new();
    params.insert(
        "x-smesh-capture-interaction-id".to_owned(),
        vec!["attacker-interaction".to_owned()],
    );
    params.insert(
        "smesh-internal-capture-parent-event".to_owned(),
        vec!["attacker-parent".to_owned()],
    );
    let mut context = CallContext::new("message/send", params);

    interceptor
        .before(&mut context, &json!({"request": true}))
        .await
        .unwrap();
    interceptor
        .after(&context, &Ok(json!({"result": true})))
        .await
        .unwrap();

    let stream = capture.snapshot().unwrap();
    assert_ne!(stream.events[0].interaction_id, "attacker-interaction");
    assert_eq!(
        stream.events[1].parent,
        CaptureParent::Event(stream.events[0].event_id.clone())
    );
}

#[tokio::test]
async fn a2a_server_interceptor_bounds_request_serialization_before_capture() {
    let capture = Arc::new(CanonicalCapture::new("run-a2a-request-bound", 2).unwrap());
    let interceptor = A2aCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::A2a, "gateway", "process").unwrap(),
    )
    .unwrap();
    let mut context = CallContext::new("message/send", ServiceParams::new());
    let request = json!({"request": "x".repeat(64 * 1024)});

    assert!(interceptor.before(&mut context, &request).await.is_err());
    let stream = capture.snapshot().unwrap();
    assert!(stream.events.is_empty());
    assert!(stream.capture_valid);
}

#[tokio::test]
async fn a2a_server_interceptor_bounds_result_and_invalidates_open_pair() {
    let capture = Arc::new(CanonicalCapture::new("run-a2a-result-bound", 2).unwrap());
    let interceptor = A2aCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::A2a, "gateway", "process").unwrap(),
    )
    .unwrap();
    let mut context = CallContext::new("message/send", ServiceParams::new());
    interceptor
        .before(&mut context, &json!({"request": true}))
        .await
        .unwrap();

    assert!(
        interceptor
            .after(&context, &Ok(json!({"result": "x".repeat(64 * 1024)})))
            .await
            .is_err()
    );
    let stream = capture.snapshot().unwrap();
    assert_eq!(stream.events.len(), 1);
    assert!(!stream.capture_valid);
    assert_eq!(stream.failure, Some(CaptureFailure::UnclosedInteraction));
}

#[tokio::test]
async fn a2a_server_interceptor_reserves_result_before_dispatch() {
    let capture = Arc::new(CanonicalCapture::new("run-a2a-capacity", 1).unwrap());
    let interceptor = A2aCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::A2a, "gateway", "process").unwrap(),
    )
    .unwrap();
    let mut context = CallContext::new("message/send", ServiceParams::new());

    assert!(
        interceptor
            .before(&mut context, &json!({"request": true}))
            .await
            .is_err()
    );
    assert!(capture.snapshot().unwrap().events.is_empty());
}

#[tokio::test]
async fn a2a_unary_wrapper_invalidates_capture_when_dispatch_is_cancelled() {
    let capture = Arc::new(CanonicalCapture::new("run-a2a-cancel", 4).unwrap());
    let interceptor = A2aCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::A2a, "gateway", "process").unwrap(),
    )
    .unwrap();
    let mut context = CallContext::new("message/send", ServiceParams::new());

    assert!(
        tokio::time::timeout(
            Duration::from_millis(10),
            interceptor.capture_unary(
                &mut context,
                &json!({"request": true}),
                std::future::pending(),
            ),
        )
        .await
        .is_err()
    );
    let stream = capture.snapshot().unwrap();
    assert_eq!(stream.events.len(), 1);
    assert!(!stream.capture_valid);
    assert_eq!(stream.failure, Some(CaptureFailure::UnclosedInteraction));

    let invocations = AtomicUsize::new(0);
    let mut later_context = CallContext::new("message/send", ServiceParams::new());
    assert!(
        interceptor
            .capture_unary(&mut later_context, &json!({"request": "later"}), async {
                invocations.fetch_add(1, Ordering::SeqCst);
                Ok(json!({"result": true}))
            },)
            .await
            .is_err()
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a2a_unary_wrapper_invalidates_capture_when_dispatch_panics() {
    let capture = Arc::new(CanonicalCapture::new("run-a2a-panic", 4).unwrap());
    let interceptor = Arc::new(
        A2aCaptureAdapter::new(
            Arc::clone(&capture),
            ProducerIdentity::new(ProducerKind::A2a, "gateway", "process").unwrap(),
        )
        .unwrap(),
    );
    let task = tokio::spawn(async move {
        let mut context = CallContext::new("message/send", ServiceParams::new());
        interceptor
            .capture_unary(&mut context, &json!({"request": true}), async {
                panic!("dispatch panic");
                #[allow(unreachable_code)]
                Ok(json!({"result": true}))
            })
            .await
    });

    assert!(task.await.unwrap_err().is_panic());
    let stream = capture.snapshot().unwrap();
    assert_eq!(stream.events.len(), 1);
    assert!(!stream.capture_valid);
    assert_eq!(stream.failure, Some(CaptureFailure::UnclosedInteraction));
}

#[tokio::test]
async fn raw_a2a_hook_blocks_finalization_and_unreserved_capture_while_open() {
    let root = CaptureTempRoot(std::env::temp_dir().join(format!(
        "smesh-a2a-raw-owner-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )));
    std::fs::create_dir(&root.0).unwrap();
    let path = root.0.join("capture.jsonl");
    let capture = Arc::new(CanonicalCapture::create_spool("run-a2a-raw-owner", 4, &path).unwrap());
    let interceptor = A2aCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::A2a, "gateway", "process").unwrap(),
    )
    .unwrap();
    let mut context = CallContext::new("message/send", ServiceParams::new());
    interceptor
        .before(&mut context, &json!({"request": true}))
        .await
        .unwrap();

    assert_eq!(capture.complete(), Err(CaptureError::CaptureInvalid));
    assert_eq!(
        interceptor.send("later", "peer", None, None, b"later", CaptureParent::Root),
        Err(CaptureError::CaptureInvalid)
    );
    assert_eq!(capture.snapshot().unwrap().events.len(), 1);
}

#[tokio::test]
async fn ingest_rejects_imported_closer_while_wrapper_reservation_is_open() {
    let root = CaptureTempRoot(std::env::temp_dir().join(format!(
        "smesh-a2a-reserved-ingest-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )));
    std::fs::create_dir(&root.0).unwrap();
    let source_path = root.0.join("source.jsonl");
    let destination_path = root.0.join("destination.jsonl");
    let identity = ProducerIdentity::new(ProducerKind::A2a, "gateway", "gateway-process").unwrap();
    let source = Arc::new(CanonicalCapture::new("run-reserved-ingest", 4).unwrap());
    let source_adapter = A2aCaptureAdapter::new(Arc::clone(&source), identity.clone()).unwrap();
    let mut source_context = CallContext::new("message/send", ServiceParams::new());
    source_adapter
        .capture_unary(&mut source_context, &json!({"request": true}), async {
            Ok(json!({"imported": true}))
        })
        .await
        .unwrap();
    source.persist_new(&source_path).unwrap();
    let imported = std::fs::read(source_path).unwrap();

    let destination = Arc::new(
        CanonicalCapture::create_spool("run-reserved-ingest", 4, &destination_path).unwrap(),
    );
    let destination_adapter = A2aCaptureAdapter::new(Arc::clone(&destination), identity).unwrap();
    let ingest_observation = std::sync::Mutex::new(None);
    let mut destination_context = CallContext::new("message/send", ServiceParams::new());
    destination_adapter
        .capture_unary(&mut destination_context, &json!({"request": true}), async {
            let before = destination.snapshot().unwrap();
            let persisted_before = std::fs::read(&destination_path).unwrap();
            let result = destination.ingest_jsonl(&imported);
            let after = destination.snapshot().unwrap();
            let persisted_after = std::fs::read(&destination_path).unwrap();
            *ingest_observation.lock().unwrap() =
                Some((result, before, after, persisted_before, persisted_after));
            Ok(json!({"imported": true}))
        })
        .await
        .unwrap();

    let finalized = destination.snapshot().unwrap();
    let completion = destination.complete();
    let replay = CanonicalCapture::replay_jsonl(&std::fs::read(&destination_path).unwrap());
    let (ingest, before, after, persisted_before, persisted_after) =
        ingest_observation.into_inner().unwrap().unwrap();
    assert_eq!(
        ingest,
        Err(CaptureError::CaptureInvalid),
        "reserved ingest escaped: completion={completion:?}, replay={replay:?}"
    );
    assert_eq!(after, before);
    assert_eq!(persisted_after, persisted_before);
    assert_eq!(finalized.events.len(), 2);
    assert!(finalized.capture_valid);
    assert_eq!(completion, Ok(()));
    assert_eq!(replay.unwrap(), finalized);
}

#[tokio::test]
async fn abandoned_a2a_hook_is_not_final_replayable() {
    let path = std::env::temp_dir().join(format!(
        "smesh-a2a-abandon-{}-{}.jsonl",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let capture = Arc::new(CanonicalCapture::create_spool("run-a2a-abandon", 2, &path).unwrap());
    let interceptor = A2aCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::A2a, "gateway", "process").unwrap(),
    )
    .unwrap();
    let mut context = CallContext::new("message/send", ServiceParams::new());
    interceptor
        .before(&mut context, &json!({"request": true}))
        .await
        .unwrap();

    assert!(!capture.snapshot().unwrap().capture_valid);
    drop(interceptor);
    assert_eq!(
        CanonicalCapture::replay_jsonl(&std::fs::read(&path).unwrap()),
        Err(CaptureError::CaptureInvalid)
    );

    drop(capture);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn smesh_journal_adapter_captures_real_runtime_event_with_causality() {
    let capture = Arc::new(CanonicalCapture::new("run-23", 16).unwrap());
    let a2a = A2aCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::A2a, "gateway", "gateway-process").unwrap(),
    )
    .unwrap();
    let smesh = SmeshJournalCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::Smesh, "atlas-runtime", "atlas-process").unwrap(),
    )
    .unwrap();
    let request = a2a
        .receive(
            "interaction-2",
            "director",
            Some("task-2"),
            Some("context-2"),
            b"request",
            CaptureParent::Root,
        )
        .unwrap();

    smesh
        .record(
            "interaction-2",
            Some("task-2"),
            Some("context-2"),
            RuntimeEvent::SignalEmitted {
                hash: "signal-hash-2".to_owned(),
            },
            CaptureParent::Event(request.event_id().to_owned()),
        )
        .unwrap();

    let stream = capture.snapshot().unwrap();
    let event = &stream.events[1];
    assert_eq!(event.kind, CaptureKind::SmeshSignalEmitted);
    assert_eq!(event.subject_id.as_deref(), Some("signal-hash-2"));
    assert_eq!(
        event.parent,
        CaptureParent::Event(stream.events[0].event_id.clone())
    );
    assert_eq!(event.producer.sequence, 0);
}

#[test]
fn repeated_smesh_same_kind_observations_are_valid_live_and_replayable() {
    let capture = Arc::new(CanonicalCapture::new("run-repeated-signal", 4).unwrap());
    let smesh = SmeshJournalCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::Smesh, "runtime", "process").unwrap(),
    )
    .unwrap();

    for hash in ["signal-a", "signal-b"] {
        smesh
            .record(
                "signal-batch",
                Some("task"),
                Some("context"),
                RuntimeEvent::SignalEmitted {
                    hash: hash.to_owned(),
                },
                CaptureParent::Root,
            )
            .unwrap();
    }

    let stream = capture.snapshot().unwrap();
    assert_eq!(stream.events.len(), 2);
    assert_eq!(
        CanonicalCapture::replay(&serde_json::to_vec(&stream).unwrap()).unwrap(),
        stream
    );
}

#[test]
fn smesh_journal_adapter_maps_required_runtime_lifecycle_without_sampling() {
    let capture = Arc::new(CanonicalCapture::new("run-23", 8).unwrap());
    let smesh = SmeshJournalCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::Smesh, "runtime", "runtime-process").unwrap(),
    )
    .unwrap();
    for event in [
        RuntimeEvent::SignalReinforced {
            hash: "signal-1".to_owned(),
            count: 2,
        },
        RuntimeEvent::SignalExpired {
            hash: "signal-1".to_owned(),
        },
        RuntimeEvent::TickCompleted {
            tick: 9,
            active_signals: 1,
            expired: 1,
        },
    ] {
        smesh
            .record(
                "runtime-flow-1",
                Some("task-runtime"),
                Some("context-runtime"),
                event,
                CaptureParent::Root,
            )
            .unwrap();
    }

    let stream = capture.snapshot().unwrap();
    assert_eq!(
        stream
            .events
            .iter()
            .map(|event| event.kind)
            .collect::<Vec<_>>(),
        vec![
            CaptureKind::SmeshSignalReinforced,
            CaptureKind::SmeshSignalExpired,
            CaptureKind::SmeshTickCompleted,
        ]
    );
    assert_eq!(
        stream
            .events
            .iter()
            .map(|event| event.producer.sequence)
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
}

#[test]
fn smesh_journal_adapter_bounds_hostile_metadata_before_capture() {
    let capture = Arc::new(CanonicalCapture::new("run-journal-bound", 1).unwrap());
    let smesh = SmeshJournalCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::Smesh, "runtime", "process").unwrap(),
    )
    .unwrap();
    let journal = JournalEvent {
        seq: 1,
        t_ms: 1,
        wall: "x".repeat(64 * 1024),
        node: "runtime".to_owned(),
        concern: None,
        kind: "signal_sent".to_owned(),
        data: json!({"hash": "signal", "payload": "x".repeat(64 * 1024)}),
    };

    assert_eq!(
        smesh.record_journal("interaction", None, None, &journal, CaptureParent::Root),
        Err(CaptureError::UnsupportedObservation)
    );
    assert!(capture.snapshot().unwrap().events.is_empty());
}

#[test]
fn smesh_journal_adapter_normalizes_pinned_journal_without_raw_payload() {
    let capture = Arc::new(CanonicalCapture::new("run-23", 8).unwrap());
    let smesh = SmeshJournalCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::Smesh, "runtime", "runtime-process").unwrap(),
    )
    .unwrap();
    let journal = JournalEvent {
        seq: 7,
        t_ms: 42,
        wall: "2026-09-03T00:00:00.000Z".to_owned(),
        node: "runtime".to_owned(),
        concern: Some("atlas".to_owned()),
        kind: "signal_sent".to_owned(),
        data: json!({
            "hash": "signal-journal-1",
            "to": "peer-1",
            "payload": "private journal payload"
        }),
    };

    smesh
        .record_journal(
            "runtime-flow-2",
            Some("task-runtime"),
            Some("context-runtime"),
            &journal,
            CaptureParent::Root,
        )
        .unwrap();

    let stream = capture.snapshot().unwrap();
    assert_eq!(stream.events[0].kind, CaptureKind::SmeshSignalSent);
    assert_eq!(
        stream.events[0].subject_id.as_deref(),
        Some("signal-journal-1")
    );
    let encoded = serde_json::to_vec(&stream).unwrap();
    assert!(
        !encoded
            .windows(b"private journal payload".len())
            .any(|window| window == b"private journal payload")
    );
}

#[test]
fn tool_mcp_wrapper_captures_call_and_result_around_real_execution() {
    let capture = Arc::new(CanonicalCapture::new("run-23", 16).unwrap());
    let tool = ToolMcpCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::Tool, "mcp-client", "tool-process").unwrap(),
    )
    .unwrap();
    let invocations = AtomicUsize::new(0);

    let output = tool
        .execute(
            "tool-call-1",
            "inventory.lookup",
            Some("task-3"),
            Some("context-3"),
            b"secret tool arguments",
            CaptureParent::Root,
            || {
                invocations.fetch_add(1, Ordering::SeqCst);
                Ok::<_, std::convert::Infallible>(b"secret tool result".to_vec())
            },
        )
        .unwrap();

    assert_eq!(output, b"secret tool result");
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    let stream = capture.snapshot().unwrap();
    assert_eq!(stream.events[0].kind, CaptureKind::ToolCall);
    assert_eq!(stream.events[1].kind, CaptureKind::ToolResult);
    assert_eq!(
        stream.events[1].parent,
        CaptureParent::Event(stream.events[0].event_id.clone())
    );
    assert_eq!(stream.events[0].interaction_id, "tool-call-1");
    assert_eq!(stream.events[1].interaction_id, "tool-call-1");
    let encoded = serde_json::to_vec(&stream).unwrap();
    assert!(
        !encoded
            .windows(b"secret tool arguments".len())
            .any(|window| window == b"secret tool arguments")
    );
    assert!(
        !encoded
            .windows(b"secret tool result".len())
            .any(|window| window == b"secret tool result")
    );
}

#[test]
fn tool_wrapper_reserves_completion_before_invoking_tool() {
    let capture = Arc::new(CanonicalCapture::new("run-tool-capacity", 1).unwrap());
    let tool = ToolMcpCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::Tool, "mcp-client", "tool-process").unwrap(),
    )
    .unwrap();
    let invocations = AtomicUsize::new(0);

    let result = tool.execute(
        "tool-call-capacity",
        "inventory.lookup",
        None,
        None,
        b"arguments",
        CaptureParent::Root,
        || {
            invocations.fetch_add(1, Ordering::SeqCst);
            Ok::<_, std::convert::Infallible>(Vec::new())
        },
    );

    assert!(matches!(
        result,
        Err(smesh_a2a::ToolCaptureError::Capture(
            CaptureError::CapacityExhausted
        ))
    ));
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let stream = capture.snapshot().unwrap();
    assert!(stream.events.is_empty());
    assert!(!stream.capture_valid);
    assert_eq!(stream.failure, Some(CaptureFailure::CapacityExhausted));
}

#[test]
fn tool_wrapper_captures_explicit_failure_completion() {
    let capture = Arc::new(CanonicalCapture::new("run-tool-failure", 2).unwrap());
    let tool = ToolMcpCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::Tool, "mcp-client", "tool-process").unwrap(),
    )
    .unwrap();

    assert!(matches!(
        tool.execute(
            "tool-call-failure",
            "inventory.lookup",
            None,
            None,
            b"arguments",
            CaptureParent::Root,
            || Err::<Vec<u8>, _>("offline"),
        ),
        Err(smesh_a2a::ToolCaptureError::Tool("offline"))
    ));
    let stream = capture.snapshot().unwrap();
    assert_eq!(stream.events.len(), 2);
    assert_eq!(stream.events[0].kind, CaptureKind::ToolCall);
    assert_eq!(stream.events[1].kind, CaptureKind::ToolFailed);
    assert_eq!(
        stream.events[1].parent,
        CaptureParent::Event(stream.events[0].event_id.clone())
    );
}

#[test]
fn replay_rejects_unclosed_paired_interaction() {
    let capture = Arc::new(CanonicalCapture::new("run-unclosed-replay", 2).unwrap());
    let tool = ToolMcpCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::Tool, "tool", "process").unwrap(),
    )
    .unwrap();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = tool.execute::<std::convert::Infallible, _>(
            "unclosed",
            "tool",
            None,
            None,
            b"request",
            CaptureParent::Root,
            || panic!("stop after durable opener"),
        );
    }));
    let mut stream = capture.snapshot().unwrap();
    stream.capture_valid = true;
    stream.failure = None;

    assert_eq!(
        CanonicalCapture::replay(&serde_json::to_vec(&stream).unwrap()),
        Err(CaptureError::MalformedReplay)
    );
}

#[test]
fn abandoned_required_reservation_invalidates_capture() {
    let capture = Arc::new(CanonicalCapture::new("run-tool-panic", 2).unwrap());
    let tool = ToolMcpCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::Tool, "mcp-client", "tool-process").unwrap(),
    )
    .unwrap();

    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = tool.execute::<std::convert::Infallible, _>(
            "tool-call-panic",
            "inventory.lookup",
            None,
            None,
            b"arguments",
            CaptureParent::Root,
            || panic!("sabotaged tool panic"),
        );
    }));
    assert!(panic.is_err());
    let stream = capture.snapshot().unwrap();
    assert!(!stream.capture_valid);
    assert_eq!(stream.failure, Some(CaptureFailure::UnclosedInteraction));
}

#[test]
fn invalid_capture_fences_later_tool_effects() {
    let capture = Arc::new(CanonicalCapture::new("run-sticky-fence", 6).unwrap());
    let tool = ToolMcpCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::Tool, "tool", "process").unwrap(),
    )
    .unwrap();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = tool.execute::<std::convert::Infallible, _>(
            "first",
            "tool",
            None,
            None,
            b"input",
            CaptureParent::Root,
            || panic!("invalidate capture"),
        );
    }));
    let invocations = AtomicUsize::new(0);

    let result = tool.execute(
        "second",
        "tool",
        None,
        None,
        b"input",
        CaptureParent::Root,
        || {
            invocations.fetch_add(1, Ordering::SeqCst);
            Ok::<_, std::convert::Infallible>(Vec::new())
        },
    );

    assert!(matches!(
        result,
        Err(smesh_a2a::ToolCaptureError::Capture(
            CaptureError::CaptureInvalid
        ))
    ));
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn durable_spool_syncs_call_before_wrapped_effect() {
    let path = std::env::temp_dir().join(format!(
        "smesh-live-capture-{}-{}.jsonl",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let capture = Arc::new(CanonicalCapture::create_spool("run-live", 4, &path).unwrap());
    let tool = ToolMcpCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::Tool, "mcp-client", "tool-process").unwrap(),
    )
    .unwrap();

    tool.execute(
        "tool-call-live",
        "inventory.lookup",
        None,
        None,
        b"arguments",
        CaptureParent::Root,
        || {
            let bytes = std::fs::read(&path).unwrap();
            let lines = bytes
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .collect::<Vec<_>>();
            assert_eq!(lines.len(), 1);
            let record: serde_json::Value = serde_json::from_slice(lines[0]).unwrap();
            assert_eq!(record["event"]["kind"], json!("toolCall"));
            let snapshot = capture.snapshot().unwrap();
            assert!(!snapshot.capture_valid);
            assert_eq!(snapshot.failure, Some(CaptureFailure::UnclosedInteraction));
            Ok::<_, std::convert::Infallible>(b"result".to_vec())
        },
    )
    .unwrap();

    capture.complete().unwrap();
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(
        CanonicalCapture::replay_jsonl(&bytes).unwrap().events.len(),
        2
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn artifact_interaction_rejects_cross_kind_subject_or_content_conflicts() {
    let capture = Arc::new(CanonicalCapture::new("run-artifact-contract", 4).unwrap());
    let artifact = ArtifactCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::Artifact, "store", "process").unwrap(),
    )
    .unwrap();
    let produced = artifact
        .produced(
            "interaction",
            "artifact-a",
            None,
            None,
            b"content",
            CaptureParent::Root,
        )
        .unwrap();

    assert_eq!(
        artifact.consumed(
            "interaction",
            "artifact-b",
            None,
            None,
            b"content",
            CaptureParent::Event(produced.event_id().to_owned()),
        ),
        Err(CaptureError::InteractionConflict)
    );
    assert_eq!(
        artifact.consumed(
            "interaction",
            "artifact-a",
            None,
            None,
            b"different",
            CaptureParent::Event(produced.event_id().to_owned()),
        ),
        Err(CaptureError::InteractionConflict)
    );
}

#[test]
fn artifact_adapter_captures_production_and_consumption_without_payload() {
    let capture = Arc::new(CanonicalCapture::new("run-23", 16).unwrap());
    let artifact_adapter = ArtifactCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::Artifact, "artifact-store", "artifact-process")
            .unwrap(),
    )
    .unwrap();

    let produced = artifact_adapter
        .produced(
            "artifact-flow-1",
            "artifact-1",
            Some("task-4"),
            Some("context-4"),
            b"restricted artifact bytes",
            CaptureParent::Root,
        )
        .unwrap();
    artifact_adapter
        .consumed(
            "artifact-flow-1",
            "artifact-1",
            Some("task-4"),
            Some("context-4"),
            b"restricted artifact bytes",
            CaptureParent::Event(produced.event_id().to_owned()),
        )
        .unwrap();

    let stream = capture.snapshot().unwrap();
    assert_eq!(stream.events[0].kind, CaptureKind::ArtifactProduced);
    assert_eq!(stream.events[1].kind, CaptureKind::ArtifactConsumed);
    assert_eq!(stream.events[0].subject_id.as_deref(), Some("artifact-1"));
    assert_eq!(stream.events[0].content, stream.events[1].content);
    let encoded = serde_json::to_vec(&stream).unwrap();
    assert!(
        !encoded
            .windows(b"restricted artifact bytes".len())
            .any(|window| window == b"restricted artifact bytes")
    );
}

#[test]
fn human_console_adapter_captures_prompt_and_decision_around_io() {
    let capture = Arc::new(CanonicalCapture::new("run-23", 16).unwrap());
    let human = HumanConsoleCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::Human, "reviewer", "console-process").unwrap(),
    )
    .unwrap();
    let mut input = Cursor::new(b"approve with private rationale\n".to_vec());
    let mut output = Vec::new();

    let decision = human
        .prompt_and_read(
            "human-review-1",
            "review-prompt-1",
            Some("task-5"),
            Some("context-5"),
            b"private evidence summary? ",
            CaptureParent::Root,
            &mut input,
            &mut output,
        )
        .unwrap();

    assert_eq!(decision, b"approve with private rationale\n");
    assert_eq!(output, b"private evidence summary? ");
    let stream = capture.snapshot().unwrap();
    assert_eq!(stream.events[0].kind, CaptureKind::HumanPrompt);
    assert_eq!(stream.events[1].kind, CaptureKind::HumanDecision);
    assert_eq!(
        stream.events[1].parent,
        CaptureParent::Event(stream.events[0].event_id.clone())
    );
    let encoded = serde_json::to_vec(&stream).unwrap();
    assert!(
        !encoded
            .windows(b"approve with private rationale".len())
            .any(|window| window == b"approve with private rationale")
    );
    assert!(
        !encoded
            .windows(b"private evidence summary".len())
            .any(|window| window == b"private evidence summary")
    );
}

#[test]
fn human_console_reserves_decision_before_prompt_io() {
    let capture = Arc::new(CanonicalCapture::new("run-human-capacity", 1).unwrap());
    let human = HumanConsoleCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::Human, "reviewer", "console-process").unwrap(),
    )
    .unwrap();
    let mut input = Cursor::new(b"approve\n".to_vec());
    let mut output = Vec::new();

    assert_eq!(
        human.prompt_and_read(
            "human-capacity",
            "prompt-capacity",
            None,
            None,
            b"prompt",
            CaptureParent::Root,
            &mut input,
            &mut output,
        ),
        Err(CaptureError::CapacityExhausted)
    );
    assert_eq!(input.position(), 0);
    assert!(output.is_empty());
    assert!(capture.snapshot().unwrap().events.is_empty());
}

#[test]
fn human_console_eof_records_terminal_failure() {
    let capture = Arc::new(CanonicalCapture::new("run-human-eof", 2).unwrap());
    let human = HumanConsoleCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::Human, "reviewer", "console-process").unwrap(),
    )
    .unwrap();
    let mut input = Cursor::new(Vec::new());
    let mut output = Vec::new();

    assert_eq!(
        human.prompt_and_read(
            "human-eof",
            "prompt-eof",
            None,
            None,
            b"prompt",
            CaptureParent::Root,
            &mut input,
            &mut output,
        ),
        Err(CaptureError::ConsoleIo)
    );
    let stream = capture.snapshot().unwrap();
    assert_eq!(stream.events.len(), 2);
    assert_eq!(stream.events[1].kind, CaptureKind::HumanFailed);
}

#[test]
fn human_console_read_error_records_terminal_failure() {
    let capture = Arc::new(CanonicalCapture::new("run-human-read-error", 2).unwrap());
    let human = HumanConsoleCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::Human, "reviewer", "console-process").unwrap(),
    )
    .unwrap();
    let mut input = FailingInput;
    let mut output = Vec::new();

    assert_eq!(
        human.prompt_and_read(
            "human-read-error",
            "prompt-read-error",
            None,
            None,
            b"prompt",
            CaptureParent::Root,
            &mut input,
            &mut output,
        ),
        Err(CaptureError::ConsoleIo)
    );
    let stream = capture.snapshot().unwrap();
    assert_eq!(stream.events.len(), 2);
    assert_eq!(stream.events[1].kind, CaptureKind::HumanFailed);
}

#[test]
fn human_console_oversize_decision_is_bounded_and_terminal() {
    let capture = Arc::new(CanonicalCapture::new("run-human-oversize", 2).unwrap());
    let human = HumanConsoleCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::Human, "reviewer", "console-process").unwrap(),
    )
    .unwrap();
    let mut input = Cursor::new(vec![b'x'; 64 * 1024 + 2]);
    let mut output = Vec::new();

    assert_eq!(
        human.prompt_and_read(
            "human-oversize",
            "prompt-oversize",
            None,
            None,
            b"prompt",
            CaptureParent::Root,
            &mut input,
            &mut output,
        ),
        Err(CaptureError::ConsoleIo)
    );
    assert_eq!(input.position(), (64 * 1024 + 1) as u64);
    let stream = capture.snapshot().unwrap();
    assert_eq!(stream.events.len(), 2);
    assert_eq!(stream.events[1].kind, CaptureKind::HumanFailed);
}

#[test]
fn human_console_output_error_records_terminal_failure() {
    let capture = Arc::new(CanonicalCapture::new("run-human-write-error", 2).unwrap());
    let human = HumanConsoleCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::Human, "reviewer", "console-process").unwrap(),
    )
    .unwrap();
    let mut input = Cursor::new(b"approve\n".to_vec());
    let mut output = FailingOutput;

    assert_eq!(
        human.prompt_and_read(
            "human-write-error",
            "prompt-write-error",
            None,
            None,
            b"prompt",
            CaptureParent::Root,
            &mut input,
            &mut output,
        ),
        Err(CaptureError::ConsoleIo)
    );
    assert_eq!(input.position(), 0);
    let stream = capture.snapshot().unwrap();
    assert_eq!(stream.events.len(), 2);
    assert_eq!(stream.events[1].kind, CaptureKind::HumanFailed);
}

#[test]
fn replay_rejects_unknown_fields_inside_capture_parent() {
    let capture = Arc::new(CanonicalCapture::new("run-parent-schema", 1).unwrap());
    A2aCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::A2a, "gateway", "process").unwrap(),
    )
    .unwrap()
    .send(
        "interaction-parent-schema",
        "peer",
        None,
        None,
        b"request",
        CaptureParent::Missing {
            expected_event_id: MISSING_EVENT_ID.to_owned(),
            reason: CaptureGapReason::ExternalBoundary,
        },
    )
    .unwrap();
    let mut forged = serde_json::to_value(capture.snapshot().unwrap()).unwrap();
    forged["events"][0]["parent"]["eventId"]["unexpected"] = json!(true);

    assert_eq!(
        CanonicalCapture::replay(&serde_json::to_vec(&forged).unwrap()),
        Err(CaptureError::MalformedReplay)
    );
}

#[test]
fn live_capture_rejects_unknown_event_parent_before_append() {
    let capture = Arc::new(CanonicalCapture::new("run-live-parent", 2).unwrap());
    let a2a = A2aCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::A2a, "gateway", "process").unwrap(),
    )
    .unwrap();

    assert_eq!(
        a2a.send(
            "interaction-parent",
            "peer",
            None,
            None,
            b"request",
            CaptureParent::Event("unknown-event".to_owned()),
        ),
        Err(CaptureError::MalformedReplay)
    );
    assert!(capture.snapshot().unwrap().events.is_empty());
}

#[test]
fn live_capture_requires_canonical_missing_parent_event_id() {
    let capture = Arc::new(CanonicalCapture::new("run-missing-id", 1).unwrap());
    let a2a = A2aCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::A2a, "gateway", "process").unwrap(),
    )
    .unwrap();

    assert_eq!(
        a2a.receive(
            "interaction-missing-id",
            "peer",
            None,
            None,
            b"response",
            CaptureParent::Missing {
                expected_event_id: "arbitrary-label".to_owned(),
                reason: CaptureGapReason::ExternalBoundary,
            },
        ),
        Err(CaptureError::MalformedReplay)
    );
    assert!(capture.snapshot().unwrap().events.is_empty());
}

#[test]
fn live_capture_rejects_missing_claim_for_existing_event() {
    let capture = Arc::new(CanonicalCapture::new("run-live-missing-conflict", 2).unwrap());
    let a2a = A2aCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::A2a, "gateway", "process").unwrap(),
    )
    .unwrap();
    let first = a2a
        .send(
            "first-live-interaction",
            "peer",
            None,
            None,
            b"first",
            CaptureParent::Root,
        )
        .unwrap();

    assert_eq!(
        a2a.send(
            "second-live-interaction",
            "peer",
            None,
            None,
            b"second",
            CaptureParent::Missing {
                expected_event_id: first.event_id().to_owned(),
                reason: CaptureGapReason::ExternalBoundary,
            },
        ),
        Err(CaptureError::MalformedReplay)
    );
    assert_eq!(capture.snapshot().unwrap().events.len(), 1);
}

#[test]
fn replay_rejects_missing_parent_claim_when_expected_event_appears_later() {
    let later_capture = Arc::new(CanonicalCapture::new("run-missing-conflict", 1).unwrap());
    A2aCaptureAdapter::new(
        Arc::clone(&later_capture),
        ProducerIdentity::new(ProducerKind::A2a, "gateway-b", "process-b").unwrap(),
    )
    .unwrap()
    .send(
        "later-interaction",
        "peer",
        None,
        None,
        b"later",
        CaptureParent::Root,
    )
    .unwrap();
    let later = later_capture.snapshot().unwrap().events.remove(0);
    let missing_capture = Arc::new(CanonicalCapture::new("run-missing-conflict", 1).unwrap());
    A2aCaptureAdapter::new(
        Arc::clone(&missing_capture),
        ProducerIdentity::new(ProducerKind::A2a, "gateway-a", "process-a").unwrap(),
    )
    .unwrap()
    .send(
        "missing-interaction",
        "peer",
        None,
        None,
        b"missing",
        CaptureParent::Missing {
            expected_event_id: later.event_id.clone(),
            reason: CaptureGapReason::ExternalBoundary,
        },
    )
    .unwrap();
    let mut forged = missing_capture.snapshot().unwrap();
    let mut later = later;
    later.sequence = 1;
    forged.events.push(later);

    assert_eq!(
        CanonicalCapture::replay(&serde_json::to_vec(&forged).unwrap()),
        Err(CaptureError::MalformedReplay)
    );
}

#[test]
fn missing_parent_is_explicit_and_offline_replay_validates_causality() {
    let capture = Arc::new(CanonicalCapture::new("run-23", 8).unwrap());
    let a2a = A2aCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::A2a, "gateway", "gateway-process").unwrap(),
    )
    .unwrap();
    a2a.receive(
        "interaction-gap",
        "remote-peer",
        Some("task-gap"),
        Some("context-gap"),
        b"response",
        CaptureParent::Missing {
            expected_event_id: MISSING_EVENT_ID.to_owned(),
            reason: CaptureGapReason::ExternalBoundary,
        },
    )
    .unwrap();

    let stream = capture.snapshot().unwrap();
    let encoded = serde_json::to_vec(&stream).unwrap();
    assert_eq!(CanonicalCapture::replay(&encoded).unwrap(), stream);

    let mut forged = stream;
    forged.events[0].parent = CaptureParent::Event("unknown-event".to_owned());
    assert!(matches!(
        CanonicalCapture::replay(&serde_json::to_vec(&forged).unwrap()),
        Err(CaptureError::MalformedReplay)
    ));
}

#[test]
fn offline_replay_sabotage_never_contacts_url_or_invokes_callbacks() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/must-not-contact", listener.local_addr().unwrap());
    let capture = Arc::new(CanonicalCapture::new("run-offline-sabotage", 1).unwrap());
    A2aCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::A2a, "gateway", "process").unwrap(),
    )
    .unwrap()
    .send(
        "offline-sabotage",
        "peer",
        None,
        None,
        url.as_bytes(),
        CaptureParent::Root,
    )
    .unwrap();
    let encoded = serde_json::to_vec(&capture.snapshot().unwrap()).unwrap();
    let tool_callbacks = AtomicUsize::new(0);
    let model_callbacks = AtomicUsize::new(0);
    let sabotaged_tool = || tool_callbacks.fetch_add(1, Ordering::SeqCst);
    let sabotaged_model = || model_callbacks.fetch_add(1, Ordering::SeqCst);
    std::hint::black_box((&sabotaged_tool, &sabotaged_model));

    CanonicalCapture::replay(&encoded).unwrap();

    assert_eq!(tool_callbacks.load(Ordering::SeqCst), 0);
    assert_eq!(model_callbacks.load(Ordering::SeqCst), 0);
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
}

#[test]
fn required_capacity_exhaustion_is_explicit_and_never_sampled() {
    let capture = Arc::new(CanonicalCapture::new("run-23", 1).unwrap());
    let a2a = A2aCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::A2a, "gateway", "gateway-process").unwrap(),
    )
    .unwrap();
    a2a.send(
        "interaction-1",
        "peer",
        None,
        None,
        b"one",
        CaptureParent::Root,
    )
    .unwrap();
    assert_eq!(
        a2a.send(
            "interaction-2",
            "peer",
            None,
            None,
            b"two",
            CaptureParent::Root,
        ),
        Err(CaptureError::CapacityExhausted)
    );

    let stream = capture.snapshot().unwrap();
    assert!(!stream.capture_valid);
    assert_eq!(stream.failure, Some(CaptureFailure::CapacityExhausted));
    assert_eq!(stream.events.len(), 1);
    assert!(matches!(
        CanonicalCapture::replay(&serde_json::to_vec(&stream).unwrap()),
        Err(CaptureError::CaptureInvalid)
    ));
}

#[test]
fn durable_capacity_failure_prefix_is_not_valid_after_restart() {
    let root = CaptureTempRoot(std::env::temp_dir().join(format!(
        "smesh-capture-capacity-failure-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )));
    std::fs::create_dir(&root.0).unwrap();
    let path = root.0.join("capture.jsonl");
    let capture =
        Arc::new(CanonicalCapture::create_spool("run-capacity-failure", 1, &path).unwrap());
    let adapter = A2aCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::A2a, "gateway", "process").unwrap(),
    )
    .unwrap();
    adapter
        .send("first", "peer", None, None, b"first", CaptureParent::Root)
        .unwrap();
    assert_eq!(
        adapter.send("second", "peer", None, None, b"second", CaptureParent::Root),
        Err(CaptureError::CapacityExhausted)
    );
    drop(adapter);
    drop(capture);

    assert_eq!(
        CanonicalCapture::replay_jsonl(&std::fs::read(path).unwrap()),
        Err(CaptureError::CaptureInvalid)
    );
}

#[test]
fn interaction_id_reuse_rejects_conflicting_binding() {
    let capture = Arc::new(CanonicalCapture::new("run-binding", 8).unwrap());
    let a2a = A2aCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::A2a, "gateway", "gateway-process").unwrap(),
    )
    .unwrap();
    a2a.send(
        "interaction-bound",
        "peer-a",
        Some("task-a"),
        Some("context-a"),
        b"request-a",
        CaptureParent::Root,
    )
    .unwrap();

    for conflicting in [
        a2a.send(
            "interaction-bound",
            "peer-b",
            Some("task-a"),
            Some("context-a"),
            b"request-a",
            CaptureParent::Root,
        ),
        a2a.send(
            "interaction-bound",
            "peer-a",
            Some("task-b"),
            Some("context-a"),
            b"request-a",
            CaptureParent::Root,
        ),
        a2a.send(
            "interaction-bound",
            "peer-a",
            Some("task-a"),
            Some("context-b"),
            b"request-a",
            CaptureParent::Root,
        ),
        a2a.send(
            "interaction-bound",
            "peer-a",
            Some("task-a"),
            Some("context-a"),
            b"request-b",
            CaptureParent::Root,
        ),
    ] {
        assert_eq!(conflicting, Err(CaptureError::InteractionConflict));
    }
    assert_eq!(capture.snapshot().unwrap().events.len(), 1);
}

#[test]
fn replay_rejects_individually_valid_events_with_conflicting_interaction_binding() {
    let first = Arc::new(CanonicalCapture::new("run-binding-replay", 2).unwrap());
    A2aCaptureAdapter::new(
        Arc::clone(&first),
        ProducerIdentity::new(ProducerKind::A2a, "gateway-a", "process-a").unwrap(),
    )
    .unwrap()
    .send(
        "interaction-reused",
        "peer-a",
        Some("task-a"),
        Some("context-a"),
        b"request",
        CaptureParent::Root,
    )
    .unwrap();
    let second = Arc::new(CanonicalCapture::new("run-binding-replay", 2).unwrap());
    A2aCaptureAdapter::new(
        Arc::clone(&second),
        ProducerIdentity::new(ProducerKind::A2a, "gateway-b", "process-b").unwrap(),
    )
    .unwrap()
    .send(
        "interaction-reused",
        "peer-b",
        Some("task-a"),
        Some("context-a"),
        b"request",
        CaptureParent::Root,
    )
    .unwrap();

    let mut forged = first.snapshot().unwrap();
    let mut conflicting = second.snapshot().unwrap().events.remove(0);
    conflicting.sequence = 1;
    forged.events.push(conflicting);
    assert_eq!(
        CanonicalCapture::replay(&serde_json::to_vec(&forged).unwrap()),
        Err(CaptureError::MalformedReplay)
    );
}

#[test]
fn ingest_many_events_and_a_duplicate_batch_preserves_exact_admission() {
    const EVENT_COUNT: usize = 2_048;
    let root = CaptureTempRoot(std::env::temp_dir().join(format!(
        "smesh-linear-ingest-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )));
    std::fs::create_dir(&root.0).unwrap();
    let source_path = root.0.join("source.jsonl");
    let destination_path = root.0.join("destination.jsonl");
    let source = Arc::new(CanonicalCapture::new("run-linear-ingest", EVENT_COUNT).unwrap());
    let adapter = A2aCaptureAdapter::new(
        Arc::clone(&source),
        ProducerIdentity::new(ProducerKind::A2a, "source", "process").unwrap(),
    )
    .unwrap();
    for index in 0..EVENT_COUNT {
        adapter
            .send(
                &format!("interaction-{index}"),
                "peer",
                None,
                None,
                b"event",
                CaptureParent::Root,
            )
            .unwrap();
    }
    source.persist_new(&source_path).unwrap();
    let bytes = std::fs::read(source_path).unwrap();
    let destination =
        CanonicalCapture::create_spool("run-linear-ingest", EVENT_COUNT, &destination_path)
            .unwrap();

    destination.ingest_jsonl(&bytes).unwrap();
    destination.ingest_jsonl(&bytes).unwrap();

    assert_eq!(destination.snapshot().unwrap().events.len(), EVENT_COUNT);
}

#[test]
fn ingest_rejects_invalid_source_order_even_when_every_event_is_already_present() {
    let root = CaptureTempRoot(std::env::temp_dir().join(format!(
        "smesh-invalid-duplicate-source-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )));
    std::fs::create_dir(&root.0).unwrap();
    let source_path = root.0.join("source.jsonl");
    let destination_path = root.0.join("destination.jsonl");
    let source = Arc::new(CanonicalCapture::new("run-invalid-duplicate-source", 2).unwrap());
    let adapter = A2aCaptureAdapter::new(
        Arc::clone(&source),
        ProducerIdentity::new(ProducerKind::A2a, "source", "process").unwrap(),
    )
    .unwrap();
    let first = adapter
        .send(
            "interaction",
            "peer",
            None,
            None,
            b"request",
            CaptureParent::Root,
        )
        .unwrap();
    adapter
        .receive(
            "interaction",
            "peer",
            None,
            None,
            b"response",
            CaptureParent::Event(first.event_id().to_owned()),
        )
        .unwrap();
    source.persist_new(&source_path).unwrap();
    let valid_bytes = std::fs::read(source_path).unwrap();
    let destination =
        CanonicalCapture::create_spool("run-invalid-duplicate-source", 2, &destination_path)
            .unwrap();
    destination.ingest_jsonl(&valid_bytes).unwrap();
    let before = destination.snapshot().unwrap();
    let persisted_before = std::fs::read(&destination_path).unwrap();

    let mut records = valid_bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    records.swap(0, 1);
    records[0]["event"]["sequence"] = json!(0);
    records[1]["event"]["sequence"] = json!(1);
    let mut invalid_bytes = Vec::new();
    for record in records {
        invalid_bytes.extend_from_slice(&serde_json::to_vec(&record).unwrap());
        invalid_bytes.push(b'\n');
    }

    assert_eq!(
        destination.ingest_jsonl(&invalid_bytes),
        Err(CaptureError::MalformedReplay)
    );
    assert_eq!(destination.snapshot().unwrap(), before);
    assert_eq!(std::fs::read(destination_path).unwrap(), persisted_before);
}

#[test]
fn jsonl_rejects_blank_records_at_every_location_without_ingest_effect() {
    let root = CaptureTempRoot(std::env::temp_dir().join(format!(
        "smesh-blank-jsonl-records-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )));
    std::fs::create_dir(&root.0).unwrap();
    let source_path = root.0.join("source.jsonl");
    let source = Arc::new(CanonicalCapture::new("run-blank-records", 1).unwrap());
    A2aCaptureAdapter::new(
        Arc::clone(&source),
        ProducerIdentity::new(ProducerKind::A2a, "gateway", "process").unwrap(),
    )
    .unwrap()
    .send(
        "interaction",
        "peer",
        None,
        None,
        b"body",
        CaptureParent::Root,
    )
    .unwrap();
    source.persist_new(&source_path).unwrap();
    let valid = std::fs::read(source_path).unwrap();
    let first_record_end = valid.iter().position(|byte| *byte == b'\n').unwrap() + 1;

    let mut leading = Vec::with_capacity(valid.len() + 1);
    leading.push(b'\n');
    leading.extend_from_slice(&valid);
    let mut interior = valid.clone();
    interior.insert(first_record_end, b'\n');
    let mut trailing = valid;
    trailing.push(b'\n');

    for (location, malformed) in [
        ("leading", leading),
        ("interior", interior),
        ("trailing", trailing),
    ] {
        assert_eq!(
            CanonicalCapture::replay_jsonl(&malformed),
            Err(CaptureError::MalformedReplay),
            "{location} blank record must fail replay"
        );
        let destination_path = root.0.join(format!("destination-{location}.jsonl"));
        let destination =
            CanonicalCapture::create_spool("run-blank-records", 1, &destination_path).unwrap();
        let before = destination.snapshot().unwrap();
        let persisted_before = std::fs::read(&destination_path).unwrap();
        assert_eq!(
            destination.ingest_jsonl(&malformed),
            Err(CaptureError::MalformedReplay),
            "{location} blank record must fail ingest"
        );
        assert_eq!(destination.snapshot().unwrap(), before);
        assert_eq!(std::fs::read(destination_path).unwrap(), persisted_before);
    }
}

#[test]
fn jsonl_rejects_complete_record_missing_terminal_newline_without_ingest_effect() {
    let root = CaptureTempRoot(std::env::temp_dir().join(format!(
        "smesh-terminal-newline-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )));
    std::fs::create_dir(&root.0).unwrap();
    let source_path = root.0.join("source.jsonl");
    let destination_path = root.0.join("destination.jsonl");
    let source = Arc::new(CanonicalCapture::new("run-terminal-newline", 2).unwrap());
    A2aCaptureAdapter::new(
        Arc::clone(&source),
        ProducerIdentity::new(ProducerKind::A2a, "gateway", "process").unwrap(),
    )
    .unwrap()
    .send(
        "interaction",
        "peer",
        None,
        None,
        b"body",
        CaptureParent::Root,
    )
    .unwrap();
    source.persist_new(&source_path).unwrap();
    let mut truncated = std::fs::read(source_path).unwrap();
    assert_eq!(truncated.pop(), Some(b'\n'));

    assert_eq!(
        CanonicalCapture::replay_jsonl(&truncated),
        Err(CaptureError::MalformedReplay)
    );
    let destination =
        CanonicalCapture::create_spool("run-terminal-newline", 2, &destination_path).unwrap();
    assert_eq!(
        destination.ingest_jsonl(&truncated),
        Err(CaptureError::MalformedReplay)
    );
    assert!(destination.snapshot().unwrap().events.is_empty());
    assert!(std::fs::read(destination_path).unwrap().is_empty());
}

#[test]
fn canonical_capture_persists_private_create_new_jsonl_and_replays_offline() {
    let capture = Arc::new(CanonicalCapture::new("run-jsonl", 8).unwrap());
    let a2a = A2aCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::A2a, "gateway", "gateway-process").unwrap(),
    )
    .unwrap();
    let send = a2a
        .send(
            "interaction-jsonl",
            "peer",
            Some("task-jsonl"),
            Some("context-jsonl"),
            b"request",
            CaptureParent::Root,
        )
        .unwrap();
    a2a.receive(
        "interaction-jsonl",
        "peer",
        Some("task-jsonl"),
        Some("context-jsonl"),
        b"response",
        CaptureParent::Event(send.event_id().to_owned()),
    )
    .unwrap();
    let path = std::env::temp_dir().join(format!(
        "smesh-full-matrix-{}-{}.jsonl",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    capture.persist_new(&path).unwrap();
    assert_eq!(capture.persist_new(&path), Err(CaptureError::Persistence));
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(
        bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .count(),
        3
    );
    assert_eq!(
        CanonicalCapture::replay_jsonl(&bytes).unwrap(),
        capture.snapshot().unwrap()
    );
    #[cfg(unix)]
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    std::fs::remove_file(path).unwrap();
}

type ChildFixtureResult = Result<(), Box<dyn std::error::Error>>;

fn child_identity(kind: ProducerKind, id: &str, instance_id: &str) -> ProducerIdentity {
    ProducerIdentity::new(kind, id, instance_id).expect("fixed child identity is valid")
}

fn run_child_producer_a(capture: &Arc<CanonicalCapture>, instance_id: &str) -> ChildFixtureResult {
    let send = A2aCaptureAdapter::new(
        Arc::clone(capture),
        child_identity(ProducerKind::A2a, "producer-a", instance_id),
    )?
    .send(
        "shared-a2a-interaction",
        "producer-b",
        Some("task-multiprocess"),
        Some("context-multiprocess"),
        b"shared-a2a-payload",
        CaptureParent::Missing {
            expected_event_id: MISSING_EVENT_ID.to_owned(),
            reason: CaptureGapReason::ExternalBoundary,
        },
    )?;
    SmeshJournalCaptureAdapter::new(
        Arc::clone(capture),
        child_identity(ProducerKind::Smesh, "runtime-a", instance_id),
    )?
    .record(
        "smesh-interaction-a",
        Some("task-multiprocess"),
        Some("context-multiprocess"),
        RuntimeEvent::SignalEmitted {
            hash: "signal-multiprocess".to_owned(),
        },
        CaptureParent::Missing {
            expected_event_id: MISSING_EVENT_ID.to_owned(),
            reason: CaptureGapReason::ExternalBoundary,
        },
    )?;
    ToolMcpCaptureAdapter::new(
        Arc::clone(capture),
        child_identity(ProducerKind::Tool, "tool-a", instance_id),
    )?
    .execute(
        "tool-interaction-a",
        "tool-a",
        Some("task-multiprocess"),
        Some("context-multiprocess"),
        b"tool-input",
        CaptureParent::Missing {
            expected_event_id: MISSING_EVENT_ID.to_owned(),
            reason: CaptureGapReason::ExternalBoundary,
        },
        || Ok::<_, std::convert::Infallible>(b"tool-output".to_vec()),
    )?;
    capture.complete()?;
    std::fs::write(
        std::env::var_os("SMESH_CAPTURE_SIGNAL").ok_or("missing signal")?,
        send.event_id(),
    )?;
    let release = std::path::PathBuf::from(
        std::env::var_os("SMESH_CAPTURE_RELEASE").ok_or("missing release")?,
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !release.exists() {
        if Instant::now() >= deadline {
            return Err("release timeout".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

fn run_child_producer_b(
    capture: &Arc<CanonicalCapture>,
    instance_id: &str,
    parent: String,
) -> ChildFixtureResult {
    A2aCaptureAdapter::new(
        Arc::clone(capture),
        child_identity(ProducerKind::A2a, "producer-b", instance_id),
    )?
    .receive(
        "shared-a2a-interaction",
        "producer-a",
        Some("task-multiprocess"),
        Some("context-multiprocess"),
        b"shared-a2a-payload",
        CaptureParent::Event(parent),
    )?;
    let artifact = ArtifactCaptureAdapter::new(
        Arc::clone(capture),
        child_identity(ProducerKind::Artifact, "artifact-b", instance_id),
    )?;
    let artifact_receipt = artifact.produced(
        "artifact-interaction-b",
        "artifact-multiprocess",
        Some("task-multiprocess"),
        Some("context-multiprocess"),
        b"artifact-bytes",
        CaptureParent::Missing {
            expected_event_id: MISSING_EVENT_ID.to_owned(),
            reason: CaptureGapReason::ExternalBoundary,
        },
    )?;
    artifact.consumed(
        "artifact-interaction-b",
        "artifact-multiprocess",
        Some("task-multiprocess"),
        Some("context-multiprocess"),
        b"artifact-bytes",
        CaptureParent::Event(artifact_receipt.event_id().to_owned()),
    )?;
    HumanConsoleCaptureAdapter::new(
        Arc::clone(capture),
        child_identity(ProducerKind::Human, "human-b", instance_id),
    )?
    .prompt_and_read(
        "human-interaction-b",
        "prompt-multiprocess",
        Some("task-multiprocess"),
        Some("context-multiprocess"),
        b"approve? ",
        CaptureParent::Missing {
            expected_event_id: MISSING_EVENT_ID.to_owned(),
            reason: CaptureGapReason::ExternalBoundary,
        },
        &mut Cursor::new(b"approve\n".to_vec()),
        &mut Vec::new(),
    )?;
    capture.complete()?;
    Ok(())
}

#[test]
fn multiprocess_child_fixture() {
    let Some(role) = std::env::var_os("SMESH_CAPTURE_CHILD_ROLE") else {
        return;
    };
    let role = role.into_string().expect("child role must be UTF-8");
    let path = std::env::var_os("SMESH_CAPTURE_CHILD_PATH").expect("missing child path");
    let instance_id = format!("process-{}", std::process::id());
    let capacity = if role == "producer-a" { 4 } else { 16 };
    let capture = Arc::new(
        CanonicalCapture::create_spool("run-multiprocess", capacity, std::path::Path::new(&path))
            .unwrap(),
    );
    if role == "producer-b" {
        let parent_spool =
            std::env::var_os("SMESH_CAPTURE_PARENT_SPOOL").expect("missing parent spool");
        capture
            .ingest_jsonl(&std::fs::read(parent_spool).unwrap())
            .unwrap();
    }
    let result = match role.as_str() {
        "producer-a" => run_child_producer_a(&capture, &instance_id),
        "producer-b" => run_child_producer_b(
            &capture,
            &instance_id,
            std::env::var("SMESH_CAPTURE_PARENT").expect("missing parent"),
        ),
        _ => Err("invalid child role".into()),
    };
    result.unwrap();
}

struct CaptureChild(Option<std::process::Child>);

impl CaptureChild {
    fn new(child: std::process::Child) -> Self {
        Self(Some(child))
    }

    fn id(&self) -> u32 {
        self.0.as_ref().expect("child is owned").id()
    }

    fn child_mut(&mut self) -> &mut std::process::Child {
        self.0.as_mut().expect("child is owned")
    }
}

impl Drop for CaptureChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn spawn_capture_child(
    path: &std::path::Path,
    role: &str,
    parent: Option<&str>,
    parent_spool: Option<&std::path::Path>,
    signal: &std::path::Path,
    release: &std::path::Path,
) -> CaptureChild {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "multiprocess_child_fixture", "--nocapture"])
        .env("SMESH_CAPTURE_CHILD_ROLE", role)
        .env("SMESH_CAPTURE_CHILD_PATH", path)
        .env("SMESH_CAPTURE_SIGNAL", signal)
        .env("SMESH_CAPTURE_RELEASE", release)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    if let Some(parent) = parent {
        command.env("SMESH_CAPTURE_PARENT", parent);
    }
    if let Some(parent_spool) = parent_spool {
        command.env("SMESH_CAPTURE_PARENT_SPOOL", parent_spool);
    }
    CaptureChild::new(command.spawn().unwrap())
}

fn wait_for_child_signal(child: &mut CaptureChild, signal: &std::path::Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(value) = std::fs::read_to_string(signal) {
            return value;
        }
        if let Some(status) = child.child_mut().try_wait().unwrap() {
            panic!("capture child exited before signaling: {status}");
        }
        assert!(Instant::now() < deadline, "capture child signal timed out");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_child(child: &mut CaptureChild) -> std::process::ExitStatus {
    if let Some(status) = child
        .child_mut()
        .wait_timeout(Duration::from_secs(10))
        .unwrap()
    {
        child.0.take();
        status
    } else {
        panic!("capture child timed out");
    }
}

struct CaptureTempRoot(std::path::PathBuf);

impl Drop for CaptureTempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn assert_multiprocess_stream(expected: &CaptureStream, first_pid: u32, second_pid: u32) {
    assert_eq!(
        expected
            .events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        (0..9).collect::<Vec<_>>()
    );
    for kind in [
        ProducerKind::A2a,
        ProducerKind::Smesh,
        ProducerKind::Tool,
        ProducerKind::Artifact,
        ProducerKind::Human,
    ] {
        assert!(
            expected
                .events
                .iter()
                .any(|event| event.producer.identity.kind == kind)
        );
    }
    let mut sources = std::collections::BTreeMap::new();
    for event in &expected.events {
        sources
            .entry((
                format!("{:?}", event.producer.identity.kind),
                event.producer.identity.id.clone(),
                event.producer.identity.instance_id.clone(),
            ))
            .or_insert_with(Vec::new)
            .push(event.producer.sequence);
    }
    for sequences in sources.values() {
        assert_eq!(
            sequences,
            &(0..u64::try_from(sequences.len()).unwrap()).collect::<Vec<_>>()
        );
    }
    assert!(
        expected.events[..4]
            .iter()
            .all(|event| event.producer.identity.instance_id == format!("process-{first_pid}"))
    );
    assert!(
        expected.events[4..]
            .iter()
            .all(|event| event.producer.identity.instance_id == format!("process-{second_pid}"))
    );
    let send = expected
        .events
        .iter()
        .find(|event| event.kind == CaptureKind::A2aSend)
        .unwrap();
    let receive = expected
        .events
        .iter()
        .find(|event| event.kind == CaptureKind::A2aReceive)
        .unwrap();
    assert_eq!(send.interaction_id, receive.interaction_id);
    assert_eq!(receive.parent, CaptureParent::Event(send.event_id.clone()));
}

#[cfg(unix)]
#[test]
fn child_owner_kills_and_reaps_on_drop() {
    let child = Command::new("sh")
        .args(["-c", "sleep 30"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id();
    let owner = CaptureChild::new(child);
    drop(owner);
    assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
}

#[test]
fn capture_process_fixture_is_not_a_shipped_binary() {
    assert!(
        !std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/bin/full-matrix-capture-helper.rs")
            .exists()
    );
}

#[test]
fn separate_processes_ingest_into_one_canonical_jsonl() {
    let root = CaptureTempRoot(std::env::temp_dir().join(format!(
        "smesh-capture-processes-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )));
    std::fs::create_dir(&root.0).unwrap();
    let first_path = root.0.join("first.jsonl");
    let second_path = root.0.join("second.jsonl");
    let canonical_path = root.0.join("canonical.jsonl");
    let signal_path = root.0.join("send-id");
    let release_path = root.0.join("release");
    let mut first = spawn_capture_child(
        &first_path,
        "producer-a",
        None,
        None,
        &signal_path,
        &release_path,
    );
    let first_pid = first.id();
    let send_id = wait_for_child_signal(&mut first, &signal_path);
    assert!(send_id.starts_with("sha256:"));
    let mut second = spawn_capture_child(
        &second_path,
        "producer-b",
        Some(&send_id),
        Some(&first_path),
        &signal_path,
        &release_path,
    );
    let second_pid = second.id();
    assert_ne!(first_pid, second_pid);
    let second_status = wait_for_child(&mut second);
    std::fs::write(&release_path, b"release").unwrap();
    let first_status = wait_for_child(&mut first);
    assert!(second_status.success());
    assert!(first_status.success());

    let canonical =
        CanonicalCapture::create_spool("run-multiprocess", 16, &canonical_path).unwrap();
    canonical
        .ingest_jsonl(&std::fs::read(&first_path).unwrap())
        .unwrap();
    canonical
        .ingest_jsonl(&std::fs::read(&first_path).unwrap())
        .unwrap();
    canonical
        .ingest_jsonl(&std::fs::read(&second_path).unwrap())
        .unwrap();
    let expected = canonical.snapshot().unwrap();
    assert_multiprocess_stream(&expected, first_pid, second_pid);
    canonical.complete().unwrap();
    assert_eq!(
        CanonicalCapture::replay_jsonl(&std::fs::read(&canonical_path).unwrap()).unwrap(),
        expected
    );
    drop(canonical);
}

#[tokio::test]
async fn ingest_rejects_an_already_invalid_destination() {
    let root = CaptureTempRoot(std::env::temp_dir().join(format!(
        "smesh-capture-invalid-ingest-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )));
    std::fs::create_dir(&root.0).unwrap();
    let source_path = root.0.join("source.jsonl");
    let source = Arc::new(CanonicalCapture::new("run-invalid-ingest", 1).unwrap());
    A2aCaptureAdapter::new(
        Arc::clone(&source),
        ProducerIdentity::new(ProducerKind::A2a, "source", "source-process").unwrap(),
    )
    .unwrap()
    .send("source", "peer", None, None, b"source", CaptureParent::Root)
    .unwrap();
    source.persist_new(&source_path).unwrap();

    let destination_path = root.0.join("destination.jsonl");
    let destination = Arc::new(
        CanonicalCapture::create_spool("run-invalid-ingest", 8, &destination_path).unwrap(),
    );
    let interceptor = A2aCaptureAdapter::new(
        Arc::clone(&destination),
        ProducerIdentity::new(ProducerKind::A2a, "gateway", "gateway-process").unwrap(),
    )
    .unwrap();
    let mut context = CallContext::new("message/send", ServiceParams::new());
    interceptor
        .before(&mut context, &json!({"request": true}))
        .await
        .unwrap();
    drop(interceptor);

    assert_eq!(
        destination.ingest_jsonl(&std::fs::read(source_path).unwrap()),
        Err(CaptureError::CaptureInvalid)
    );
    assert_eq!(destination.snapshot().unwrap().events.len(), 1);
}

#[test]
fn ingest_rejects_source_local_sequence_gap_without_destination_effect() {
    let root = CaptureTempRoot(std::env::temp_dir().join(format!(
        "smesh-capture-gap-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )));
    std::fs::create_dir(&root.0).unwrap();
    let source_path = root.0.join("source.jsonl");
    let canonical_path = root.0.join("canonical.jsonl");
    let signal_path = root.0.join("send-id");
    let release_path = root.0.join("release");
    let mut child = spawn_capture_child(
        &source_path,
        "producer-a",
        None,
        None,
        &signal_path,
        &release_path,
    );
    let _ = wait_for_child_signal(&mut child, &signal_path);
    std::fs::write(&release_path, b"release").unwrap();
    assert!(wait_for_child(&mut child).success());
    let bytes = std::fs::read(&source_path).unwrap();
    let second_line = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .nth(3)
        .unwrap();
    let mut gap: serde_json::Value = serde_json::from_slice(second_line).unwrap();
    gap["event"]["sequence"] = json!(0);
    let mut gap_bytes = serde_json::to_vec(&gap).unwrap();
    gap_bytes.push(b'\n');
    let mut complete: serde_json::Value = serde_json::from_slice(
        bytes
            .split(|byte| *byte == b'\n')
            .rfind(|line| !line.is_empty())
            .unwrap(),
    )
    .unwrap();
    complete["eventCount"] = json!(1);
    gap_bytes.extend_from_slice(&serde_json::to_vec(&complete).unwrap());
    gap_bytes.push(b'\n');

    let canonical = CanonicalCapture::create_spool("run-multiprocess", 8, &canonical_path).unwrap();
    assert_eq!(
        canonical.ingest_jsonl(&gap_bytes),
        Err(CaptureError::MalformedReplay)
    );
    let stream = canonical.snapshot().unwrap();
    assert!(stream.capture_valid);
    assert_eq!(stream.failure, None);
    assert!(stream.events.is_empty());
    assert!(std::fs::read(canonical_path).unwrap().is_empty());
    drop(canonical);
}
