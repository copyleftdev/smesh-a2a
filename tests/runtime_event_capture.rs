use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use smesh_a2a::{
    ClosedAttestation, CompletionEvidence, CorrelatingRuntimeProcessor, MeshDispatcher,
    MeshRequest, RatificationReceipt, RatificationStatement, RuntimeAdmissionProcessor,
    RuntimeCancellationOutcome, RuntimeClaimKind, RuntimeEventCapture, RuntimeTerminalState,
    RuntimeTraceDetails, RuntimeTraceError, RuntimeTraceKind, RuntimeWorker, content_digest,
};
use smesh_core::{Network, Node};
use smesh_runtime::{RuntimeConfig, RuntimeEvent, SmeshRuntime};

#[tokio::test]
#[allow(clippy::too_many_lines)] // One end-to-end capture, persistence, replay, and corruption fixture.
async fn required_runtime_lifecycle_is_correlated_while_optional_metrics_drop_first() {
    let capture = RuntimeEventCapture::new(16, 1);
    capture
        .register_correlation("signal-hash", "task-trace", "context-trace")
        .await
        .unwrap();

    for tick in 0..32 {
        capture
            .record(RuntimeEvent::TickCompleted {
                tick,
                active_signals: usize::MAX,
                expired: 0,
            })
            .await
            .unwrap();
    }
    capture
        .record(RuntimeEvent::SignalEmitted {
            hash: "signal-hash".to_owned(),
        })
        .await
        .unwrap();
    let secret_canary = b"TRACE_SECRET_EVIDENCE_CANARY".to_vec();
    capture
        .record_evidence(
            "task-trace",
            "context-trace",
            &CompletionEvidence::Review {
                id: "review-trace".to_owned(),
                issuer: "reviewer".to_owned(),
                subject_digest: content_digest(b"subject"),
                evidence: secret_canary.clone(),
                evidence_digest: "sha256:evidence".to_owned(),
                approved: true,
                assurance_bps: 9_000,
            },
        )
        .await
        .unwrap();
    capture
        .record_terminal(
            "task-trace",
            "context-trace",
            RuntimeTerminalState::Completed,
            vec![content_digest(b"artifact")],
        )
        .await
        .unwrap();

    let trace = capture.snapshot().await;
    assert!(trace.dropped_optional > 0);
    assert!(trace.events.iter().any(|event| {
        event.kind == RuntimeTraceKind::SignalEmitted
            && event.task_id.as_deref() == Some("task-trace")
            && event.context_id.as_deref() == Some("context-trace")
            && event.signal_hash.as_deref() == Some("signal-hash")
    }));
    assert!(
        trace
            .events
            .windows(2)
            .all(|window| window[0].sequence < window[1].sequence)
    );
    assert!(
        trace
            .events
            .iter()
            .any(|event| matches!(event.details, RuntimeTraceDetails::Tick { .. }))
    );

    let encoded = serde_json::to_vec(&trace).unwrap();
    assert!(
        !encoded
            .windows(b"safeDetails".len())
            .any(|window| window == b"safeDetails")
    );
    assert!(
        !encoded
            .windows(secret_canary.len())
            .any(|window| window == secret_canary)
    );
    let replayed = RuntimeEventCapture::replay(&encoded).unwrap();
    assert_eq!(replayed, trace);

    let mut missing_signal_hash = trace.clone();
    missing_signal_hash
        .events
        .iter_mut()
        .find(|event| event.kind == RuntimeTraceKind::SignalEmitted)
        .unwrap()
        .signal_hash = None;
    assert!(
        RuntimeEventCapture::replay(&serde_json::to_vec(&missing_signal_hash).unwrap()).is_err()
    );
    let mut forged_terminal_signal = trace.clone();
    forged_terminal_signal
        .events
        .iter_mut()
        .find(|event| event.kind == RuntimeTraceKind::TerminalOutput)
        .unwrap()
        .signal_hash = Some("forged-signal".to_owned());
    assert!(
        RuntimeEventCapture::replay(&serde_json::to_vec(&forged_terminal_signal).unwrap()).is_err()
    );

    let fixture_path = std::env::temp_dir().join(format!(
        "smesh-runtime-trace-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    capture.persist_new(&fixture_path).await.unwrap();
    assert!(capture.persist_new(&fixture_path).await.is_err());
    let persisted = std::fs::read(&fixture_path).unwrap();
    assert_eq!(RuntimeEventCapture::replay(&persisted).unwrap(), trace);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&fixture_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    std::fs::remove_file(&fixture_path).unwrap();

    let mut unsupported = trace.clone();
    unsupported.schema_version = "runtime-trace/999".to_owned();
    assert!(RuntimeEventCapture::replay(&serde_json::to_vec(&unsupported).unwrap()).is_err());

    let mut gapped = trace;
    gapped.events.last_mut().unwrap().sequence += 1;
    assert!(RuntimeEventCapture::replay(&serde_json::to_vec(&gapped).unwrap()).is_err());
}

#[tokio::test]
async fn genuine_runtime_emission_enters_captured_correlated_fixture() {
    let mut network = Network::new();
    network.add_node(Node::named("trace-runtime"));
    let mut runtime_value = SmeshRuntime::with_network(network, RuntimeConfig::default());
    let mut runtime_events = runtime_value.take_events().unwrap();
    let runtime = Arc::new(runtime_value);
    let capture = Arc::new(RuntimeEventCapture::new(16, 4));
    let processor =
        CorrelatingRuntimeProcessor::new(RuntimeAdmissionProcessor, Arc::clone(&capture));
    let (dispatcher, worker) =
        RuntimeWorker::spawn(Arc::clone(&runtime), "trace-runtime", processor, 4)
            .await
            .unwrap();
    let events = dispatcher
        .dispatch(MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "trace-task".to_owned(),
            context_id: "trace-context".to_owned(),
            text: "capture genuine runtime event".to_owned(),
        })
        .collect::<Vec<_>>()
        .await;
    assert!(events.iter().all(Result::is_ok));
    let runtime_event = tokio::time::timeout(Duration::from_secs(1), runtime_events.recv())
        .await
        .unwrap()
        .unwrap();
    capture.record(runtime_event).await.unwrap();
    let fixture = capture.snapshot().await;
    assert!(fixture.events.iter().any(|event| {
        event.kind == RuntimeTraceKind::SignalEmitted
            && event.task_id.as_deref() == Some("trace-task")
            && event.context_id.as_deref() == Some("trace-context")
    }));
    worker.shutdown().await.unwrap();
}

#[tokio::test]
async fn required_capacity_exhaustion_fails_without_sampling_or_sequence_gap() {
    let capture = RuntimeEventCapture::new(1, 1);
    capture
        .record(RuntimeEvent::SignalEmitted {
            hash: "first-required".to_owned(),
        })
        .await
        .unwrap();
    assert!(
        capture
            .record(RuntimeEvent::SignalExpired {
                hash: "second-required".to_owned(),
            })
            .await
            .is_err()
    );
    assert!(capture.failure_token().is_cancelled());
    let trace = capture.snapshot().await;
    assert_eq!(trace.events.len(), 1);
    assert_eq!(trace.events[0].sequence, 0);
    assert!(!trace.capture_valid);
    assert!(RuntimeEventCapture::replay(&serde_json::to_vec(&trace).unwrap()).is_err());
}

#[tokio::test]
async fn zero_optional_capacity_drops_metrics_without_disabling_required_capture() {
    let capture = RuntimeEventCapture::new(1, 0);
    capture
        .record(RuntimeEvent::TickCompleted {
            tick: 1,
            active_signals: 1,
            expired: 0,
        })
        .await
        .unwrap();
    capture
        .record(RuntimeEvent::SignalEmitted {
            hash: "required-without-optionals".to_owned(),
        })
        .await
        .unwrap();
    let trace = capture.snapshot().await;
    assert_eq!(trace.dropped_optional, 1);
    assert_eq!(trace.events.len(), 1);
    assert_eq!(trace.events[0].kind, RuntimeTraceKind::SignalEmitted);
}

#[tokio::test]
async fn correlation_registration_backfills_an_already_captured_emission() {
    let capture = RuntimeEventCapture::new(2, 1);
    capture
        .record(RuntimeEvent::SignalEmitted {
            hash: "late-correlation".to_owned(),
        })
        .await
        .unwrap();
    assert!(capture.snapshot().await.events[0].task_id.is_none());
    capture
        .register_correlation("late-correlation", "late-task", "late-context")
        .await
        .unwrap();
    let trace = capture.snapshot().await;
    assert_eq!(trace.events[0].task_id.as_deref(), Some("late-task"));
    assert_eq!(trace.events[0].context_id.as_deref(), Some("late-context"));
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Exhaustive typed variant and redaction matrix stays auditable together.
async fn adapter_covers_runtime_lifecycle_and_untrusted_claim_semantics() {
    let capture = RuntimeEventCapture::new(16, 1);
    for event in [
        RuntimeEvent::SignalReinforced {
            hash: "reinforced".to_owned(),
            count: 3,
        },
        RuntimeEvent::SignalReceived {
            hash: "received".to_owned(),
            from: "SECRET_PEER_ID".to_owned(),
            hops: 2,
        },
        RuntimeEvent::SignalExpired {
            hash: "expired".to_owned(),
        },
        RuntimeEvent::PeerConnected {
            peer_id: "SECRET_PEER_ID".to_owned(),
        },
        RuntimeEvent::PeerDisconnected {
            peer_id: "SECRET_PEER_ID".to_owned(),
        },
    ] {
        capture.record(event).await.unwrap();
    }
    capture
        .record_evidence(
            "claim-task",
            "claim-context",
            &CompletionEvidence::Attestation {
                id: "attestation".to_owned(),
                subject_digest: content_digest(b"attested"),
                attestation: ClosedAttestation {
                    node_id: "node".to_owned(),
                    public_key: "SECRET_PUBLIC_KEY".to_owned(),
                    signature: "SECRET_SIGNATURE".to_owned(),
                },
                assurance_bps: 8_000,
            },
        )
        .await
        .unwrap();
    capture
        .record_evidence(
            "claim-task",
            "claim-context",
            &CompletionEvidence::Ratification(RatificationReceipt {
                statement: RatificationStatement {
                    policy_hash: "sha256:policy".to_owned(),
                    evidence_snapshot_hash: "sha256:evidence".to_owned(),
                    artifact_set_digest: content_digest(b"artifact"),
                    approved: false,
                },
                authority: ClosedAttestation {
                    node_id: "authority".to_owned(),
                    public_key: "SECRET_RATIFICATION_KEY".to_owned(),
                    signature: "SECRET_RATIFICATION_SIGNATURE".to_owned(),
                },
            }),
        )
        .await
        .unwrap();

    let trace = capture.snapshot().await;
    for kind in [
        RuntimeTraceKind::SignalReinforced,
        RuntimeTraceKind::SignalReceived,
        RuntimeTraceKind::SignalExpired,
        RuntimeTraceKind::PeerConnected,
        RuntimeTraceKind::PeerDisconnected,
    ] {
        assert!(trace.events.iter().any(|event| event.kind == kind));
    }
    assert!(trace.events.windows(2).all(|window| {
        window[0].sequence + 1 == window[1].sequence
            && window[0].monotonic_micros <= window[1].monotonic_micros
    }));
    assert!(trace.events.iter().any(|event| matches!(
        event.details,
        RuntimeTraceDetails::Claim {
            claim_kind: RuntimeClaimKind::Attestation,
            asserted_outcome: None,
            ..
        }
    )));
    assert!(trace.events.iter().any(|event| matches!(
        event.details,
        RuntimeTraceDetails::Claim {
            claim_kind: RuntimeClaimKind::Ratification,
            asserted_outcome: Some(false),
            ..
        }
    )));
    let encoded = serde_json::to_vec(&trace).unwrap();
    for secret in [
        b"SECRET_PEER_ID".as_slice(),
        b"SECRET_PUBLIC_KEY".as_slice(),
        b"SECRET_SIGNATURE".as_slice(),
        b"SECRET_RATIFICATION_KEY".as_slice(),
    ] {
        assert!(!encoded.windows(secret.len()).any(|window| window == secret));
    }

    let mut regressed = trace;
    regressed.events[0].monotonic_micros = 1;
    regressed.events[1].monotonic_micros = 0;
    assert!(RuntimeEventCapture::replay(&serde_json::to_vec(&regressed).unwrap()).is_err());
}

#[tokio::test]
async fn cancellation_trace_outcomes_are_typed_state_bound_and_round_trip() {
    let capture = RuntimeEventCapture::new(2, 1);
    capture
        .record_cancellation_terminal(
            "canceled-task",
            "canceled-context",
            RuntimeTerminalState::Canceled,
            RuntimeCancellationOutcome::CooperativeStop,
        )
        .await
        .unwrap();
    capture
        .record_cancellation_terminal(
            "forced-task",
            "forced-context",
            RuntimeTerminalState::Failed,
            RuntimeCancellationOutcome::ForcedAbort,
        )
        .await
        .unwrap();
    let trace = capture.snapshot().await;
    let encoded = serde_json::to_vec(&trace).unwrap();
    let decoded: smesh_a2a::RuntimeTrace = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded, trace);
    assert!(trace.events.iter().any(|event| {
        matches!(
            event.details,
            RuntimeTraceDetails::TerminalOutput {
                state: RuntimeTerminalState::Failed,
                cancellation_outcome: Some(RuntimeCancellationOutcome::ForcedAbort),
                ..
            }
        )
    }));

    let mut contradictory: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    contradictory["events"][1]["details"]["state"] = serde_json::json!("canceled");
    assert!(RuntimeEventCapture::replay(&serde_json::to_vec(&contradictory).unwrap()).is_err());
    contradictory["events"][1]["details"]["state"] = serde_json::json!("failed");
    contradictory["schemaVersion"] = serde_json::json!("runtime-trace/1");
    assert!(RuntimeEventCapture::replay(&serde_json::to_vec(&contradictory).unwrap()).is_err());

    let ordinary = RuntimeEventCapture::new(1, 1);
    ordinary
        .record_terminal(
            "completed-task",
            "completed-context",
            RuntimeTerminalState::Completed,
            Vec::new(),
        )
        .await
        .unwrap();
    let ordinary_json = serde_json::to_string(&ordinary.snapshot().await).unwrap();
    assert!(!ordinary_json.contains("cancellationOutcome"));

    let invalid = RuntimeEventCapture::new(1, 1);
    assert_eq!(
        invalid
            .record_cancellation_terminal(
                "invalid-task",
                "invalid-context",
                RuntimeTerminalState::Canceled,
                RuntimeCancellationOutcome::ForcedAbort,
            )
            .await
            .unwrap_err(),
        RuntimeTraceError::InvalidCorrelation
    );
}

#[tokio::test]
async fn canonical_trace_represents_every_gateway_terminal_state() {
    let capture = RuntimeEventCapture::new(5, 1);
    for state in [
        RuntimeTerminalState::Completed,
        RuntimeTerminalState::Failed,
        RuntimeTerminalState::InputRequired,
        RuntimeTerminalState::Rejected,
    ] {
        capture
            .record_terminal("terminal-task", "terminal-context", state, Vec::new())
            .await
            .unwrap();
    }
    capture
        .record_cancellation_terminal(
            "terminal-task",
            "terminal-context",
            RuntimeTerminalState::Canceled,
            RuntimeCancellationOutcome::CooperativeStop,
        )
        .await
        .unwrap();
    let trace = capture.snapshot().await;
    assert_eq!(trace.schema_version, "runtime-trace/2");
    assert_eq!(trace.events.len(), 5);
    assert!(trace.events.iter().all(|event| {
        event.kind == RuntimeTraceKind::TerminalOutput
            && matches!(event.details, RuntimeTraceDetails::TerminalOutput { .. })
    }));
}
