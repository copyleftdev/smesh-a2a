use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use a2a::{Message, Part, Role, StreamResponse, TaskState};
use a2a_server::{AgentExecutor, ExecutorContext};
use async_trait::async_trait;
use futures::StreamExt;
use futures::stream::{self, BoxStream};
use smesh_a2a::{
    ArtifactManifest, CompletionEvidence, CompletionPolicySpec, CompletionSnapshot, DispatchError,
    ExecutionBudget, ExecutionLimits, InputLimits, MeshDispatcher, MeshEvent, MeshRequest,
    PolicyDecision, RatificationReceipt, RatificationStatement, RuntimeCancellationOutcome,
    RuntimeEventCapture, RuntimeTerminalState, RuntimeTraceKind, SmeshExecutor, TrustedAuthority,
    VersionedCompletionPolicy, artifact_set_digest, content_digest,
};
use smesh_core::NodeIdentity;
use tokio::sync::{Barrier, Notify, mpsc};
use tokio_stream::wrappers::ReceiverStream;

#[derive(Clone, Default)]
struct RecordingDispatcher {
    requests: Arc<Mutex<Vec<MeshRequest>>>,
}

#[async_trait]
impl MeshDispatcher for RecordingDispatcher {
    fn dispatch(
        &self,
        request: MeshRequest,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        self.requests.lock().unwrap().push(request);
        let subject_digest = artifact_set_digest(&[ArtifactManifest {
            name: "review.md".into(),
            media_type: "text/markdown".into(),
            digest: content_digest(b"all clear"),
        }])
        .unwrap();
        Box::pin(stream::iter([
            Ok(MeshEvent::Progress("claimed by reviewer".into())),
            Ok(MeshEvent::Evidence(CompletionEvidence::Review {
                id: "review".into(),
                issuer: "review-authority".into(),
                subject_digest: subject_digest.clone(),
                evidence: b"review evidence".to_vec(),
                evidence_digest: content_digest(b"review evidence"),
                approved: true,
                assurance_bps: 9_000,
            })),
            Ok(MeshEvent::Evidence(CompletionEvidence::Test {
                id: "test".into(),
                issuer: "test-authority".into(),
                subject_digest: subject_digest.clone(),
                evidence: b"test evidence".to_vec(),
                evidence_digest: content_digest(b"test evidence"),
                passed: true,
                assurance_bps: 9_000,
            })),
            Ok(MeshEvent::Evidence(CompletionEvidence::Contradiction {
                id: "contradiction-clearance".into(),
                issuer: "contradiction-monitor".into(),
                subject_digest,
                evidence: b"contradiction clearance".to_vec(),
                evidence_digest: content_digest(b"contradiction clearance"),
                blocking: false,
            })),
            Ok(MeshEvent::Artifact {
                name: "review.md".into(),
                media_type: "text/markdown".into(),
                content: "all clear".into(),
            }),
            Ok(MeshEvent::Completed {
                summary: "review complete".into(),
            }),
        ]))
    }

    async fn cancel(&self, _task_id: &str) -> Result<(), DispatchError> {
        Ok(())
    }
}

fn context(text: &str) -> ExecutorContext {
    context_with_id("task-1", text)
}

fn context_with_id(task_id: &str, text: &str) -> ExecutorContext {
    ExecutorContext {
        message: Some(Message::new(Role::User, vec![Part::text(text)])),
        task_id: task_id.into(),
        stored_task: None,
        context_id: "context-1".into(),
        metadata: None,
        user: None,
        service_params: HashMap::new(),
        tenant: None,
    }
}

#[derive(Clone, Default)]
struct BudgetRecordingDispatcher {
    budgets: Arc<Mutex<Vec<ExecutionBudget>>>,
}

#[async_trait]
impl MeshDispatcher for BudgetRecordingDispatcher {
    fn dispatch(
        &self,
        request: MeshRequest,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        self.dispatch_bounded(request, ExecutionBudget::new(1, 1).unwrap())
    }

    fn dispatch_bounded(
        &self,
        _request: MeshRequest,
        budget: ExecutionBudget,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        self.budgets.lock().unwrap().push(budget);
        Box::pin(stream::empty())
    }

    async fn cancel(&self, _task_id: &str) -> Result<(), DispatchError> {
        Ok(())
    }
}

#[tokio::test]
async fn dispatcher_execution_budget_clamps_event_limit_to_protocol_bounds() {
    for (configured, expected) in [(0, 1), (17, 16)] {
        let dispatcher = BudgetRecordingDispatcher::default();
        let budgets = Arc::clone(&dispatcher.budgets);
        let executor = SmeshExecutor::new(dispatcher, InputLimits::default(), "gateway-node")
            .with_execution_limits(ExecutionLimits {
                max_events: configured,
                ..ExecutionLimits::default()
            });
        let _ = executor
            .execute(context("budget clamp"))
            .collect::<Vec<_>>()
            .await;
        assert_eq!(budgets.lock().unwrap()[0].max_event_count(), expected);
    }
}

#[tokio::test]
async fn executor_streams_work_artifact_and_terminal_completion() {
    let dispatcher = RecordingDispatcher::default();
    let recorded = dispatcher.requests.clone();
    let executor = SmeshExecutor::new(dispatcher, InputLimits::default(), "gateway-node");

    let events: Vec<_> = executor.execute(context("review it")).collect().await;
    let events: Vec<_> = events.into_iter().collect::<Result<_, _>>().unwrap();

    assert_eq!(recorded.lock().unwrap()[0].text, "review it");
    assert!(matches!(
        &events[0],
        StreamResponse::Task(task) if task.status.state == TaskState::Working
    ));
    assert!(matches!(&events[1], StreamResponse::StatusUpdate(_)));
    assert!(matches!(
        &events[2],
        StreamResponse::Task(task) if task.status.state == TaskState::Completed
    ));
    let StreamResponse::Task(completed) = &events[2] else {
        unreachable!();
    };
    assert_eq!(completed.artifacts.as_ref().map(Vec::len), Some(1));
    let metadata = completed.metadata.as_ref().unwrap();
    let policy = &metadata["smesh.completionPolicy"];
    assert_eq!(policy["status"], "accepted");
    assert!(
        policy["record"]["policyHash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:"))
    );
    assert!(
        policy["record"]["evidenceSnapshotHash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:"))
    );
    assert_eq!(
        policy["record"]["evidenceHashes"].as_array().map(Vec::len),
        Some(3)
    );
    assert_eq!(policy["record"]["assuranceBps"], 9_000);
}

#[tokio::test]
async fn executor_records_claim_contradiction_and_terminal_without_raw_evidence() {
    let capture = Arc::new(RuntimeEventCapture::new(16, 1));
    let executor = SmeshExecutor::new(
        RecordingDispatcher::default(),
        InputLimits::default(),
        "gateway-node",
    )
    .with_runtime_trace(Arc::clone(&capture));
    let events = executor
        .execute(context("trace policy lifecycle"))
        .collect::<Vec<_>>()
        .await;
    assert!(events.iter().all(Result::is_ok));

    let trace = capture.snapshot().await;
    assert_eq!(
        trace
            .events
            .iter()
            .filter(|event| event.kind == RuntimeTraceKind::Claim)
            .count(),
        2
    );
    assert!(
        trace
            .events
            .iter()
            .any(|event| event.kind == RuntimeTraceKind::Contradiction)
    );
    assert!(trace.events.iter().any(|event| {
        event.kind == RuntimeTraceKind::TerminalOutput
            && matches!(
                event.details,
                smesh_a2a::RuntimeTraceDetails::TerminalOutput {
                    state: RuntimeTerminalState::Completed,
                    ..
                }
            )
    }));
    let encoded = serde_json::to_vec(&trace).unwrap();
    for secret in [
        b"review evidence".as_slice(),
        b"test evidence".as_slice(),
        b"contradiction clearance".as_slice(),
    ] {
        assert!(!encoded.windows(secret.len()).any(|window| window == secret));
    }
}

#[derive(Clone)]
struct StaticDispatcher {
    events: Vec<MeshEvent>,
}

#[async_trait]
impl MeshDispatcher for StaticDispatcher {
    fn dispatch(
        &self,
        _request: MeshRequest,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        Box::pin(stream::iter(self.events.clone().into_iter().map(Ok)))
    }

    async fn cancel(&self, _task_id: &str) -> Result<(), DispatchError> {
        Ok(())
    }
}

fn machine_evidence(name: &str, media_type: &str, content: &str) -> Vec<CompletionEvidence> {
    let subject_digest = artifact_set_digest(&[ArtifactManifest {
        name: name.to_owned(),
        media_type: media_type.to_owned(),
        digest: content_digest(content.as_bytes()),
    }])
    .unwrap();
    vec![
        CompletionEvidence::Review {
            id: "review".into(),
            issuer: "review-authority".into(),
            subject_digest: subject_digest.clone(),
            evidence: b"review evidence".to_vec(),
            evidence_digest: content_digest(b"review evidence"),
            approved: true,
            assurance_bps: 9_000,
        },
        CompletionEvidence::Test {
            id: "test".into(),
            issuer: "test-authority".into(),
            subject_digest: subject_digest.clone(),
            evidence: b"test evidence".to_vec(),
            evidence_digest: content_digest(b"test evidence"),
            passed: true,
            assurance_bps: 9_000,
        },
        CompletionEvidence::Contradiction {
            id: "contradiction-clearance".into(),
            issuer: "contradiction-monitor".into(),
            subject_digest,
            evidence: b"contradiction clearance".to_vec(),
            evidence_digest: content_digest(b"contradiction clearance"),
            blocking: false,
        },
    ]
}

#[tokio::test]
async fn worker_completion_without_policy_evidence_cannot_publish_artifacts_or_complete() {
    let executor = SmeshExecutor::new(
        StaticDispatcher {
            events: vec![
                MeshEvent::Artifact {
                    name: "candidate.txt".into(),
                    media_type: "text/plain".into(),
                    content: "unreviewed".into(),
                },
                MeshEvent::Completed {
                    summary: "worker claims completion".into(),
                },
            ],
        },
        InputLimits::default(),
        "gateway-node",
    );

    let events = executor
        .execute(context("untrusted completion"))
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(!events.iter().any(|event| matches!(
        event,
        StreamResponse::ArtifactUpdate(_)
            | StreamResponse::Task(a2a::Task {
                status: a2a::TaskStatus {
                    state: TaskState::Completed,
                    ..
                },
                ..
            })
    )));
    assert!(matches!(
        events.last(),
        Some(StreamResponse::Task(task)) if task.status.state == TaskState::Failed
    ));
}

#[derive(Clone, Default)]
struct LeakyDispatcher;

#[async_trait]
impl MeshDispatcher for LeakyDispatcher {
    fn dispatch(
        &self,
        _request: MeshRequest,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        Box::pin(stream::iter([
            Ok(MeshEvent::Progress("SECRET-CANDIDATE-CONTENT".into())),
            Err(DispatchError::Message("SECRET-WORKER-ERROR".into())),
        ]))
    }

    async fn cancel(&self, _task_id: &str) -> Result<(), DispatchError> {
        Ok(())
    }
}

#[tokio::test]
async fn pre_acceptance_progress_and_errors_are_sanitized() {
    let executor = SmeshExecutor::new(LeakyDispatcher, InputLimits::default(), "gateway-node");
    let events = executor
        .execute(context("sanitize"))
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let encoded = serde_json::to_string(&events).unwrap();
    assert!(!encoded.contains("SECRET-CANDIDATE-CONTENT"));
    assert!(!encoded.contains("SECRET-WORKER-ERROR"));
    assert!(encoded.contains("SMESH worker reported progress"));
    assert!(encoded.contains("SMESH worker failed"));
}

#[tokio::test]
async fn duplicate_completion_proposals_fail_without_publishing_candidates() {
    let content = "candidate";
    let artifact = ArtifactManifest {
        name: "candidate.txt".into(),
        media_type: "text/plain".into(),
        digest: content_digest(content.as_bytes()),
    };
    let mut events = machine_evidence(&artifact.name, &artifact.media_type, content)
        .into_iter()
        .map(MeshEvent::Evidence)
        .collect::<Vec<_>>();
    events.extend([
        MeshEvent::Artifact {
            name: artifact.name,
            media_type: artifact.media_type,
            content: content.into(),
        },
        MeshEvent::Completed {
            summary: "first proposal".into(),
        },
        MeshEvent::Completed {
            summary: "second proposal".into(),
        },
    ]);
    let executor = SmeshExecutor::new(
        StaticDispatcher { events },
        InputLimits::default(),
        "gateway-node",
    );
    let result = executor
        .execute(context("duplicate completion"))
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(
        !result
            .iter()
            .any(|event| matches!(event, StreamResponse::ArtifactUpdate(_)))
    );
    assert!(matches!(
        result.last(),
        Some(StreamResponse::Task(task)) if task.status.state == TaskState::Failed
    ));
}

#[tokio::test]
async fn contradiction_after_completion_proposal_still_blocks_publication() {
    let content = "candidate";
    let artifact = ArtifactManifest {
        name: "candidate.txt".into(),
        media_type: "text/plain".into(),
        digest: content_digest(content.as_bytes()),
    };
    let subject = artifact_set_digest(std::slice::from_ref(&artifact)).unwrap();
    let mut events = machine_evidence(&artifact.name, &artifact.media_type, content)
        .into_iter()
        .map(MeshEvent::Evidence)
        .collect::<Vec<_>>();
    events.extend([
        MeshEvent::Artifact {
            name: artifact.name,
            media_type: artifact.media_type,
            content: content.into(),
        },
        MeshEvent::Completed {
            summary: "premature proposal".into(),
        },
        MeshEvent::Evidence(CompletionEvidence::Contradiction {
            id: "late-contradiction".into(),
            issuer: "contradiction-monitor".into(),
            subject_digest: subject,
            evidence: b"late contradiction evidence".to_vec(),
            evidence_digest: content_digest(b"late contradiction evidence"),
            blocking: true,
        }),
    ]);
    let executor = SmeshExecutor::new(
        StaticDispatcher { events },
        InputLimits::default(),
        "gateway-node",
    );

    let result = executor
        .execute(context("late contradiction"))
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(
        !result
            .iter()
            .any(|event| matches!(event, StreamResponse::ArtifactUpdate(_)))
    );
    assert!(matches!(
        result.last(),
        Some(StreamResponse::Task(task)) if task.status.state == TaskState::Failed
    ));
}

#[tokio::test]
async fn malformed_input_required_checkpoint_fails_closed_before_dispatch() {
    let executor = SmeshExecutor::new(EmptyDispatcher, InputLimits::default(), "gateway-node");
    let events = executor
        .execute(ExecutorContext {
            message: Some(Message::new(Role::User, vec![Part::text("approve")])),
            task_id: "task-1".into(),
            stored_task: Some(a2a::Task {
                id: "task-1".into(),
                context_id: "context-1".into(),
                status: a2a::TaskStatus {
                    state: TaskState::InputRequired,
                    message: None,
                    timestamp: None,
                },
                artifacts: None,
                history: None,
                metadata: None,
            }),
            context_id: "context-1".into(),
            metadata: None,
            user: None,
            service_params: HashMap::new(),
            tenant: None,
        })
        .collect::<Vec<_>>()
        .await;
    assert!(matches!(
        events.as_slice(),
        [Err(error)] if error.code == a2a::error_code::INVALID_AGENT_RESPONSE
    ));
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One end-to-end signed-ratification lifecycle.
async fn human_required_policy_waits_for_and_then_verifies_ratification() {
    let authority = NodeIdentity::generate_named("human-authority");
    let mut spec = CompletionPolicySpec::development();
    spec.require_human_ratification = true;
    spec.ratification_authorities = vec![TrustedAuthority {
        node_id: authority.node_id().to_owned(),
        public_key: authority.public_key_hex(),
    }];
    let policy = VersionedCompletionPolicy::new(spec).unwrap();
    let artifact = ArtifactManifest {
        name: "result.txt".into(),
        media_type: "text/plain".into(),
        digest: content_digest(b"accepted candidate"),
    };
    let evidence = machine_evidence(&artifact.name, &artifact.media_type, "accepted candidate");
    let snapshot = CompletionSnapshot {
        task_id: "task-1".into(),
        context_id: "context-1".into(),
        request_digest: content_digest(
            &serde_json::to_vec(&MeshRequest {
                protocol: "a2a-v1".into(),
                task_id: "task-1".into(),
                context_id: "context-1".into(),
                text: "ratify it".into(),
            })
            .unwrap(),
        ),
        artifacts: vec![artifact.clone()],
        evidence: evidence.clone(),
    };
    let PolicyDecision::AwaitingRatification(checkpoint) = policy.evaluate(&snapshot).unwrap()
    else {
        panic!("expected ratification checkpoint");
    };
    let statement = RatificationStatement {
        policy_hash: checkpoint.policy_hash,
        evidence_snapshot_hash: checkpoint.evidence_snapshot_hash,
        artifact_set_digest: checkpoint.artifact_set_digest,
        approved: true,
    };
    let receipt = RatificationReceipt {
        authority: authority.attest(&statement.digest().unwrap()).into(),
        statement,
    };

    let without_receipt = SmeshExecutor::new(
        StaticDispatcher {
            events: evidence
                .iter()
                .cloned()
                .map(MeshEvent::Evidence)
                .chain([
                    MeshEvent::Artifact {
                        name: artifact.name.clone(),
                        media_type: artifact.media_type.clone(),
                        content: "accepted candidate".into(),
                    },
                    MeshEvent::Completed {
                        summary: "candidate complete".into(),
                    },
                ])
                .collect(),
        },
        InputLimits::default(),
        "gateway-node",
    )
    .with_completion_policy(policy.clone());
    let waiting = without_receipt
        .execute(context("ratify it"))
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(
        !waiting
            .iter()
            .any(|event| matches!(event, StreamResponse::ArtifactUpdate(_)))
    );
    assert!(matches!(
        waiting.last(),
        Some(StreamResponse::Task(task)) if task.status.state == TaskState::InputRequired
    ));
    let StreamResponse::Task(waiting_task) = waiting.last().unwrap() else {
        unreachable!();
    };

    let mut ratified_evidence = evidence;
    ratified_evidence.push(CompletionEvidence::Ratification(receipt));
    let ratified = SmeshExecutor::new(
        StaticDispatcher {
            events: ratified_evidence
                .into_iter()
                .map(MeshEvent::Evidence)
                .chain([
                    MeshEvent::Artifact {
                        name: artifact.name,
                        media_type: artifact.media_type,
                        content: "accepted candidate".into(),
                    },
                    MeshEvent::Completed {
                        summary: "ratified complete".into(),
                    },
                ])
                .collect(),
        },
        InputLimits::default(),
        "gateway-node",
    )
    .with_completion_policy(policy);
    let completed = ratified
        .execute(ExecutorContext {
            message: Some(Message::new(Role::User, vec![Part::text("approve")])),
            task_id: "task-1".into(),
            stored_task: Some(waiting_task.clone()),
            context_id: "context-1".into(),
            metadata: None,
            user: None,
            service_params: HashMap::new(),
            tenant: None,
        })
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(matches!(
        completed.last(),
        Some(StreamResponse::Task(task))
            if task.status.state == TaskState::Completed
                && task.artifacts.as_ref().map(Vec::len) == Some(1)
    ));
}

#[derive(Clone, Default)]
struct EmptyDispatcher;

#[async_trait]
impl MeshDispatcher for EmptyDispatcher {
    fn dispatch(
        &self,
        _request: MeshRequest,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        Box::pin(stream::empty())
    }

    async fn cancel(&self, _task_id: &str) -> Result<(), DispatchError> {
        Ok(())
    }
}

#[tokio::test]
async fn executor_fails_a_task_if_the_mesh_stream_ends_without_a_terminal_event() {
    let executor = SmeshExecutor::new(EmptyDispatcher, InputLimits::default(), "gateway-node");

    let events: Vec<_> = executor.execute(context("review it")).collect().await;
    let events: Vec<_> = events.into_iter().collect::<Result<_, _>>().unwrap();

    assert!(matches!(
        events.last(),
        Some(StreamResponse::Task(task)) if task.status.state == TaskState::Failed
    ));
}

#[derive(Clone, Default)]
struct HoldingDispatcher {
    canceled: Arc<Mutex<Vec<String>>>,
    canceled_notify: Arc<Notify>,
}

#[async_trait]
impl MeshDispatcher for HoldingDispatcher {
    fn dispatch(
        &self,
        _request: MeshRequest,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        Box::pin(stream::pending())
    }

    async fn cancel(&self, task_id: &str) -> Result<(), DispatchError> {
        self.canceled.lock().unwrap().push(task_id.to_owned());
        self.canceled_notify.notify_waiters();
        Ok(())
    }
}

#[tokio::test]
async fn cancellation_wakes_and_closes_the_original_execution_stream() {
    let executor = SmeshExecutor::new(
        HoldingDispatcher::default(),
        InputLimits::default(),
        "gateway-node",
    );
    let mut execution = executor.execute(context("hold"));
    assert!(matches!(
        execution.next().await,
        Some(Ok(StreamResponse::Task(task))) if task.status.state == TaskState::Working
    ));

    let cancel_events: Vec<_> = executor
        .cancel(ExecutorContext {
            message: None,
            task_id: "task-1".into(),
            stored_task: None,
            context_id: "context-1".into(),
            metadata: None,
            user: None,
            service_params: HashMap::new(),
            tenant: None,
        })
        .collect()
        .await;
    assert!(cancel_events.is_empty());

    assert!(matches!(
        execution.next().await,
        Some(Ok(StreamResponse::Task(task))) if task.status.state == TaskState::Canceled
    ));
    let closed = tokio::time::timeout(Duration::from_millis(100), execution.next()).await;
    assert!(closed.unwrap().is_none());
}

#[derive(Clone, Default)]
struct ArtifactBurstDispatcher;

#[async_trait]
impl MeshDispatcher for ArtifactBurstDispatcher {
    fn dispatch(
        &self,
        _request: MeshRequest,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        Box::pin(stream::iter([
            Ok(MeshEvent::Artifact {
                name: "one".into(),
                media_type: "text/plain".into(),
                content: "one".into(),
            }),
            Ok(MeshEvent::Artifact {
                name: "two".into(),
                media_type: "text/plain".into(),
                content: "two".into(),
            }),
            Ok(MeshEvent::Completed {
                summary: "done".into(),
            }),
        ]))
    }

    async fn cancel(&self, _task_id: &str) -> Result<(), DispatchError> {
        Ok(())
    }
}

#[tokio::test]
async fn dropping_execution_stream_requests_dispatcher_cancellation() {
    let dispatcher = HoldingDispatcher::default();
    let canceled = Arc::clone(&dispatcher.canceled);
    let canceled_notify = Arc::clone(&dispatcher.canceled_notify);
    let executor = SmeshExecutor::new(dispatcher, InputLimits::default(), "gateway-node");
    let mut execution = executor.execute(context("drop"));
    assert!(matches!(
        execution.next().await,
        Some(Ok(StreamResponse::Task(task))) if task.status.state == TaskState::Working
    ));
    drop(execution);
    tokio::time::timeout(Duration::from_millis(100), async {
        loop {
            let notified = canceled_notify.notified();
            if !canceled.lock().unwrap().is_empty() {
                break;
            }
            notified.await;
        }
    })
    .await
    .unwrap();
    assert_eq!(canceled.lock().unwrap().as_slice(), ["task-1"]);
}

#[tokio::test]
async fn executor_fails_when_worker_exceeds_artifact_budget() {
    let executor = SmeshExecutor::new(
        ArtifactBurstDispatcher,
        InputLimits::default(),
        "gateway-node",
    )
    .with_execution_limits(ExecutionLimits {
        max_artifacts: 1,
        ..ExecutionLimits::default()
    });

    let events: Vec<_> = executor.execute(context("burst")).collect().await;
    let events: Vec<_> = events.into_iter().collect::<Result<_, _>>().unwrap();

    assert!(matches!(
        events.last(),
        Some(StreamResponse::Task(task)) if task.status.state == TaskState::Failed
    ));
}

#[tokio::test]
async fn executor_fails_after_worker_inactivity_timeout() {
    let dispatcher = HoldingDispatcher::default();
    let canceled = Arc::clone(&dispatcher.canceled);
    let executor = SmeshExecutor::new(dispatcher, InputLimits::default(), "gateway-node")
        .with_execution_limits(ExecutionLimits {
            worker_idle_timeout: Duration::from_millis(10),
            ..ExecutionLimits::default()
        });

    let events = tokio::time::timeout(
        Duration::from_millis(100),
        executor.execute(context("idle")).collect::<Vec<_>>(),
    )
    .await
    .unwrap();
    let events: Vec<_> = events.into_iter().collect::<Result<_, _>>().unwrap();

    assert!(matches!(
        events.last(),
        Some(StreamResponse::Task(task)) if task.status.state == TaskState::Failed
    ));
    assert_eq!(canceled.lock().unwrap().as_slice(), ["task-1"]);
}

#[tokio::test]
async fn executor_fails_after_total_task_deadline() {
    let dispatcher = HoldingDispatcher::default();
    let canceled = Arc::clone(&dispatcher.canceled);
    let executor = SmeshExecutor::new(dispatcher, InputLimits::default(), "gateway-node")
        .with_execution_limits(ExecutionLimits {
            worker_idle_timeout: Duration::from_secs(1),
            task_timeout: Duration::from_millis(10),
            ..ExecutionLimits::default()
        });

    let events = tokio::time::timeout(
        Duration::from_millis(100),
        executor.execute(context("deadline")).collect::<Vec<_>>(),
    )
    .await
    .unwrap();
    let events: Vec<_> = events.into_iter().collect::<Result<_, _>>().unwrap();
    assert!(matches!(
        events.last(),
        Some(StreamResponse::Task(task)) if task.status.state == TaskState::Failed
    ));
    assert_eq!(canceled.lock().unwrap().as_slice(), ["task-1"]);
}

#[tokio::test]
async fn executor_rejects_work_above_concurrency_limit() {
    let executor = SmeshExecutor::new(
        HoldingDispatcher::default(),
        InputLimits::default(),
        "gateway-node",
    )
    .with_execution_limits(ExecutionLimits {
        max_concurrent_tasks: 1,
        ..ExecutionLimits::default()
    });
    let mut first = executor.execute(context_with_id("first", "hold"));
    assert!(matches!(
        first.next().await,
        Some(Ok(StreamResponse::Task(task))) if task.status.state == TaskState::Working
    ));

    let second = tokio::time::timeout(
        Duration::from_millis(100),
        executor
            .execute(context_with_id("second", "overflow"))
            .collect::<Vec<_>>(),
    )
    .await
    .unwrap();
    let second: Vec<_> = second.into_iter().collect::<Result<_, _>>().unwrap();
    assert!(matches!(
        second.as_slice(),
        [StreamResponse::Task(task)] if task.status.state == TaskState::Rejected
    ));

    let _ = executor
        .cancel(ExecutorContext {
            message: None,
            task_id: "first".into(),
            stored_task: None,
            context_id: "context-1".into(),
            metadata: None,
            user: None,
            service_params: HashMap::new(),
            tenant: None,
        })
        .collect::<Vec<_>>()
        .await;
}

#[derive(Clone, Default)]
struct SeventeenEventDispatcher;

#[async_trait]
impl MeshDispatcher for SeventeenEventDispatcher {
    fn dispatch(
        &self,
        _request: MeshRequest,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        let mut events = (0..16)
            .map(|index| Ok(MeshEvent::Progress(format!("progress-{index}"))))
            .collect::<Vec<_>>();
        events.push(Ok(MeshEvent::Completed {
            summary: "should exceed clamped budget".into(),
        }));
        Box::pin(stream::iter(events))
    }

    async fn cancel(&self, _task_id: &str) -> Result<(), DispatchError> {
        Ok(())
    }
}

#[tokio::test]
async fn caller_supplied_event_budget_is_clamped_below_a2a_broadcast_capacity() {
    let executor = SmeshExecutor::new(
        SeventeenEventDispatcher,
        InputLimits::default(),
        "gateway-node",
    )
    .with_execution_limits(ExecutionLimits {
        max_events: 256,
        ..ExecutionLimits::default()
    });

    let events: Vec<_> = executor.execute(context("clamp")).collect().await;
    let events: Vec<_> = events.into_iter().collect::<Result<_, _>>().unwrap();
    assert!(matches!(
        events.last(),
        Some(StreamResponse::Task(task)) if task.status.state == TaskState::Failed
    ));
}

#[derive(Clone, Default)]
struct CompletionCancelRaceDispatcher {
    completion_release: Arc<Notify>,
    cancel_started: Arc<Notify>,
    cancel_ack_release: Arc<Notify>,
}

#[async_trait]
impl MeshDispatcher for CompletionCancelRaceDispatcher {
    fn dispatch(
        &self,
        _request: MeshRequest,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        let completion_release = Arc::clone(&self.completion_release);
        let (tx, rx) = mpsc::channel(16);
        tokio::spawn(async move {
            completion_release.notified().await;
            let content = "race candidate";
            for evidence in machine_evidence("race.txt", "text/plain", content) {
                let _ = tx.send(Ok(MeshEvent::Evidence(evidence))).await;
            }
            let _ = tx
                .send(Ok(MeshEvent::Artifact {
                    name: "race.txt".to_owned(),
                    media_type: "text/plain".to_owned(),
                    content: content.to_owned(),
                }))
                .await;
            let _ = tx
                .send(Ok(MeshEvent::Completed {
                    summary: "completion raced cancellation".to_owned(),
                }))
                .await;
        });
        Box::pin(ReceiverStream::new(rx))
    }

    async fn cancel(&self, _task_id: &str) -> Result<(), DispatchError> {
        self.cancel_started.notify_one();
        self.cancel_ack_release.notified().await;
        Ok(())
    }
}

#[tokio::test]
async fn accepted_cancel_request_suppresses_completion_while_ack_is_pending() {
    let dispatcher = CompletionCancelRaceDispatcher::default();
    let completion_release = Arc::clone(&dispatcher.completion_release);
    let cancel_started = Arc::clone(&dispatcher.cancel_started);
    let cancel_ack_release = Arc::clone(&dispatcher.cancel_ack_release);
    let capture = Arc::new(RuntimeEventCapture::new(4, 1));
    let executor = SmeshExecutor::new(dispatcher, InputLimits::default(), "gateway-node")
        .with_runtime_trace(Arc::clone(&capture));
    let mut execution = executor.execute(context("race completion and cancellation"));
    assert!(matches!(
        execution.next().await,
        Some(Ok(StreamResponse::Task(task))) if task.status.state == TaskState::Working
    ));
    let cancel = tokio::spawn(async move {
        executor
            .cancel(ExecutorContext {
                message: None,
                task_id: "task-1".to_owned(),
                stored_task: None,
                context_id: "context-1".to_owned(),
                metadata: None,
                user: None,
                service_params: HashMap::new(),
                tenant: None,
            })
            .collect::<Vec<_>>()
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), cancel_started.notified())
        .await
        .unwrap();
    completion_release.notify_one();

    assert!(
        tokio::time::timeout(Duration::from_millis(10), execution.next())
            .await
            .is_err()
    );
    assert!(!cancel.is_finished());
    cancel_ack_release.notify_one();
    let cancel_events = cancel.await.unwrap();
    assert!(cancel_events.is_empty());
    assert!(matches!(
        execution.next().await,
        Some(Ok(StreamResponse::Task(task))) if task.status.state == TaskState::Canceled
    ));
    let trace = capture.snapshot().await;
    assert!(trace.events.iter().any(|event| {
        matches!(
            event.details,
            smesh_a2a::RuntimeTraceDetails::TerminalOutput {
                state: RuntimeTerminalState::Canceled,
                cancellation_outcome: Some(RuntimeCancellationOutcome::CooperativeStop),
                ..
            }
        )
    }));
}

#[derive(Clone)]
struct InvalidArtifactCancelRaceDispatcher {
    content: String,
    invalid_release: Arc<Barrier>,
    cancel_started: Arc<Barrier>,
    cancel_ack_release: Arc<Barrier>,
    cancel_calls: Arc<AtomicUsize>,
    cancel_joined: Arc<AtomicBool>,
}

impl InvalidArtifactCancelRaceDispatcher {
    fn new(content: &str) -> Self {
        Self {
            content: content.to_owned(),
            invalid_release: Arc::new(Barrier::new(2)),
            cancel_started: Arc::new(Barrier::new(2)),
            cancel_ack_release: Arc::new(Barrier::new(2)),
            cancel_calls: Arc::new(AtomicUsize::new(0)),
            cancel_joined: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[async_trait]
impl MeshDispatcher for InvalidArtifactCancelRaceDispatcher {
    fn dispatch(
        &self,
        _request: MeshRequest,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        let invalid_release = Arc::clone(&self.invalid_release);
        let content = self.content.clone();
        let (tx, rx) = mpsc::channel(1);
        tokio::spawn(async move {
            invalid_release.wait().await;
            let _ = tx
                .send(Ok(MeshEvent::Artifact {
                    name: "invalid.bin".to_owned(),
                    media_type: "application/octet-stream".to_owned(),
                    content,
                }))
                .await;
        });
        Box::pin(ReceiverStream::new(rx))
    }

    async fn cancel(&self, _task_id: &str) -> Result<(), DispatchError> {
        self.cancel_calls.fetch_add(1, Ordering::SeqCst);
        self.cancel_started.wait().await;
        self.cancel_ack_release.wait().await;
        self.cancel_joined.store(true, Ordering::SeqCst);
        Ok(())
    }
}

async fn assert_cancel_wins_invalid_internal_artifact(content: &str) {
    let dispatcher = InvalidArtifactCancelRaceDispatcher::new(content);
    let invalid_release = Arc::clone(&dispatcher.invalid_release);
    let cancel_started = Arc::clone(&dispatcher.cancel_started);
    let cancel_ack_release = Arc::clone(&dispatcher.cancel_ack_release);
    let cancel_calls = Arc::clone(&dispatcher.cancel_calls);
    let cancel_joined = Arc::clone(&dispatcher.cancel_joined);
    let capture = Arc::new(RuntimeEventCapture::new(4, 1));
    let executor = SmeshExecutor::new(dispatcher, InputLimits::default(), "gateway-node")
        .with_runtime_trace(Arc::clone(&capture));
    let mut execution = executor.execute(context("cancel before invalid internal artifact"));
    assert!(matches!(
        execution.next().await,
        Some(Ok(StreamResponse::Task(task))) if task.status.state == TaskState::Working
    ));

    let cancel = tokio::spawn(async move {
        executor
            .cancel(ExecutorContext {
                message: None,
                task_id: "task-1".to_owned(),
                stored_task: None,
                context_id: "context-1".to_owned(),
                metadata: None,
                user: None,
                service_params: HashMap::new(),
                tenant: None,
            })
            .collect::<Vec<_>>()
            .await
    });
    cancel_started.wait().await;
    invalid_release.wait().await;
    assert!(
        tokio::time::timeout(Duration::from_millis(10), execution.next())
            .await
            .is_err()
    );
    assert!(!cancel.is_finished());
    cancel_ack_release.wait().await;

    assert!(cancel.await.unwrap().is_empty());
    let remaining = tokio::time::timeout(Duration::from_secs(1), execution.collect::<Vec<_>>())
        .await
        .unwrap()
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(matches!(
        remaining.as_slice(),
        [StreamResponse::Task(task)] if task.status.state == TaskState::Canceled
    ));
    assert_eq!(cancel_calls.load(Ordering::SeqCst), 1);
    assert!(cancel_joined.load(Ordering::SeqCst));

    let trace = capture.snapshot().await;
    let terminals = trace
        .events
        .iter()
        .filter(|event| event.kind == RuntimeTraceKind::TerminalOutput)
        .collect::<Vec<_>>();
    assert_eq!(terminals.len(), 1);
    assert!(matches!(
        terminals[0].details,
        smesh_a2a::RuntimeTraceDetails::TerminalOutput {
            state: RuntimeTerminalState::Canceled,
            cancellation_outcome: Some(RuntimeCancellationOutcome::CooperativeStop),
            ..
        }
    ));
}

#[tokio::test]
async fn cancellation_owns_terminal_when_invalid_internal_base64_arrives() {
    assert_cancel_wins_invalid_internal_artifact(
        r#"smesh-internal-artifact/v1:{"kind":"binary","bytes":"***"}"#,
    )
    .await;
}

#[tokio::test]
async fn cancellation_owns_terminal_when_invalid_published_projection_arrives() {
    assert_cancel_wins_invalid_internal_artifact(
        r#"smesh-internal-artifact/v1:{"kind":"published","projection":"not-json"}"#,
    )
    .await;
}

#[tokio::test]
async fn dropping_cancel_response_stream_does_not_abandon_terminal_publication() {
    let dispatcher = CompletionCancelRaceDispatcher::default();
    let cancel_started = Arc::clone(&dispatcher.cancel_started);
    let cancel_ack_release = Arc::clone(&dispatcher.cancel_ack_release);
    let executor = SmeshExecutor::new(dispatcher, InputLimits::default(), "gateway-node");
    let mut execution = executor.execute(context("drop cancel response"));
    assert!(matches!(
        execution.next().await,
        Some(Ok(StreamResponse::Task(task))) if task.status.state == TaskState::Working
    ));
    let cancel = executor.cancel(ExecutorContext {
        message: None,
        task_id: "task-1".to_owned(),
        stored_task: None,
        context_id: "context-1".to_owned(),
        metadata: None,
        user: None,
        service_params: HashMap::new(),
        tenant: None,
    });
    drop(cancel);
    tokio::time::timeout(Duration::from_secs(1), cancel_started.notified())
        .await
        .unwrap();
    cancel_ack_release.notify_one();
    assert!(matches!(
        execution.next().await,
        Some(Ok(StreamResponse::Task(task))) if task.status.state == TaskState::Canceled
    ));
}

#[derive(Clone, Default)]
struct CancelFailureDispatcher;

#[async_trait]
impl MeshDispatcher for CancelFailureDispatcher {
    fn dispatch(
        &self,
        _request: MeshRequest,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        Box::pin(stream::pending())
    }

    async fn cancel(&self, _task_id: &str) -> Result<(), DispatchError> {
        Err(DispatchError::Message(
            "dropped cancellation acknowledgement".to_owned(),
        ))
    }
}

#[tokio::test]
async fn failed_cancellation_acknowledgement_fails_task_and_closes_execution() {
    let capture = Arc::new(RuntimeEventCapture::new(4, 1));
    let executor = SmeshExecutor::new(
        CancelFailureDispatcher,
        InputLimits::default(),
        "gateway-node",
    )
    .with_runtime_trace(Arc::clone(&capture));
    let mut execution = executor.execute(context("cancel failure"));
    assert!(matches!(
        execution.next().await,
        Some(Ok(StreamResponse::Task(task))) if task.status.state == TaskState::Working
    ));
    let cancel_events = executor
        .cancel(ExecutorContext {
            message: None,
            task_id: "task-1".to_owned(),
            stored_task: None,
            context_id: "context-1".to_owned(),
            metadata: None,
            user: None,
            service_params: HashMap::new(),
            tenant: None,
        })
        .collect::<Vec<_>>()
        .await;
    assert!(cancel_events.is_empty());
    assert!(matches!(
        execution.next().await,
        Some(Ok(StreamResponse::Task(task))) if task.status.state == TaskState::Failed
    ));
    let trace = capture.snapshot().await;
    assert!(trace.events.iter().any(|event| {
        matches!(
            event.details,
            smesh_a2a::RuntimeTraceDetails::TerminalOutput {
                state: RuntimeTerminalState::Failed,
                cancellation_outcome: Some(RuntimeCancellationOutcome::Failed),
                ..
            }
        )
    }));
    assert!(
        tokio::time::timeout(Duration::from_secs(1), execution.next())
            .await
            .unwrap()
            .is_none()
    );
}

#[derive(Clone, Default)]
struct ForcedAbortCancellationDispatcher;

#[async_trait]
impl MeshDispatcher for ForcedAbortCancellationDispatcher {
    fn dispatch(
        &self,
        _request: MeshRequest,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        Box::pin(stream::pending())
    }

    async fn cancel(&self, _task_id: &str) -> Result<(), DispatchError> {
        Err(DispatchError::CancellationForcedAbort)
    }
}

#[tokio::test]
async fn forced_abort_cancellation_fails_closed_and_records_containment_outcome() {
    let capture = Arc::new(RuntimeEventCapture::new(4, 1));
    let executor = SmeshExecutor::new(
        ForcedAbortCancellationDispatcher,
        InputLimits::default(),
        "gateway-node",
    )
    .with_runtime_trace(Arc::clone(&capture));
    let mut execution = executor.execute(context("forced abort cancellation"));
    assert!(matches!(
        execution.next().await,
        Some(Ok(StreamResponse::Task(task))) if task.status.state == TaskState::Working
    ));

    let cancel_events = executor
        .cancel(ExecutorContext {
            message: None,
            task_id: "task-1".to_owned(),
            stored_task: None,
            context_id: "context-1".to_owned(),
            metadata: None,
            user: None,
            service_params: HashMap::new(),
            tenant: None,
        })
        .collect::<Vec<_>>()
        .await;
    assert!(cancel_events.is_empty());
    let terminal = execution.next().await.unwrap().unwrap();
    let StreamResponse::Task(task) = terminal else {
        panic!("forced abort must publish a terminal task");
    };
    assert_eq!(task.status.state, TaskState::Failed);
    let message = task.status.message.unwrap();
    assert!(matches!(
        message.parts.as_slice(),
        [Part { content: a2a::PartContent::Text(text), .. }]
            if text.contains("forced") && text.contains("containment")
    ));

    let trace = capture.snapshot().await;
    assert!(trace.events.iter().any(|event| {
        matches!(
            event.details,
            smesh_a2a::RuntimeTraceDetails::TerminalOutput {
                state: RuntimeTerminalState::Failed,
                cancellation_outcome: Some(RuntimeCancellationOutcome::ForcedAbort),
                ..
            }
        )
    }));
}

#[tokio::test]
async fn committed_completion_rejects_late_cancellation_without_second_terminal() {
    let dispatcher = CompletionCancelRaceDispatcher::default();
    let completion_release = Arc::clone(&dispatcher.completion_release);
    let executor = SmeshExecutor::new(dispatcher, InputLimits::default(), "gateway-node");
    let mut execution = executor.execute(context("completion wins"));
    assert!(matches!(
        execution.next().await,
        Some(Ok(StreamResponse::Task(task))) if task.status.state == TaskState::Working
    ));
    completion_release.notify_one();
    let remaining = execution
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(matches!(
        remaining.last(),
        Some(StreamResponse::Task(task)) if task.status.state == TaskState::Completed
    ));

    let cancel = executor
        .cancel(ExecutorContext {
            message: None,
            task_id: "task-1".to_owned(),
            stored_task: None,
            context_id: "context-1".to_owned(),
            metadata: None,
            user: None,
            service_params: HashMap::new(),
            tenant: None,
        })
        .collect::<Vec<_>>()
        .await;
    assert!(matches!(
        cancel.as_slice(),
        [Err(error)] if error.code == a2a::error_code::TASK_NOT_CANCELABLE
    ));
}
