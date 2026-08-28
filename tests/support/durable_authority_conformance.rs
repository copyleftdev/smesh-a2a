#![allow(dead_code, clippy::too_many_lines)]

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use a2a::{
    A2AError, ListTasksRequest, ListTasksResponse, Message, Part, Role, SendMessageRequest,
    SendMessageResponse, StreamResponse, Task, TaskState, TaskStatus, TaskStatusUpdateEvent,
};
use async_trait::async_trait;
use smesh_a2a::{
    AdmissionOutcome, AdmissionRecord, AtomicRecordCounts, AttemptDisposition,
    AuthorityDiagnostics, AuthorityIdentity, AuthorityShutdown, AuthorizationAuditInput,
    AuthorizationAuditSink, AuthorizationDecisionEffect, AuthorizedTaskRead, CancellationAuthority,
    CancellationOutcome, ChangeObservation, ChangeObserver, DurableAuthority,
    DurableDispatchEnvelope, DurableReceiverResult, DurableReceiverTermination, InputLimits,
    MeshEvent, MeshRequest, OutboxAuthority, OutboxLease, OwnedTaskScope, ReceiverAdmission,
    ReceiverAuthority, ReceiverLease, SendMessageAdmission, StreamTranscriptBatch,
    SubscriptionCursor, TaskAdmission, TaskEventBatch, TaskLifecycle, TranscriptAuthority,
    TransitionOutcome, VisibilityScope, authorized_message_identity, content_digest,
};

const NOW: i64 = 1_700_000_000_000;
const TENANT: &str = "tenant-conformance";
const OWNER: &str = "owner-conformance";
const TASK_ID: &str = "task-conformance";
const MESSAGE_ID: &str = "message-conformance";
const DISPATCH_ID: &str = "dispatch-conformance";

fn task(state: TaskState) -> Task {
    Task {
        id: TASK_ID.to_owned(),
        context_id: "context-conformance".to_owned(),
        status: TaskStatus {
            state,
            message: None,
            timestamp: chrono::DateTime::from_timestamp_millis(NOW),
        },
        artifacts: None,
        history: None,
        metadata: None,
    }
}

fn progress_frame() -> StreamResponse {
    StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
        task_id: TASK_ID.to_owned(),
        context_id: "context-conformance".to_owned(),
        status: TaskStatus {
            state: TaskState::Working,
            message: None,
            timestamp: chrono::DateTime::from_timestamp_millis(NOW + 1),
        },
        metadata: None,
    })
}

fn request(text: &str) -> SendMessageRequest {
    let mut message = Message::new(Role::User, vec![Part::text(text)]);
    MESSAGE_ID.clone_into(&mut message.message_id);
    SendMessageRequest {
        message,
        configuration: None,
        metadata: None,
        tenant: None,
    }
}

fn audit(
    id: &str,
    operation: &str,
    effect: AuthorizationDecisionEffect,
) -> AuthorizationAuditInput {
    audit_with_reason(
        id,
        operation,
        effect,
        if effect == AuthorizationDecisionEffect::Allow {
            "grant"
        } else {
            "deny"
        },
    )
}

fn audit_with_reason(
    id: &str,
    operation: &str,
    effect: AuthorizationDecisionEffect,
    reason: &str,
) -> AuthorizationAuditInput {
    AuthorizationAuditInput::new(
        id,
        TENANT,
        OWNER,
        "policy-conformance",
        9,
        "sha256:policy-conformance",
        operation,
        effect,
        reason,
        "task",
        format!("sha256:resource-{id}"),
        Some(TASK_ID.to_owned()),
        NOW,
    )
    .expect("valid conformance audit")
}

fn denied_audit_without_task(id: &str, operation: &str) -> AuthorizationAuditInput {
    AuthorizationAuditInput::new(
        id,
        TENANT,
        OWNER,
        "policy-conformance",
        9,
        "sha256:policy-conformance",
        operation,
        AuthorizationDecisionEffect::Deny,
        "deny",
        "task",
        format!("sha256:resource-{id}"),
        None,
        NOW,
    )
    .expect("valid denied conformance audit")
}

fn allowed_audit_without_task(id: &str, operation: &str, reason: &str) -> AuthorizationAuditInput {
    AuthorizationAuditInput::new(
        id,
        TENANT,
        OWNER,
        "policy-conformance",
        9,
        "sha256:policy-conformance",
        operation,
        AuthorizationDecisionEffect::Allow,
        reason,
        "task",
        format!("sha256:resource-{id}"),
        None,
        NOW,
    )
    .expect("valid standalone allowed conformance audit")
}

fn command(text: &str) -> SendMessageAdmission {
    let request = request(text);
    let mut admitted = task(TaskState::Submitted);
    admitted.history = Some(vec![request.message.clone()]);
    SendMessageAdmission {
        request,
        streaming: true,
        task: admitted.clone(),
        original_result: SendMessageResponse::Task(admitted),
        input_limits: InputLimits::default(),
        now: NOW,
        max_attempts: 4,
    }
}

fn outbox_lease() -> OutboxLease {
    OutboxLease {
        tenant_scope: TENANT.to_owned(),
        outbox_id: 41,
        dispatch_id: DISPATCH_ID.to_owned(),
        task_id: TASK_ID.to_owned(),
        attempt_no: 1,
        max_attempts: 4,
        lease_owner: "sender-conformance".to_owned(),
        lease_token: "sender-fence-conformance".to_owned(),
        lease_until: NOW + 500,
        request: MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: TASK_ID.to_owned(),
            context_id: "context-conformance".to_owned(),
            text: "work-conformance".to_owned(),
        },
    }
}

fn receiver_lease() -> ReceiverLease {
    ReceiverLease {
        tenant_scope: TENANT.to_owned(),
        dispatch_id: DISPATCH_ID.to_owned(),
        payload_digest: "sha256:payload-conformance".to_owned(),
        lease_owner: "receiver-conformance".to_owned(),
        lease_token: "receiver-fence-conformance".to_owned(),
        lease_epoch: 3,
        lease_until: NOW + 700,
    }
}

/// Runs the backend-neutral command contract directly against an authority.
/// Every await is watchdog-bounded; the function owns and verifies shutdown.
pub async fn run_durable_authority_command_conformance(authority: Arc<dyn DurableAuthority>) {
    tokio::time::timeout(Duration::from_secs(5), async move {
        assert!(authority.completion_receipt_key().is_some());
        let digest = authority
            .authorization_resource_digest("resource-conformance")
            .unwrap();
        assert!(!digest.is_empty());
        assert_eq!(
            digest,
            authority
                .authorization_resource_digest("resource-conformance")
                .unwrap()
        );
        let poll = authority.change_observation().poll_interval().as_duration();
        assert!((Duration::from_millis(10)..=Duration::from_secs(5)).contains(&poll));

        authority
            .append_denied_authorization_decision(denied_audit_without_task(
                "audit-denial",
                "TaskGet",
            ))
            .await
            .unwrap();
        authority
            .append_authorization_decision(allowed_audit_without_task(
                "audit-failure",
                "TaskGet",
                "grant",
            ))
            .await
            .unwrap();
        assert!(
            authority
                .append_authorization_decision(allowed_audit_without_task(
                    "audit-failure",
                    "TaskGet",
                    "conflicting-grant",
                ))
                .await
                .is_err()
        );

        let scope = OwnedTaskScope::new(TENANT, OWNER, VisibilityScope::Own).unwrap();
        assert!(
            authority
                .replay_authorized(
                    &scope,
                    OWNER,
                    &request("work-conformance"),
                    true,
                    audit(
                        "audit-replay-miss",
                        "TaskCreate",
                        AuthorizationDecisionEffect::Allow
                    ),
                )
                .await
                .unwrap()
                .is_none()
        );
        let admitted = authority
            .authorize_and_admit(
                &scope,
                command("work-conformance"),
                audit(
                    "audit-admit",
                    "TaskCreate",
                    AuthorizationDecisionEffect::Allow,
                ),
            )
            .await
            .unwrap();
        let AdmissionOutcome::Admitted(record) = admitted else {
            panic!("first admission must be new")
        };
        assert_eq!(record.task_id, TASK_ID);
        assert_eq!(record.revision, 1);
        assert!(!record.dispatch_id.is_empty());
        assert!(matches!(authority.replay_authorized(
            &scope,
            OWNER,
            &request("work-conformance"),
            true,
            audit("audit-replay-hit", "TaskCreate", AuthorizationDecisionEffect::Allow),
        ).await.unwrap(), Some(SendMessageResponse::Task(value)) if value.id == TASK_ID));
        assert!(
            authority
                .authorize_and_admit(
                    &scope,
                    command("conflicting-work"),
                    audit(
                        "audit-conflict",
                        "TaskCreate",
                        AuthorizationDecisionEffect::Allow
                    ),
                )
                .await
                .is_err()
        );

        assert_eq!(
            authority
                .get_authorized(
                    &scope,
                    TASK_ID,
                    audit("audit-get", "TaskGet", AuthorizationDecisionEffect::Allow),
                )
                .await
                .unwrap()
                .unwrap()
                .id,
            TASK_ID
        );
        let page = authority
            .list_authorized(
                &scope,
                &ListTasksRequest {
                    context_id: None,
                    status: None,
                    page_size: Some(1),
                    page_token: None,
                    history_length: None,
                    status_timestamp_after: None,
                    include_artifacts: Some(false),
                    tenant: None,
                },
                audit("audit-list", "TaskList", AuthorizationDecisionEffect::Allow),
                "cursor-scope-conformance",
            )
            .await
            .unwrap();
        assert_eq!(page.tasks.len(), 1);
        assert_eq!(page.tasks[0].id, TASK_ID);

        let lease = authority
            .claim_outbox("sender-conformance", NOW, 500)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(lease.tenant_scope, TENANT);
        assert_eq!(lease.task_id, TASK_ID);
        assert_eq!(lease.dispatch_id, record.dispatch_id);
        assert_eq!(lease.lease_owner, "sender-conformance");
        assert_eq!(lease.lease_until, NOW + 500);
        assert!(!lease.lease_token.is_empty());
        let admitted_task = authority.task_for_outbox(&lease).await.unwrap().unwrap();
        assert_eq!(admitted_task.id, TASK_ID);
        let frame = progress_frame();
        let committed_progress = authority
            .append_stream_progress(TENANT, &lease.dispatch_id, frame.clone(), NOW + 1)
            .await
            .unwrap();
        assert!(
            committed_progress
                .as_ref()
                .is_none_or(|value| value == &frame)
        );

        let payload = serde_json::to_vec(&lease.request).unwrap();
        let envelope = DurableDispatchEnvelope {
            tenant_scope: TENANT.to_owned(),
            dispatch_id: lease.dispatch_id.clone(),
            payload_digest: content_digest(&payload),
            request: lease.request.clone(),
        };
        let receiver = authority
            .begin_receive(envelope, "receiver-conformance", NOW, 700)
            .await
            .unwrap();
        let ReceiverAdmission::Execute(receiver) = receiver else {
            panic!("first receive must execute")
        };
        assert_eq!(receiver.tenant_scope, TENANT);
        assert_eq!(receiver.dispatch_id, lease.dispatch_id);
        assert_eq!(receiver.lease_owner, "receiver-conformance");
        assert_eq!(receiver.lease_until, NOW + 700);
        assert!(!receiver.lease_token.is_empty());
        assert!(
            !authority
                .cancellation_requested(&lease.dispatch_id)
                .await
                .unwrap()
        );
        let events = vec![
            MeshEvent::Progress("progress-conformance".to_owned()),
            MeshEvent::Completed {
                summary: "complete-conformance".to_owned(),
            },
        ];
        authority
            .complete_loopback_receive(&receiver, &events, NOW + 2)
            .await
            .unwrap();
        assert!(
            authority
                .complete_loopback_outcome(
                    &receiver,
                    &DurableReceiverResult {
                        events: events.clone(),
                        termination: DurableReceiverTermination::Success,
                    },
                    NOW + 2
                )
                .await
                .is_err()
        );
        assert!(
            authority
                .complete_canceled_receive(&receiver, &events, NOW + 2)
                .await
                .is_err()
        );

        let mut completed = admitted_task.clone();
        completed.status = TaskStatus {
            state: TaskState::Completed,
            message: None,
            timestamp: chrono::DateTime::from_timestamp_millis(NOW + 3),
        };
        let terminal_frame = StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
            task_id: completed.id.clone(),
            context_id: completed.context_id.clone(),
            status: completed.status.clone(),
            metadata: None,
        });
        let public_transcript = [
            StreamResponse::Task(admitted_task),
            frame.clone(),
            terminal_frame,
        ];
        assert_eq!(
            authority
                .commit_delivery(
                    &lease,
                    completed.clone(),
                    SendMessageResponse::Task(completed.clone()),
                    &public_transcript,
                    NOW + 3,
                )
                .await
                .unwrap(),
            TransitionOutcome::Applied
        );
        assert_eq!(
            authority
                .finish_outbox_attempt(
                    &lease,
                    AttemptDisposition::Retry {
                        available_at: NOW + 10,
                        error: "retry-conformance".to_owned()
                    },
                    NOW + 4,
                )
                .await
                .unwrap(),
            TransitionOutcome::Stale
        );

        let scoped_message_id = authorized_message_identity(TENANT, OWNER, MESSAGE_ID);
        assert!(
            matches!(authority.final_result_scoped(TENANT, &scoped_message_id).await.unwrap(),
            Some(SendMessageResponse::Task(value)) if value.status.state == TaskState::Completed)
        );
        let transcript = authority
            .stream_frames_after_scoped(TENANT, &scoped_message_id, 0)
            .await
            .unwrap();
        assert!(!transcript.frames.is_empty());
        assert!(transcript.closed);
        let snapshot = authority
            .subscription_snapshot_authorized(&scope, TASK_ID)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.0.id, TASK_ID);
        assert!(matches!(
            snapshot.1,
            SubscriptionCursor::TaskRevision(_) | SubscriptionCursor::Transcript { .. }
        ));
        let batch = authority
            .task_events_after_scoped(&scope, TASK_ID, 0)
            .await
            .unwrap();
        assert!(!batch.frames.is_empty());
        assert!(batch.closed);
        assert!(batch.last_revision >= 1);

        assert!(
            authority
                .authorize_and_continue(
                    &scope,
                    command("continuation-conformance"),
                    audit(
                        "audit-continuation",
                        "TaskContinue",
                        AuthorizationDecisionEffect::Allow
                    ),
                )
                .await
                .is_err()
        );
        assert!(
            authority
                .cancel_authorized(
                    &scope,
                    TASK_ID,
                    NOW + 5,
                    audit(
                        "audit-cancel",
                        "TaskCancel",
                        AuthorizationDecisionEffect::Allow
                    ),
                )
                .await
                .is_err()
        );

        assert!(authority.authorization_decision_count().await.unwrap() >= 2);
        let counts = authority.atomic_record_counts().await.unwrap();
        assert_eq!(counts.tasks, 1);
        assert!(counts.events >= 2);
        assert_eq!(counts.idempotency_records, 1);
        assert_eq!(counts.outbox, 1);
        assert_eq!(authority.durable_effect_count().await.unwrap(), 1);
        authority.shutdown().await.unwrap();
        authority.close_owned_sync();
    })
    .await
    .expect("durable authority conformance watchdog");
}

/// Creates a backend fixture, runs the reusable command contract, then performs
/// backend-specific cleanup under a second watchdog.
pub async fn run_durable_authority_fixture_conformance<
    Fixture,
    Factory,
    FactoryFuture,
    Cleanup,
    CleanupFuture,
>(
    factory: Factory,
    cleanup: Cleanup,
) where
    Factory: FnOnce() -> FactoryFuture,
    FactoryFuture: Future<Output = (Arc<dyn DurableAuthority>, Fixture)>,
    Cleanup: FnOnce(Fixture) -> CleanupFuture,
    CleanupFuture: Future<Output = ()>,
{
    let (authority, fixture) = tokio::time::timeout(Duration::from_secs(5), factory())
        .await
        .expect("durable authority fixture factory watchdog");
    run_durable_authority_command_conformance(authority).await;
    tokio::time::timeout(Duration::from_secs(5), cleanup(fixture))
        .await
        .expect("durable authority fixture cleanup watchdog");
}

#[derive(Default)]
struct FakeState {
    calls: Vec<String>,
    admitted: bool,
    delivered: bool,
    audit_failure_seen: bool,
}

/// Fully recording deterministic backend used to prove the harness itself.
pub struct RecordingAuthority {
    state: Mutex<FakeState>,
}

impl RecordingAuthority {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(FakeState::default()),
        })
    }

    fn record(&self, call: impl Into<String>) {
        self.state.lock().unwrap().calls.push(call.into());
    }

    pub fn assert_complete(&self) {
        let calls = &self.state.lock().unwrap().calls;
        for required in [
            "identity:key",
            "identity:digest:resource-conformance",
            "change:25",
            "audit:denied:audit-denial",
            "audit:failure:audit-failure",
            "replay:miss",
            "admit",
            "replay:hit",
            "conflict",
            "get",
            "list:cursor-scope-conformance",
            "claim:sender-conformance:1700000000000:500",
            "task_for_outbox:sender-fence-conformance",
            "progress:tenant-conformance:dispatch-conformance:1700000000001",
            "receive:receiver-conformance:1700000000000:700",
            "receiver:cancel_requested",
            "receiver:complete",
            "receiver:outcome",
            "receiver:canceled",
            "delivery:sender-fence-conformance:1700000000003",
            "attempt:sender-fence-conformance:1700000000004",
            "final",
            "transcript",
            "snapshot",
            "events",
            "continue",
            "cancel",
            "diagnostics:audit",
            "diagnostics:records",
            "diagnostics:effects",
            "shutdown",
            "close",
        ] {
            assert!(
                calls.iter().any(|call| call == required),
                "missing call {required}; calls={calls:?}"
            );
        }
    }
}

impl AuthorityIdentity for RecordingAuthority {
    fn completion_receipt_key(&self) -> Option<[u8; 32]> {
        self.record("identity:key");
        Some([0x61; 32])
    }
    fn authorization_resource_digest(&self, resource: &str) -> Result<String, A2AError> {
        self.record(format!("identity:digest:{resource}"));
        Ok(format!("digest:{resource}"))
    }
}
impl ChangeObserver for RecordingAuthority {
    fn change_observation(&self) -> ChangeObservation {
        self.record("change:25");
        ChangeObservation::new(Duration::from_millis(25)).unwrap()
    }
}

#[async_trait]
impl AuthorizationAuditSink for RecordingAuthority {
    async fn append_denied_authorization_decision(
        &self,
        audit: AuthorizationAuditInput,
    ) -> Result<(), A2AError> {
        assert_eq!(audit.effect(), AuthorizationDecisionEffect::Deny);
        self.record(format!("audit:denied:{}", audit.decision_id()));
        Ok(())
    }
    async fn append_authorization_decision(
        &self,
        audit: AuthorizationAuditInput,
    ) -> Result<(), A2AError> {
        let mut state = self.state.lock().unwrap();
        state
            .calls
            .push(format!("audit:failure:{}", audit.decision_id()));
        if state.audit_failure_seen {
            Err(A2AError::internal("scripted audit write failure"))
        } else {
            state.audit_failure_seen = true;
            Ok(())
        }
    }
}

#[async_trait]
impl TaskAdmission for RecordingAuthority {
    async fn replay_authorized(
        &self,
        scope: &OwnedTaskScope,
        actor: &str,
        request: &SendMessageRequest,
        streaming: bool,
        audit: AuthorizationAuditInput,
    ) -> Result<Option<SendMessageResponse>, A2AError> {
        assert_eq!(
            (
                scope.tenant_scope(),
                scope.owner_account_id(),
                actor,
                streaming
            ),
            (TENANT, OWNER, OWNER, true)
        );
        assert_eq!(request.message.message_id, MESSAGE_ID);
        assert_eq!(audit.tenant_scope(), TENANT);
        let admitted = self.state.lock().unwrap().admitted;
        self.record(if admitted {
            "replay:hit"
        } else {
            "replay:miss"
        });
        Ok(admitted.then(|| SendMessageResponse::Task(task(TaskState::Submitted))))
    }
    async fn authorize_and_admit(
        &self,
        scope: &OwnedTaskScope,
        command: SendMessageAdmission,
        audit: AuthorizationAuditInput,
    ) -> Result<AdmissionOutcome, A2AError> {
        assert_eq!(
            (
                scope.tenant_scope(),
                scope.owner_account_id(),
                command.now,
                command.max_attempts
            ),
            (TENANT, OWNER, NOW, 4)
        );
        assert_eq!(audit.policy_revision(), 9);
        if command.request.message.parts == request("conflicting-work").message.parts {
            self.record("conflict");
            return Err(A2AError::invalid_request("idempotency conflict"));
        }
        let mut state = self.state.lock().unwrap();
        state.calls.push("admit".to_owned());
        state.admitted = true;
        Ok(AdmissionOutcome::Admitted(AdmissionRecord {
            task_id: TASK_ID.to_owned(),
            revision: 1,
            dispatch_id: DISPATCH_ID.to_owned(),
        }))
    }
    async fn authorize_and_continue(
        &self,
        scope: &OwnedTaskScope,
        command: SendMessageAdmission,
        audit: AuthorizationAuditInput,
    ) -> Result<AdmissionOutcome, A2AError> {
        assert_eq!(
            (scope.tenant_scope(), command.now, audit.operation()),
            (TENANT, NOW, "TaskContinue")
        );
        self.record("continue");
        Err(A2AError::invalid_request("terminal task"))
    }
}

#[async_trait]
impl AuthorizedTaskRead for RecordingAuthority {
    async fn get_authorized(
        &self,
        scope: &OwnedTaskScope,
        task_id: &str,
        audit: AuthorizationAuditInput,
    ) -> Result<Option<Task>, A2AError> {
        assert_eq!(
            (scope.tenant_scope(), task_id, audit.operation()),
            (TENANT, TASK_ID, "TaskGet")
        );
        self.record("get");
        Ok(Some(task(TaskState::Submitted)))
    }
    async fn list_authorized(
        &self,
        scope: &OwnedTaskScope,
        request: &ListTasksRequest,
        audit: AuthorizationAuditInput,
        digest: &str,
    ) -> Result<ListTasksResponse, A2AError> {
        assert_eq!(
            (scope.tenant_scope(), request.page_size, audit.operation()),
            (TENANT, Some(1), "TaskList")
        );
        self.record(format!("list:{digest}"));
        Ok(ListTasksResponse {
            tasks: vec![task(TaskState::Submitted)],
            next_page_token: String::new(),
            page_size: 1,
            total_size: 1,
        })
    }
}

#[async_trait]
impl TaskLifecycle for RecordingAuthority {
    async fn final_result_scoped(
        &self,
        tenant: &str,
        message: &str,
    ) -> Result<Option<SendMessageResponse>, A2AError> {
        assert_eq!(tenant, TENANT);
        assert_eq!(
            message,
            authorized_message_identity(TENANT, OWNER, MESSAGE_ID)
        );
        self.record("final");
        Ok(Some(SendMessageResponse::Task(task(TaskState::Completed))))
    }
}

#[async_trait]
impl OutboxAuthority for RecordingAuthority {
    async fn claim_outbox(
        &self,
        owner: &str,
        now: i64,
        duration: i64,
    ) -> Result<Option<OutboxLease>, A2AError> {
        self.record(format!("claim:{owner}:{now}:{duration}"));
        Ok(Some(outbox_lease()))
    }
    async fn task_for_outbox(&self, lease: &OutboxLease) -> Result<Option<Task>, A2AError> {
        assert_eq!(lease, &outbox_lease());
        self.record(format!("task_for_outbox:{}", lease.lease_token));
        Ok(Some(task(TaskState::Submitted)))
    }
    async fn finish_outbox_attempt(
        &self,
        lease: &OutboxLease,
        disposition: AttemptDisposition,
        now: i64,
    ) -> Result<TransitionOutcome, A2AError> {
        assert_eq!(lease, &outbox_lease());
        assert_eq!(
            disposition,
            AttemptDisposition::Retry {
                available_at: NOW + 10,
                error: "retry-conformance".to_owned(),
            }
        );
        assert_eq!(now, NOW + 4);
        self.record(format!("attempt:{}:{now}", lease.lease_token));
        Ok(TransitionOutcome::Stale)
    }
    async fn append_stream_progress(
        &self,
        tenant: &str,
        dispatch: &str,
        frame: StreamResponse,
        now: i64,
    ) -> Result<Option<StreamResponse>, A2AError> {
        self.record(format!("progress:{tenant}:{dispatch}:{now}"));
        Ok(Some(frame))
    }
    async fn commit_delivery(
        &self,
        lease: &OutboxLease,
        completed_task: Task,
        result: SendMessageResponse,
        transcript: &[StreamResponse],
        now: i64,
    ) -> Result<TransitionOutcome, A2AError> {
        assert_eq!(lease, &outbox_lease());
        let mut expected_task = task(TaskState::Submitted);
        expected_task.status = TaskStatus {
            state: TaskState::Completed,
            message: None,
            timestamp: chrono::DateTime::from_timestamp_millis(NOW + 3),
        };
        let expected_terminal = StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
            task_id: TASK_ID.to_owned(),
            context_id: "context-conformance".to_owned(),
            status: expected_task.status.clone(),
            metadata: None,
        });
        let expected_transcript = [
            StreamResponse::Task(task(TaskState::Submitted)),
            progress_frame(),
            expected_terminal,
        ];
        assert_eq!(completed_task, expected_task);
        assert_eq!(result, SendMessageResponse::Task(expected_task));
        assert_eq!(transcript, expected_transcript);
        assert_eq!(now, NOW + 3);
        self.record(format!("delivery:{}:{now}", lease.lease_token));
        self.state.lock().unwrap().delivered = true;
        Ok(TransitionOutcome::Applied)
    }
}

#[async_trait]
impl ReceiverAuthority for RecordingAuthority {
    async fn begin_receive(
        &self,
        envelope: DurableDispatchEnvelope,
        owner: &str,
        now: i64,
        duration: i64,
    ) -> Result<ReceiverAdmission, A2AError> {
        assert_eq!(
            (
                envelope.tenant_scope.as_str(),
                envelope.dispatch_id.as_str()
            ),
            (TENANT, DISPATCH_ID)
        );
        self.record(format!("receive:{owner}:{now}:{duration}"));
        Ok(ReceiverAdmission::Execute(receiver_lease()))
    }
    async fn complete_loopback_receive(
        &self,
        lease: &ReceiverLease,
        events: &[MeshEvent],
        now: i64,
    ) -> Result<(), A2AError> {
        assert_eq!(lease, &receiver_lease());
        assert_eq!(events.len(), 2);
        assert_eq!(now, NOW + 2);
        self.record("receiver:complete");
        Ok(())
    }
    async fn complete_loopback_outcome(
        &self,
        lease: &ReceiverLease,
        outcome: &DurableReceiverResult,
        now: i64,
    ) -> Result<(), A2AError> {
        assert_eq!(lease, &receiver_lease());
        assert_eq!(outcome.termination, DurableReceiverTermination::Success);
        assert_eq!(now, NOW + 2);
        self.record("receiver:outcome");
        Err(A2AError::invalid_request("receiver already completed"))
    }
    async fn complete_canceled_receive(
        &self,
        lease: &ReceiverLease,
        events: &[MeshEvent],
        now: i64,
    ) -> Result<(), A2AError> {
        assert_eq!(lease, &receiver_lease());
        assert_eq!(events.len(), 2);
        assert_eq!(now, NOW + 2);
        self.record("receiver:canceled");
        Err(A2AError::invalid_request("receiver already completed"))
    }
    async fn cancellation_requested(&self, dispatch: &str) -> Result<bool, A2AError> {
        assert_eq!(dispatch, DISPATCH_ID);
        self.record("receiver:cancel_requested");
        Ok(false)
    }
}

#[async_trait]
impl TranscriptAuthority for RecordingAuthority {
    async fn stream_frames_after_scoped(
        &self,
        tenant: &str,
        message: &str,
        sequence: usize,
    ) -> Result<StreamTranscriptBatch, A2AError> {
        assert_eq!(tenant, TENANT);
        assert_eq!(
            message,
            authorized_message_identity(TENANT, OWNER, MESSAGE_ID)
        );
        assert_eq!(sequence, 0);
        self.record("transcript");
        Ok(StreamTranscriptBatch {
            frames: vec![progress_frame()],
            closed: true,
            interruption: None,
        })
    }
    async fn subscription_snapshot_authorized(
        &self,
        scope: &OwnedTaskScope,
        task_id: &str,
    ) -> Result<Option<(Task, SubscriptionCursor)>, A2AError> {
        assert_eq!((scope.tenant_scope(), task_id), (TENANT, TASK_ID));
        self.record("snapshot");
        Ok(Some((
            task(TaskState::Completed),
            SubscriptionCursor::TaskRevision(2),
        )))
    }
    async fn task_events_after_scoped(
        &self,
        scope: &OwnedTaskScope,
        task_id: &str,
        revision: u64,
    ) -> Result<TaskEventBatch, A2AError> {
        assert_eq!(
            (scope.tenant_scope(), task_id, revision),
            (TENANT, TASK_ID, 0)
        );
        self.record("events");
        Ok(TaskEventBatch {
            frames: vec![progress_frame()],
            closed: true,
            last_revision: 2,
        })
    }
}

#[async_trait]
impl CancellationAuthority for RecordingAuthority {
    async fn cancel_authorized(
        &self,
        scope: &OwnedTaskScope,
        task_id: &str,
        now: i64,
        audit: AuthorizationAuditInput,
    ) -> Result<CancellationOutcome, A2AError> {
        assert_eq!(
            (scope.tenant_scope(), task_id, now, audit.operation()),
            (TENANT, TASK_ID, NOW + 5, "TaskCancel")
        );
        self.record("cancel");
        Err(A2AError::invalid_request("terminal task"))
    }
}

#[async_trait]
impl AuthorityDiagnostics for RecordingAuthority {
    async fn authorization_decision_count(&self) -> Result<u64, A2AError> {
        self.record("diagnostics:audit");
        Ok(8)
    }
    async fn atomic_record_counts(&self) -> Result<AtomicRecordCounts, A2AError> {
        self.record("diagnostics:records");
        Ok(AtomicRecordCounts {
            tasks: 1,
            events: 2,
            idempotency_records: 1,
            outbox: 1,
        })
    }
    async fn durable_effect_count(&self) -> Result<u64, A2AError> {
        self.record("diagnostics:effects");
        Ok(1)
    }
}

#[async_trait]
impl AuthorityShutdown for RecordingAuthority {
    async fn shutdown(&self) -> Result<(), A2AError> {
        self.record("shutdown");
        Ok(())
    }
    fn close_owned_sync(&self) {
        self.record("close");
    }
}
