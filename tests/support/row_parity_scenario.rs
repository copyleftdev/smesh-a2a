#![allow(dead_code, clippy::too_many_lines)]

use std::sync::Arc;

use a2a::{
    ListTasksRequest, Message, Part, Role, SendMessageRequest, SendMessageResponse, Task,
    TaskState, TaskStatus,
};
use smesh_a2a::{
    AdmissionOutcome, AuthorizationAuditInput, AuthorizationDecisionEffect, DurableAuthority,
    DurableDispatchEnvelope, DurableReceiverResult, DurableReceiverTermination, InputLimits,
    MeshEvent, OwnedTaskScope, ReceiverAdmission, SendMessageAdmission, VisibilityScope,
    content_digest,
};

pub async fn populate_pagination_and_active_cancellation(authority: Arc<dyn DurableAuthority>) {
    const NOW: i64 = 1_700_000_010_000;
    let scope = OwnedTaskScope::new(
        "tenant-conformance",
        "owner-conformance",
        VisibilityScope::Own,
    )
    .unwrap();
    let mut message = Message::new(Role::User, vec![Part::text("héllo 🦀 — null timestamp")]);
    message.message_id = "message-parity-utf8".into();
    let task = Task {
        id: "task-parity-utf8".into(),
        context_id: "context-parity-世界".into(),
        status: TaskStatus {
            state: TaskState::Submitted,
            message: None,
            timestamp: None,
        },
        artifacts: None,
        history: Some(vec![message.clone()]),
        metadata: None,
    };
    let command = SendMessageAdmission {
        request: SendMessageRequest {
            message,
            configuration: None,
            metadata: None,
            tenant: None,
        },
        streaming: false,
        task: task.clone(),
        original_result: SendMessageResponse::Task(task),
        input_limits: InputLimits::default(),
        now: NOW,
        max_attempts: 3,
    };
    let admission_audit = audit(
        "audit-parity-admit",
        "TaskCreate",
        "sha256:resource-parity",
        Some("task-parity-utf8"),
        NOW,
    );
    assert!(matches!(
        authority
            .authorize_and_admit(&scope, command, admission_audit)
            .await
            .unwrap(),
        AdmissionOutcome::Admitted(_)
    ));

    let page = authority
        .list_authorized(
            &scope,
            &ListTasksRequest {
                context_id: None,
                status: None,
                page_size: Some(1),
                page_token: None,
                history_length: Some(0),
                status_timestamp_after: None,
                include_artifacts: Some(false),
                tenant: None,
            },
            audit(
                "audit-parity-list",
                "TaskList",
                "sha256:list-parity",
                None,
                NOW + 1,
            ),
            "cursor-scope-parity",
        )
        .await
        .unwrap();
    assert_eq!(page.total_size, 2);
    assert!(!page.next_page_token.is_empty());

    let lease = authority
        .claim_outbox("parity-cancel-sender", NOW + 2, 500)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lease.task_id, "task-parity-utf8");
    let payload = serde_json::to_vec(&lease.request).unwrap();
    let ReceiverAdmission::Execute(receiver) = authority
        .begin_receive(
            DurableDispatchEnvelope {
                tenant_scope: lease.tenant_scope.clone(),
                dispatch_id: lease.dispatch_id.clone(),
                payload_digest: content_digest(&payload),
                request: lease.request.clone(),
                execution_reservation: lease.execution_reservation.clone(),
            },
            "parity-cancel-receiver",
            NOW + 2,
            700,
        )
        .await
        .unwrap()
    else {
        panic!("parity receiver must execute")
    };
    authority
        .cancel_authorized(
            &scope,
            "task-parity-utf8",
            NOW + 3,
            audit(
                "audit-parity-cancel",
                "TaskCancel",
                "sha256:cancel-parity",
                Some("task-parity-utf8"),
                NOW + 3,
            ),
        )
        .await
        .unwrap();
    authority
        .complete_canceled_receive(
            &receiver,
            &[
                MeshEvent::Progress("取消処理 🦀".into()),
                MeshEvent::Completed {
                    summary: "SMESH durable receiver cooperatively canceled".into(),
                },
            ],
            NOW + 4,
        )
        .await
        .unwrap();

    let mut interrupted_message = Message::new(Role::User, vec![Part::text("need credentials")]);
    interrupted_message.message_id = "message-parity-interrupted".into();
    let interrupted_task = Task {
        id: "task-parity-interrupted".into(),
        context_id: "context-parity-interrupted".into(),
        status: TaskStatus {
            state: TaskState::Submitted,
            message: None,
            timestamp: None,
        },
        artifacts: None,
        history: Some(vec![interrupted_message.clone()]),
        metadata: None,
    };
    authority
        .authorize_and_admit(
            &scope,
            SendMessageAdmission {
                request: SendMessageRequest {
                    message: interrupted_message,
                    configuration: None,
                    metadata: None,
                    tenant: None,
                },
                streaming: false,
                task: interrupted_task.clone(),
                original_result: SendMessageResponse::Task(interrupted_task),
                input_limits: InputLimits::default(),
                now: NOW + 5,
                max_attempts: 2,
            },
            audit(
                "audit-parity-interrupted",
                "TaskCreate",
                "sha256:interrupted",
                Some("task-parity-interrupted"),
                NOW + 5,
            ),
        )
        .await
        .unwrap();
    let interrupted_outbox = authority
        .claim_outbox("parity-interrupted-sender", NOW + 6, 500)
        .await
        .unwrap()
        .unwrap();
    let interrupted_payload = serde_json::to_vec(&interrupted_outbox.request).unwrap();
    let envelope = DurableDispatchEnvelope {
        tenant_scope: interrupted_outbox.tenant_scope.clone(),
        dispatch_id: interrupted_outbox.dispatch_id.clone(),
        payload_digest: content_digest(&interrupted_payload),
        request: interrupted_outbox.request.clone(),
        execution_reservation: interrupted_outbox.execution_reservation.clone(),
    };
    let ReceiverAdmission::Execute(interrupted_lease) = authority
        .begin_receive(
            envelope.clone(),
            "parity-interrupted-receiver",
            NOW + 6,
            500,
        )
        .await
        .unwrap()
    else {
        panic!("interrupted receiver executes")
    };
    let outcome = DurableReceiverResult {
        events: vec![MeshEvent::Progress("awaiting credentials".into())],
        termination: DurableReceiverTermination::AuthRequired {
            message: "credentials required".into(),
        },
    };
    authority
        .complete_loopback_outcome(&interrupted_lease, &outcome, NOW + 7)
        .await
        .unwrap();
    assert!(
        matches!(authority.begin_receive(envelope, "parity-interrupted-replay", NOW + 8, 500).await.unwrap(), ReceiverAdmission::ReplayOutcome(replayed) if replayed == outcome)
    );
}

fn audit(
    id: &str,
    operation: &str,
    resource_digest: &str,
    task_id: Option<&str>,
    now: i64,
) -> AuthorizationAuditInput {
    AuthorizationAuditInput::new(
        id,
        "tenant-conformance",
        "owner-conformance",
        "policy-conformance",
        9,
        "sha256:policy-conformance",
        operation,
        AuthorizationDecisionEffect::Allow,
        "grant",
        "task",
        resource_digest,
        task_id.map(str::to_owned),
        now,
    )
    .unwrap()
}
