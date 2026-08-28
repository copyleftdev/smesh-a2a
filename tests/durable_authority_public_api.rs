use a2a::{
    Message, Part, Role, SendMessageRequest, SendMessageResponse, Task, TaskState, TaskStatus,
};
use smesh_a2a::{
    AuthorizationAuditInput, AuthorizationDecisionEffect, InputLimits, OwnedTaskScope,
    SendMessageAdmission, VisibilityScope,
};

fn task() -> Task {
    Task {
        id: "task-public-api".to_owned(),
        context_id: "context-public-api".to_owned(),
        status: TaskStatus {
            state: TaskState::Submitted,
            message: None,
            timestamp: chrono::DateTime::from_timestamp_millis(1_700_000_000_000),
        },
        artifacts: None,
        history: None,
        metadata: None,
    }
}

#[test]
fn external_backend_can_borrow_and_persist_every_audit_field() {
    let audit = AuthorizationAuditInput::new(
        "decision-public-api",
        "tenant-public-api",
        "actor-public-api",
        "policy-public-api",
        7,
        "policy-digest-public-api",
        "sendMessage",
        AuthorizationDecisionEffect::Deny,
        "denied-for-public-api-probe",
        "message",
        "resource-digest-public-api",
        Some("task-public-api".to_owned()),
        1_700_000_000_123,
    )
    .expect("valid audit input");

    assert_eq!(audit.decision_id(), "decision-public-api");
    assert_eq!(audit.tenant_scope(), "tenant-public-api");
    assert_eq!(audit.actor_account_id(), "actor-public-api");
    assert_eq!(audit.policy_id(), "policy-public-api");
    assert_eq!(audit.policy_revision(), 7);
    assert_eq!(audit.policy_digest(), "policy-digest-public-api");
    assert_eq!(audit.operation(), "sendMessage");
    assert_eq!(audit.effect(), AuthorizationDecisionEffect::Deny);
    assert_eq!(audit.reason(), "denied-for-public-api-probe");
    assert_eq!(audit.resource_kind(), "message");
    assert_eq!(audit.resource_digest(), "resource-digest-public-api");
    assert_eq!(audit.task_id(), Some("task-public-api"));
    assert_eq!(audit.decided_at(), 1_700_000_000_123);

    let parts = audit.into_parts();
    assert_eq!(parts.decision_id, "decision-public-api");
    assert_eq!(parts.tenant_scope, "tenant-public-api");
    assert_eq!(parts.actor_account_id, "actor-public-api");
    assert_eq!(parts.policy_id, "policy-public-api");
    assert_eq!(parts.policy_revision, 7);
    assert_eq!(parts.policy_digest, "policy-digest-public-api");
    assert_eq!(parts.operation, "sendMessage");
    assert_eq!(parts.effect, AuthorizationDecisionEffect::Deny);
    assert_eq!(parts.reason, "denied-for-public-api-probe");
    assert_eq!(parts.resource_kind, "message");
    assert_eq!(parts.resource_digest, "resource-digest-public-api");
    assert_eq!(parts.task_id.as_deref(), Some("task-public-api"));
    assert_eq!(parts.decided_at, 1_700_000_000_123);
}

#[test]
fn external_backend_can_inspect_backend_neutral_command_fields() {
    let scope = OwnedTaskScope::new(
        "tenant-public-api",
        "owner-public-api",
        VisibilityScope::Own,
    )
    .expect("valid scope");
    assert_eq!(scope.tenant_scope(), "tenant-public-api");
    assert_eq!(scope.owner_account_id(), "owner-public-api");
    assert_eq!(scope.visibility(), VisibilityScope::Own);

    let mut message = Message::new(Role::User, vec![Part::text("public command probe")]);
    message.message_id = "message-public-api".to_owned();
    let request = SendMessageRequest {
        message,
        configuration: None,
        metadata: None,
        tenant: None,
    };
    let task = task();
    let command = SendMessageAdmission {
        request: request.clone(),
        streaming: true,
        task: task.clone(),
        original_result: SendMessageResponse::Task(task),
        input_limits: InputLimits { max_text_bytes: 99 },
        now: 1_700_000_000_456,
        max_attempts: 5,
    };

    assert_eq!(command.request, request);
    assert!(command.streaming);
    assert_eq!(command.task.id, "task-public-api");
    assert!(matches!(
        command.original_result,
        SendMessageResponse::Task(_)
    ));
    assert_eq!(command.input_limits.max_text_bytes, 99);
    assert_eq!(command.now, 1_700_000_000_456);
    assert_eq!(command.max_attempts, 5);
}
