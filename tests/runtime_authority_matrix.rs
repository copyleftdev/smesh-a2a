#![cfg(debug_assertions)]

use std::{env, os::unix::fs::PermissionsExt as _, path::PathBuf, sync::Arc, time::Duration};

use a2a::{
    Message, Part, Role, SendMessageRequest, SendMessageResponse, StreamResponse, Task, TaskState,
    TaskStatus, TaskStatusUpdateEvent,
};
use rusqlite::{Connection, functions::FunctionFlags, params};
use smesh_a2a::{
    AdmissionOutcome, AuthorityShutdown, AuthorizationAuditInput, AuthorizationDecisionEffect,
    AuthorizedMutation, DurableAuthority, DurableDispatchEnvelope, DurableReceiverResult,
    DurableReceiverTermination, InputLimits, OutboxLease, OwnedTaskScope, PostgresStoreConfig,
    PostgresTaskStore, QuotaOperation, QuotaPolicy, QuotaSubject, ReceiverAdmission, ReceiverLease,
    SendMessageAdmission, SqliteTaskStore, TransitionOutcome, VisibilityScope,
    authorized_message_identity, canonical_send_message_digest_v2, content_digest,
};

const BASE_NOW: i64 = 1_700_090_000_000;
const UNAVAILABLE: &str = "durable runtime authority unavailable";

fn register_disabled_projection_functions(connection: &Connection) {
    let flags = FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS;
    connection
        .create_scalar_function("smesh_audit_projection_enabled", 0, flags, |_| Ok(0_i64))
        .unwrap();
    for name in ["smesh_projection_digest", "smesh_projection_pk_digest"] {
        connection
            .create_scalar_function(name, 4, flags, |_| Ok(content_digest(b"matrix-projection")))
            .unwrap();
    }
}

#[derive(Clone, Copy, Debug)]
struct MatrixCase {
    streaming: bool,
    continuation: bool,
    cross_account: bool,
}

impl MatrixCase {
    fn label(self) -> &'static str {
        if self.cross_account {
            return if self.streaming {
                "streaming-tenant-continuation"
            } else {
                "unary-tenant-continuation"
            };
        }
        match (self.streaming, self.continuation) {
            (false, false) => "unary-initial",
            (true, false) => "streaming-initial",
            (false, true) => "unary-continuation",
            (true, true) => "streaming-continuation",
        }
    }

    fn invocation(self) -> &'static str {
        if self.streaming { "streaming" } else { "unary" }
    }

    fn operation(self) -> &'static str {
        if self.continuation {
            "TaskContinue"
        } else {
            "TaskCreate"
        }
    }
}

const CASES: [MatrixCase; 6] = [
    MatrixCase {
        streaming: false,
        continuation: false,
        cross_account: false,
    },
    MatrixCase {
        streaming: true,
        continuation: false,
        cross_account: false,
    },
    MatrixCase {
        streaming: false,
        continuation: true,
        cross_account: false,
    },
    MatrixCase {
        streaming: true,
        continuation: true,
        cross_account: false,
    },
    MatrixCase {
        streaming: false,
        continuation: true,
        cross_account: true,
    },
    MatrixCase {
        streaming: true,
        continuation: true,
        cross_account: true,
    },
];

#[derive(Debug)]
struct DecisionEvidence {
    decision_id: String,
    invocation_kind: String,
    operation: String,
    resource_kind: String,
    resource_digest: String,
    actor: String,
    principal: String,
    authentication: String,
    visibility: String,
    policy_id: String,
    policy_revision: i64,
    policy_digest: String,
}

enum MatrixBackend {
    Sqlite { path: PathBuf },
    Postgres { admin_url: String, schema: String },
}

impl MatrixBackend {
    async fn evidence(
        &self,
        tenant: &str,
        account: &str,
        raw_message_id: &str,
    ) -> DecisionEvidence {
        let message_id = authorized_message_identity(tenant, account, raw_message_id);
        match self {
            Self::Sqlite { path } => {
                let connection = Connection::open(path).unwrap();
                connection
                    .query_row(
                        "SELECT d.decision_id,i.invocation_kind,d.operation,d.resource_kind,
                                d.resource_digest,d.actor_account_id,
                                i.authorization_principal_scope,i.authorization_authentication_method,
                                i.authorization_visibility,d.policy_id,d.policy_revision,d.policy_digest
                         FROM idempotency_records i
                         JOIN authorization_decisions d
                           ON d.tenant_scope=i.tenant_scope AND d.decision_id=i.authorization_decision_id
                         WHERE i.tenant_scope=?1 AND i.message_id=?2",
                        params![tenant, message_id],
                        |row| Ok(DecisionEvidence {
                            decision_id: row.get(0)?, invocation_kind: row.get(1)?,
                            operation: row.get(2)?, resource_kind: row.get(3)?,
                            resource_digest: row.get(4)?, actor: row.get(5)?,
                            principal: row.get(6)?, authentication: row.get(7)?,
                            visibility: row.get(8)?, policy_id: row.get(9)?,
                            policy_revision: row.get(10)?, policy_digest: row.get(11)?,
                        }),
                    )
                    .unwrap()
            }
            Self::Postgres { admin_url, schema } => {
                let (client, connection) =
                    tokio_postgres::connect(admin_url, tokio_postgres::NoTls)
                        .await
                        .unwrap();
                let driver = tokio::spawn(connection);
                client
                    .query_one(
                        "SELECT set_config('smesh.internal_global','diag-v1',false),
                                set_config('smesh.tenant_scope',$1,false)",
                        &[&tenant],
                    )
                    .await
                    .unwrap();
                let row = client
                    .query_one(
                        &format!(
                            "SELECT d.decision_id,i.invocation_kind,d.operation,d.resource_kind,
                                    d.resource_digest,d.actor_account_id,
                                    i.authorization_principal_scope,i.authorization_authentication_method,
                                    i.authorization_visibility,d.policy_id,d.policy_revision,d.policy_digest
                             FROM {schema}.idempotency_records i
                             JOIN {schema}.authorization_decisions d
                               ON d.tenant_scope=i.tenant_scope AND d.decision_id=i.authorization_decision_id
                             WHERE i.tenant_scope=$1 AND i.message_id=$2"
                        ),
                        &[&tenant, &message_id],
                    )
                    .await
                    .unwrap();
                let evidence = DecisionEvidence {
                    decision_id: row.get(0),
                    invocation_kind: row.get(1),
                    operation: row.get(2),
                    resource_kind: row.get(3),
                    resource_digest: row.get(4),
                    actor: row.get(5),
                    principal: row.get(6),
                    authentication: row.get(7),
                    visibility: row.get(8),
                    policy_id: row.get(9),
                    policy_revision: row.get(10),
                    policy_digest: row.get(11),
                };
                drop(client);
                driver.abort();
                evidence
            }
        }
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn bind_opposite_invocation_decision(
        &self,
        tenant: &str,
        account: &str,
        task_id: &str,
        raw_message_id: &str,
        request: &SendMessageRequest,
        case: MatrixCase,
        evidence: &DecisionEvidence,
        decided_at: i64,
    ) {
        let message_id = authorized_message_identity(tenant, account, raw_message_id);
        let opposite_digest =
            canonical_send_message_digest_v2(tenant, account, request, !case.streaming).unwrap();
        assert_ne!(
            opposite_digest,
            evidence.resource_digest,
            "{}",
            case.label()
        );
        let substitute_id = format!("decision-{}-opposite", case.label());
        match self {
            Self::Sqlite { path } => {
                let connection = Connection::open(path).unwrap();
                register_disabled_projection_functions(&connection);
                connection
                    .execute_batch("DROP TRIGGER IF EXISTS idempotency_runtime_authority_immutable")
                    .unwrap();
                connection
                    .execute(
                        "INSERT INTO authorization_decisions(
                             decision_id,tenant_scope,actor_account_id,policy_id,policy_revision,
                             policy_digest,operation,effect,reason,resource_kind,resource_digest,
                             task_id,decided_at)
                         VALUES(?1,?2,?3,?4,?5,?6,?7,'allow','matrix substitute',
                                'send-message-request',?8,?9,?10)",
                        params![
                            substitute_id,
                            tenant,
                            account,
                            evidence.policy_id,
                            evidence.policy_revision,
                            evidence.policy_digest,
                            case.operation(),
                            opposite_digest,
                            task_id,
                            decided_at
                        ],
                    )
                    .unwrap();
                assert_eq!(
                    connection
                        .execute(
                            "UPDATE idempotency_records SET authorization_decision_id=?1
                             WHERE tenant_scope=?2 AND message_id=?3",
                            params![substitute_id, tenant, message_id],
                        )
                        .unwrap(),
                    1
                );
            }
            Self::Postgres { admin_url, schema } => {
                let (client, connection) =
                    tokio_postgres::connect(admin_url, tokio_postgres::NoTls)
                        .await
                        .unwrap();
                let driver = tokio::spawn(connection);
                client
                    .query_one(
                        "SELECT set_config('smesh.internal_global','diag-v1',false),
                                set_config('smesh.tenant_scope',$1,false)",
                        &[&tenant],
                    )
                    .await
                    .unwrap();
                client
                    .batch_execute(&format!(
                        "ALTER TABLE {schema}.idempotency_records DISABLE ROW LEVEL SECURITY;
                         ALTER TABLE {schema}.retained_authority_usage DISABLE ROW LEVEL SECURITY;
                         ALTER TABLE {schema}.idempotency_records DISABLE TRIGGER idempotency_runtime_authority_immutable;"
                    ))
                    .await
                    .unwrap();
                client
                    .execute(
                        &format!(
                            "INSERT INTO {schema}.authorization_decisions(
                                 decision_id,tenant_scope,actor_account_id,policy_id,policy_revision,
                                 policy_digest,operation,effect,reason,resource_kind,resource_digest,
                                 task_id,decided_at)
                             VALUES($1,$2,$3,$4,$5,$6,$7,'allow','matrix substitute',
                                    'send-message-request',$8,$9,$10)"
                        ),
                        &[&substitute_id, &tenant, &account, &evidence.policy_id,
                          &evidence.policy_revision, &evidence.policy_digest, &case.operation(),
                          &opposite_digest, &task_id, &decided_at],
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    client
                        .execute(
                            &format!(
                                "UPDATE {schema}.idempotency_records SET authorization_decision_id=$1
                                 WHERE tenant_scope=$2 AND message_id=$3"
                            ),
                            &[&substitute_id, &tenant, &message_id],
                        )
                        .await
                        .unwrap(),
                    1
                );
                client
                    .batch_execute(&format!(
                        "ALTER TABLE {schema}.idempotency_records ENABLE TRIGGER idempotency_runtime_authority_immutable;
                         ALTER TABLE {schema}.retained_authority_usage ENABLE ROW LEVEL SECURITY;
                         ALTER TABLE {schema}.retained_authority_usage FORCE ROW LEVEL SECURITY;
                         ALTER TABLE {schema}.idempotency_records ENABLE ROW LEVEL SECURITY;
                         ALTER TABLE {schema}.idempotency_records FORCE ROW LEVEL SECURITY;"
                    ))
                    .await
                    .unwrap();
                drop(client);
                driver.abort();
            }
        }
    }
}

fn quota_policy() -> Arc<QuotaPolicy> {
    Arc::new(
        QuotaPolicy::from_json(
            br#"{
      "schemaVersion":"smesh-quota-policy/v1","policyId":"matrix-quota","revision":3,
      "requestWindowMillis":1000,"reconnectWindowMillis":60000,
      "limits":{
        "requestCount":{"tenant":4,"account":4,"principal":4},
        "concurrentActiveWork":{"tenant":1,"account":1,"principal":1},
        "inputBytes":{"tenant":1048576,"account":1048576,"principal":1048576},
        "outputBytes":{"tenant":8192,"account":8192,"principal":8192},
        "eventCount":{"tenant":32,"account":32,"principal":32},
        "concurrentStreams":{"tenant":2,"account":2,"principal":2},
        "concurrentSubscriptions":{"tenant":2,"account":2,"principal":2},
        "reconnectCount":{"tenant":4,"account":4,"principal":4},
        "retainedAuthorityBytes":{"tenant":16777216,"account":16777216,"principal":16777216}
      },"overrides":[]
    }"#,
        )
        .unwrap(),
    )
}

fn request_and_task(label: &str, task_id: &str, context_id: &str) -> (SendMessageRequest, Task) {
    let mut message = Message::new(Role::User, vec![Part::text(format!("work-{label}"))]);
    message.message_id = format!("message-{label}");
    let request = SendMessageRequest {
        message: message.clone(),
        configuration: None,
        metadata: None,
        tenant: None,
    };
    let task = Task {
        id: task_id.to_owned(),
        context_id: context_id.to_owned(),
        status: TaskStatus {
            state: TaskState::Submitted,
            message: None,
            timestamp: None,
        },
        artifacts: None,
        history: Some(vec![message]),
        metadata: None,
    };
    (request, task)
}

fn admission(
    request: SendMessageRequest,
    task: Task,
    streaming: bool,
    now: i64,
) -> SendMessageAdmission {
    SendMessageAdmission {
        request,
        streaming,
        task: task.clone(),
        original_result: SendMessageResponse::Task(task),
        input_limits: InputLimits::default(),
        now,
        max_attempts: 3,
    }
}

#[allow(clippy::too_many_arguments)]
fn audit(
    id: String,
    tenant: &str,
    account: &str,
    policy_id: &str,
    policy_revision: u64,
    policy_digest: &str,
    operation: &str,
    request: &SendMessageRequest,
    streaming: bool,
    task_id: &str,
    now: i64,
) -> AuthorizationAuditInput {
    AuthorizationAuditInput::new(
        id,
        tenant,
        account,
        policy_id,
        policy_revision,
        policy_digest,
        operation,
        AuthorizationDecisionEffect::Allow,
        "matrix allow",
        "send-message-request",
        canonical_send_message_digest_v2(tenant, account, request, streaming).unwrap(),
        Some(task_id.to_owned()),
        now,
    )
    .unwrap()
}

async fn admit(
    authority: &Arc<dyn DurableAuthority>,
    quota: Option<&Arc<QuotaPolicy>>,
    scope: &OwnedTaskScope,
    command: SendMessageAdmission,
    decision: AuthorizationAuditInput,
    continuation: bool,
) {
    let outcome = admit_result(authority, quota, scope, command, decision, continuation)
        .await
        .unwrap();
    assert!(matches!(outcome, AdmissionOutcome::Admitted(_)));
}

async fn admit_result(
    authority: &Arc<dyn DurableAuthority>,
    quota: Option<&Arc<QuotaPolicy>>,
    scope: &OwnedTaskScope,
    command: SendMessageAdmission,
    decision: AuthorizationAuditInput,
    continuation: bool,
) -> Result<AdmissionOutcome, a2a::A2AError> {
    if let Some(policy) = quota {
        let subject = QuotaSubject::new(
            scope.tenant_scope(),
            scope.owner_account_id(),
            scope.principal_scope(),
        )
        .unwrap();
        let input_bytes = serde_json::to_vec(&command.request).unwrap().len() as u64;
        let intent = if continuation {
            policy
                .operation_intent(
                    &subject,
                    QuotaOperation::TaskContinue,
                    &command.request.message.message_id,
                    input_bytes,
                )
                .unwrap()
        } else {
            policy
                .admission_intent(
                    &subject,
                    &command.request.message.message_id,
                    input_bytes,
                    command.streaming,
                )
                .unwrap()
        };
        let mutation = AuthorizedMutation::with_quota_intent(command, intent);
        if continuation {
            authority
                .authorize_and_continue_mutation(scope, mutation, decision)
                .await
        } else {
            authority
                .authorize_and_admit_mutation(scope, mutation, decision)
                .await
        }
    } else if continuation {
        authority
            .authorize_and_continue(scope, command, decision)
            .await
    } else {
        authority
            .authorize_and_admit(scope, command, decision)
            .await
    }
}

async fn claim_and_begin(
    authority: &Arc<dyn DurableAuthority>,
    owner: &str,
    now: i64,
) -> (OutboxLease, ReceiverLease, i64) {
    let sender = authority
        .claim_outbox(owner, now, 60_000)
        .await
        .unwrap()
        .unwrap();
    let receiver_now = now + 1;
    let receiver = match authority
        .begin_receive(
            DurableDispatchEnvelope {
                tenant_scope: sender.tenant_scope.clone(),
                dispatch_id: sender.dispatch_id.clone(),
                payload_digest: content_digest(&serde_json::to_vec(&sender.request).unwrap()),
                request: sender.request.clone(),
                execution_reservation: sender.execution_reservation.clone(),
            },
            &format!("{owner}-receiver"),
            receiver_now,
            60_000,
        )
        .await
        .unwrap()
    {
        ReceiverAdmission::Execute(lease) => lease,
        other => panic!("expected receiver execution, got {other:?}"),
    };
    (sender, receiver, receiver_now)
}

async fn interrupt_for_continuation(
    authority: &Arc<dyn DurableAuthority>,
    sender: &OutboxLease,
    receiver: &ReceiverLease,
    mut task: Task,
    now: i64,
) -> Task {
    let admitted = task.clone();
    authority
        .complete_loopback_outcome(
            receiver,
            &DurableReceiverResult {
                events: vec![],
                termination: DurableReceiverTermination::InputRequired {
                    message: "matrix input".to_owned(),
                },
            },
            now,
        )
        .await
        .unwrap();
    task.status = TaskStatus {
        state: TaskState::InputRequired,
        message: None,
        timestamp: chrono::DateTime::from_timestamp_millis(now + 1),
    };
    let terminal = StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
        task_id: task.id.clone(),
        context_id: task.context_id.clone(),
        status: task.status.clone(),
        metadata: None,
    });
    assert_eq!(
        authority
            .commit_delivery(
                sender,
                task.clone(),
                SendMessageResponse::Task(task.clone()),
                &[StreamResponse::Task(admitted), terminal],
                now + 1,
            )
            .await
            .unwrap(),
        TransitionOutcome::Applied
    );
    task
}

#[allow(clippy::too_many_lines)]
async fn run_matrix(
    authority: Arc<dyn DurableAuthority>,
    backend: &MatrixBackend,
    quota: Option<Arc<QuotaPolicy>>,
) {
    for (index, case) in CASES.into_iter().enumerate() {
        let now = BASE_NOW + i64::try_from(index).unwrap() * 100;
        let label = case.label();
        let tenant = format!("tenant-{label}");
        let account = format!("account-{label}");
        let task_id = format!("task-{label}");
        let context_id = format!("context-{label}");
        let policy_id = format!("policy-p2-{label}");
        let policy_digest = content_digest(format!("{policy_id}/v2").as_bytes());
        let principal = format!("principal-p2-{label}");
        let authentication = if case.streaming {
            "mutual-tls"
        } else {
            "bearer-jwt"
        };
        let visibility = if case.streaming || case.cross_account {
            VisibilityScope::Tenant
        } else {
            VisibilityScope::Own
        };
        let mut scope = OwnedTaskScope::new_with_principal_and_authentication(
            &tenant,
            &account,
            &principal,
            visibility,
            authentication,
        )
        .unwrap();
        let (mut request, mut task) = request_and_task(label, &task_id, &context_id);

        if case.continuation {
            let owner = if case.cross_account {
                format!("owner-a-{label}")
            } else {
                account.clone()
            };
            let p1_policy = format!("policy-p1-{label}");
            let p1_digest = content_digest(format!("{p1_policy}/v1").as_bytes());
            let p1_scope = OwnedTaskScope::new_with_principal_and_authentication(
                &tenant,
                &owner,
                format!("principal-p1-{label}"),
                VisibilityScope::Tenant,
                "signed-session",
            )
            .unwrap();
            let p1 = admission(request.clone(), task.clone(), case.streaming, now);
            admit(
                &authority,
                quota.as_ref(),
                &p1_scope,
                p1.clone(),
                audit(
                    format!("decision-p1-{label}"),
                    &tenant,
                    &owner,
                    &p1_policy,
                    1,
                    &p1_digest,
                    "TaskCreate",
                    &p1.request,
                    case.streaming,
                    &task_id,
                    now,
                ),
                false,
            )
            .await;
            let (sender, receiver, receiver_now) =
                claim_and_begin(&authority, &format!("sender-p1-{label}"), now + 1).await;
            let p1_context = authority
                .load_runtime_authority_context(&sender, &receiver, receiver_now)
                .await
                .expect("P1 initial runtime authority must succeed");
            assert_eq!(p1_context.scope().authorization_policy_id(), p1_policy);
            task =
                interrupt_for_continuation(&authority, &sender, &receiver, task, receiver_now + 1)
                    .await;
            let mut message =
                Message::new(Role::User, vec![Part::text(format!("continue-{label}"))]);
            message.message_id = format!("message-p2-{label}");
            message.task_id = Some(task_id.clone());
            message.context_id = Some(context_id.clone());
            request = SendMessageRequest {
                message,
                configuration: None,
                metadata: None,
                tenant: None,
            };
            if case.cross_account {
                let own_scope = OwnedTaskScope::new_with_principal_and_authentication(
                    &tenant,
                    &account,
                    &principal,
                    VisibilityScope::Own,
                    authentication,
                )
                .unwrap();
                let error = admit_result(
                    &authority,
                    quota.as_ref(),
                    &own_scope,
                    admission(request.clone(), task.clone(), case.streaming, now + 9),
                    audit(
                        format!("decision-own-denied-{label}"),
                        &tenant,
                        &account,
                        &policy_id,
                        2,
                        &policy_digest,
                        "TaskContinue",
                        &request,
                        case.streaming,
                        &task_id,
                        now + 9,
                    ),
                    true,
                )
                .await
                .expect_err("Own visibility must not continue another account's task");
                assert_eq!(
                    error.code, -32001,
                    "Own denial must be scoped task-not-found: {error:?}"
                );
            }
            scope = OwnedTaskScope::new_with_principal_and_authentication(
                &tenant,
                &account,
                &principal,
                visibility,
                authentication,
            )
            .unwrap();
        }

        let command = admission(request.clone(), task.clone(), case.streaming, now + 10);
        admit(
            &authority,
            quota.as_ref(),
            &scope,
            command.clone(),
            audit(
                format!("decision-p2-{label}"),
                &tenant,
                &account,
                &policy_id,
                2,
                &policy_digest,
                case.operation(),
                &request,
                case.streaming,
                &task_id,
                now + 10,
            ),
            case.continuation,
        )
        .await;
        let (sender, receiver, authority_now) =
            claim_and_begin(&authority, &format!("sender-p2-{label}"), now + 11).await;
        let context = authority
            .load_runtime_authority_context(&sender, &receiver, authority_now)
            .await
            .unwrap_or_else(|error| panic!("valid {label} authority failed: {error:?}"));
        let authorized_digest =
            canonical_send_message_digest_v2(&tenant, &account, &request, case.streaming).unwrap();
        let transport_digest = content_digest(&serde_json::to_vec(&sender.request).unwrap());
        assert_eq!(context.request(), &sender.request, "{label}");
        assert_eq!(
            context.transport_payload_digest(),
            transport_digest,
            "{label}"
        );
        assert_eq!(
            context.authorized_request_digest(),
            authorized_digest,
            "{label}"
        );
        assert_ne!(
            context.transport_payload_digest(),
            context.authorized_request_digest(),
            "{label}"
        );
        assert_eq!(context.scope().tenant_scope(), tenant, "{label}");
        assert_eq!(context.scope().account_id(), account, "{label}");
        assert_eq!(context.scope().principal_scope(), principal, "{label}");
        assert_eq!(
            context.scope().authentication_method(),
            authentication,
            "{label}"
        );
        assert_eq!(context.scope().visibility(), visibility, "{label}");
        assert_eq!(
            context.scope().authorization_policy_id(),
            policy_id,
            "{label}"
        );
        assert_eq!(
            context.scope().authorization_policy_revision(),
            2,
            "{label}"
        );
        assert_eq!(
            context.scope().authorization_policy_digest(),
            policy_digest,
            "{label}"
        );
        assert_eq!(
            context.correlation().attempt(),
            sender.attempt_no,
            "{label}"
        );
        assert_eq!(
            context.correlation().fence(),
            receiver.lease_epoch,
            "{label}"
        );
        assert_eq!(
            context.correlation().dispatch_id(),
            sender.dispatch_id,
            "{label}"
        );
        if let Some(reservation) = sender.execution_reservation.as_ref() {
            assert!(!context.is_loopback_development(), "{label}");
            assert_eq!(
                context.production_reservation(),
                Some(reservation),
                "{label}"
            );
            assert_eq!(context.budget(), reservation.budget, "{label}");
        } else {
            assert!(context.is_loopback_development(), "{label}");
            assert!(context.production_reservation().is_none(), "{label}");
            assert!(context.budget().max_output_bytes() > 0, "{label}");
            assert!(context.budget().max_event_count() > 0, "{label}");
        }

        let evidence = backend
            .evidence(&tenant, &account, &request.message.message_id)
            .await;
        assert_eq!(
            evidence.decision_id,
            format!("decision-p2-{label}"),
            "{label}"
        );
        assert_eq!(evidence.invocation_kind, case.invocation(), "{label}");
        assert_eq!(evidence.operation, case.operation(), "{label}");
        assert_eq!(evidence.resource_kind, "send-message-request", "{label}");
        assert_eq!(evidence.resource_digest, authorized_digest, "{label}");
        assert_eq!(evidence.actor, account, "{label}");
        assert_eq!(evidence.principal, principal, "{label}");
        assert_eq!(evidence.authentication, authentication, "{label}");
        assert_eq!(
            evidence.visibility,
            if visibility == VisibilityScope::Own {
                "own"
            } else {
                "tenant"
            },
            "{label}"
        );
        assert_eq!(evidence.policy_id, policy_id, "{label}");
        assert_eq!(evidence.policy_revision, 2, "{label}");
        assert_eq!(evidence.policy_digest, policy_digest, "{label}");

        backend
            .bind_opposite_invocation_decision(
                &tenant,
                &account,
                &task_id,
                &request.message.message_id,
                &request,
                case,
                &evidence,
                now + 10,
            )
            .await;
        let error = authority
            .load_runtime_authority_context(&sender, &receiver, authority_now)
            .await
            .expect_err("opposite invocation decision substitution must fail");
        assert_eq!(error.code, -32603, "{label}");
        assert_eq!(error.message, UNAVAILABLE, "{label}");
        assert!(error.details.is_none(), "{label}");
    }
}

#[tokio::test]
async fn sqlite_runtime_authority_unary_streaming_initial_continuation_matrix() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let directory = env::temp_dir().join(format!(
            "smesh-runtime-matrix-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("authority.sqlite3");
        let store = Arc::new(SqliteTaskStore::open(&path, 8).await.unwrap());
        run_matrix(store.clone(), &MatrixBackend::Sqlite { path }, None).await;
        store.shutdown().await.unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    })
    .await
    .expect("SQLite runtime-authority matrix watchdog");
}

struct RecordingAdapter(tokio::sync::mpsc::UnboundedSender<smesh_a2a::DurableWorkEnvelope>);

#[async_trait::async_trait]
impl smesh_a2a::DurableRuntimeAdapter for RecordingAdapter {
    async fn prepare(&self) -> smesh_a2a::RuntimeAdapterPreparation {
        smesh_a2a::RuntimeAdapterPreparation::Ready(Box::new(Self(self.0.clone())))
    }

    async fn cancel_durable(
        &self,
        _: &smesh_a2a::DurableDispatchCorrelation,
    ) -> smesh_a2a::RuntimeCancellationRequest {
        smesh_a2a::RuntimeCancellationRequest::Unknown
    }
}

#[async_trait::async_trait]
impl smesh_a2a::PreparedDurableRuntimeDispatch for RecordingAdapter {
    async fn admit(
        self: Box<Self>,
        envelope: smesh_a2a::DurableWorkEnvelope,
        _: tokio_util::sync::CancellationToken,
    ) -> smesh_a2a::RuntimeAdapterAdmission {
        self.0.send(envelope).unwrap();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        sender
            .send(smesh_a2a::RuntimeAdapterOutcome::AdmittedUnknown)
            .unwrap();
        smesh_a2a::RuntimeAdapterAdmission::Admitted(smesh_a2a::RuntimeAdapterExecution::new(
            receiver,
        ))
    }
}

struct NoHttpCredentials;
#[async_trait::async_trait]
impl smesh_a2a::auth::BearerVerifier for NoHttpCredentials {
    async fn verify(
        &self,
        _: smesh_a2a::auth::PresentedBearer<'_>,
    ) -> Result<smesh_a2a::auth::Principal, smesh_a2a::auth::AuthenticationError> {
        Err(smesh_a2a::auth::AuthenticationError::InvalidToken)
    }
}

#[allow(clippy::too_many_lines)]
async fn cross_account_adapter_probe(admin: &str, runtime: &str, streaming: bool) {
    use futures::FutureExt as _;
    let quota = quota_policy();
    let config = PostgresStoreConfig::new(
        admin,
        runtime,
        format!("smesh_actor_adapter_{:016x}", rand::random::<u64>()),
    )
    .unwrap()
    .with_test_only_insecure_loopback(true)
    .with_quota_policy(quota.clone());
    let store = PostgresTaskStore::open(config.clone()).await.unwrap();
    let authority: Arc<dyn DurableAuthority> = Arc::new(store.clone());
    let owner = OwnedTaskScope::new_with_principal_and_authentication(
        "tenant-adapter",
        "owner-a",
        "principal-a",
        VisibilityScope::Own,
        "signed-session",
    )
    .unwrap();
    let actor = OwnedTaskScope::new_with_principal_and_authentication(
        "tenant-adapter",
        "actor-b",
        "principal-b",
        VisibilityScope::Tenant,
        "mutual-tls",
    )
    .unwrap();
    let (request_a, task) = request_and_task("adapter-a", "task-adapter", "context-adapter");
    let policy_a = content_digest(b"policy-a");
    let policy_b = content_digest(b"policy-b");
    admit(
        &authority,
        Some(&quota),
        &owner,
        admission(request_a.clone(), task.clone(), streaming, BASE_NOW),
        audit(
            "decision-adapter-a".into(),
            owner.tenant_scope(),
            owner.owner_account_id(),
            "policy-a",
            1,
            &policy_a,
            "TaskCreate",
            &request_a,
            streaming,
            &task.id,
            BASE_NOW,
        ),
        false,
    )
    .await;
    let (sender, receiver, now) = claim_and_begin(&authority, "adapter-seed", BASE_NOW + 1).await;
    let task = interrupt_for_continuation(&authority, &sender, &receiver, task, now + 1).await;
    let (mut request_b, _) = request_and_task("adapter-b", &task.id, &task.context_id);
    request_b.message.task_id = Some(task.id.clone());
    request_b.message.context_id = Some(task.context_id.clone());
    admit(
        &authority,
        Some(&quota),
        &actor,
        admission(request_b.clone(), task.clone(), streaming, BASE_NOW + 10),
        audit(
            "decision-adapter-b".into(),
            actor.tenant_scope(),
            actor.owner_account_id(),
            "policy-b",
            2,
            &policy_b,
            "TaskContinue",
            &request_b,
            streaming,
            &task.id,
            BASE_NOW + 10,
        ),
        true,
    )
    .await;
    let (observed, mut observations) = tokio::sync::mpsc::unbounded_channel();
    let policy = smesh_a2a::AuthorizationPolicy::from_json(br#"{
        "schemaVersion":"smesh-authz-policy/v1","policyId":"adapter-test","revision":1,
        "tenants":[{"id":"tenant-adapter","enabled":true}],
        "accounts":[{"id":"actor-b","kind":"serviceAccount","memberships":[{"tenantId":"tenant-adapter","roles":["taskAgent"]}]}],
        "principalBindings":[{"principal":{"issuer":"test:adapter","subject":"actor-b"},"accountId":"actor-b"}]
    }"#).unwrap();
    let gateway = smesh_a2a::build_authorized_postgres_runtime_gateway(
        smesh_a2a::GatewayConfig::new("http://127.0.0.1:1", "actor-probe"),
        store.clone(),
        Arc::new(RecordingAdapter(observed)),
        smesh_a2a::InjectedClock::new(BASE_NOW + 11),
        smesh_a2a::auth::AuthState::new(Arc::new(NoHttpCredentials), [0x94; 32]),
        Arc::new(policy),
    )
    .unwrap();
    let result = std::panic::AssertUnwindSafe(async {
        let envelope = tokio::time::timeout(std::time::Duration::from_secs(5), observations.recv())
            .await
            .expect("actor B must reach external adapter")
            .unwrap();
        assert_eq!(envelope.scope().account_id(), "actor-b");
        assert_eq!(envelope.scope().principal_scope(), "principal-b");
        assert_eq!(envelope.scope().authentication_method(), "mutual-tls");
        assert_eq!(envelope.scope().visibility(), VisibilityScope::Tenant);
        assert_eq!(envelope.scope().authorization_policy_id(), "policy-b");
        assert_eq!(envelope.scope().authorization_policy_revision(), 2);
        assert_eq!(envelope.scope().authorization_policy_digest(), policy_b);
        assert_eq!(
            envelope.authorized_request_digest(),
            canonical_send_message_digest_v2(
                actor.tenant_scope(),
                actor.owner_account_id(),
                &request_b,
                streaming
            )
            .unwrap()
        );
        assert!(envelope.execution_reservation().is_some());
        gateway.wait_for_coordinator_idle().await.unwrap();
        // Task ownership is not rewritten to the continuation actor.
        let (client, connection) = tokio_postgres::connect(admin, tokio_postgres::NoTls)
            .await
            .unwrap();
        let driver = tokio::spawn(connection);
        client
            .query_one(
                "SELECT set_config('smesh.tenant_scope',$1,false)",
                &[&actor.tenant_scope()],
            )
            .await
            .unwrap();
        let row = client
            .query_one(
                &format!(
                    "SELECT owner_account_id FROM {}.tasks WHERE task_id=$1",
                    config.schema_name()
                ),
                &[&task.id],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, String>(0), "owner-a");
        drop(client);
        driver.abort();
    })
    .catch_unwind()
    .await;
    let shutdown = gateway.shutdown().await;
    drop(authority);
    drop(store);
    PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
    assert_eq!(
        shutdown.unwrap_err().message,
        "durable post-receive outcome is unresolved"
    );
}

#[tokio::test]
async fn postgres_runtime_authority_unary_streaming_initial_continuation_matrix() {
    tokio::time::timeout(Duration::from_secs(180), async {
        let admin_url = match env::var("SMESH_TEST_POSTGRES_ADMIN_URL") {
            Ok(value) => value,
            Err(env::VarError::NotPresent)
                if env::var("SMESH_POSTGRES_TEST_REQUIRED").as_deref() == Ok("1") =>
            {
                panic!("SMESH_TEST_POSTGRES_ADMIN_URL is required")
            }
            Err(env::VarError::NotPresent) => {
                eprintln!("skipping PostgreSQL runtime authority matrix: fixture is absent");
                return;
            }
            Err(env::VarError::NotUnicode(_)) => {
                panic!("SMESH_TEST_POSTGRES_ADMIN_URL must be valid Unicode")
            }
        };
        let runtime_url = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL")
            .expect("SMESH_TEST_POSTGRES_RUNTIME_URL is required");
        for streaming in [false, true] {
            cross_account_adapter_probe(&admin_url, &runtime_url, streaming).await;
        }
        let schema = format!("smesh_runtime_matrix_{:016x}", rand::random::<u64>());
        let quota = quota_policy();
        let config = PostgresStoreConfig::new(&admin_url, &runtime_url, &schema)
            .unwrap()
            .with_test_only_insecure_loopback(true)
            .with_quota_policy(Arc::clone(&quota));
        let store = Arc::new(PostgresTaskStore::open(config.clone()).await.unwrap());
        run_matrix(
            store.clone(),
            &MatrixBackend::Postgres { admin_url, schema },
            Some(quota),
        )
        .await;
        store.shutdown().await.unwrap();
        drop(store);
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    })
    .await
    .expect("PostgreSQL runtime-authority matrix watchdog");
}
