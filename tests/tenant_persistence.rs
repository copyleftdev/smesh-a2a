#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use a2a::{Message, Part, Role, SendMessageRequest, Task, TaskState, TaskStatus};
use smesh_a2a::{
    AdmissionOutcome, AuthorizationAuditInput, AuthorizationDecisionEffect, InputLimits,
    LegacyTenantBinding, OwnedTaskScope, SendMessageAdmission, SqliteTaskStore, VisibilityScope,
    canonical_send_message_digest_v2,
};

struct FixturePath(PathBuf);

impl AsRef<Path> for FixturePath {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for FixturePath {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm", ".lock"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.0.display()));
        }
        if let Some(parent) = self.0.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }
}

fn path(label: &str) -> FixturePath {
    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "smesh-tenant-v5-{label}-{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    FixturePath(dir.join("tasks.sqlite3"))
}

fn task(id: &str) -> Task {
    Task {
        id: id.to_owned(),
        context_id: "ctx".to_owned(),
        status: TaskStatus {
            state: TaskState::Submitted,
            message: None,
            timestamp: None,
        },
        artifacts: None,
        history: None,
        metadata: None,
    }
}

fn audit(effect: AuthorizationDecisionEffect, resource_digest: &str) -> AuthorizationAuditInput {
    AuthorizationAuditInput::new(
        format!("decision-{resource_digest}"),
        "tenant-a",
        "account-a",
        "policy-a",
        1,
        "sha256:policy",
        "task.get",
        effect,
        "policy_result",
        "task",
        resource_digest,
        None,
        100,
    )
    .unwrap()
}

async fn admit_v2(store: &SqliteTaskStore, task_id: &str) {
    let scope = OwnedTaskScope::new("tenant-a", "account-a", VisibilityScope::Own).unwrap();
    let mut message = Message::new(Role::User, vec![Part::text("work")]);
    message.message_id = format!("message-{task_id}");
    let request = SendMessageRequest {
        message: message.clone(),
        configuration: None,
        metadata: None,
        tenant: None,
    };
    let admitted_task = Task {
        id: task_id.to_owned(),
        context_id: "ctx".to_owned(),
        status: TaskStatus {
            state: TaskState::Submitted,
            message: None,
            timestamp: None,
        },
        artifacts: None,
        history: Some(vec![message.clone()]),
        metadata: None,
    };

    store
        .authorize_and_admit(
            &scope,
            SendMessageAdmission {
                request,
                streaming: false,
                task: admitted_task.clone(),
                original_result: a2a::SendMessageResponse::Task(admitted_task),
                input_limits: InputLimits::default(),
                now: 100,
                max_attempts: 3,
            },
            audit(
                AuthorizationDecisionEffect::Allow,
                &format!("sha256:{task_id}"),
            ),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn fresh_database_is_v5_with_immutable_ownership_and_append_only_audit() {
    let path = path("fresh");
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    drop(store);
    let db = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        db.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        5
    );
    let task_columns: Vec<String> = db
        .prepare("SELECT name FROM pragma_table_info('tasks') ORDER BY cid")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(task_columns.iter().any(|c| c == "tenant_scope"));
    assert!(task_columns.iter().any(|c| c == "owner_account_id"));
    let audit_table: i64 = db.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='authorization_decisions'", [], |r| r.get(0)).unwrap();
    assert_eq!(audit_table, 1);
}

#[tokio::test]
async fn scoped_reads_hide_foreign_and_audit_is_append_only() {
    let path = path("scoped");
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    let owner = OwnedTaskScope::new("tenant-a", "account-a", VisibilityScope::Own).unwrap();
    store
        .create_scoped(
            &owner,
            task("owned"),
            audit(AuthorizationDecisionEffect::Allow, "sha256:owned"),
        )
        .await
        .unwrap();
    assert!(store.get_scoped(&owner, "owned").await.unwrap().is_some());
    let foreign = OwnedTaskScope::new("tenant-b", "account-b", VisibilityScope::Tenant).unwrap();
    assert!(store.get_scoped(&foreign, "owned").await.unwrap().is_none());
    store
        .append_denied_authorization_decision(audit(
            AuthorizationDecisionEffect::Deny,
            "hmac:unknown",
        ))
        .await
        .unwrap();
    assert_eq!(store.authorization_decision_count().await.unwrap(), 2);
    drop(store);
    let db = rusqlite::Connection::open(&path).unwrap();
    assert!(
        db.execute("UPDATE authorization_decisions SET reason = 'changed'", [])
            .is_err()
    );
    assert!(
        db.execute("DELETE FROM authorization_decisions", [])
            .is_err()
    );
}

#[tokio::test]
async fn authorized_get_and_list_audit_allow_and_existence_safe_deny() {
    let path = path("authorized-reads");
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    let owner = OwnedTaskScope::new("tenant-a", "account-a", VisibilityScope::Own).unwrap();
    store
        .create_scoped(
            &owner,
            task("owned"),
            audit(AuthorizationDecisionEffect::Allow, "sha256:create"),
        )
        .await
        .unwrap();

    assert!(
        store
            .get_authorized(
                &owner,
                "owned",
                audit(AuthorizationDecisionEffect::Allow, "sha256:get-owned"),
            )
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .get_authorized(
                &owner,
                "missing",
                audit(AuthorizationDecisionEffect::Allow, "sha256:get-missing"),
            )
            .await
            .unwrap()
            .is_none()
    );
    let foreign = OwnedTaskScope::new("tenant-b", "account-a", VisibilityScope::Tenant).unwrap();
    assert!(
        store
            .get_authorized(
                &foreign,
                "owned",
                AuthorizationAuditInput::new(
                    "decision-foreign",
                    "tenant-b",
                    "account-a",
                    "policy-a",
                    1,
                    "sha256:policy",
                    "task.get",
                    AuthorizationDecisionEffect::Allow,
                    "policy_result",
                    "task",
                    "sha256:get-foreign",
                    None,
                    101,
                )
                .unwrap(),
            )
            .await
            .unwrap()
            .is_none()
    );
    let request = a2a::ListTasksRequest {
        context_id: None,
        status: None,
        page_size: None,
        page_token: None,
        history_length: None,
        status_timestamp_after: None,
        include_artifacts: None,
        tenant: None,
    };
    let listed = store
        .list_authorized(
            &owner,
            &request,
            audit(AuthorizationDecisionEffect::Allow, "sha256:list"),
            "sha256:cursor-scope",
        )
        .await
        .unwrap();
    assert_eq!(listed.total_size, 1);
    assert_eq!(store.authorization_decision_count().await.unwrap(), 5);
}

#[tokio::test]
async fn authorized_admission_persists_actual_owner_and_isolates_same_message_id() {
    let path = path("authorized-admission");
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    for (tenant, account, task_id, decision) in [
        ("tenant-a", "account-a", "task-a", "admit-a"),
        ("tenant-b", "account-b", "task-b", "admit-b"),
    ] {
        let scope = OwnedTaskScope::new(tenant, account, VisibilityScope::Own).unwrap();
        let mut message = Message::new(Role::User, vec![Part::text("work")]);
        message.message_id = "shared-message".to_owned();
        let admitted_task = Task {
            id: task_id.to_owned(),
            context_id: format!("ctx-{tenant}"),
            status: TaskStatus {
                state: TaskState::Submitted,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: Some(vec![message.clone()]),
            metadata: None,
        };
        let audit = AuthorizationAuditInput::new(
            decision,
            tenant,
            account,
            "policy-a",
            1,
            "sha256:policy",
            "TaskCreate",
            AuthorizationDecisionEffect::Allow,
            "policy_grant",
            "message",
            format!("sha256:{decision}"),
            None,
            200,
        )
        .unwrap();
        let outcome = store
            .authorize_and_admit(
                &scope,
                SendMessageAdmission {
                    request: SendMessageRequest {
                        message,
                        configuration: None,
                        metadata: None,
                        tenant: None,
                    },
                    streaming: false,
                    task: admitted_task.clone(),
                    original_result: a2a::SendMessageResponse::Task(admitted_task),
                    input_limits: InputLimits::default(),
                    now: 200,
                    max_attempts: 8,
                },
                audit,
            )
            .await
            .unwrap();
        assert!(matches!(outcome, AdmissionOutcome::Admitted(_)));
        assert!(store.get_scoped(&scope, task_id).await.unwrap().is_some());
    }
    let first = store
        .claim_outbox("worker", 200, 1000)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        first.tenant_scope.as_str(),
        "tenant-a" | "tenant-b"
    ));
    assert_eq!(store.authorization_decision_count().await.unwrap(), 2);
}

#[tokio::test]
async fn ownership_child_scope_and_audit_survive_restart_fail_closed() {
    let path = path("relations");
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    let owner = OwnedTaskScope::new("tenant-a", "account-a", VisibilityScope::Own).unwrap();
    store
        .create_scoped(
            &owner,
            task("owned"),
            audit(AuthorizationDecisionEffect::Allow, "hmac:owned"),
        )
        .await
        .unwrap();
    drop(store);
    let db = rusqlite::Connection::open(&path).unwrap();
    assert!(
        db.execute(
            "UPDATE tasks SET tenant_scope='tenant-b' WHERE task_id='owned'",
            []
        )
        .is_err()
    );
    assert!(db.execute(
        "INSERT INTO task_events(tenant_scope,task_id,event_seq,task_revision,event_kind,from_state,to_state,event_json,created_at)
         SELECT 'tenant-b',task_id,2,2,'forged',state,state,task_json,101 FROM tasks WHERE task_id='owned'", [],
    ).is_err());
    drop(db);
    let reopened = SqliteTaskStore::open(&path, 8).await.unwrap();
    assert_eq!(reopened.authorization_decision_count().await.unwrap(), 1);
    assert!(
        reopened
            .get_scoped(&owner, "owned")
            .await
            .unwrap()
            .is_some()
    );
}

#[test]
fn digest_v2_binds_tenant_actor_invocation_and_semantics() {
    let mut message = Message::new(Role::User, vec![Part::text("work")]);
    message.message_id = "message".to_owned();
    let request = SendMessageRequest {
        message,
        configuration: None,
        metadata: None,
        tenant: Some("caller-data".to_owned()),
    };
    let base = canonical_send_message_digest_v2("tenant-a", "account-a", &request, false).unwrap();
    assert_ne!(
        base,
        canonical_send_message_digest_v2("tenant-b", "account-a", &request, false).unwrap()
    );
    assert_ne!(
        base,
        canonical_send_message_digest_v2("tenant-a", "account-b", &request, false).unwrap()
    );
    assert_ne!(
        base,
        canonical_send_message_digest_v2("tenant-a", "account-a", &request, true).unwrap()
    );
    let mut different_caller_tenant = request.clone();
    different_caller_tenant.tenant = Some("untrusted-other-tenant".to_owned());
    assert_eq!(
        base,
        canonical_send_message_digest_v2("tenant-a", "account-a", &different_caller_tenant, false,)
            .unwrap(),
        "caller tenant data must not enter the server-authoritative digest"
    );
}

#[tokio::test]
async fn legacy_database_requires_explicit_validated_binding() {
    let path = path("legacy");
    {
        let db = rusqlite::Connection::open(&path).unwrap();
        db.pragma_update(None, "application_id", 0x534D_4132_i64)
            .unwrap();
        db.pragma_update(None, "user_version", 4_i64).unwrap();
    }
    assert!(SqliteTaskStore::open(&path, 8).await.is_err());
    assert_eq!(
        rusqlite::Connection::open(&path)
            .unwrap()
            .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        4
    );
    assert!(LegacyTenantBinding::new("", "account", "policy", 1, "digest").is_err());
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn audit_write_fault_rolls_back_authorized_admission_and_cancellation() {
    let admission_path = path("audit-admission-rollback");
    let admission_store = SqliteTaskStore::open(&admission_path, 8).await.unwrap();
    rusqlite::Connection::open(&admission_path)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER inject_authorization_audit_failure
             BEFORE INSERT ON authorization_decisions
             BEGIN SELECT RAISE(ABORT, 'injected audit write failure'); END;",
        )
        .unwrap();
    let scope = OwnedTaskScope::new("tenant-a", "account-a", VisibilityScope::Own).unwrap();
    let mut message = Message::new(Role::User, vec![Part::text("must roll back")]);
    message.message_id = "audit-fault-admission".to_owned();
    let admitted_task = Task {
        id: "audit-fault-task".to_owned(),
        context_id: "audit-fault-context".to_owned(),
        status: TaskStatus {
            state: TaskState::Submitted,
            message: None,
            timestamp: None,
        },
        artifacts: None,
        history: Some(vec![message.clone()]),
        metadata: None,
    };
    let result = admission_store
        .authorize_and_admit(
            &scope,
            SendMessageAdmission {
                request: SendMessageRequest {
                    message,
                    configuration: None,
                    metadata: None,
                    tenant: None,
                },
                streaming: false,
                task: admitted_task.clone(),
                original_result: a2a::SendMessageResponse::Task(admitted_task),
                input_limits: InputLimits::default(),
                now: 300,
                max_attempts: 8,
            },
            audit(
                AuthorizationDecisionEffect::Allow,
                "sha256:audit-fault-admit",
            ),
        )
        .await;
    assert!(result.is_err());
    assert!(
        admission_store
            .get_scoped(&scope, "audit-fault-task")
            .await
            .unwrap()
            .is_none()
    );
    drop(admission_store);
    let db = rusqlite::Connection::open(&admission_path).unwrap();
    for table in [
        "tasks",
        "task_events",
        "idempotency_records",
        "outbox",
        "authorization_decisions",
    ] {
        let count: i64 = db
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "{table} escaped failed admission transaction");
    }
    drop(db);

    let cancellation_path = path("audit-cancel-rollback");
    let cancellation_store = SqliteTaskStore::open(&cancellation_path, 8).await.unwrap();
    cancellation_store
        .create_scoped(
            &scope,
            task("cancel-audit-fault"),
            audit(
                AuthorizationDecisionEffect::Allow,
                "sha256:create-before-cancel",
            ),
        )
        .await
        .unwrap();
    let decisions_before = cancellation_store
        .authorization_decision_count()
        .await
        .unwrap();
    rusqlite::Connection::open(&cancellation_path)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER inject_cancel_audit_failure
             BEFORE INSERT ON authorization_decisions
             BEGIN SELECT RAISE(ABORT, 'injected cancel audit write failure'); END;",
        )
        .unwrap();
    let canceled = cancellation_store
        .cancel_authorized(
            &scope,
            "cancel-audit-fault",
            301,
            audit(
                AuthorizationDecisionEffect::Allow,
                "sha256:cancel-audit-fault",
            ),
        )
        .await;
    assert!(canceled.is_err());
    let unchanged = cancellation_store
        .get_scoped(&scope, "cancel-audit-fault")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.status.state, TaskState::Submitted);
    assert_eq!(
        cancellation_store
            .authorization_decision_count()
            .await
            .unwrap(),
        decisions_before
    );
}

#[tokio::test]
async fn v5_schema_rejects_partial_index_mutation() {
    let path = path("partial-index");
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    store.shutdown_shared().await.unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch(
        "DROP INDEX authorization_decisions_tenant_time;
         CREATE INDEX authorization_decisions_tenant_time
         ON authorization_decisions(tenant_scope, decided_at, decision_order)
         WHERE effect='allow';",
    )
    .unwrap();
    drop(db);
    assert!(matches!(
        SqliteTaskStore::open(&path, 8).await,
        Err(smesh_a2a::SqliteStoreError::InvalidSchema)
    ));
}

#[tokio::test]
async fn child_identity_columns_are_immutable() {
    let path = path("child-identity");
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    let owner = OwnedTaskScope::new("tenant-a", "account-a", VisibilityScope::Own).unwrap();
    store
        .create_scoped(
            &owner,
            task("owned"),
            audit(AuthorizationDecisionEffect::Allow, "sha256:create-identity"),
        )
        .await
        .unwrap();
    admit_v2(&store, "identity-admission").await;
    store.shutdown_shared().await.unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.pragma_update(None, "foreign_keys", true).unwrap();
    for statement in [
        "UPDATE task_events SET tenant_scope='tenant-b' WHERE task_id='owned'",
        "UPDATE task_events SET task_id='other' WHERE task_id='owned'",
        "UPDATE idempotency_records SET tenant_scope='tenant-b'",
        "UPDATE idempotency_records SET task_id='other'",
        "UPDATE outbox SET tenant_scope='tenant-b'",
        "UPDATE outbox SET task_id='other'",
        "UPDATE outbox SET message_id='other'",
    ] {
        assert!(
            db.execute(statement, []).is_err(),
            "identity mutation succeeded: {statement}"
        );
    }
}

#[tokio::test]
async fn continuation_and_cancellation_reject_misattributed_or_deny_audits_before_mutation() {
    let path = path("audit-binding");
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    let scope = OwnedTaskScope::new("tenant-a", "account-a", VisibilityScope::Tenant).unwrap();
    store
        .create_scoped(
            &scope,
            task("audit-bound-task"),
            audit(
                AuthorizationDecisionEffect::Allow,
                "sha256:create-audit-bound",
            ),
        )
        .await
        .unwrap();
    let mut message = Message::new(Role::User, vec![Part::text("continue")]);
    message.message_id = "audit-bound-message".into();
    message.task_id = Some("audit-bound-task".into());
    message.context_id = Some("ctx".into());
    let command = SendMessageAdmission {
        request: SendMessageRequest {
            message,
            configuration: None,
            metadata: None,
            tenant: None,
        },
        streaming: false,
        task: task("audit-bound-task"),
        original_result: a2a::SendMessageResponse::Task(task("audit-bound-task")),
        input_limits: InputLimits::default(),
        now: 200,
        max_attempts: 3,
    };
    let wrong_actor = AuthorizationAuditInput::new(
        "decision-wrong-actor",
        "tenant-a",
        "account-b",
        "policy-a",
        1,
        "sha256:policy",
        "TaskContinue",
        AuthorizationDecisionEffect::Allow,
        "policy_grant",
        "task",
        "sha256:wrong-actor",
        None,
        200,
    )
    .unwrap();
    assert!(
        store
            .authorize_and_continue(&scope, command, wrong_actor)
            .await
            .is_err()
    );
    let deny = AuthorizationAuditInput::new(
        "decision-deny-cancel",
        "tenant-a",
        "account-a",
        "policy-a",
        1,
        "sha256:policy",
        "TaskCancel",
        AuthorizationDecisionEffect::Deny,
        "role_denied",
        "task",
        "sha256:deny-cancel",
        None,
        201,
    )
    .unwrap();
    assert!(
        store
            .cancel_authorized(&scope, "audit-bound-task", 201, deny)
            .await
            .is_err()
    );
    assert_eq!(
        store
            .get_scoped(&scope, "audit-bound-task")
            .await
            .unwrap()
            .unwrap()
            .status
            .state,
        TaskState::Submitted
    );
    assert_eq!(store.authorization_decision_count().await.unwrap(), 1);
}

#[tokio::test]
async fn reopen_rejects_v2_digest_tamper_and_version_flip() {
    for (label, mutation) in [
        (
            "digest-tamper",
            "UPDATE idempotency_records SET request_digest='x'",
        ),
        (
            "version-flip",
            "UPDATE idempotency_records SET digest_version=1",
        ),
    ] {
        let path = path(label);
        let store = SqliteTaskStore::open(&path, 8).await.unwrap();
        admit_v2(&store, label).await;
        store.shutdown_shared().await.unwrap();
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute(mutation, []).unwrap();
        drop(db);
        assert!(matches!(
            SqliteTaskStore::open(&path, 8).await,
            Err(smesh_a2a::SqliteStoreError::InvalidSchema)
        ));
    }
}

#[tokio::test]
async fn foreign_and_missing_use_one_scoped_indexed_query_with_bounded_latency_evidence() {
    let path = path("scoped-query-plan");
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    admit_v2(&store, "foreign-row").await;
    let foreign_scope =
        OwnedTaskScope::new("tenant-b", "account-b", VisibilityScope::Tenant).unwrap();

    let mut foreign = Vec::with_capacity(64);
    let mut missing = Vec::with_capacity(64);
    for _ in 0..64 {
        let started = Instant::now();
        assert!(
            store
                .get_scoped(&foreign_scope, "foreign-row")
                .await
                .unwrap()
                .is_none()
        );
        foreign.push(started.elapsed());

        let started = Instant::now();
        assert!(
            store
                .get_scoped(&foreign_scope, "missing-row")
                .await
                .unwrap()
                .is_none()
        );
        missing.push(started.elapsed());
    }
    store.shutdown_shared().await.unwrap();

    let connection = rusqlite::Connection::open(&path).unwrap();
    let sql = "SELECT task_json FROM tasks WHERE tenant_scope=?1 AND task_id=?2
               AND (?3=0 OR owner_account_id=?4)";
    let plan = |task_id: &str| {
        connection
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .unwrap()
            .query_map(
                rusqlite::params!["tenant-b", task_id, 0_i64, "account-b"],
                |row| row.get::<_, String>(3),
            )
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    let foreign_plan = plan("foreign-row");
    let missing_plan = plan("missing-row");
    assert_eq!(
        foreign_plan, missing_plan,
        "resource values must not select another plan"
    );
    assert_eq!(foreign_plan.len(), 1, "lookup must remain one query branch");
    assert!(
        foreign_plan[0].contains("SEARCH tasks USING INDEX"),
        "scoped lookup must be indexed: {foreign_plan:?}"
    );
    assert!(!foreign_plan[0].contains("SCAN"));

    // Supplemental operational evidence only: this is deliberately generous and is
    // not a constant-time or cryptographic timing claim.
    foreign.sort_unstable();
    missing.sort_unstable();
    let p95 = 60;
    assert!(foreign[p95] < Duration::from_millis(500));
    assert!(missing[p95] < Duration::from_millis(500));
    assert!(foreign[p95].abs_diff(missing[p95]) < Duration::from_millis(100));
}
