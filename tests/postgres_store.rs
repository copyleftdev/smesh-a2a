#![allow(clippy::match_wild_err_arm)]

mod support;

use std::{env, fs, os::unix::fs::PermissionsExt as _, sync::Arc, time::Duration};

use smesh_a2a::{
    ArtifactAuthority, ArtifactPublicationTestFault, ArtifactStoreConfig, AuthorityDiagnostics,
    AuthorityIdentity, AuthorityShutdown, AuthorizationAuditInput, AuthorizationAuditSink,
    AuthorizationDecisionEffect, AuthorizedMutation, AuthorizedTaskRead, DurableAuthority,
    OutboxAuthority, OwnedTaskScope, PostgresStoreConfig, PostgresTaskStore,
    PostgresTransactionTestFault, QuotaReservationInput, ReceiverAuthority, SqliteTaskStore,
    TaskAdmission, TaskLifecycle, TranscriptAuthority, VisibilityScope,
};
#[cfg(debug_assertions)]
use smesh_a2a::{
    DurableLoopbackEndpoint, GatewayConfig, InjectedClock, SendMessageAdmission,
    build_durable_loopback_gateway,
};
use support::artifact_test_root::ArtifactTestRoot;
use support::authority_row_parity::{
    AUTHORITY_TABLES, assert_postgres_tables_match, assert_sqlite_tables_match, dump_postgres,
    dump_sqlite,
};
use support::durable_authority_conformance::{
    run_continuation_cancellation_conformance, run_durable_authority_command_conformance,
    run_durable_authority_command_conformance_open,
    run_quota_continuation_cancellation_conformance,
};
use support::row_parity_scenario::populate_pagination_and_active_cancellation;
use tokio_postgres::NoTls;
use url::Url;

macro_rules! postgres_test {
    ($name:ident, $seconds:literal, $body:block) => {
        #[tokio::test]
        async fn $name() {
            tokio::time::timeout(Duration::from_secs($seconds), async move $body)
                .await
                .unwrap_or_else(|_| panic!("PostgreSQL test {} exceeded {}s watchdog", stringify!($name), $seconds));
        }
    };
    ($name:ident, $body:block) => {
        #[tokio::test]
        async fn $name() {
            tokio::time::timeout(Duration::from_secs(30), async move $body)
                .await
                .unwrap_or_else(|_| panic!("PostgreSQL test {} exceeded 30s watchdog", stringify!($name)));
        }
    };
}

#[test]
fn callback_revision_seven_checksum_remains_immutable() {
    assert_eq!(
        smesh_a2a::content_digest(
            include_str!("../migrations/postgres/0007_callback_authority.sql").as_bytes()
        ),
        "sha256:1a7554355a426d933acc7cf7eb87af0b03e3fa919222b9699a387d60d844a65b"
    );
}

fn required_postgres_url(name: &str) -> String {
    env::var(name)
        .unwrap_or_else(|_| panic!("{name} is required by the PostgreSQL evidence harness"))
}

fn admin_url() -> Option<String> {
    match env::var("SMESH_TEST_POSTGRES_ADMIN_URL") {
        Ok(url) => Some(url),
        Err(_)
            if env::var("SMESH_POSTGRES_TEST_REQUIRED").as_deref() == Ok("1")
                || env::var("SMESH_TEST_POSTGRES_REQUIRED").as_deref() == Ok("1") =>
        {
            panic!("SMESH_TEST_POSTGRES_ADMIN_URL is required")
        }
        Err(_) => {
            eprintln!("skipping PostgreSQL test: SMESH_TEST_POSTGRES_ADMIN_URL is absent");
            None
        }
    }
}

fn superuser_url() -> String {
    required_postgres_url("SMESH_TEST_POSTGRES_SUPERUSER_URL")
}

struct EphemeralRoleGuard {
    superuser_url: String,
    schema: String,
    migrator: String,
}

impl EphemeralRoleGuard {
    fn new(schema: String, migrator: String) -> Self {
        assert!(schema.starts_with("smesh_non_super_") || schema.starts_with("smesh_guard_"));
        assert!(migrator.starts_with("smesh_migrator_"));
        Self {
            superuser_url: superuser_url(),
            schema,
            migrator,
        }
    }
}

impl Drop for EphemeralRoleGuard {
    fn drop(&mut self) {
        let url = self.superuser_url.clone();
        let schema = self.schema.clone();
        let migrator = self.migrator.clone();
        let _ = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .ok()?;
            runtime.block_on(async move {
                let (client, connection) = tokio_postgres::connect(&url, NoTls).await.ok()?;
                let driver = tokio::spawn(connection);
                let _ = client
                    .execute(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = $1 AND pid <> pg_backend_pid()",
                        &[&migrator],
                    )
                    .await;
                let _ = client
                    .batch_execute(&format!(
                        "DROP SCHEMA IF EXISTS {schema} CASCADE; DROP ROLE IF EXISTS {schema}_runtime; REVOKE CREATE ON DATABASE smesh_test FROM {migrator}; DROP OWNED BY {migrator}; DROP ROLE IF EXISTS {migrator}"
                    ))
                    .await;
                drop(client);
                driver.abort();
                Some(())
            })
        })
        .join();
    }
}

const RETAINED_AUTHORITY_TABLES: &[&str] = &[
    "tasks",
    "task_events",
    "idempotency_records",
    "outbox",
    "outbox_attempts",
    "outbox_tenant_scheduler",
    "receiver_inbox",
    "receiver_frames",
    "loopback_effects",
    "stream_transcripts",
    "stream_frames",
    "cancellation_intents",
    "authorization_decisions",
    "list_snapshots",
    "list_snapshot_entries",
    "list_page_tokens",
    "quota_reservations",
    "quota_policy_versions",
    "quota_policy_reconciliation_audits",
    "quota_intents",
    "quota_buckets",
    "quota_receipts",
    "quota_request_receipts",
    "quota_execution_reservations",
    "quota_allocations",
    "quota_leases",
    "quota_denial_audits",
    "quota_override_audits",
];

async fn assert_retained_counter_table_parity(
    client: &tokio_postgres::Client,
    schema: &str,
    tenant: &str,
    principal: &str,
) {
    let mut tenant_total = 0_i64;
    let mut principal_total = 0_i64;
    let mut detail = Vec::new();
    for table in RETAINED_AUTHORITY_TABLES {
        let row = client.query_one(
            &format!("SELECT COALESCE(sum({schema}.row_retained_bytes(r)),0)::bigint,COALESCE(sum({schema}.row_retained_bytes(r)) FILTER (WHERE {schema}.retained_principal(to_jsonb(r))=$2),0)::bigint FROM {schema}.{table} r WHERE tenant_scope=$1"),
            &[&tenant, &principal],
        ).await.unwrap();
        let tenant_bytes = row.get::<_, i64>(0);
        let principal_bytes = row.get::<_, i64>(1);
        tenant_total += tenant_bytes;
        principal_total += principal_bytes;
        detail.push((*table, tenant_bytes, principal_bytes));
    }
    let rows = client.query(
        &format!("SELECT scope_kind,scope_id,retained_bytes FROM {schema}.retained_authority_usage WHERE tenant_scope=$1 ORDER BY scope_kind,scope_id"),
        &[&tenant],
    ).await.unwrap();
    let materialized_tenant = rows
        .iter()
        .find(|row| row.get::<_, String>(0) == "tenant")
        .unwrap()
        .get::<_, i64>(2);
    let materialized_principal = rows
        .iter()
        .find(|row| row.get::<_, String>(0) == "principal" && row.get::<_, String>(1) == principal)
        .unwrap()
        .get::<_, i64>(2);
    assert_eq!(
        materialized_tenant, tenant_total,
        "tenant retained-byte table parity: {detail:?}"
    );
    assert_eq!(
        materialized_principal, principal_total,
        "principal retained-byte table parity: {detail:?}"
    );
}

fn config(url: String, suffix: &str) -> PostgresStoreConfig {
    let runtime_url = required_postgres_url("SMESH_TEST_POSTGRES_RUNTIME_URL");
    PostgresStoreConfig::new(
        url,
        runtime_url,
        format!("smesh_test_{suffix}_{:016x}", rand::random::<u64>()),
    )
    .unwrap()
    .with_test_only_insecure_loopback(true)
    .with_pool_size(4)
    .unwrap()
    .with_timeouts(Duration::from_secs(5), Duration::from_secs(5))
    .unwrap()
}

postgres_test!(
    injected_time_cannot_be_enabled_outside_loopback_test_transport,
    {
        let config = PostgresStoreConfig::new(
            "postgresql://migrator:secret@127.0.0.1:1/db?sslmode=require",
            "postgresql://runtime:secret@127.0.0.1:2/db?sslmode=require",
            "smesh_clock_seam",
        )
        .unwrap()
        .with_test_only_trust_injected_time(true)
        .with_timeouts(Duration::from_millis(50), Duration::from_millis(50))
        .unwrap();
        assert!(matches!(
            PostgresTaskStore::open(config).await,
            Err(smesh_a2a::PostgresStoreError::InvalidConfig)
        ));
    }
);

#[cfg(debug_assertions)]
postgres_test!(
    quota_enforcement_fails_closed_when_authorized_admission_omits_server_intent,
    {
        let Some(url) = admin_url() else { return };
        let config = config(url, "quota_missing_intent").with_quota_enforcement(true);
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        let scope = OwnedTaskScope::new(
            "tenant-quota-required",
            "account-quota-required",
            VisibilityScope::Own,
        )
        .unwrap();
        let mut message = a2a::Message::new(
            a2a::Role::User,
            vec![a2a::Part::text("caller metadata cannot opt into quota")],
        );
        message.message_id = "message-quota-required".into();
        message.metadata = Some(std::collections::HashMap::from([(
            "quota".to_owned(),
            serde_json::json!({"limit": 999_999}),
        )]));
        let request = a2a::SendMessageRequest {
            message: message.clone(),
            configuration: None,
            metadata: Some(std::collections::HashMap::from([(
                "x-quota-limit".to_owned(),
                serde_json::json!(999_999),
            )])),
            tenant: None,
        };
        let task = a2a::Task {
            id: "task-quota-required".into(),
            context_id: "context-quota-required".into(),
            status: a2a::TaskStatus {
                state: a2a::TaskState::Submitted,
                message: None,
                timestamp: chrono::DateTime::from_timestamp_millis(100),
            },
            artifacts: None,
            history: Some(vec![message]),
            metadata: None,
        };
        let command = SendMessageAdmission {
            request,
            streaming: false,
            task: task.clone(),
            original_result: a2a::SendMessageResponse::Task(task),
            input_limits: smesh_a2a::InputLimits::default(),
            now: 100,
            max_attempts: 2,
        };
        let audit = AuthorizationAuditInput::new(
            "audit-quota-required",
            "tenant-quota-required",
            "account-quota-required",
            "policy-quota-required",
            1,
            "digest-quota-required",
            "TaskCreate",
            AuthorizationDecisionEffect::Allow,
            "policy_grant",
            "message",
            "resource-quota-required",
            None,
            100,
        )
        .unwrap();
        let before = store.atomic_record_counts().await.unwrap();
        let error = store
            .authorize_and_admit(&scope, command, audit)
            .await
            .unwrap_err();
        assert_eq!(error.code, -32_011);
        assert_eq!(error.message, "quota authority unavailable");
        assert_eq!(store.atomic_record_counts().await.unwrap(), before);
        store.shutdown().await.unwrap();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    }
);

#[cfg(debug_assertions)]
postgres_test!(
    stream_snapshot_is_consistent_when_publication_commits_between_metadata_and_frames,
    {
        let Some(url) = admin_url() else { return };
        let config = config(url, "stream_snapshot");
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        let tenant = "tenant-stream-snapshot";
        let message_id = "message-stream-snapshot";
        let bound_message_id =
            smesh_a2a::authorized_message_identity(tenant, "owner-stream-snapshot", message_id);
        let mut message = a2a::Message::new(
            a2a::Role::User,
            vec![a2a::Part::text("consistent stream snapshot")],
        );
        message.message_id = message_id.into();
        let task = a2a::Task {
            id: "task-stream-snapshot".into(),
            context_id: "context-stream-snapshot".into(),
            status: a2a::TaskStatus {
                state: a2a::TaskState::Submitted,
                message: None,
                timestamp: chrono::DateTime::from_timestamp_millis(100),
            },
            artifacts: None,
            history: Some(vec![message.clone()]),
            metadata: None,
        };
        let initial = a2a::StreamResponse::Task(task.clone());
        let command = SendMessageAdmission {
            request: a2a::SendMessageRequest {
                message,
                configuration: None,
                metadata: None,
                tenant: None,
            },
            streaming: true,
            task: task.clone(),
            original_result: a2a::SendMessageResponse::Task(task.clone()),
            input_limits: smesh_a2a::InputLimits::default(),
            now: 100,
            max_attempts: 2,
        };
        let scope =
            OwnedTaskScope::new(tenant, "owner-stream-snapshot", VisibilityScope::Own).unwrap();
        let audit = AuthorizationAuditInput::new(
            "audit-stream-snapshot",
            tenant,
            "owner-stream-snapshot",
            "policy-stream-snapshot",
            1,
            "digest-stream-snapshot",
            "TaskCreate",
            AuthorizationDecisionEffect::Allow,
            "policy_grant",
            "message",
            "resource-stream-snapshot",
            None,
            100,
        )
        .unwrap();
        store
            .authorize_and_admit(&scope, command, audit)
            .await
            .unwrap();

        let (mut writer, writer_connection) = tokio_postgres::connect(&superuser_url(), NoTls)
            .await
            .unwrap();
        let writer_driver = tokio::spawn(writer_connection);
        let tx = writer.transaction().await.unwrap();
        let schema = config.schema_name();
        tx.batch_execute(&format!(
            "LOCK TABLE {schema}.stream_frames IN ACCESS EXCLUSIVE MODE"
        ))
        .await
        .unwrap();
        let reader_store = store.clone();
        let reader_message_id = bound_message_id.clone();
        let reader = tokio::spawn(async move {
            reader_store
                .stream_frames_after_scoped(tenant, &reader_message_id, 0)
                .await
        });
        let reached = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let blocked: bool = tx
                    .query_one(
                        "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE NOT granted AND relation=to_regclass($1))",
                        &[&format!("{schema}.stream_frames")],
                    )
                    .await
                    .unwrap()
                    .get(0);
                if blocked {
                    break;
                }
                if reader.is_finished() {
                    break;
                }
            }
        })
        .await;
        if reached.is_err() || reader.is_finished() {
            tx.rollback().await.unwrap();
            panic!("reader barrier failed; reader={:?}", reader.await.unwrap());
        }

        let update = a2a::StreamResponse::StatusUpdate(a2a::TaskStatusUpdateEvent {
            task_id: task.id.clone(),
            context_id: task.context_id.clone(),
            status: a2a::TaskStatus {
                state: a2a::TaskState::Working,
                message: None,
                timestamp: chrono::DateTime::from_timestamp_millis(101),
            },
            metadata: None,
        });
        let update_json = serde_json::to_string(&update).unwrap();
        let transcript_digest = smesh_a2a::content_digest(
            &serde_json::to_vec(&[initial.clone(), update.clone()]).unwrap(),
        );
        tx.batch_execute(&format!("SET LOCAL smesh.tenant_scope='{tenant}'"))
            .await
            .unwrap();
        tx.execute(
            &format!("INSERT INTO {schema}.stream_frames(tenant_scope,message_id,frame_seq,frame_version,frame_kind,frame_json,frame_digest,created_at) VALUES($1,$2,2,1,'status_update',$3,$4,101)"),
            &[&tenant, &bound_message_id, &update_json, &smesh_a2a::content_digest(update_json.as_bytes())],
        ).await.unwrap();
        tx.execute(
            &format!("UPDATE {schema}.stream_transcripts SET frame_count=2,transcript_digest=$1,updated_at=101 WHERE tenant_scope=$2 AND message_id=$3"),
            &[&transcript_digest, &tenant, &bound_message_id],
        ).await.unwrap();
        tx.commit().await.unwrap();

        let snapshot = reader
            .await
            .unwrap()
            .expect("snapshot read must remain valid");
        assert_eq!(snapshot.frames, vec![initial]);
        assert!(!snapshot.closed);
        let after = store
            .stream_frames_after_scoped(tenant, &bound_message_id, 1)
            .await
            .unwrap();
        assert_eq!(after.frames, vec![update]);
        writer_driver.abort();
        store.shutdown().await.unwrap();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    }
);

#[test]
fn postgres_config_redacts_both_migrator_and_runtime_urls() {
    let config = PostgresStoreConfig::new(
        "postgresql://migrator:migrator-canary@localhost/db",
        "postgresql://runtime:runtime-canary@localhost/db",
        "smesh_redaction",
    )
    .unwrap();
    let debug = format!("{config:?}");
    assert!(!debug.contains("migrator-canary"));
    assert!(!debug.contains("runtime-canary"));
    assert!(debug.contains("<redacted>"));
}

fn denied_audit(id: &str) -> AuthorizationAuditInput {
    AuthorizationAuditInput::new(
        id,
        "tenant-retry",
        "actor-retry",
        "policy-retry",
        1,
        "sha256:policy-retry",
        "TaskGet",
        AuthorizationDecisionEffect::Deny,
        "denied",
        "task",
        "sha256:resource-retry",
        None,
        1,
    )
    .unwrap()
}

#[tokio::test]
async fn sqlite_rejects_quota_before_any_schema_v6_mutation() {
    let root =
        std::env::temp_dir().join(format!("smesh-sqlite-quota-{:016x}", rand::random::<u64>()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.join("authority.sqlite3");
    let store = SqliteTaskStore::open(&path, 16).await.unwrap();
    assert!(!store.capabilities().quota_reservations);
    let scope = OwnedTaskScope::new(
        "tenant-sqlite-quota",
        "owner-sqlite-quota",
        VisibilityScope::Own,
    )
    .unwrap();
    let mut message = a2a::Message::new(a2a::Role::User, vec![a2a::Part::text("quota")]);
    message.message_id = "message-sqlite-quota".into();
    let task = a2a::Task {
        id: "task-sqlite-quota".into(),
        context_id: "context-sqlite-quota".into(),
        status: a2a::TaskStatus {
            state: a2a::TaskState::Submitted,
            message: None,
            timestamp: None,
        },
        artifacts: None,
        history: Some(vec![message.clone()]),
        metadata: None,
    };
    let command = smesh_a2a::SendMessageAdmission {
        request: a2a::SendMessageRequest {
            message,
            configuration: None,
            metadata: None,
            tenant: None,
        },
        streaming: false,
        task: task.clone(),
        original_result: a2a::SendMessageResponse::Task(task),
        input_limits: smesh_a2a::InputLimits::default(),
        now: 100,
        max_attempts: 2,
    };
    let quota = QuotaReservationInput::new(
        "tenant-sqlite-quota",
        "owner-sqlite-quota",
        "principal-sqlite-quota",
        "TaskCreate",
        "mutations",
        1,
        "reservation-sqlite-quota",
        10_000,
        None,
    )
    .unwrap();
    let audit = AuthorizationAuditInput::new(
        "audit-sqlite-quota",
        "tenant-sqlite-quota",
        "owner-sqlite-quota",
        "policy",
        1,
        "sha256:policy",
        "TaskCreate",
        AuthorizationDecisionEffect::Allow,
        "grant",
        "task",
        "sha256:resource",
        None,
        100,
    )
    .unwrap();
    let before = store.atomic_record_counts().await.unwrap();
    let error = store
        .authorize_and_admit_mutation(
            &scope,
            AuthorizedMutation::with_quota(command, quota),
            audit,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("unsupported"));
    assert_eq!(store.atomic_record_counts().await.unwrap(), before);
    store.shutdown().await.unwrap();
    let sqlite = rusqlite::Connection::open(&path).unwrap();
    let tables: i64 = sqlite
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='quota_reservations'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        tables, 0,
        "SQLite schema v6 must remain without a quota table"
    );
    drop(sqlite);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn retryable_growth_uses_materialized_quota_enforcement_without_global_hot_path_lock() {
    let source = include_str!("../src/postgres_store.rs");
    let runner = &source[source.find("async fn run_retryable_transaction").unwrap()
        ..source.find("fn q(&self").unwrap()];
    assert!(!runner.contains("pg_advisory_xact_lock"));
    assert!(!runner.contains("ensure_capacity"));
    assert!(!runner.contains("authority_tenants_bounded"));
    let migration = include_str!("../migrations/postgres/0004_distributed_quota_authority.sql");
    assert!(migration.contains("account_retained_authority_row"));
    assert!(migration.contains("tenant_limit:=COALESCE(tenant_limit,67108864)"));
    assert!(migration.contains("retained authority account quota exceeded"));
    assert!(migration.contains("retained authority tenant quota exceeded"));
    assert!(migration.contains("retained authority principal quota exceeded"));
    for mutation in [
        "insert_audit(tx",
        "INSERT INTO __S__.tasks",
        "UPDATE __S__.tasks SET",
        "INSERT INTO __S__.task_events",
        "INSERT INTO __S__.idempotency_records",
        "UPDATE __S__.idempotency_records SET",
        "INSERT INTO __S__.outbox",
        "UPDATE __S__.outbox SET",
        "UPDATE __S__.outbox_attempts SET",
        "INSERT INTO __S__.stream_frames",
        "INSERT INTO __S__.list_snapshots",
        "INSERT INTO __S__.list_snapshot_entries",
        "INSERT INTO __S__.list_page_tokens",
        "UPDATE __S__.receiver_inbox SET",
        "INSERT INTO __S__.receiver_inbox",
        "INSERT INTO __S__.receiver_frames",
        "INSERT INTO __S__.loopback_effects",
        "INSERT INTO __S__.cancellation_intents",
    ] {
        assert!(
            source.contains(mutation),
            "growth inventory drifted: {mutation}"
        );
    }
}

#[test]
fn direct_postgres_transactions_are_only_runner_migration_or_read_only_allowlist() {
    let source = include_str!("../src/postgres_store.rs");
    assert_eq!(
        source.matches(".transaction()").count() + source.matches(".build_transaction()").count(),
        17,
        "new direct transaction site must be routed through the bounded runner or explicitly reviewed"
    );
    assert_eq!(
        source.matches("IsolationLevel::RepeatableRead").count(),
        1,
        "the multi-statement transcript snapshot must use one PostgreSQL snapshot"
    );
    for reason in [
        "central whole-transaction retry runner owns this site",
        "migration uses advisory-lock fencing",
        "read-only consistent final-result lookup",
        "read-only task/lease snapshot",
        "read-only transcript snapshot",
        "read-only subscription snapshot",
        "read-only event snapshot",
        "read-only tenant-scoped startup semantic validation",
        "read-only callback semantic validation needs a transaction-local forced-RLS marker",
        "read-only indexed quota diagnostics for deterministic evidence",
        "read-only indexed scoped telemetry correlation lookup",
        "policy reconciliation is startup-only, advisory-fenced, and atomically audited",
        "artifact orphan claim persists before unlink",
        "artifact orphan finalize fences exact ownership",
        "read-only tenant/key-generation snapshot before atomic reload",
        "operator-only bounded authorization retention transaction",
    ] {
        assert!(
            source.contains(reason),
            "missing transaction allowlist reason: {reason}"
        );
    }
    for mutating in [
        "authorized replay transaction failed",
        "atomic admission transaction failed",
        "continuation transaction failed",
        "authorized get transaction failed",
        "task snapshot transaction failed",
        "outbox claim transaction failed",
        "outbox finish transaction failed",
        "stream progress transaction failed",
        "delivery transaction failed",
        "receiver transaction failed",
        "receiver completion transaction failed",
        "cancellation transaction failed",
    ] {
        assert!(
            !source.contains(mutating),
            "mutating command retained a direct transaction path: {mutating}"
        );
    }
}

postgres_test!(
    whole_transaction_retries_retryable_sqlstates_and_commits_once,
    {
        let Some(url) = admin_url() else { return };
        let config = config(url, "transaction_retry").with_transaction_test_faults([
            PostgresTransactionTestFault::SerializationFailure,
            PostgresTransactionTestFault::DeadlockDetected,
        ]);
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        store
            .append_denied_authorization_decision(denied_audit("retry-success"))
            .await
            .unwrap();
        assert_eq!(store.transaction_attempts(), 3);
        assert_eq!(store.authorization_decision_count().await.unwrap(), 1);
        store.shutdown().await.unwrap();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    }
);

postgres_test!(
    exhausted_nonretryable_and_ambiguous_commit_never_mutate_or_overretry,
    {
        let Some(url) = admin_url() else { return };

        let exhausted_config = config(url.clone(), "tx_exhaust")
            .with_transaction_test_faults([PostgresTransactionTestFault::SerializationFailure; 3]);
        let exhausted = PostgresTaskStore::open(exhausted_config.clone())
            .await
            .unwrap();
        let error = exhausted
            .append_denied_authorization_decision(denied_audit("retry-exhausted"))
            .await
            .unwrap_err();
        assert_eq!(error.message, "PostgreSQL transaction retry limit reached");
        assert_eq!(exhausted.transaction_attempts(), 3);
        assert_eq!(exhausted.authorization_decision_count().await.unwrap(), 0);
        exhausted.shutdown().await.unwrap();
        PostgresTaskStore::drop_test_schema(&exhausted_config)
            .await
            .unwrap();

        let nonretryable_config = config(url.clone(), "tx_nonretry")
            .with_transaction_test_faults([PostgresTransactionTestFault::NonRetryable]);
        let nonretryable = PostgresTaskStore::open(nonretryable_config.clone())
            .await
            .unwrap();
        nonretryable
            .append_denied_authorization_decision(denied_audit("nonretryable"))
            .await
            .unwrap_err();
        assert_eq!(nonretryable.transaction_attempts(), 1);
        assert_eq!(
            nonretryable.authorization_decision_count().await.unwrap(),
            0
        );
        nonretryable.shutdown().await.unwrap();
        PostgresTaskStore::drop_test_schema(&nonretryable_config)
            .await
            .unwrap();

        let ambiguous_config = config(url, "tx_ambig")
            .with_transaction_test_faults([PostgresTransactionTestFault::AmbiguousCommit]);
        let ambiguous = PostgresTaskStore::open(ambiguous_config.clone())
            .await
            .unwrap();
        ambiguous
            .append_denied_authorization_decision(denied_audit("ambiguous"))
            .await
            .unwrap_err();
        assert_eq!(ambiguous.transaction_attempts(), 1);
        assert_eq!(ambiguous.authorization_decision_count().await.unwrap(), 0);
        ambiguous.shutdown().await.unwrap();
        PostgresTaskStore::drop_test_schema(&ambiguous_config)
            .await
            .unwrap();
    }
);

postgres_test!(
    independent_retrying_stores_preserve_both_committed_winners,
    {
        let Some(url) = admin_url() else { return };
        let base = config(url, "tx_concurrent");
        let retrying_config = base
            .clone()
            .with_transaction_test_faults([PostgresTransactionTestFault::SerializationFailure]);
        let retrying = PostgresTaskStore::open(retrying_config).await.unwrap();
        let independent = PostgresTaskStore::open(base.clone()).await.unwrap();
        let (left, right) = tokio::join!(
            retrying.append_denied_authorization_decision(denied_audit("concurrent-left")),
            independent.append_denied_authorization_decision(denied_audit("concurrent-right")),
        );
        left.unwrap();
        right.unwrap();
        assert_eq!(retrying.transaction_attempts(), 2);
        assert_eq!(retrying.authorization_decision_count().await.unwrap(), 2);
        retrying.shutdown().await.unwrap();
        independent.shutdown().await.unwrap();
        PostgresTaskStore::drop_test_schema(&base).await.unwrap();
    }
);

postgres_test!(
    migrates_empty_real_postgres_and_reopens_with_same_identity,
    {
        let Some(url) = admin_url() else { return };
        let config = config(url, "open");
        let first = PostgresTaskStore::open(config.clone()).await.unwrap();
        let key = first.completion_receipt_key();
        first.shutdown().await.unwrap();
        let second = PostgresTaskStore::open(config.clone()).await.unwrap();
        assert_eq!(key, second.completion_receipt_key());
        second.shutdown().await.unwrap();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    }
);

postgres_test!(
    sqlite_and_postgres_have_exhaustive_normalized_authority_row_parity,
    {
        let Some(url) = admin_url() else { return };
        let root = env::temp_dir().join(format!("smesh-row-parity-{}", rand::random::<u64>()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let sqlite_path = root.join("authority.sqlite3");
        let sqlite = Arc::new(
            SqliteTaskStore::open_with_audit_projection(&sqlite_path, 64)
                .await
                .unwrap(),
        );
        let sqlite_key = sqlite.completion_receipt_key();

        let pg_config = config(url.clone(), "row_parity").with_audit_projection(true);
        let postgres = Arc::new(PostgresTaskStore::open(pg_config.clone()).await.unwrap());
        let postgres_key = postgres
            .completion_receipt_key()
            .expect("PostgreSQL authority key");
        assert_ne!(
            sqlite_key, postgres_key,
            "fresh stores must have distinct keys"
        );

        let sqlite_authority: Arc<dyn DurableAuthority> = sqlite;
        run_durable_authority_command_conformance_open(sqlite_authority.clone()).await;
        populate_pagination_and_active_cancellation(sqlite_authority.clone()).await;
        sqlite_authority.shutdown().await.unwrap();
        let postgres_authority: Arc<dyn DurableAuthority> = postgres;
        run_durable_authority_command_conformance_open(postgres_authority.clone()).await;
        populate_pagination_and_active_cancellation(postgres_authority.clone()).await;
        postgres_authority.shutdown().await.unwrap();

        assert_sqlite_tables_match(&sqlite_path);
        let sqlite_dump = dump_sqlite(&sqlite_path);
        let (client, driver) = admin_client(&superuser_url()).await;
        assert_postgres_tables_match(&client, pg_config.schema_name()).await;
        assert_retained_counter_table_parity(
            &client,
            pg_config.schema_name(),
            "tenant-conformance",
            "account:owner-conformance",
        )
        .await;
        let postgres_dump = dump_postgres(&client, pg_config.schema_name()).await;

        assert_eq!(sqlite_dump.counts.len(), AUTHORITY_TABLES.len());
        assert_eq!(postgres_dump.counts.len(), AUTHORITY_TABLES.len());
        assert_eq!(sqlite_dump, postgres_dump);
        for table in AUTHORITY_TABLES {
            if table.starts_with("callback_") {
                continue;
            }
            assert!(
                sqlite_dump.counts[table] > 0,
                "row-parity scenario did not populate {table}"
            );
        }

        let sqlite_reopened = SqliteTaskStore::open_with_audit_projection(&sqlite_path, 64)
            .await
            .unwrap();
        assert_eq!(sqlite_reopened.completion_receipt_key(), sqlite_key);
        sqlite_reopened.shutdown().await.unwrap();
        let postgres_reopened = PostgresTaskStore::open(pg_config.clone()).await.unwrap();
        assert_eq!(
            postgres_reopened.completion_receipt_key(),
            Some(postgres_key)
        );
        postgres_reopened.shutdown().await.unwrap();

        client
            .execute(
                &format!("UPDATE {}.retained_authority_usage SET retained_bytes=retained_bytes+1 WHERE tenant_scope='tenant-conformance' AND scope_kind='principal' AND scope_id='account:owner-conformance'", pg_config.schema_name()),
                &[],
            )
            .await
            .unwrap();
        assert!(matches!(
            PostgresTaskStore::open(pg_config.clone()).await,
            Err(smesh_a2a::PostgresStoreError::InvalidSchema)
        ));

        drop(client);
        driver.abort();
        PostgresTaskStore::drop_test_schema(&pg_config)
            .await
            .unwrap();
        fs::remove_dir_all(root).unwrap();
    }
);

postgres_test!(
    postgres_runs_shared_durable_authority_command_conformance,
    {
        let Some(url) = admin_url() else { return };
        let config = config(url, "conformance");
        let store = Arc::new(PostgresTaskStore::open(config.clone()).await.unwrap());
        let authority: Arc<dyn DurableAuthority> = store;
        run_durable_authority_command_conformance(authority).await;
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    }
);

postgres_test!(postgres_runs_continuation_and_cancellation_conformance, {
    let Some(url) = admin_url() else { return };
    let config = config(url, "continuation");
    let store = Arc::new(PostgresTaskStore::open(config.clone()).await.unwrap());
    let authority: Arc<dyn DurableAuthority> = store;
    run_continuation_cancellation_conformance(authority).await;
    PostgresTaskStore::drop_test_schema(&config).await.unwrap();
});

postgres_test!(postgres_quota_continuation_and_cancellation_are_atomic, {
    let Some(url) = admin_url() else { return };
    let config = config(url, "quota_cc");
    let store = Arc::new(PostgresTaskStore::open(config.clone()).await.unwrap());
    let authority: Arc<dyn DurableAuthority> = store;
    run_quota_continuation_cancellation_conformance(authority).await;
    let (client, driver) = admin_client(&superuser_url()).await;
    let count: i64 = client.query_one(
        &format!("SELECT count(*) FROM {}.quota_reservations WHERE tenant_scope='tenant-conformance'", config.schema_name()),
        &[],
    ).await.unwrap().get(0);
    assert_eq!(
        count, 3,
        "admission, continuation replay, and cancellation reserve each key once"
    );
    drop(client);
    driver.abort();
    PostgresTaskStore::drop_test_schema(&config).await.unwrap();
});

async fn admin_client(url: &str) -> (tokio_postgres::Client, tokio::task::JoinHandle<()>) {
    let (client, connection) = tokio_postgres::connect(url, NoTls).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    (client, driver)
}

postgres_test!(concurrent_openers_share_one_advisory_locked_migration, {
    let Some(url) = admin_url() else { return };
    let config = config(url, "race");
    let (a, b) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            PostgresTaskStore::open(config.clone()),
            PostgresTaskStore::open(config.clone())
        )
    })
    .await
    .unwrap();
    let a = a.unwrap();
    let b = b.unwrap();
    assert_eq!(a.completion_receipt_key(), b.completion_receipt_key());
    a.shutdown().await.unwrap();
    assert_eq!(b.atomic_record_counts().await.unwrap().tasks, 0);
    b.shutdown().await.unwrap();
    PostgresTaskStore::drop_test_schema(&config).await.unwrap();
});

postgres_test!(
    populated_revision_three_migrates_atomically_and_reopens_reconciled,
    {
        let Some(_) = admin_url() else { return };
        let schema = format!("smesh_v3_upgrade_{:016x}", rand::random::<u64>());
        let role = format!("{schema}_runtime");
        let migrator = url::Url::parse(&superuser_url())
            .unwrap()
            .username()
            .to_owned();
        let render = |sql: &str| {
            sql.replace("__SCHEMA__", &schema)
                .replace("__ROLE__", &role)
                .replace("__MIGRATOR__", &migrator)
        };
        let (client, driver) = admin_client(&superuser_url()).await;
        client
            .batch_execute(&render(include_str!(
                "../migrations/postgres/0001_authority_schema_v6.sql"
            )))
            .await
            .unwrap();
        client
            .batch_execute(&render(include_str!(
                "../migrations/postgres/0002_quota_reservation_seam.sql"
            )))
            .await
            .unwrap();
        client
            .batch_execute(&render(include_str!(
                "../migrations/postgres/0003_receiver_sender_fence.sql"
            )))
            .await
            .unwrap();
        for (tenant, account, suffix, receiver_state) in [
            ("tenant-v3-a", "account-a", "a", "completed"),
            ("tenant-v3-b", "account-b", "b", "processing"),
        ] {
            let task = format!("task-{suffix}");
            let message = format!("message-{suffix}");
            let dispatch = format!("dispatch-{suffix}");
            client.execute(&format!("INSERT INTO {schema}.tasks(tenant_scope,task_id,context_id,state,revision,task_json,owner_account_id) VALUES($1,$2,'context','\"TASK_STATE_WORKING\"',1,'{{}}',$3)"), &[&tenant,&task,&account]).await.unwrap();
            client.execute(&format!("INSERT INTO {schema}.task_events(tenant_scope,task_id,event_seq,task_revision,event_kind,to_state,event_json,created_at) VALUES($1,$2,1,1,'seed','\"TASK_STATE_WORKING\"','{{}}',100)"), &[&tenant,&task]).await.unwrap();
            client.execute(&format!("INSERT INTO {schema}.idempotency_records(tenant_scope,message_id,request_digest,task_id,state,admission_result_json,created_at,updated_at,digest_version,actor_account_id) VALUES($1,$2,'digest',$3,'in_progress','{{}}',100,100,2,$4)"), &[&tenant,&message,&task,&account]).await.unwrap();
            let outbox_state = if receiver_state == "processing" {
                "leased"
            } else {
                "delivered"
            };
            let lease_owner: Option<&str> = (outbox_state == "leased").then_some("owner");
            let lease_token: Option<&str> = (outbox_state == "leased").then_some("token");
            let lease_until: Option<i64> = (outbox_state == "leased").then_some(1_000);
            let outbox_id: i64 = client.query_one(&format!("INSERT INTO {schema}.outbox(tenant_scope,dispatch_id,task_id,message_id,causative_revision,payload_json,payload_digest,state,attempt_count,max_attempts,available_at,lease_owner,lease_token,lease_until,created_at,updated_at,dispatch_identity_version) VALUES($1,$2,$3,$4,1,'{{}}','digest',$5,1,2,100,$6,$7,$8,100,100,2) RETURNING outbox_id"), &[&tenant,&dispatch,&task,&message,&outbox_state,&lease_owner,&lease_token,&lease_until]).await.unwrap().get(0);
            client.execute(&format!("INSERT INTO {schema}.outbox_attempts(tenant_scope,outbox_id,attempt_no,lease_token,started_at,finished_at,outcome) VALUES($1,$2,1,'token',100,CASE WHEN $3='completed' THEN 200 END,CASE WHEN $3='completed' THEN 'delivered' END)"), &[&tenant,&outbox_id,&receiver_state]).await.unwrap();
            if receiver_state == "completed" {
                client.execute(&format!("INSERT INTO {schema}.receiver_inbox(tenant_scope,dispatch_id,payload_digest,payload_json,task_id,context_id,state,lease_epoch,completion_kind,termination_json,frame_count,transcript_digest,accepted_at,completed_at,updated_at,sender_attempt_no,sender_lease_token) VALUES($1,$2,'digest','{{}}',$3,'context','completed',1,'success','{{}}',1,'transcript',100,200,200,1,'token')"), &[&tenant,&dispatch,&task]).await.unwrap();
                client.execute(&format!("INSERT INTO {schema}.receiver_frames VALUES($1,$2,1,1,'mesh_event','{{\"Progress\":\"done\"}}','digest',150)"), &[&tenant,&dispatch]).await.unwrap();
            } else {
                client.execute(&format!("INSERT INTO {schema}.receiver_inbox(tenant_scope,dispatch_id,payload_digest,payload_json,task_id,context_id,state,lease_epoch,lease_owner,lease_token,lease_until,accepted_at,updated_at,sender_attempt_no,sender_lease_token) VALUES($1,$2,'digest','{{}}',$3,'context','processing',1,'owner','token',1000,100,100,1,'token')"), &[&tenant,&dispatch,&task]).await.unwrap();
            }
            client.execute(&format!("INSERT INTO {schema}.stream_transcripts(tenant_scope,message_id,dispatch_id,task_id,transcript_version,state,frame_count,created_at,updated_at) VALUES($1,$2,$3,$4,1,'open',1,100,100)"), &[&tenant,&message,&dispatch,&task]).await.unwrap();
            client.execute(&format!("INSERT INTO {schema}.stream_frames VALUES($1,$2,1,1,'task','{{}}','digest',100)"), &[&tenant,&message]).await.unwrap();
            client.execute(&format!("INSERT INTO {schema}.authorization_decisions(decision_id,tenant_scope,actor_account_id,policy_id,policy_revision,policy_digest,operation,effect,reason,resource_kind,resource_digest,task_id,decided_at) VALUES($1,$2,$3,'policy',1,'digest','TaskGet','allow','seed','task','resource',$4,100)"), &[&format!("decision-{suffix}"),&tenant,&account,&task]).await.unwrap();
        }
        let v4 = render(include_str!(
            "../migrations/postgres/0004_distributed_quota_authority.sql"
        ));
        client.batch_execute("BEGIN").await.unwrap();
        client.batch_execute(&v4).await.unwrap();
        assert!(client.batch_execute("SELECT 1/0").await.is_err());
        client.batch_execute("ROLLBACK").await.unwrap();
        let absent: bool = client.query_one("SELECT NOT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=$1 AND table_name='receiver_inbox' AND column_name='measured_output_bytes')", &[&schema]).await.unwrap().get(0);
        assert!(
            absent,
            "faulted migration must leave exact revision three catalog"
        );
        client.batch_execute("BEGIN").await.unwrap();
        client.batch_execute(&v4).await.unwrap();
        client.batch_execute("COMMIT").await.unwrap();
        drop(client);
        driver.abort();

        let (reopened, reopened_driver) = admin_client(&superuser_url()).await;
        let completed = reopened.query_one(&format!("SELECT measured_output_bytes,measured_event_count FROM {schema}.receiver_inbox WHERE tenant_scope='tenant-v3-a'"), &[]).await.unwrap();
        assert!(completed.get::<_, i64>(0) > 0);
        assert_eq!(completed.get::<_, i64>(1), 1);
        let processing = reopened.query_one(&format!("SELECT measured_output_bytes IS NULL AND measured_event_count IS NULL FROM {schema}.receiver_inbox WHERE tenant_scope='tenant-v3-b'"), &[]).await.unwrap();
        assert!(processing.get::<_, bool>(0));
        let schedulers: i64 = reopened
            .query_one(
                &format!("SELECT count(*) FROM {schema}.outbox_tenant_scheduler"),
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(schedulers, 2);
        for tenant in ["tenant-v3-a", "tenant-v3-b"] {
            let row = reopened.query_one(&format!("SELECT retained_bytes,{schema}.retained_authority_oracle($1,NULL) FROM {schema}.retained_authority_usage WHERE tenant_scope=$1 AND scope_kind='tenant' AND scope_id=$1"), &[&tenant]).await.unwrap();
            assert_eq!(row.get::<_, i64>(0), row.get::<_, i64>(1));
        }
        reopened
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE; DROP ROLE {role}"))
            .await
            .unwrap();
        drop(reopened);
        reopened_driver.abort();
    }
);

postgres_test!(startup_rejects_mutated_catalog_index, {
    let Some(url) = admin_url() else { return };
    let config = config(url.clone(), "drift");
    let store = PostgresTaskStore::open(config.clone()).await.unwrap();
    store.shutdown().await.unwrap();
    let (client, driver) = admin_client(&superuser_url()).await;
    client
        .batch_execute(&format!("DROP INDEX {}.outbox_due", config.schema_name()))
        .await
        .unwrap();
    assert!(PostgresTaskStore::open(config.clone()).await.is_err());
    drop(client);
    driver.abort();
    PostgresTaskStore::drop_test_schema(&config).await.unwrap();
});

postgres_test!(
    startup_rejects_poisoned_definer_owner_and_internal_policy,
    {
        let Some(url) = admin_url() else { return };
        let (client, driver) = admin_client(&superuser_url()).await;

        let owner_config = config(url.clone(), "poisoned_owner");
        let owner_store = PostgresTaskStore::open(owner_config.clone()).await.unwrap();
        owner_store.shutdown().await.unwrap();
        client
            .batch_execute(&format!(
                "ALTER FUNCTION {}.claim_outbox_bounded(bigint,text,text,bigint) OWNER TO postgres",
                owner_config.schema_name()
            ))
            .await
            .unwrap();
        assert!(matches!(
            PostgresTaskStore::open(owner_config.clone()).await,
            Err(smesh_a2a::PostgresStoreError::InvalidSchema)
        ));
        PostgresTaskStore::drop_test_schema(&owner_config)
            .await
            .unwrap();

        let policy_config = config(url, "poisoned_policy");
        let policy_store = PostgresTaskStore::open(policy_config.clone())
            .await
            .unwrap();
        policy_store.shutdown().await.unwrap();
        client
            .batch_execute(&format!(
                "ALTER POLICY internal_diagnostics ON {}.tasks USING (true)",
                policy_config.schema_name()
            ))
            .await
            .unwrap();
        assert!(matches!(
            PostgresTaskStore::open(policy_config.clone()).await,
            Err(smesh_a2a::PostgresStoreError::InvalidSchema)
        ));
        PostgresTaskStore::drop_test_schema(&policy_config)
            .await
            .unwrap();
        drop(client);
        driver.abort();
    }
);

postgres_test!(startup_rejects_runtime_membership_in_migrator, {
    let Some(url) = admin_url() else { return };
    let migrator = Url::parse(&url).unwrap().username().to_owned();
    let runtime_url = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap_or_else(|_| {
        "postgresql://smesh_test_runtime:smesh_runtime_password@127.0.0.1:55432/smesh_test".into()
    });
    let runtime = Url::parse(&runtime_url).unwrap().username().to_owned();
    let config = config(url, "runtime_member");
    let (client, driver) = admin_client(&superuser_url()).await;
    client
        .batch_execute(&format!("GRANT {migrator} TO {runtime}"))
        .await
        .unwrap();
    let result = PostgresTaskStore::open(config).await;
    client
        .batch_execute(&format!("REVOKE {migrator} FROM {runtime}"))
        .await
        .unwrap();
    assert!(matches!(
        result,
        Err(smesh_a2a::PostgresStoreError::InvalidSchema)
    ));
    drop(client);
    driver.abort();
});

postgres_test!(
    startup_rejects_nested_bypass_membership_before_first_open,
    {
        let Some(url) = admin_url() else { return };
        let runtime_url = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap();
        let runtime = Url::parse(&runtime_url).unwrap().username().to_owned();
        let suffix = format!("{:016x}", rand::random::<u64>());
        let benign = format!("smesh_benign_{suffix}");
        let bypass = format!("smesh_bypass_{suffix}");
        let config = config(url, "nested_bypass");
        let (client, driver) = admin_client(&superuser_url()).await;
        client.batch_execute(&format!(
        "CREATE ROLE {benign} NOLOGIN NOINHERIT; CREATE ROLE {bypass} NOLOGIN NOINHERIT BYPASSRLS; GRANT {bypass} TO {benign} WITH INHERIT FALSE, SET FALSE; GRANT {benign} TO {runtime} WITH INHERIT FALSE, SET TRUE"
    )).await.unwrap();
        assert!(matches!(
            PostgresTaskStore::open(config).await,
            Err(smesh_a2a::PostgresStoreError::InvalidSchema)
        ));
        client.batch_execute(&format!(
        "REVOKE {benign} FROM {runtime}; REVOKE {bypass} FROM {benign}; DROP ROLE {benign}; DROP ROLE {bypass}"
    )).await.unwrap();
        drop(client);
        driver.abort();
    }
);

postgres_test!(
    startup_rejects_unexpected_membership_after_catalog_sealing,
    {
        let Some(url) = admin_url() else { return };
        let runtime_url = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap();
        let runtime = Url::parse(&runtime_url).unwrap().username().to_owned();
        let config = config(url, "sealed_membership");
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        store.shutdown().await.unwrap();
        let role = format!("smesh_unexpected_{:016x}", rand::random::<u64>());
        let (client, driver) = admin_client(&superuser_url()).await;
        client.batch_execute(&format!(
        "CREATE ROLE {role} NOLOGIN NOINHERIT; GRANT {role} TO {runtime} WITH INHERIT FALSE, SET TRUE"
    )).await.unwrap();
        assert!(matches!(
            PostgresTaskStore::open(config.clone()).await,
            Err(smesh_a2a::PostgresStoreError::InvalidSchema)
        ));
        client
            .batch_execute(&format!("REVOKE {role} FROM {runtime}; DROP ROLE {role}"))
            .await
            .unwrap();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
        drop(client);
        driver.abort();
    }
);

postgres_test!(
    startup_rejects_runtime_admin_option_after_catalog_sealing,
    {
        let Some(url) = admin_url() else { return };
        let runtime_url = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap();
        let runtime = Url::parse(&runtime_url).unwrap().username().to_owned();
        let config = config(url, "sealed_admin_option");
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        store.shutdown().await.unwrap();
        let generated = format!("{}_runtime", config.schema_name());
        let (client, driver) = admin_client(&superuser_url()).await;
        client
            .batch_execute(&format!("GRANT {generated} TO {runtime} WITH ADMIN OPTION"))
            .await
            .unwrap();
        assert!(matches!(
            PostgresTaskStore::open(config.clone()).await,
            Err(smesh_a2a::PostgresStoreError::InvalidSchema)
        ));
        client
            .batch_execute(&format!(
                "REVOKE ADMIN OPTION FOR {generated} FROM {runtime}"
            ))
            .await
            .unwrap();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
        drop(client);
        driver.abort();
    }
);

postgres_test!(startup_rejects_preexisting_privileged_runtime_role, {
    let Some(url) = admin_url() else { return };
    let config = config(url.clone(), "poisoned_role");
    let role = format!("{}_runtime", config.schema_name());
    let (client, driver) = admin_client(&superuser_url()).await;
    client
        .batch_execute(&format!("CREATE ROLE {role} NOLOGIN SUPERUSER BYPASSRLS"))
        .await
        .unwrap();
    let Err(error) = PostgresTaskStore::open(config.clone()).await else {
        panic!("privileged runtime role must be rejected");
    };
    assert_eq!(error, smesh_a2a::PostgresStoreError::InvalidSchema);
    client
        .batch_execute(&format!("DROP ROLE {role}"))
        .await
        .unwrap();
    drop(client);
    driver.abort();
});

postgres_test!(non_superuser_migrator_opens_and_runtime_cannot_escalate, {
    let Some(_admin) = admin_url() else { return };
    let suffix = format!("{:016x}", rand::random::<u64>());
    let migrator = format!("smesh_migrator_{suffix}");
    let schema = format!("smesh_non_super_{suffix}");
    let (client, driver) = admin_client(&superuser_url()).await;
    client.batch_execute(&format!(
        "CREATE ROLE {migrator} LOGIN PASSWORD 'bounded-migrator' NOSUPERUSER NOBYPASSRLS NOCREATEDB CREATEROLE NOREPLICATION NOINHERIT; GRANT CREATE ON DATABASE smesh_test TO {migrator}"
    )).await.unwrap();
    let _cleanup = EphemeralRoleGuard::new(schema.clone(), migrator.clone());
    let migrator_url =
        format!("postgresql://{migrator}:bounded-migrator@127.0.0.1:55432/smesh_test");
    let runtime_url = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap_or_else(|_| {
        "postgresql://smesh_test_runtime:smesh_runtime_password@127.0.0.1:55432/smesh_test".into()
    });
    let config = PostgresStoreConfig::new(migrator_url, runtime_url.clone(), schema.clone())
        .unwrap()
        .with_test_only_insecure_loopback(true);
    let store = PostgresTaskStore::open(config.clone()).await.unwrap();
    assert_eq!(store.atomic_record_counts().await.unwrap().tasks, 0);
    let (mut runtime, runtime_driver) = admin_client(&runtime_url).await;
    let tx = runtime.transaction().await.unwrap();
    tx.batch_execute(&format!("SET LOCAL ROLE {schema}_runtime"))
        .await
        .unwrap();
    let count: i64 = tx
        .query_one(&format!("SELECT count(*) FROM {schema}.tasks"), &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
    assert!(
        tx.batch_execute(&format!("CREATE TABLE {schema}.forbidden(id int)"))
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    store.shutdown().await.unwrap();
    PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    client
        .batch_execute(&format!(
            "REVOKE CREATE ON DATABASE smesh_test FROM {migrator}; DROP ROLE {migrator}"
        ))
        .await
        .unwrap();
    drop(runtime);
    runtime_driver.abort();
    drop(client);
    driver.abort();
});

postgres_test!(ephemeral_migrator_guard_cleans_after_injected_failure, {
    let Some(_admin) = admin_url() else { return };
    let suffix = format!("{:016x}", rand::random::<u64>());
    let migrator = format!("smesh_migrator_{suffix}");
    let schema = format!("smesh_guard_{suffix}");
    let (client, driver) = admin_client(&superuser_url()).await;
    client
        .batch_execute(&format!(
            "CREATE ROLE {migrator} LOGIN CREATEROLE; GRANT CREATE ON DATABASE smesh_test TO {migrator}; CREATE SCHEMA {schema} AUTHORIZATION {migrator}; CREATE ROLE {schema}_runtime NOLOGIN"
        ))
        .await
        .unwrap();
    let failed = std::panic::catch_unwind({
        let schema = schema.clone();
        let migrator = migrator.clone();
        move || {
            let _cleanup = EphemeralRoleGuard::new(schema, migrator);
            panic!("injected failure after schema creation");
        }
    });
    assert!(failed.is_err());
    assert_eq!(
        client
            .query_one(
                "SELECT count(*) FROM pg_roles WHERE rolname = $1 OR rolname = $2",
                &[&migrator, &format!("{schema}_runtime")],
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        client
            .query_one(
                "SELECT count(*) FROM information_schema.schemata WHERE schema_name = $1",
                &[&schema],
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    drop(client);
    driver.abort();
});

postgres_test!(
    forced_rls_fails_closed_and_transaction_context_does_not_leak,
    {
        let Some(url) = admin_url() else { return };
        let config = config(url.clone(), "rls");
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        let (mut client, driver) = admin_client(&superuser_url()).await;
        let role = format!("{}_runtime", config.schema_name());
        let table = format!("{}.tasks", config.schema_name());
        let insert = format!(
            "INSERT INTO {table}(tenant_scope,task_id,context_id,state,revision,task_json,owner_account_id) VALUES($1,'task','ctx','state',1,'{{}}','owner')"
        );

        let tx = client.transaction().await.unwrap();
        tx.batch_execute(&format!("SET LOCAL ROLE {role}"))
            .await
            .unwrap();
        assert!(tx.execute(&insert, &[&"tenant-a"]).await.is_err());
        tx.rollback().await.unwrap();

        let malicious = "tenant-a'; RESET ROLE; --";
        let tx = client.transaction().await.unwrap();
        tx.batch_execute(&format!("SET LOCAL ROLE {role}"))
            .await
            .unwrap();
        tx.query_one(
            "SELECT set_config('smesh.tenant_scope',$1,true)",
            &[&malicious],
        )
        .await
        .unwrap();
        tx.execute(&insert, &[&malicious]).await.unwrap();
        let count: i64 = tx
            .query_one(&format!("SELECT count(*) FROM {table}"), &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, 1);
        tx.commit().await.unwrap();

        let tx = client.transaction().await.unwrap();
        tx.batch_execute(&format!("SET LOCAL ROLE {role}"))
            .await
            .unwrap();
        let missing: i64 = tx
            .query_one(&format!("SELECT count(*) FROM {table}"), &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(missing, 0);
        tx.query_one(
            "SELECT set_config('smesh.tenant_scope',$1,true)",
            &[&"tenant-b"],
        )
        .await
        .unwrap();
        let foreign: i64 = tx
            .query_one(&format!("SELECT count(*) FROM {table}"), &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(foreign, 0);
        tx.rollback().await.unwrap();

        store.shutdown().await.unwrap();
        drop(client);
        driver.abort();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    }
);

postgres_test!(runtime_cannot_forge_internal_rls_operation_gucs, {
    let Some(url) = admin_url() else { return };
    let config = config(url, "internal_forgery");
    let store = PostgresTaskStore::open(config.clone()).await.unwrap();
    let schema = config.schema_name();
    let (admin, admin_driver) = admin_client(&superuser_url()).await;
    for tenant in ["tenant-a", "tenant-b"] {
        admin.execute(
            &format!("INSERT INTO {schema}.tasks(tenant_scope,task_id,context_id,state,revision,task_json,owner_account_id) VALUES($1,$2,'ctx','state',1,'{{}}','owner')"),
            &[&tenant, &format!("task-{tenant}")],
        ).await.unwrap();
    }

    let runtime_url = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap_or_else(|_| {
        "postgresql://smesh_test_runtime:smesh_runtime_password@127.0.0.1:55432/smesh_test".into()
    });
    let (mut runtime, runtime_driver) = admin_client(&runtime_url).await;
    for operation in ["diag-v1", "claim-v1", "cancel-v1"] {
        let tx = runtime.transaction().await.unwrap();
        tx.batch_execute(&format!("SET LOCAL ROLE {schema}_runtime"))
            .await
            .unwrap();
        tx.query_one(
            "SELECT set_config('smesh.tenant_scope','tenant-a',true), set_config('smesh.internal_global',$1,true)",
            &[&operation],
        )
        .await
        .unwrap();
        let visible: Vec<String> = tx
            .query(
                &format!("SELECT tenant_scope FROM {schema}.tasks ORDER BY tenant_scope"),
                &[],
            )
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.get(0))
            .collect();
        assert_eq!(
            visible,
            ["tenant-a"],
            "forged {operation} bypassed tenant RLS"
        );
        tx.rollback().await.unwrap();
    }

    let tx = runtime.transaction().await.unwrap();
    tx.batch_execute(&format!("SET LOCAL ROLE {schema}_runtime"))
        .await
        .unwrap();
    tx.query_one(
        "SELECT set_config('smesh.tenant_scope','',true), set_config('smesh.internal_global','diag-v1',true)",
        &[],
    )
    .await
    .unwrap();
    let direct: i64 = tx
        .query_one(&format!("SELECT count(*) FROM {schema}.tasks"), &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(direct, 0, "forged diagnostics GUC exposed global rows");
    let bounded: i64 = tx
        .query_one(
            &format!("SELECT tasks FROM {schema}.authority_diagnostics_bounded()"),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(bounded, 2, "bounded diagnostic procedure stopped working");
    tx.rollback().await.unwrap();

    store.shutdown().await.unwrap();
    drop(runtime);
    runtime_driver.abort();
    drop(admin);
    admin_driver.abort();
    PostgresTaskStore::drop_test_schema(&config).await.unwrap();
});

postgres_test!(
    frozen_pages_survive_reopen_and_reject_tamper_and_query_changes,
    {
        use a2a::{ListTasksRequest, Task, TaskState, TaskStatus};
        let Some(url) = admin_url() else { return };
        let config = config(url.clone(), "frozen");
        let first = PostgresTaskStore::open(config.clone()).await.unwrap();
        let (client, driver) = admin_client(&superuser_url()).await;
        let insert = format!(
            "INSERT INTO {}.tasks(tenant_scope,task_id,context_id,state,status_timestamp,revision,task_json,owner_account_id) VALUES($1,$2,'ctx',$3,$4,1,$5,$6)",
            config.schema_name()
        );
        for n in 0..3 {
            let task = Task {
                id: format!("task-{n}"),
                context_id: "ctx".into(),
                status: TaskStatus {
                    state: TaskState::Submitted,
                    message: None,
                    timestamp: chrono::DateTime::from_timestamp_millis(100 + n),
                },
                artifacts: None,
                history: None,
                metadata: None,
            };
            client
                .execute(
                    &insert,
                    &[
                        &"tenant",
                        &task.id,
                        &serde_json::to_string(&task.status.state).unwrap(),
                        &task.status.timestamp.map(|v| v.to_rfc3339()),
                        &serde_json::to_string(&task).unwrap(),
                        &"owner",
                    ],
                )
                .await
                .unwrap();
            client.execute(
            &format!("INSERT INTO {}.task_events(tenant_scope,task_id,event_seq,task_revision,event_kind,from_state,to_state,event_json,created_at) VALUES($1,$2,1,1,'authorized_admitted',NULL,$3,$4,$5)", config.schema_name()),
            &[&"tenant", &task.id, &serde_json::to_string(&task.status.state).unwrap(), &serde_json::to_string(&task).unwrap(), &(100_i64 + n)],
        ).await.unwrap();
        }
        let scope = OwnedTaskScope::new("tenant", "owner", VisibilityScope::Own).unwrap();
        let request = ListTasksRequest {
            context_id: None,
            status: None,
            page_size: Some(1),
            page_token: None,
            history_length: Some(0),
            status_timestamp_after: None,
            include_artifacts: Some(false),
            tenant: None,
        };
        let audit = |id: &str| {
            AuthorizationAuditInput::new(
                id,
                "tenant",
                "owner",
                "policy",
                1,
                "sha256:policy",
                "TaskList",
                AuthorizationDecisionEffect::Allow,
                "visible_set",
                "task-list",
                "sha256:list",
                None,
                1,
            )
            .unwrap()
        };
        let page1 = first
            .list_authorized(&scope, &request, audit("list-1"), "scope-a")
            .await
            .unwrap();
        assert_eq!(page1.total_size, 3);
        assert_eq!(page1.tasks.len(), 1);
        assert!(!page1.next_page_token.is_empty());
        first.shutdown().await.unwrap();
        let second = PostgresTaskStore::open(config.clone()).await.unwrap();
        let mut next = request.clone();
        next.page_token = Some(page1.next_page_token.clone());
        let page2 = second
            .list_authorized(&scope, &next, audit("list-2"), "scope-a")
            .await
            .unwrap();
        assert_eq!(page2.tasks.len(), 1);
        assert_ne!(page1.tasks[0].id, page2.tasks[0].id);
        let mut tampered = next.clone();
        tampered.page_token = Some(format!("{}x", page1.next_page_token));
        assert!(
            second
                .list_authorized(&scope, &tampered, audit("list-3"), "scope-a")
                .await
                .is_err()
        );
        let mut changed = next;
        changed.history_length = Some(1);
        assert!(
            second
                .list_authorized(&scope, &changed, audit("list-4"), "scope-a")
                .await
                .is_err()
        );
        second.shutdown().await.unwrap();
        assert!(
            PostgresTaskStore::open(config.clone().with_max_tasks(2).unwrap())
                .await
                .is_err()
        );
        drop(client);
        driver.abort();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    }
);

postgres_test!(startup_rejects_corrupt_task_event_history, {
    let Some(url) = admin_url() else { return };
    let config = config(url.clone(), "event_corruption");
    let store = Arc::new(PostgresTaskStore::open(config.clone()).await.unwrap());
    let authority: Arc<dyn DurableAuthority> = store;
    run_durable_authority_command_conformance(authority).await;
    let (client, driver) = admin_client(&superuser_url()).await;
    client
        .execute(
            &format!(
                "UPDATE {}.task_events SET event_json='{{}}' WHERE event_seq=1",
                config.schema_name()
            ),
            &[],
        )
        .await
        .unwrap();
    assert!(matches!(
        PostgresTaskStore::open(config.clone()).await,
        Err(smesh_a2a::PostgresStoreError::InvalidSchema)
    ));
    drop(client);
    driver.abort();
    PostgresTaskStore::drop_test_schema(&config).await.unwrap();
});

postgres_test!(populated_external_query_families_use_bounded_index_plans, {
    let Some(url) = admin_url() else { return };
    let config = config(url.clone(), "plans");
    let store = Arc::new(PostgresTaskStore::open(config.clone()).await.unwrap());
    let authority: Arc<dyn DurableAuthority> = store;
    run_durable_authority_command_conformance_open(authority.clone()).await;
    populate_pagination_and_active_cancellation(authority.clone()).await;
    authority.shutdown().await.unwrap();
    let (client, driver) = admin_client(&superuser_url()).await;
    client
        .batch_execute(&format!(
            "INSERT INTO {0}.tasks(tenant_scope,task_id,context_id,state,status_timestamp,revision,task_json,owner_account_id) SELECT 'plan-index','plan-task-'||g,'context','\"TASK_STATE_SUBMITTED\"',NULL,1,'{{\"id\":\"fixture\"}}','owner' FROM generate_series(1,2000) g; INSERT INTO {0}.outbox(dispatch_id,tenant_scope,task_id,message_id,causative_revision,payload_json,payload_digest,state,attempt_count,max_attempts,available_at,created_at,updated_at,dispatch_identity_version) SELECT 'plan-dispatch-'||g,'plan-index','plan-task-'||g,'plan-message-'||g,1,'{{}}','digest','pending',0,3,0,1,1,1 FROM generate_series(1,2000) g; INSERT INTO {0}.cancellation_intents(tenant_scope,dispatch_id,task_id,state,requested_at) SELECT 'plan-index','plan-dispatch-'||g,'plan-task-'||g,'requested',1 FROM generate_series(1,2000) g; ANALYZE {0}.outbox; ANALYZE {0}.cancellation_intents",
            config.schema_name()
        ))
        .await
        .unwrap();
    let cancellation = client.query(&format!("EXPLAIN SELECT 1 FROM {0}.cancellation_intents WHERE dispatch_id='missing' AND state='requested'", config.schema_name()), &[]).await.unwrap().into_iter().map(|row| row.get::<_,String>(0)).collect::<Vec<_>>().join("\n");
    assert!(
        cancellation.contains("cancellation_intents_dispatch_requested"),
        "{cancellation}"
    );
    drop(client);
    driver.abort();
    PostgresTaskStore::drop_test_schema(&config).await.unwrap();
});

postgres_test!(outbox_claims_rotate_durably_between_due_tenants, {
    let Some(url) = admin_url() else { return };
    let config = config(url, "fair_claim").with_test_only_trust_injected_time(true);
    let store = Arc::new(PostgresTaskStore::open(config.clone()).await.unwrap());
    let peer = Arc::new(PostgresTaskStore::open(config.clone()).await.unwrap());
    let (client, driver) = admin_client(&superuser_url()).await;
    let schema = config.schema_name();
    for (tenant, suffix, available_at) in [
        ("tenant-a", "a1", 1_i64),
        ("tenant-a", "a2", 2_i64),
        ("tenant-b", "b1", 3_i64),
    ] {
        let task_id = format!("task-{suffix}");
        let context_id = format!("context-{suffix}");
        let message_id = format!("message-{suffix}");
        let dispatch_id = format!("dispatch-{suffix}");
        let task = a2a::Task {
            id: task_id.clone(),
            context_id: context_id.clone(),
            status: a2a::TaskStatus {
                state: a2a::TaskState::Submitted,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        };
        let task_json = serde_json::to_string(&task).unwrap();
        let state = serde_json::to_string(&task.status.state).unwrap();
        let request = smesh_a2a::MeshRequest {
            protocol: "a2a-v1".into(),
            task_id: task_id.clone(),
            context_id: context_id.clone(),
            text: suffix.into(),
        };
        let payload = serde_json::to_string(&request).unwrap();
        let payload_digest = smesh_a2a::content_digest(payload.as_bytes());
        let admission = serde_json::to_string(&a2a::SendMessageResponse::Task(task)).unwrap();
        client.execute(&format!("INSERT INTO {schema}.tasks(tenant_scope,task_id,context_id,state,revision,task_json,owner_account_id) VALUES($1,$2,$3,$4,1,$5,'owner')"), &[&tenant,&task_id,&context_id,&state,&task_json]).await.unwrap();
        client.execute(&format!("INSERT INTO {schema}.idempotency_records(tenant_scope,message_id,request_digest,task_id,state,admission_result_json,created_at,updated_at,digest_version,actor_account_id) VALUES($1,$2,$3,$4,'in_progress',$5,1,1,2,'owner')"), &[&tenant,&message_id,&format!("sha256:{suffix}"),&task_id,&admission]).await.unwrap();
        client.execute(&format!("INSERT INTO {schema}.outbox(tenant_scope,dispatch_id,task_id,message_id,causative_revision,payload_json,payload_digest,state,max_attempts,available_at,created_at,updated_at,dispatch_identity_version) VALUES($1,$2,$3,$4,1,$5,$6,'pending',2,$7,1,1,2)"), &[&tenant,&dispatch_id,&task_id,&message_id,&payload,&payload_digest,&available_at]).await.unwrap();
    }
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let claim = |authority: Arc<PostgresTaskStore>, owner: &'static str| {
        let barrier = Arc::clone(&barrier);
        tokio::spawn(async move {
            barrier.wait().await;
            authority
                .claim_outbox(owner, 10, 100)
                .await
                .unwrap()
                .unwrap()
        })
    };
    let first = claim(Arc::clone(&store), "fair-owner-1");
    let second = claim(Arc::clone(&peer), "fair-owner-2");
    barrier.wait().await;
    let (first, second) = tokio::join!(first, second);
    let mut tenants = [first.unwrap().tenant_scope, second.unwrap().tenant_scope];
    tenants.sort();
    assert_eq!(
        tenants,
        ["tenant-a", "tenant-b"],
        "tenant A backlog starved tenant B"
    );
    drop(client);
    driver.abort();
    store.shutdown().await.unwrap();
    peer.shutdown().await.unwrap();
    PostgresTaskStore::drop_test_schema(&config).await.unwrap();
});

postgres_test!(
    expired_final_attempt_with_pending_cancellation_reconciles_to_canceled,
    {
        let Some(url) = admin_url() else { return };
        let config = config(url.clone(), "final_expiry").with_test_only_trust_injected_time(true);
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        let (client, driver) = admin_client(&superuser_url()).await;
        let task = a2a::Task {
            id: "expiry-task".into(),
            context_id: "expiry-context".into(),
            status: a2a::TaskStatus {
                state: a2a::TaskState::Submitted,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        };
        let task_json = serde_json::to_string(&task).unwrap();
        let state = serde_json::to_string(&task.status.state).unwrap();
        let request = smesh_a2a::MeshRequest {
            protocol: "a2a-v1".into(),
            task_id: task.id.clone(),
            context_id: task.context_id.clone(),
            text: "expire".into(),
        };
        let payload = serde_json::to_string(&request).unwrap();
        let digest = smesh_a2a::content_digest(payload.as_bytes());
        let admission =
            serde_json::to_string(&a2a::SendMessageResponse::Task(task.clone())).unwrap();
        let initial = a2a::StreamResponse::Task(task.clone());
        let initial_json = serde_json::to_string(&initial).unwrap();
        let transcript_digest =
            smesh_a2a::content_digest(&serde_json::to_vec(std::slice::from_ref(&initial)).unwrap());
        let schema = config.schema_name();
        client.execute(&format!("INSERT INTO {schema}.tasks(tenant_scope,task_id,context_id,state,revision,task_json,owner_account_id) VALUES($1,$2,$3,$4,1,$5,$6)"), &[&"tenant-expiry",&task.id,&task.context_id,&state,&task_json,&"owner"]).await.unwrap();
        client.execute(&format!("INSERT INTO {schema}.task_events(tenant_scope,task_id,event_seq,task_revision,event_kind,from_state,to_state,event_json,created_at) VALUES($1,$2,1,1,'admitted',NULL,$3,$4,100)"), &[&"tenant-expiry",&task.id,&state,&task_json]).await.unwrap();
        client.execute(&format!("INSERT INTO {schema}.idempotency_records(tenant_scope,message_id,request_digest,task_id,state,admission_result_json,created_at,updated_at,digest_version,actor_account_id) VALUES('tenant-expiry','message-expiry','sha256:request',$1,'in_progress',$2,100,100,2,'owner')"), &[&task.id,&admission]).await.unwrap();
        client.execute(&format!("INSERT INTO {schema}.outbox(tenant_scope,dispatch_id,task_id,message_id,causative_revision,payload_json,payload_digest,state,max_attempts,available_at,created_at,updated_at,dispatch_identity_version) VALUES($1,$2,$3,$4,1,$5,$6,'pending',1,100,100,100,2)"), &[&"tenant-expiry",&"dispatch-expiry",&task.id,&"message-expiry",&payload,&digest]).await.unwrap();
        client.execute(&format!("INSERT INTO {schema}.stream_transcripts(tenant_scope,message_id,dispatch_id,task_id,transcript_version,state,frame_count,transcript_digest,created_at,updated_at) VALUES('tenant-expiry','message-expiry','dispatch-expiry',$1,1,'open',1,$2,100,100)"), &[&task.id,&transcript_digest]).await.unwrap();
        client.execute(&format!("INSERT INTO {schema}.stream_frames(tenant_scope,message_id,frame_seq,frame_version,frame_kind,frame_json,frame_digest,created_at) VALUES('tenant-expiry','message-expiry',1,1,'task',$1,$2,100)"), &[&initial_json,&smesh_a2a::content_digest(initial_json.as_bytes())]).await.unwrap();
        let lease = store
            .claim_outbox("expiry-owner", 100, 10)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(lease.attempt_no, 1);
        for (suffix, disposition) in [
            (
                "retry",
                smesh_a2a::AttemptDisposition::Retry {
                    available_at: 105,
                    error: "final live retry".into(),
                },
            ),
            (
                "permanent",
                smesh_a2a::AttemptDisposition::Permanent {
                    error: "final live permanent".into(),
                },
            ),
        ] {
            let mut live_task = task.clone();
            live_task.id = format!("live-{suffix}-task");
            live_task.context_id = format!("live-{suffix}-context");
            let live_task_json = serde_json::to_string(&live_task).unwrap();
            let mut live_request = request.clone();
            live_request.task_id = live_task.id.clone();
            live_request.context_id = live_task.context_id.clone();
            let live_payload = serde_json::to_string(&live_request).unwrap();
            let live_digest = smesh_a2a::content_digest(live_payload.as_bytes());
            let live_admission =
                serde_json::to_string(&a2a::SendMessageResponse::Task(live_task.clone())).unwrap();
            let live_initial = a2a::StreamResponse::Task(live_task.clone());
            let live_initial_json = serde_json::to_string(&live_initial).unwrap();
            let live_transcript_digest =
                smesh_a2a::content_digest(&serde_json::to_vec(&[live_initial]).unwrap());
            let message_id = format!("live-{suffix}-message");
            let dispatch_id = format!("live-{suffix}-dispatch");
            client.execute(&format!("INSERT INTO {schema}.tasks(tenant_scope,task_id,context_id,state,revision,task_json,owner_account_id) VALUES('tenant-expiry',$1,$2,$3,1,$4,'owner')"), &[&live_task.id,&live_task.context_id,&state,&live_task_json]).await.unwrap();
            client.execute(&format!("INSERT INTO {schema}.task_events(tenant_scope,task_id,event_seq,task_revision,event_kind,from_state,to_state,event_json,created_at) VALUES('tenant-expiry',$1,1,1,'admitted',NULL,$2,$3,100)"), &[&live_task.id,&state,&live_task_json]).await.unwrap();
            client.execute(&format!("INSERT INTO {schema}.idempotency_records(tenant_scope,message_id,request_digest,task_id,state,admission_result_json,created_at,updated_at,digest_version,actor_account_id) VALUES('tenant-expiry',$1,'sha256:request',$2,'in_progress',$3,100,100,2,'owner')"), &[&message_id,&live_task.id,&live_admission]).await.unwrap();
            client.execute(&format!("INSERT INTO {schema}.outbox(tenant_scope,dispatch_id,task_id,message_id,causative_revision,payload_json,payload_digest,state,max_attempts,available_at,created_at,updated_at,dispatch_identity_version) VALUES('tenant-expiry',$1,$2,$3,1,$4,$5,'pending',1,100,100,100,2)"), &[&dispatch_id,&live_task.id,&message_id,&live_payload,&live_digest]).await.unwrap();
            client.execute(&format!("INSERT INTO {schema}.stream_transcripts(tenant_scope,message_id,dispatch_id,task_id,transcript_version,state,frame_count,transcript_digest,created_at,updated_at) VALUES('tenant-expiry',$1,$2,$3,1,'open',1,$4,100,100)"), &[&message_id,&dispatch_id,&live_task.id,&live_transcript_digest]).await.unwrap();
            client.execute(&format!("INSERT INTO {schema}.stream_frames(tenant_scope,message_id,frame_seq,frame_version,frame_kind,frame_json,frame_digest,created_at) VALUES('tenant-expiry',$1,1,1,'task',$2,$3,100)"), &[&message_id,&live_initial_json,&smesh_a2a::content_digest(live_initial_json.as_bytes())]).await.unwrap();
            let live_owner = format!("live-{suffix}-owner");
            let live_lease = store
                .claim_outbox(&live_owner, 100, 10)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                store
                    .finish_outbox_attempt(&live_lease, disposition, 101)
                    .await
                    .unwrap(),
                smesh_a2a::TransitionOutcome::DeadLettered
            );
            let live_state: String = client.query_one(&format!("SELECT state FROM {schema}.tasks WHERE tenant_scope='tenant-expiry' AND task_id=$1"), &[&live_task.id]).await.unwrap().get(0);
            assert_eq!(
                live_state,
                serde_json::to_string(&a2a::TaskState::Failed).unwrap()
            );
        }
        let envelope = smesh_a2a::DurableDispatchEnvelope {
            tenant_scope: "tenant-expiry".into(),
            dispatch_id: "dispatch-expiry".into(),
            payload_digest: digest,
            request: request.clone(),
            execution_reservation: lease.execution_reservation.clone(),
        };
        let smesh_a2a::ReceiverAdmission::Execute(receiver) = store
            .begin_receive(envelope, "incomplete-receiver", 100, 10)
            .await
            .unwrap()
        else {
            panic!("receiver execution lease expected")
        };
        assert_eq!(receiver.lease_until, 110);
        client.execute(&format!("INSERT INTO {schema}.cancellation_intents(tenant_scope,dispatch_id,task_id,state,requested_at) VALUES('tenant-expiry','dispatch-expiry','expiry-task','requested',105)"), &[]).await.unwrap();

        let (left, right) = tokio::join!(
            store.claim_outbox("next-owner-a", 111, 10),
            store.claim_outbox("next-owner-b", 111, 10),
        );
        let left = left.unwrap();
        let right = right.unwrap();
        assert_ne!(
            left.is_some(),
            right.is_some(),
            "exactly one final-attempt reconciler wins"
        );
        let reconciliation = left.or(right).unwrap();
        assert_eq!(reconciliation.attempt_no, 1);
        assert_ne!(reconciliation.lease_token, lease.lease_token);

        let envelope = smesh_a2a::DurableDispatchEnvelope {
            tenant_scope: "tenant-expiry".into(),
            dispatch_id: "dispatch-expiry".into(),
            payload_digest: smesh_a2a::content_digest(payload.as_bytes()),
            request: request.clone(),
            execution_reservation: reconciliation.execution_reservation.clone(),
        };
        let smesh_a2a::ReceiverAdmission::Execute(reclaimed_receiver) = store
            .begin_receive(envelope, "reclaimed-receiver", 111, 10)
            .await
            .unwrap()
        else {
            panic!("expired processing receiver must be reclaimable")
        };
        assert_eq!(reclaimed_receiver.lease_epoch, receiver.lease_epoch + 1);
        assert_eq!(reclaimed_receiver.sender_attempt_no, 1);
        assert_eq!(
            reclaimed_receiver.sender_lease_token,
            reconciliation.lease_token
        );
        assert_ne!(reclaimed_receiver.lease_token, receiver.lease_token);

        let canceled_events = vec![
            smesh_a2a::MeshEvent::Progress("SMESH swarm is processing the durable dispatch".into()),
            smesh_a2a::MeshEvent::Completed {
                summary: "SMESH durable receiver cooperatively canceled".into(),
            },
        ];
        assert!(
            store
                .complete_canceled_receive(&receiver, &canceled_events, 112)
                .await
                .is_err(),
            "the expired receiver fence must not complete after reclaim"
        );
        store
            .complete_canceled_receive(&reclaimed_receiver, &canceled_events, 112)
            .await
            .unwrap();
        assert!(
            store
                .complete_canceled_receive(&reclaimed_receiver, &canceled_events, 112)
                .await
                .is_err(),
            "receiver cancellation completion is single-effect"
        );

        let mut canceled = task.clone();
        let mut cancel_message = a2a::Message::new(
            a2a::Role::Agent,
            vec![a2a::Part::text("SMESH task canceled")],
        );
        cancel_message.message_id = format!(
            "cancel-{}",
            &smesh_a2a::content_digest(b"dispatch-expiry")[..32]
        );
        cancel_message.task_id = Some(task.id.clone());
        cancel_message.context_id = Some(task.context_id.clone());
        canceled.status = a2a::TaskStatus {
            state: a2a::TaskState::Canceled,
            message: Some(cancel_message),
            timestamp: chrono::DateTime::from_timestamp_millis(113),
        };
        let terminal = a2a::StreamResponse::StatusUpdate(a2a::TaskStatusUpdateEvent {
            task_id: canceled.id.clone(),
            context_id: canceled.context_id.clone(),
            status: canceled.status.clone(),
            metadata: None,
        });
        let public_transcript = vec![initial.clone(), terminal];
        assert_eq!(
            store
                .commit_delivery(
                    &reconciliation,
                    canceled.clone(),
                    a2a::SendMessageResponse::Task(canceled.clone()),
                    &public_transcript,
                    113,
                )
                .await
                .unwrap(),
            smesh_a2a::TransitionOutcome::Applied
        );
        assert_eq!(
            store
                .commit_delivery(
                    &reconciliation,
                    canceled.clone(),
                    a2a::SendMessageResponse::Task(canceled.clone()),
                    &public_transcript,
                    113,
                )
                .await
                .unwrap(),
            smesh_a2a::TransitionOutcome::Stale
        );

        let canceled_state = serde_json::to_string(&a2a::TaskState::Canceled).unwrap();
        let canceled_json = serde_json::to_string(&canceled).unwrap();
        let final_json =
            serde_json::to_string(&a2a::SendMessageResponse::Task(canceled.clone())).unwrap();
        let public_digest =
            smesh_a2a::content_digest(&serde_json::to_vec(&public_transcript).unwrap());
        let row=client.query_one(&format!("SELECT o.state,o.lease_owner,o.lease_token,o.lease_until,o.last_error,o.updated_at,a.finished_at,a.outcome,a.error,t.state,t.revision,t.task_json,i.state,i.final_result_json,s.state,s.frame_count,s.transcript_digest,s.interruption_error FROM {schema}.outbox o JOIN {schema}.outbox_attempts a USING(tenant_scope,outbox_id) JOIN {schema}.tasks t USING(tenant_scope,task_id) JOIN {schema}.idempotency_records i USING(tenant_scope,task_id) JOIN {schema}.stream_transcripts s USING(tenant_scope,task_id) WHERE o.dispatch_id='dispatch-expiry'"),&[]).await.unwrap();
        assert_eq!(row.get::<_, String>(0), "delivered");
        assert_eq!(row.get::<_, Option<String>>(1), None);
        assert_eq!(row.get::<_, Option<String>>(2), None);
        assert_eq!(row.get::<_, Option<i64>>(3), None);
        assert_eq!(row.get::<_, Option<String>>(4), None);
        assert_eq!(row.get::<_, i64>(5), 113);
        assert_eq!(row.get::<_, Option<i64>>(6), Some(113));
        assert_eq!(
            row.get::<_, Option<String>>(7).as_deref(),
            Some("delivered")
        );
        assert_eq!(row.get::<_, Option<String>>(8), None);
        assert_eq!(row.get::<_, String>(9), canceled_state);
        assert_eq!(row.get::<_, i64>(10), 2);
        assert_eq!(row.get::<_, String>(11), canceled_json);
        assert_eq!(row.get::<_, String>(12), "completed");
        assert_eq!(
            row.get::<_, Option<String>>(13).as_deref(),
            Some(final_json.as_str())
        );
        assert_eq!(row.get::<_, String>(14), "terminal");
        assert_eq!(row.get::<_, i64>(15), 2);
        assert_eq!(row.get::<_, String>(16), public_digest);
        assert_eq!(row.get::<_, Option<String>>(17), None);

        let event=client.query_one(&format!("SELECT event_seq,task_revision,event_kind,from_state,to_state,event_json,created_at FROM {schema}.task_events WHERE tenant_scope='tenant-expiry' AND task_id='expiry-task' ORDER BY event_seq DESC LIMIT 1"),&[]).await.unwrap();
        assert_eq!(event.get::<_, i64>(0), 2);
        assert_eq!(event.get::<_, i64>(1), 2);
        assert_eq!(event.get::<_, String>(2), "durable_completed");
        assert_eq!(
            event.get::<_, Option<String>>(3).as_deref(),
            Some(state.as_str())
        );
        assert_eq!(event.get::<_, String>(4), canceled_state);
        assert_eq!(event.get::<_, String>(5), canceled_json);
        assert_eq!(event.get::<_, i64>(6), 113);

        let receiver_row = client.query_one(&format!("SELECT state,lease_epoch,lease_owner,lease_token,lease_until,sender_attempt_no,sender_lease_token,frame_count,completed_at FROM {schema}.receiver_inbox WHERE tenant_scope='tenant-expiry' AND dispatch_id='dispatch-expiry'"), &[]).await.unwrap();
        assert_eq!(receiver_row.get::<_, String>(0), "completed");
        assert_eq!(receiver_row.get::<_, i64>(1), 2);
        assert_eq!(receiver_row.get::<_, Option<String>>(2), None);
        assert_eq!(receiver_row.get::<_, Option<String>>(3), None);
        assert_eq!(receiver_row.get::<_, Option<i64>>(4), None);
        assert_eq!(receiver_row.get::<_, i64>(5), 1);
        assert_eq!(receiver_row.get::<_, String>(6), reconciliation.lease_token);
        assert_eq!(receiver_row.get::<_, Option<i64>>(7), Some(2));
        assert_eq!(receiver_row.get::<_, Option<i64>>(8), Some(112));
        let cancellation = client.query_one(&format!("SELECT state,requested_at,completed_at FROM {schema}.cancellation_intents WHERE tenant_scope='tenant-expiry' AND dispatch_id='dispatch-expiry'"), &[]).await.unwrap();
        assert_eq!(cancellation.get::<_, String>(0), "receiver_canceled");
        assert_eq!(cancellation.get::<_, i64>(1), 105);
        assert_eq!(cancellation.get::<_, Option<i64>>(2), Some(112));
        let effects: i64 = client.query_one(&format!("SELECT count(*) FROM {schema}.loopback_effects WHERE tenant_scope='tenant-expiry' AND dispatch_id='dispatch-expiry'"), &[]).await.unwrap().get(0);
        assert_eq!(
            effects, 0,
            "cancellation containment must not commit the normal effect"
        );
        assert_eq!(
            store
                .final_result_scoped("tenant-expiry", "message-expiry")
                .await
                .unwrap(),
            Some(a2a::SendMessageResponse::Task(canceled.clone()))
        );
        let batch = store
            .stream_frames_after_scoped("tenant-expiry", "message-expiry", 0)
            .await
            .unwrap();
        assert!(batch.closed);
        assert_eq!(batch.frames, public_transcript);
        assert_eq!(batch.interruption, None);
        store.shutdown().await.unwrap();
        let reopened = PostgresTaskStore::open(config.clone()).await.unwrap();
        assert_eq!(
            reopened
                .final_result_scoped("tenant-expiry", "message-expiry")
                .await
                .unwrap(),
            Some(a2a::SendMessageResponse::Task(canceled.clone()))
        );
        let replay = reopened
            .stream_frames_after_scoped("tenant-expiry", "message-expiry", 0)
            .await
            .unwrap();
        assert!(replay.closed);
        assert_eq!(replay.frames, public_transcript);
        let scope = OwnedTaskScope::new("tenant-expiry", "owner", VisibilityScope::Own).unwrap();
        let events = reopened
            .task_events_after_scoped(&scope, "expiry-task", 0)
            .await
            .unwrap();
        assert!(events.closed);
        assert!(matches!(
            events.frames.last(),
            Some(a2a::StreamResponse::StatusUpdate(update))
                if update.status.state == a2a::TaskState::Canceled
        ));
        reopened.shutdown().await.unwrap();
        drop(client);
        driver.abort();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    }
);

postgres_test!(global_outbox_claim_preserves_principal_retained_counter, {
    let Some(url) = admin_url() else { return };
    let config = config(url, "claim_retained")
        .with_test_only_trust_injected_time(true)
        .with_test_only_parent_managed_cleanup();
    let store = PostgresTaskStore::open(config.clone()).await.unwrap();
    let (client, driver) = admin_client(&superuser_url()).await;
    let schema = config.schema_name();
    let task = a2a::Task {
        id: "claim-retained-task".into(),
        context_id: "claim-retained-context".into(),
        status: a2a::TaskStatus {
            state: a2a::TaskState::Submitted,
            message: None,
            timestamp: None,
        },
        artifacts: None,
        history: None,
        metadata: None,
    };
    let task_json = serde_json::to_string(&task).unwrap();
    let state = serde_json::to_string(&task.status.state).unwrap();
    let request = smesh_a2a::MeshRequest {
        protocol: "a2a-v1".into(),
        task_id: task.id.clone(),
        context_id: task.context_id.clone(),
        text: "claim retained counter".into(),
    };
    let payload = serde_json::to_string(&request).unwrap();
    let payload_digest = smesh_a2a::content_digest(payload.as_bytes());
    client.execute(&format!("INSERT INTO {schema}.tasks(tenant_scope,task_id,context_id,state,revision,task_json,owner_account_id) VALUES('tenant-claim-retained',$1,$2,$3,1,$4,'owner')"), &[&task.id,&task.context_id,&state,&task_json]).await.unwrap();
    client.execute(&format!("INSERT INTO {schema}.outbox(tenant_scope,dispatch_id,task_id,message_id,causative_revision,payload_json,payload_digest,state,max_attempts,available_at,created_at,updated_at,dispatch_identity_version) VALUES('tenant-claim-retained','dispatch-claim-retained',$1,'message-claim-retained',1,$2,$3,'pending',2,100,100,100,2)"), &[&task.id,&payload,&payload_digest]).await.unwrap();
    let query = format!(
        "SELECT retained_bytes,{schema}.retained_authority_oracle(tenant_scope,scope_id) FROM {schema}.retained_authority_usage WHERE tenant_scope='tenant-claim-retained' AND scope_kind='principal' AND scope_id='account:owner'"
    );
    let before = client.query_one(&query, &[]).await.unwrap();
    assert_eq!(before.get::<_, i64>(0), before.get::<_, i64>(1));
    store
        .claim_outbox("global-claimer", 100, 10)
        .await
        .unwrap()
        .unwrap();
    let after = client.query_one(&query, &[]).await.unwrap();
    assert_eq!(
        after.get::<_, i64>(0),
        after.get::<_, i64>(1),
        "global claim must retain the task owner's principal attribution"
    );
    store.shutdown().await.unwrap();
    drop(client);
    driver.abort();
    PostgresTaskStore::drop_test_schema(&config).await.unwrap();
});

postgres_test!(expired_final_attempt_without_receiver_is_dead_lettered, {
    let Some(url) = admin_url() else { return };
    let config = config(url, "final_unaccepted").with_test_only_trust_injected_time(true);
    let store = PostgresTaskStore::open(config.clone()).await.unwrap();
    let (client, driver) = admin_client(&superuser_url()).await;
    let schema = config.schema_name();
    let task = a2a::Task {
        id: "unaccepted-final-task".into(),
        context_id: "unaccepted-final-context".into(),
        status: a2a::TaskStatus {
            state: a2a::TaskState::Submitted,
            message: None,
            timestamp: None,
        },
        artifacts: None,
        history: None,
        metadata: None,
    };
    let task_json = serde_json::to_string(&task).unwrap();
    let state = serde_json::to_string(&task.status.state).unwrap();
    let request = smesh_a2a::MeshRequest {
        protocol: "a2a-v1".into(),
        task_id: task.id.clone(),
        context_id: task.context_id.clone(),
        text: "never accepted".into(),
    };
    let payload = serde_json::to_string(&request).unwrap();
    let payload_digest = smesh_a2a::content_digest(payload.as_bytes());
    let admission = serde_json::to_string(&a2a::SendMessageResponse::Task(task.clone())).unwrap();
    client.execute(&format!("INSERT INTO {schema}.tasks(tenant_scope,task_id,context_id,state,revision,task_json,owner_account_id) VALUES('tenant-unaccepted',$1,$2,$3,1,$4,'owner')"), &[&task.id,&task.context_id,&state,&task_json]).await.unwrap();
    client.execute(&format!("INSERT INTO {schema}.task_events(tenant_scope,task_id,event_seq,task_revision,event_kind,from_state,to_state,event_json,created_at) VALUES('tenant-unaccepted',$1,1,1,'admitted',NULL,$2,$3,100)"), &[&task.id,&state,&task_json]).await.unwrap();
    client.execute(&format!("INSERT INTO {schema}.idempotency_records(tenant_scope,message_id,request_digest,task_id,state,admission_result_json,created_at,updated_at,digest_version,actor_account_id) VALUES('tenant-unaccepted','message-unaccepted','sha256:request',$1,'in_progress',$2,100,100,2,'owner')"), &[&task.id,&admission]).await.unwrap();
    client.execute(&format!("INSERT INTO {schema}.outbox(tenant_scope,dispatch_id,task_id,message_id,causative_revision,payload_json,payload_digest,state,max_attempts,available_at,created_at,updated_at,dispatch_identity_version) VALUES('tenant-unaccepted','dispatch-unaccepted',$1,'message-unaccepted',1,$2,$3,'pending',1,100,100,100,2)"), &[&task.id,&payload,&payload_digest]).await.unwrap();
    client.execute(&format!("INSERT INTO {schema}.stream_transcripts(tenant_scope,message_id,dispatch_id,task_id,transcript_version,state,frame_count,transcript_digest,created_at,updated_at) VALUES('tenant-unaccepted','message-unaccepted','dispatch-unaccepted',$1,1,'open',0,$2,100,100)"), &[&task.id,&smesh_a2a::content_digest(b"[]")]).await.unwrap();
    let lease = store
        .claim_outbox("crashed", 100, 10)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lease.attempt_no, 1);
    assert!(
        store
            .claim_outbox("reaper", 111, 10)
            .await
            .unwrap()
            .is_none()
    );
    let failed = store
        .final_result_scoped("tenant-unaccepted", "message-unaccepted")
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(failed, a2a::SendMessageResponse::Task(task) if task.status.state == a2a::TaskState::Failed)
    );
    let row = client.query_one(&format!("SELECT o.state,a.outcome,t.state FROM {schema}.outbox o JOIN {schema}.outbox_attempts a USING(tenant_scope,outbox_id) JOIN {schema}.tasks t USING(tenant_scope,task_id) WHERE o.dispatch_id='dispatch-unaccepted'"), &[]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "dead");
    assert_eq!(row.get::<_, Option<String>>(1).as_deref(), Some("dead"));
    assert_eq!(
        row.get::<_, String>(2),
        serde_json::to_string(&a2a::TaskState::Failed).unwrap()
    );
    store.shutdown().await.unwrap();
    drop(client);
    driver.abort();
    PostgresTaskStore::drop_test_schema(&config).await.unwrap();
});

postgres_test!(
    dead_letter_fault_points_roll_back_the_entire_failed_lifecycle,
    {
        let Some(url) = admin_url() else { return };
        for (index, (table, timing)) in [
            ("tasks", "UPDATE"),
            ("task_events", "INSERT"),
            ("idempotency_records", "UPDATE"),
            ("stream_transcripts", "UPDATE"),
            ("outbox", "UPDATE"),
        ]
        .into_iter()
        .enumerate()
        {
            let config = config(url.clone(), &format!("dead_fault_{index}"))
                .with_test_only_trust_injected_time(true);
            let store = PostgresTaskStore::open(config.clone()).await.unwrap();
            let (client, driver) = admin_client(&superuser_url()).await;
            let schema = config.schema_name();
            let task = a2a::Task {
                id: "fault-task".into(),
                context_id: "fault-context".into(),
                status: a2a::TaskStatus {
                    state: a2a::TaskState::Submitted,
                    message: None,
                    timestamp: None,
                },
                artifacts: None,
                history: None,
                metadata: None,
            };
            let task_json = serde_json::to_string(&task).unwrap();
            let state = serde_json::to_string(&task.status.state).unwrap();
            let request = smesh_a2a::MeshRequest {
                protocol: "a2a-v1".into(),
                task_id: task.id.clone(),
                context_id: task.context_id.clone(),
                text: "fault".into(),
            };
            let payload = serde_json::to_string(&request).unwrap();
            let digest = smesh_a2a::content_digest(payload.as_bytes());
            let admission =
                serde_json::to_string(&a2a::SendMessageResponse::Task(task.clone())).unwrap();
            let initial = a2a::StreamResponse::Task(task.clone());
            let initial_json = serde_json::to_string(&initial).unwrap();
            let transcript_digest =
                smesh_a2a::content_digest(&serde_json::to_vec(&[initial]).unwrap());
            client.execute(&format!("INSERT INTO {schema}.tasks(tenant_scope,task_id,context_id,state,revision,task_json,owner_account_id) VALUES('tenant-fault',$1,$2,$3,1,$4,'owner')"), &[&task.id,&task.context_id,&state,&task_json]).await.unwrap();
            client.execute(&format!("INSERT INTO {schema}.task_events(tenant_scope,task_id,event_seq,task_revision,event_kind,from_state,to_state,event_json,created_at) VALUES('tenant-fault',$1,1,1,'admitted',NULL,$2,$3,100)"), &[&task.id,&state,&task_json]).await.unwrap();
            client.execute(&format!("INSERT INTO {schema}.idempotency_records(tenant_scope,message_id,request_digest,task_id,state,admission_result_json,created_at,updated_at,digest_version,actor_account_id) VALUES('tenant-fault','message-fault','sha256:request',$1,'in_progress',$2,100,100,2,'owner')"), &[&task.id,&admission]).await.unwrap();
            client.execute(&format!("INSERT INTO {schema}.outbox(tenant_scope,dispatch_id,task_id,message_id,causative_revision,payload_json,payload_digest,state,max_attempts,available_at,created_at,updated_at,dispatch_identity_version) VALUES('tenant-fault','dispatch-fault',$1,'message-fault',1,$2,$3,'pending',1,100,100,100,2)"), &[&task.id,&payload,&digest]).await.unwrap();
            client.execute(&format!("INSERT INTO {schema}.stream_transcripts(tenant_scope,message_id,dispatch_id,task_id,transcript_version,state,frame_count,transcript_digest,created_at,updated_at) VALUES('tenant-fault','message-fault','dispatch-fault',$1,1,'open',1,$2,100,100)"), &[&task.id,&transcript_digest]).await.unwrap();
            client.execute(&format!("INSERT INTO {schema}.stream_frames(tenant_scope,message_id,frame_seq,frame_version,frame_kind,frame_json,frame_digest,created_at) VALUES('tenant-fault','message-fault',1,1,'task',$1,$2,100)"), &[&initial_json,&smesh_a2a::content_digest(initial_json.as_bytes())]).await.unwrap();
            let lease = store
                .claim_outbox("fault-owner", 100, 10)
                .await
                .unwrap()
                .unwrap();
            let trigger_when = if table == "outbox" {
                " WHEN (NEW.state IN ('dead','superseded'))"
            } else {
                ""
            };
            client.batch_execute(&format!("CREATE FUNCTION {schema}.fail_dead_letter() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'dead-letter fault'; END $$; CREATE TRIGGER fail_dead_letter BEFORE {timing} ON {schema}.{table} FOR EACH ROW{trigger_when} EXECUTE FUNCTION {schema}.fail_dead_letter()" )).await.unwrap();
            assert!(
                store
                    .claim_outbox("fault-reclaimer", 111, 10)
                    .await
                    .is_err(),
                "fault at {table} must abort"
            );
            let unchanged = client.query_one(&format!("SELECT t.state,t.revision,(SELECT count(*) FROM {schema}.task_events WHERE task_id='fault-task'),i.state,i.final_result_json,s.state,s.interruption_error,o.state,o.lease_token,o.lease_until,a.finished_at,a.outcome FROM {schema}.tasks t JOIN {schema}.idempotency_records i USING(tenant_scope,task_id) JOIN {schema}.stream_transcripts s USING(tenant_scope,task_id) JOIN {schema}.outbox o USING(tenant_scope,task_id) JOIN {schema}.outbox_attempts a USING(tenant_scope,outbox_id) WHERE t.task_id='fault-task'"), &[]).await.unwrap();
            assert_eq!(unchanged.get::<_, String>(0), state, "fault at {table}");
            assert_eq!(unchanged.get::<_, i64>(1), 1, "fault at {table}");
            assert_eq!(unchanged.get::<_, i64>(2), 1, "fault at {table}");
            assert_eq!(
                unchanged.get::<_, String>(3),
                "in_progress",
                "fault at {table}"
            );
            assert_eq!(
                unchanged.get::<_, Option<String>>(4),
                None,
                "fault at {table}"
            );
            assert_eq!(unchanged.get::<_, String>(5), "open", "fault at {table}");
            assert_eq!(
                unchanged.get::<_, Option<String>>(6),
                None,
                "fault at {table}"
            );
            assert_eq!(unchanged.get::<_, String>(7), "leased", "fault at {table}");
            assert_eq!(
                unchanged.get::<_, Option<String>>(8).as_deref(),
                Some(lease.lease_token.as_str()),
                "fault at {table}"
            );
            assert_eq!(
                unchanged.get::<_, Option<i64>>(9),
                Some(110),
                "fault at {table}"
            );
            assert_eq!(
                unchanged.get::<_, Option<i64>>(10),
                None,
                "fault at {table}"
            );
            assert_eq!(
                unchanged.get::<_, Option<String>>(11),
                None,
                "fault at {table}"
            );
            client.batch_execute(&format!("DROP TRIGGER fail_dead_letter ON {schema}.{table}; DROP FUNCTION {schema}.fail_dead_letter()" )).await.unwrap();
            assert!(
                store
                    .claim_outbox("fault-reclaimer", 111, 10)
                    .await
                    .unwrap()
                    .is_none()
            );
            store.shutdown().await.unwrap();
            drop(client);
            driver.abort();
            PostgresTaskStore::drop_test_schema(&config).await.unwrap();
        }
    }
);

postgres_test!(
    completed_receiver_on_final_attempt_reconciles_after_sender_crash,
    {
        use smesh_a2a::{OutboxAuthority as _, ReceiverAdmission, ReceiverAuthority as _};
        let Some(url) = admin_url() else { return };
        let config = config(url, "final_reconcile").with_test_only_trust_injected_time(true);
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        let (client, driver) = admin_client(&superuser_url()).await;
        let mut task = a2a::Task {
            id: "final-reconcile-task".into(),
            context_id: "final-reconcile-context".into(),
            status: a2a::TaskStatus {
                state: a2a::TaskState::Submitted,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        };
        let submitted_json = serde_json::to_string(&task).unwrap();
        let submitted_state = serde_json::to_string(&task.status.state).unwrap();
        let request = smesh_a2a::MeshRequest {
            protocol: "a2a-v1".into(),
            task_id: task.id.clone(),
            context_id: task.context_id.clone(),
            text: "exactly once".into(),
        };
        let payload = serde_json::to_string(&request).unwrap();
        let payload_digest = smesh_a2a::content_digest(payload.as_bytes());
        let admission =
            serde_json::to_string(&a2a::SendMessageResponse::Task(task.clone())).unwrap();
        let schema = config.schema_name();
        client.execute(&format!("INSERT INTO {schema}.tasks(tenant_scope,task_id,context_id,state,revision,task_json,owner_account_id) VALUES('tenant-final',$1,$2,$3,1,$4,'owner')"), &[&task.id,&task.context_id,&submitted_state,&submitted_json]).await.unwrap();
        client.execute(&format!("INSERT INTO {schema}.task_events(tenant_scope,task_id,event_seq,task_revision,event_kind,from_state,to_state,event_json,created_at) VALUES('tenant-final',$1,1,1,'admitted',NULL,$2,$3,100)"), &[&task.id,&submitted_state,&submitted_json]).await.unwrap();
        client.execute(&format!("INSERT INTO {schema}.idempotency_records(tenant_scope,message_id,request_digest,task_id,state,admission_result_json,created_at,updated_at,digest_version,actor_account_id) VALUES('tenant-final','message-final','sha256:request',$1,'in_progress',$2,100,100,2,'owner')"), &[&task.id,&admission]).await.unwrap();
        client.execute(&format!("INSERT INTO {schema}.outbox(tenant_scope,dispatch_id,task_id,message_id,causative_revision,payload_json,payload_digest,state,max_attempts,available_at,created_at,updated_at,dispatch_identity_version) VALUES('tenant-final','dispatch-final',$1,'message-final',1,$2,$3,'pending',1,100,100,100,2)"), &[&task.id,&payload,&payload_digest]).await.unwrap();
        client.execute(&format!("INSERT INTO {schema}.stream_transcripts(tenant_scope,message_id,dispatch_id,task_id,transcript_version,state,frame_count,transcript_digest,created_at,updated_at) VALUES('tenant-final','message-final','dispatch-final',$1,1,'open',0,$2,100,100)"), &[&task.id,&smesh_a2a::content_digest(b"[]")]).await.unwrap();
        let crashed = store
            .claim_outbox("crashed", 100, 10)
            .await
            .unwrap()
            .unwrap();
        let envelope = smesh_a2a::DurableDispatchEnvelope {
            tenant_scope: "tenant-final".into(),
            dispatch_id: "dispatch-final".into(),
            payload_digest,
            execution_reservation: crashed.execution_reservation.clone(),
            request,
        };
        let ReceiverAdmission::Execute(receiver) = store
            .begin_receive(envelope.clone(), "receiver", 100, 10)
            .await
            .unwrap()
        else {
            panic!("receiver execute expected")
        };
        let events = vec![smesh_a2a::MeshEvent::Completed {
            summary: "exact result".into(),
        }];
        store
            .complete_loopback_receive(&receiver, &events, 101)
            .await
            .unwrap();
        drop(crashed);
        let reconciliation = store
            .claim_outbox("restart", 111, 10)
            .await
            .unwrap()
            .expect("completed final receiver must reconcile");
        assert_eq!(reconciliation.attempt_no, 1);
        assert!(
            matches!(store.begin_receive(envelope, "restart-receiver", 111, 10).await.unwrap(), ReceiverAdmission::Replay(replayed) if replayed == events)
        );
        task.status.state = a2a::TaskState::Completed;
        task.status.timestamp = chrono::DateTime::from_timestamp_millis(112);
        let result = a2a::SendMessageResponse::Task(task.clone());
        let transcript = [
            a2a::StreamResponse::Task(serde_json::from_str(&submitted_json).unwrap()),
            a2a::StreamResponse::StatusUpdate(a2a::TaskStatusUpdateEvent {
                task_id: task.id.clone(),
                context_id: task.context_id.clone(),
                status: task.status.clone(),
                metadata: None,
            }),
        ];
        assert_eq!(
            store
                .commit_delivery(&reconciliation, task, result, &transcript, 112)
                .await
                .unwrap(),
            smesh_a2a::TransitionOutcome::Applied
        );
        let row = client.query_one(&format!("SELECT o.state,t.state,i.state,s.state,(SELECT count(*) FROM {schema}.loopback_effects WHERE dispatch_id='dispatch-final') FROM {schema}.outbox o JOIN {schema}.tasks t USING(tenant_scope,task_id) JOIN {schema}.idempotency_records i USING(tenant_scope,task_id) JOIN {schema}.stream_transcripts s USING(tenant_scope,task_id) WHERE o.dispatch_id='dispatch-final'"), &[]).await.unwrap();
        assert_eq!(
            (
                row.get::<_, String>(0),
                row.get::<_, String>(1),
                row.get::<_, String>(2),
                row.get::<_, String>(3),
                row.get::<_, i64>(4)
            ),
            (
                "delivered".into(),
                serde_json::to_string(&a2a::TaskState::Completed).unwrap(),
                "completed".into(),
                "terminal".into(),
                1
            )
        );
        store.shutdown().await.unwrap();
        drop(client);
        driver.abort();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    }
);

postgres_test!(postgres_renews_fenced_outbox_and_receiver_leases, {
    use smesh_a2a::{AuthorityCapabilities, LeaseRenewalOutcome};
    let Some(url) = admin_url() else { return };
    let config = config(url, "lease_renewal");
    let store = PostgresTaskStore::open(config.clone()).await.unwrap();
    assert_eq!(
        store.capabilities(),
        AuthorityCapabilities {
            lease_renewal: true,
            quota_reservations: true,
        }
    );
    let stale_outbox = smesh_a2a::OutboxLease {
        tenant_scope: "tenant".into(),
        outbox_id: -1,
        dispatch_id: "dispatch".into(),
        task_id: "task".into(),
        attempt_no: 1,
        max_attempts: 1,
        lease_owner: "replica".into(),
        lease_token: "token".into(),
        lease_until: 1,
        request: smesh_a2a::MeshRequest {
            protocol: "a2a-v1".into(),
            task_id: "task".into(),
            context_id: "context".into(),
            text: "x".into(),
        },
        execution_reservation: None,
    };
    assert_eq!(
        store
            .renew_outbox_lease(&stale_outbox, 1_000)
            .await
            .unwrap(),
        LeaseRenewalOutcome::Stale
    );
    let stale_receiver = smesh_a2a::ReceiverLease {
        tenant_scope: "tenant".into(),
        task_id: "task".into(),
        dispatch_id: "dispatch".into(),
        payload_digest: "digest".into(),
        sender_attempt_no: 1,
        sender_lease_token: "sender-token".into(),
        lease_owner: "replica".into(),
        lease_token: "token".into(),
        lease_epoch: 1,
        lease_until: 1,
        execution_reservation: None,
    };
    assert_eq!(
        store
            .renew_receiver_lease(&stale_receiver, 1_000)
            .await
            .unwrap(),
        LeaseRenewalOutcome::Stale
    );
    store.shutdown().await.unwrap();
    PostgresTaskStore::drop_test_schema(&config).await.unwrap();
});

postgres_test!(postgres_quota_reservation_seam_is_transactional, {
    let Some(url) = admin_url() else { return };
    let config = config(url, "quota_seam").with_test_only_trust_injected_time(true);
    let store = PostgresTaskStore::open(config.clone()).await.unwrap();
    let scope = OwnedTaskScope::new("tenant-quota", "account-quota", VisibilityScope::Own).unwrap();
    let command = |suffix: &str| {
        let mut message = a2a::Message::new(a2a::Role::User, vec![a2a::Part::text("quota")]);
        message.message_id = format!("message-quota-{suffix}");
        let task = a2a::Task {
            id: format!("task-quota-{suffix}"),
            context_id: "context-quota".into(),
            status: a2a::TaskStatus {
                state: a2a::TaskState::Submitted,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: Some(vec![message.clone()]),
            metadata: None,
        };
        smesh_a2a::SendMessageAdmission {
            request: a2a::SendMessageRequest {
                message,
                configuration: None,
                metadata: None,
                tenant: None,
            },
            streaming: false,
            task: task.clone(),
            original_result: a2a::SendMessageResponse::Task(task),
            input_limits: smesh_a2a::InputLimits::default(),
            now: 100,
            max_attempts: 2,
        }
    };
    let audit = |suffix: &str| {
        AuthorizationAuditInput::new(
            format!("audit-quota-{suffix}"),
            "tenant-quota",
            "account-quota",
            "policy-quota",
            1,
            "sha256:policy-quota",
            "TaskCreate",
            AuthorizationDecisionEffect::Allow,
            "grant",
            "task",
            format!("sha256:quota-{suffix}"),
            None,
            100,
        )
        .unwrap()
    };
    let quota = |reservation: &str, dimension: &str| {
        QuotaReservationInput::new(
            "tenant-quota",
            "account-quota",
            "principal-quota",
            "sendMessage",
            dimension,
            1,
            reservation,
            10_000,
            Some("{\"source\":\"server-policy\"}".into()),
        )
        .unwrap()
    };

    let admitted = command("one");
    store
        .authorize_and_admit_mutation(
            &scope,
            AuthorizedMutation::with_quota(admitted.clone(), quota("reservation-1", "requests")),
            audit("one"),
        )
        .await
        .unwrap();
    assert!(
        admitted.task.metadata.is_none(),
        "wire metadata never carries quota authority"
    );
    let (client, driver) = admin_client(&superuser_url()).await;
    let count: i64 = client
        .query_one(
            &format!(
                "SELECT count(*) FROM {}.quota_reservations WHERE tenant_scope='tenant-quota'",
                config.schema_name()
            ),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);

    store
        .authorize_and_admit_mutation(
            &scope,
            AuthorizedMutation::with_quota(admitted.clone(), quota("reservation-1", "requests")),
            audit("replay"),
        )
        .await
        .unwrap();
    let count_after_replay: i64 = client
        .query_one(
            &format!(
                "SELECT count(*) FROM {}.quota_reservations WHERE tenant_scope='tenant-quota'",
                config.schema_name()
            ),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count_after_replay, 1, "exact replay cannot double reserve");

    let counts_before_replay_rejections = store.atomic_record_counts().await.unwrap();
    assert!(
        store
            .authorize_and_admit(&scope, admitted.clone(), audit("missing-replay"),)
            .await
            .is_err(),
        "missing trusted task-local reservation must not replay"
    );
    assert!(
        store
            .authorize_and_admit_mutation(
                &scope,
                AuthorizedMutation::with_quota(
                    admitted.clone(),
                    quota("reservation-changed", "requests")
                ),
                audit("changed-replay"),
            )
            .await
            .is_err(),
        "changed trusted task-local reservation must not replay"
    );
    assert_eq!(
        store.atomic_record_counts().await.unwrap(),
        counts_before_replay_rejections
    );
    let mut after_expiry = admitted.clone();
    after_expiry.now = 20_000;
    store
        .authorize_and_admit_mutation(
            &scope,
            AuthorizedMutation::with_quota(after_expiry, quota("reservation-1", "requests")),
            audit("expired-exact-replay"),
        )
        .await
        .expect("exact immutable replay remains valid after reservation expiry");

    let counts_before_conflict = store.atomic_record_counts().await.unwrap();
    assert!(
        store
            .authorize_and_admit_mutation(
                &scope,
                AuthorizedMutation::with_quota(command("two"), quota("reservation-1", "different")),
                audit("conflict"),
            )
            .await
            .is_err()
    );
    assert_eq!(
        store.atomic_record_counts().await.unwrap(),
        counts_before_conflict
    );

    client.batch_execute(&format!(
        "CREATE FUNCTION {}.fail_quota_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'quota fault'; END $$; CREATE TRIGGER fail_quota BEFORE INSERT ON {}.quota_reservations FOR EACH ROW EXECUTE FUNCTION {}.fail_quota_insert()",
        config.schema_name(), config.schema_name(), config.schema_name()
    )).await.unwrap();
    let counts_before_fault = store.atomic_record_counts().await.unwrap();
    assert!(
        store
            .authorize_and_admit_mutation(
                &scope,
                AuthorizedMutation::with_quota(
                    command("fault"),
                    quota("reservation-fault", "requests")
                ),
                audit("fault"),
            )
            .await
            .is_err()
    );
    assert_eq!(
        store.atomic_record_counts().await.unwrap(),
        counts_before_fault,
        "quota trigger failure rolls back task/event/idempotency/outbox/audit"
    );

    store.shutdown().await.unwrap();
    drop(client);
    driver.abort();
    PostgresTaskStore::drop_test_schema(&config).await.unwrap();
});

postgres_test!(
    startup_rejects_noncanonical_quota_row_with_intact_catalog,
    {
        let Some(url) = admin_url() else { return };
        let config = config(url, "quota_corrupt");
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        let (client, driver) = admin_client(&superuser_url()).await;
        let task = a2a::Task {
            id: "quota-corrupt-task".into(),
            context_id: "quota-corrupt-context".into(),
            status: a2a::TaskStatus {
                state: a2a::TaskState::Submitted,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        };
        let state = serde_json::to_string(&task.status.state).unwrap();
        let task_json = serde_json::to_string(&task).unwrap();
        let schema = config.schema_name();
        client.execute(&format!("INSERT INTO {schema}.tasks(tenant_scope,task_id,context_id,state,revision,task_json,owner_account_id) VALUES('tenant-corrupt',$1,$2,$3,1,$4,'account-corrupt')"), &[&task.id,&task.context_id,&state,&task_json]).await.unwrap();
        let now: i64 = client
            .query_one(&format!("SELECT {schema}.db_millis()"), &[])
            .await
            .unwrap()
            .get(0);
        client.execute(&format!("INSERT INTO {schema}.quota_reservations(tenant_scope,reservation_id,account_id,principal_scope,operation,dimension,units,task_id,expires_at,metadata_json,created_at) VALUES('tenant-corrupt','reservation-corrupt','account-corrupt','principal-corrupt','sendMessage','requests',1,$1,$2,'{{\"source\": \"noncanonical\"}}',$3)"), &[&task.id,&(now+60_000),&now]).await.unwrap();
        store.shutdown().await.unwrap();
        assert!(matches!(
            PostgresTaskStore::open(config.clone()).await,
            Err(smesh_a2a::PostgresStoreError::InvalidSchema)
        ));
        drop(client);
        driver.abort();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    }
);

postgres_test!(concurrent_independent_pools_never_exceed_global_task_cap, {
    let Some(url) = admin_url() else { return };
    let config = config(url, "capacity_one").with_max_tasks(1).unwrap();
    let left = PostgresTaskStore::open(config.clone()).await.unwrap();
    let right = PostgresTaskStore::open(config.clone()).await.unwrap();
    let scope =
        OwnedTaskScope::new("tenant-capacity", "owner-capacity", VisibilityScope::Own).unwrap();
    let command = |suffix: &str| {
        let mut message = a2a::Message::new(
            a2a::Role::User,
            vec![a2a::Part::text(format!("capacity-{suffix}"))],
        );
        message.message_id = format!("message-capacity-{suffix}");
        let task = a2a::Task {
            id: format!("task-capacity-{suffix}"),
            context_id: "context-capacity".into(),
            status: a2a::TaskStatus {
                state: a2a::TaskState::Submitted,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: Some(vec![message.clone()]),
            metadata: None,
        };
        smesh_a2a::SendMessageAdmission {
            request: a2a::SendMessageRequest {
                message,
                configuration: None,
                metadata: None,
                tenant: None,
            },
            streaming: false,
            task: task.clone(),
            original_result: a2a::SendMessageResponse::Task(task),
            input_limits: smesh_a2a::InputLimits::default(),
            now: 100,
            max_attempts: 2,
        }
    };
    let audit = |suffix: &str| {
        AuthorizationAuditInput::new(
            format!("audit-capacity-{suffix}"),
            "tenant-capacity",
            "owner-capacity",
            "policy-capacity",
            1,
            "sha256:policy-capacity",
            "TaskCreate",
            AuthorizationDecisionEffect::Allow,
            "grant",
            "task",
            format!("sha256:capacity-{suffix}"),
            None,
            100,
        )
        .unwrap()
    };
    let (a, b) = tokio::join!(
        left.authorize_and_admit(&scope, command("left"), audit("left")),
        right.authorize_and_admit(&scope, command("right"), audit("right"))
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(left.atomic_record_counts().await.unwrap().tasks, 1);
    left.shutdown().await.unwrap();
    right.shutdown().await.unwrap();
    PostgresTaskStore::drop_test_schema(&config).await.unwrap();
});

postgres_test!(
    production_database_clock_ignores_extreme_caller_skew_for_fences,
    {
        let Some(url) = admin_url() else { return };
        let base = config(url, "database_clock");
        let trusted = PostgresTaskStore::open(base.clone()).await.unwrap();
        let schema = base.schema_name();
        let (admin, admin_driver) = admin_client(&superuser_url()).await;
        let task = a2a::Task {
            id: "clock-task".into(),
            context_id: "clock-context".into(),
            status: a2a::TaskStatus {
                state: a2a::TaskState::Submitted,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        };
        let task_json = serde_json::to_string(&task).unwrap();
        let state = serde_json::to_string(&task.status.state).unwrap();
        admin.execute(&format!("INSERT INTO {schema}.tasks(tenant_scope,task_id,context_id,state,revision,task_json,owner_account_id) VALUES('tenant-clock',$1,$2,$3,1,$4,'owner')"), &[&task.id,&task.context_id,&state,&task_json]).await.unwrap();
        admin.execute(&format!("INSERT INTO {schema}.task_events(tenant_scope,task_id,event_seq,task_revision,event_kind,from_state,to_state,event_json,created_at) VALUES('tenant-clock',$1,1,1,'admitted',NULL,$2,$3,1)"), &[&task.id,&state,&task_json]).await.unwrap();
        let request = smesh_a2a::MeshRequest {
            protocol: "a2a-v1".into(),
            task_id: task.id.clone(),
            context_id: task.context_id.clone(),
            text: "clock".into(),
        };
        let payload = serde_json::to_string(&request).unwrap();
        let digest = smesh_a2a::content_digest(payload.as_bytes());
        for (dispatch, message) in [
            ("dispatch-expired", "message-expired"),
            ("dispatch-fresh", "message-fresh"),
        ] {
            admin.execute(&format!("INSERT INTO {schema}.outbox(tenant_scope,dispatch_id,task_id,message_id,causative_revision,payload_json,payload_digest,state,max_attempts,available_at,created_at,updated_at,dispatch_identity_version) VALUES('tenant-clock',$1,$2,$3,1,$4,$5,'pending',2,1,1,1,2)"), &[&dispatch,&task.id,&message,&payload,&digest]).await.unwrap();
        }
        let expired = trusted
            .claim_outbox("old-worker", 100, 10)
            .await
            .unwrap()
            .unwrap();
        trusted.shutdown().await.unwrap();

        let production_config = base.clone().with_test_only_trust_injected_time(false);
        let past_clock = PostgresTaskStore::open(production_config.clone())
            .await
            .unwrap();
        assert_eq!(
            past_clock
                .finish_outbox_attempt(
                    &expired,
                    smesh_a2a::AttemptDisposition::Permanent {
                        error: "expired".into()
                    },
                    i64::MIN,
                )
                .await
                .unwrap(),
            smesh_a2a::TransitionOutcome::Stale,
        );
        admin.execute(
            &format!("UPDATE {schema}.outbox SET state='dead',lease_owner=NULL,lease_token=NULL,lease_until=NULL WHERE dispatch_id='dispatch-expired'"),
            &[],
        ).await.unwrap();
        let fresh = past_clock
            .claim_outbox("fresh-worker", i64::MAX, 60_000)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fresh.dispatch_id, "dispatch-fresh");
        let envelope = smesh_a2a::DurableDispatchEnvelope {
            tenant_scope: "tenant-clock".into(),
            dispatch_id: "dispatch-fresh".into(),
            payload_digest: digest,
            request,
            execution_reservation: fresh.execution_reservation.clone(),
        };
        let smesh_a2a::ReceiverAdmission::Execute(receiver_lease) = past_clock
            .begin_receive(envelope, "receiver", i64::MIN, 60_000)
            .await
            .unwrap()
        else {
            panic!("fresh receiver lease expected")
        };
        past_clock
            .complete_loopback_receive(&receiver_lease, &[], i64::MAX)
            .await
            .unwrap();
        past_clock.shutdown().await.unwrap();
        drop(admin);
        admin_driver.abort();
        PostgresTaskStore::drop_test_schema(&base).await.unwrap();
    }
);

postgres_test!(
    independent_pools_serialize_aggregate_snapshot_and_audit_growth,
    {
        let Some(url) = admin_url() else { return };
        let config = config(url, "aggregate_capacity");
        let left = PostgresTaskStore::open(config.clone()).await.unwrap();
        let right = PostgresTaskStore::open(config.clone()).await.unwrap();
        let schema = config.schema_name();
        let (admin, admin_driver) = admin_client(&superuser_url()).await;
        let decision_id = "capacity-left-01";
        let tenant = "tenant-retry";
        let audit_bytes = decision_id.len()
            + tenant.len()
            + "actor-retry".len()
            + "policy-retry".len()
            + "sha256:policy-retry".len()
            + "TaskGet".len()
            + "deny".len()
            + "denied".len()
            + "task".len()
            + "sha256:resource-retry".len();
        let snapshot_overhead =
            tenant.len() + 32 + "owner".len() + "scope".len() + "query".len() + 32;
        let entry_overhead =
            tenant.len() + 32 + "seed".len() + smesh_a2a::content_digest(b"seed").len();
        // row_retained_bytes includes jsonb field names and numeric columns. Keep
        // enough exact-encoding headroom for one audit, but not two.
        let frozen_bytes =
            64 * 1024 * 1024 - audit_bytes - snapshot_overhead - entry_overhead - 1_050;
        let frozen_bytes_i64 = i64::try_from(frozen_bytes).unwrap();
        let snapshot = [7_u8; 32];
        let metadata = [9_u8; 32];
        admin.execute(
        &format!("INSERT INTO {schema}.list_snapshots(tenant_scope,snapshot_id,owner_account_id,scope_digest,query_digest,total_size,page_size,issued_at,expires_at,projection_version,frozen_bytes,metadata_digest) VALUES('tenant-retry',$1,'owner','scope','query',1,1,1,2,1,$2,$3)"),
        &[&&snapshot[..], &frozen_bytes_i64, &&metadata[..]],
    ).await.unwrap();
        admin.execute(
        &format!("INSERT INTO {schema}.list_snapshot_entries(tenant_scope,snapshot_id,ordinal,task_id,task_revision,task_digest,task_json) VALUES('tenant-retry',$1,0,'seed',1,$2,to_json(repeat('x',$3))::text)"),
        &[&&snapshot[..], &smesh_a2a::content_digest(b"seed"), &i32::try_from(frozen_bytes - 2).unwrap()],
    ).await.unwrap();

        let (a, b) = tokio::join!(
            left.append_denied_authorization_decision(denied_audit(decision_id)),
            right.append_denied_authorization_decision(denied_audit("capacity-right01")),
        );
        assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
        let row = admin.query_one(
        &format!("SELECT count(*),(SELECT COALESCE(sum(octet_length(tenant_scope)+octet_length(snapshot_id)+octet_length(owner_account_id)+octet_length(scope_digest)+octet_length(query_digest)+octet_length(metadata_digest)),0) FROM {schema}.list_snapshots)+(SELECT COALESCE(sum(octet_length(tenant_scope)+octet_length(snapshot_id)+octet_length(task_id)+octet_length(task_digest)+octet_length(task_json)),0) FROM {schema}.list_snapshot_entries)+(SELECT COALESCE(sum(octet_length(decision_id)+octet_length(tenant_scope)+octet_length(actor_account_id)+octet_length(policy_id)+octet_length(policy_digest)+octet_length(operation)+octet_length(effect)+octet_length(reason)+octet_length(resource_kind)+octet_length(resource_digest)+COALESCE(octet_length(task_id),0)),0) FROM {schema}.authorization_decisions) FROM {schema}.authorization_decisions"),
        &[],
    ).await.unwrap();
        assert_eq!(row.get::<_, i64>(0), 1, "losing audit was not rolled back");
        let legacy_bytes = row.get::<_, i64>(1);
        assert!(legacy_bytes <= 64 * 1024 * 1024 && legacy_bytes > 64 * 1024 * 1024 - 2_000);
        left.shutdown().await.unwrap();
        right.shutdown().await.unwrap();
        drop(admin);
        admin_driver.abort();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    }
);

postgres_test!(outage_fails_closed_and_redacts_both_credentials, {
    let config = PostgresStoreConfig::new(
        "postgresql://migrator:migrator-outage-canary@127.0.0.1:1/smesh_test",
        "postgresql://runtime:runtime-outage-canary@127.0.0.1:2/smesh_test",
        "smesh_outage",
    )
    .unwrap()
    .with_test_only_insecure_loopback(true)
    .with_timeouts(Duration::from_millis(50), Duration::from_millis(50))
    .unwrap();
    let error = PostgresTaskStore::open(config)
        .await
        .err()
        .expect("outage must fail");
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains("migrator-outage-canary"));
    assert!(!rendered.contains("runtime-outage-canary"));
});

postgres_test!(bounded_pool_saturation_times_out_without_using_migrator, {
    let Some(url) = admin_url() else { return };
    let config = config(url, "pool_saturation")
        .with_pool_size(1)
        .unwrap()
        .with_timeouts(Duration::from_secs(5), Duration::from_secs(1))
        .unwrap();
    let store = Arc::new(PostgresTaskStore::open(config.clone()).await.unwrap());
    let acquired = Arc::new(tokio::sync::Barrier::new(2));
    let release = Arc::new(tokio::sync::Barrier::new(2));
    let holder = {
        let store = store.clone();
        let acquired = acquired.clone();
        let release = release.clone();
        tokio::spawn(async move { store.hold_test_pool_connection(acquired, release).await })
    };
    acquired.wait().await;
    let error = store.atomic_record_counts().await.unwrap_err();
    assert!(
        error.message.contains("timed out") || error.message.contains("unavailable"),
        "{}",
        error.message
    );
    release.wait().await;
    holder.await.unwrap().unwrap();
    store.shutdown().await.unwrap();
    PostgresTaskStore::drop_test_schema(&config).await.unwrap();
});

postgres_test!(
    injected_migration_privilege_fault_rolls_back_schema_atomically,
    {
        let Some(_admin) = admin_url() else { return };
        let suffix = format!("{:016x}", rand::random::<u64>());
        let migrator = format!("smesh_norole_{suffix}");
        let schema = format!("smesh_migration_fault_{suffix}");
        let (client, driver) = admin_client(&superuser_url()).await;
        client.batch_execute(&format!("CREATE ROLE {migrator} LOGIN PASSWORD 'migration-fault' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT; GRANT CREATE ON DATABASE smesh_test TO {migrator}")).await.unwrap();
        let runtime_url = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap_or_else(|_| {
            "postgresql://smesh_test_runtime:smesh_runtime_password@127.0.0.1:55432/smesh_test"
                .into()
        });
        let config = PostgresStoreConfig::new(
            format!("postgresql://{migrator}:migration-fault@127.0.0.1:55432/smesh_test"),
            runtime_url,
            schema.clone(),
        )
        .unwrap()
        .with_test_only_insecure_loopback(true);
        assert!(PostgresTaskStore::open(config).await.is_err());
        let exists: bool = client
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=$1)",
                &[&schema],
            )
            .await
            .unwrap()
            .get(0);
        assert!(!exists, "failed migration transaction leaked schema");
        client
            .batch_execute(&format!(
                "REVOKE CREATE ON DATABASE smesh_test FROM {migrator}; DROP ROLE {migrator}"
            ))
            .await
            .unwrap();
        drop(client);
        driver.abort();
    }
);

postgres_test!(postgres_fixture_raii_cleans_schema_and_role_after_panic, {
    let Some(url) = admin_url() else { return };
    let config = config(url.clone(), "raii_panic");
    let schema = config.schema_name().to_owned();
    let task = tokio::spawn(async move {
        let _store = PostgresTaskStore::open(config).await.unwrap();
        panic!("intentional PostgreSQL fixture unwind probe");
    });
    assert!(task.await.is_err());
    let (client, driver) = admin_client(&superuser_url()).await;
    let schema_exists: bool = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=$1)",
            &[&schema],
        )
        .await
        .unwrap()
        .get(0);
    let role = format!("{schema}_runtime");
    let role_exists: bool = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)",
            &[&role],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!schema_exists && !role_exists);
    drop(client);
    driver.abort();
});

postgres_test!(startup_rejects_incompatible_schema_version_before_pool, {
    let Some(url) = admin_url() else { return };
    let config = config(url.clone(), "incompatible_version");
    let store = PostgresTaskStore::open(config.clone()).await.unwrap();
    store.shutdown().await.unwrap();
    let (client, driver) = admin_client(&superuser_url()).await;
    client.batch_execute(&format!("ALTER TABLE {0}.schema_migrations DISABLE TRIGGER schema_migrations_immutable; ALTER TABLE {0}.schema_migrations DROP CONSTRAINT schema_migrations_logical_schema_version_check; UPDATE {0}.schema_migrations SET logical_schema_version=7",config.schema_name())).await.unwrap();
    assert!(matches!(
        PostgresTaskStore::open(config.clone()).await,
        Err(smesh_a2a::PostgresStoreError::InvalidSchema)
    ));
    drop(client);
    driver.abort();
    PostgresTaskStore::drop_test_schema(&config).await.unwrap();
});

postgres_test!(startup_rejects_unexpected_migration_revision, {
    let Some(url) = admin_url() else { return };
    let config = config(url, "unexpected_migration");
    let store = PostgresTaskStore::open(config.clone()).await.unwrap();
    store.shutdown().await.unwrap();
    let (client, driver) = admin_client(&superuser_url()).await;
    let schema = config.schema_name();
    client
        .batch_execute(&format!(
            "ALTER TABLE {schema}.schema_migrations DISABLE TRIGGER schema_migrations_immutable;
             INSERT INTO {schema}.schema_migrations(revision,logical_schema_version,name,checksum,applied_at)
             VALUES(999,6,'unexpected_revision','sha256:0000000000000000000000000000000000000000000000000000000000000000',0)"
        ))
        .await
        .unwrap();
    assert!(matches!(
        PostgresTaskStore::open(config.clone()).await,
        Err(smesh_a2a::PostgresStoreError::InvalidSchema)
    ));
    drop(client);
    driver.abort();
    PostgresTaskStore::drop_test_schema(&config).await.unwrap();
});

#[cfg(debug_assertions)]
postgres_test!(
    drop_gateway_reaps_blocked_receiver_renewal_and_releases_postgres_pool,
    {
        if env::var_os("SMESH_DROP_REAPER_PG_CHILD").is_none() {
            let output = tokio::time::timeout(
                Duration::from_secs(25),
                tokio::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "drop_gateway_reaps_blocked_receiver_renewal_and_releases_postgres_pool",
                        "--nocapture",
                    ])
                    .env("SMESH_DROP_REAPER_PG_CHILD", "1")
                    .env("SMESH_TEST_DRIVER_LEASE_MILLIS", "300")
                    .kill_on_drop(true)
                    .output(),
            )
            .await
            .expect("PostgreSQL drop-reaper subprocess watchdog")
            .expect("launch PostgreSQL drop-reaper subprocess");
            assert!(
                output.status.success(),
                "drop-reaper child failed: {output:?}"
            );
            return;
        }
        let Some(admin) = admin_url() else { return };
        let runtime = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap();
        let application_name = format!("smesh_drop_reaper_{:016x}", rand::random::<u64>());
        let mut migrator_url = Url::parse(&admin).unwrap();
        migrator_url
            .query_pairs_mut()
            .append_pair("application_name", &application_name);
        let mut runtime_url = Url::parse(&runtime).unwrap();
        runtime_url
            .query_pairs_mut()
            .append_pair("application_name", &application_name);
        let entered = Arc::new(tokio::sync::Notify::new());
        let released = Arc::new(tokio::sync::Notify::new());
        let config = PostgresStoreConfig::new(
            migrator_url.to_string(),
            runtime_url.to_string(),
            format!("smesh_drop_reaper_{:016x}", rand::random::<u64>()),
        )
        .unwrap()
        .with_test_only_insecure_loopback(true)
        .with_test_only_parent_managed_cleanup()
        .with_pool_size(1)
        .unwrap()
        .with_timeouts(Duration::from_secs(5), Duration::from_secs(5))
        .unwrap()
        .with_receiver_renewal_test_probe(Arc::clone(&entered), Arc::clone(&released));
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        let now = 1_700_009_000_000;
        let mut message =
            a2a::Message::new(a2a::Role::User, vec![a2a::Part::text("blocked renewal")]);
        message.message_id = "postgres-drop-renewal-message".into();
        let request = a2a::SendMessageRequest {
            message: message.clone(),
            configuration: None,
            metadata: None,
            tenant: None,
        };
        let task = a2a::Task {
            id: "postgres-drop-renewal-task".into(),
            context_id: "postgres-drop-renewal-context".into(),
            status: a2a::TaskStatus {
                state: a2a::TaskState::Submitted,
                message: None,
                timestamp: chrono::DateTime::from_timestamp_millis(now),
            },
            artifacts: None,
            history: Some(vec![message]),
            metadata: None,
        };
        let scope = OwnedTaskScope::new(
            "tenant-drop-renewal",
            "owner-drop-renewal",
            VisibilityScope::Own,
        )
        .unwrap();
        let audit = AuthorizationAuditInput::new(
            "audit-drop-renewal",
            "tenant-drop-renewal",
            "owner-drop-renewal",
            "policy-drop-renewal",
            1,
            "sha256:policy-drop-renewal",
            "TaskCreate",
            AuthorizationDecisionEffect::Allow,
            "grant",
            "task",
            "sha256:resource-drop-renewal",
            None,
            now,
        )
        .unwrap();
        store
            .authorize_and_admit(
                &scope,
                SendMessageAdmission {
                    request,
                    streaming: false,
                    task: task.clone(),
                    original_result: a2a::SendMessageResponse::Task(task),
                    input_limits: smesh_a2a::InputLimits::default(),
                    now,
                    max_attempts: 2,
                },
                audit,
            )
            .await
            .unwrap();

        let receiver_started = Arc::new(tokio::sync::Notify::new());
        let receiver_release = Arc::new(tokio::sync::Notify::new());
        let gateway = build_durable_loopback_gateway(
            GatewayConfig::new("http://127.0.0.1:1", "postgres-drop-reaper"),
            store.clone(),
            DurableLoopbackEndpoint::with_completion_barrier(
                Arc::clone(&receiver_started),
                receiver_release,
            ),
            InjectedClock::new(now),
        )
        .unwrap();
        receiver_started.notified().await;

        let acquired = Arc::new(tokio::sync::Barrier::new(2));
        let holder_release = Arc::new(tokio::sync::Barrier::new(2));
        let holder = {
            let held_store = store.clone();
            let acquired = Arc::clone(&acquired);
            let holder_release = Arc::clone(&holder_release);
            tokio::spawn(async move {
                held_store
                    .hold_test_pool_connection(acquired, holder_release)
                    .await
            })
        };
        acquired.wait().await;
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .expect("receiver renewal entered its blocked PostgreSQL call");

        drop(gateway);
        tokio::time::timeout(Duration::from_secs(5), released.notified())
            .await
            .expect("gateway drop reaper released blocked receiver renewal");
        holder_release.wait().await;
        tokio::time::timeout(Duration::from_secs(5), holder)
            .await
            .expect("pool holder join watchdog")
            .expect("pool holder task")
            .expect("pool holder result");
        drop(store);

        let second = PostgresTaskStore::open(config.clone())
            .await
            .expect("second store must remain usable after drop cleanup");
        second
            .atomic_record_counts()
            .await
            .expect("second store query after cleanup");
        second.shutdown().await.unwrap();
        drop(second);
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
        drop(config);

        let (admin_client, admin_driver) = admin_client(&superuser_url()).await;
        let sessions: i64 = admin_client
            .query_one(
                "SELECT count(*) FROM pg_stat_activity WHERE application_name=$1",
                &[&application_name],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(
            sessions, 0,
            "gateway drop left PostgreSQL application sessions"
        );
        drop(admin_client);
        admin_driver.abort();
    }
);

postgres_test!(
    artifact_promoter_workers_claim_disjoint_batches_and_reject_stale_tokens,
    {
        let Some(url) = admin_url() else { return };
        let root = ArtifactTestRoot::new("artifact-pg-race");
        let keyring = root.join("keys.json");
        fs::write(&keyring, r#"{"activeGeneration":"key-a","generations":{"key-a":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"}}"#).unwrap();
        fs::set_permissions(&keyring, fs::Permissions::from_mode(0o600)).unwrap();
        let artifact = ArtifactStoreConfig::new(&root, &keyring).unwrap();
        let config = config(url, "artifact_race").with_artifact_store(artifact);
        let store = Arc::new(PostgresTaskStore::open(config.clone()).await.unwrap());
        let (client, driver) = admin_client(&superuser_url()).await;
        let schema = config.schema_name();
        client.batch_execute(&format!("INSERT INTO {schema}.retained_authority_usage VALUES('tenant-a','tenant','tenant-a',0,1),('tenant-a','account','owner',0,1),('tenant-a','principal','account:owner',0,1); INSERT INTO {schema}.artifact_key_generations VALUES('tenant-a','tenant-a/confidential','key-a','active',1,NULL);" )).await.unwrap();
        for index in 0..4_i64 {
            let object = format!("object-{index}");
            let upload = format!("upload-{index}");
            let artifact_id = format!("artifact-{index}");
            let locator = format!("stage/{index:064x}.blob");
            let final_locator = format!("objects/{index:064x}.blob");
            let digest = format!("sha256:{index:064x}");
            client.execute(&format!("INSERT INTO {schema}.content_objects(tenant_scope,owner_account_id,object_id,content_digest,classification,encryption_domain,key_generation,plaintext_length,ciphertext_length,ciphertext_digest,backend_locator,nonce,state,reference_count,retain_until,created_at) VALUES('tenant-a','owner',$1,$2,'confidential','tenant-a/confidential','key-a',1,16,$2,$3,$4,'staged',0,9999999999999,1)"), &[&object,&digest,&final_locator,&vec![0_u8;12]]).await.unwrap();
            client.execute(&format!("INSERT INTO {schema}.upload_intents(tenant_scope,upload_id,artifact_id,object_id,state,stage_locator,final_locator,ciphertext_digest,ciphertext_length,lease_epoch,created_at,updated_at) VALUES('tenant-a',$1,$2,$3,'committed',$4,$5,$6,16,1,1,$7)"), &[&upload,&artifact_id,&object,&locator,&final_locator,&digest,&index]).await.unwrap();
        }
        let probe_sql =
            format!("SELECT * FROM {schema}.claim_artifact_upload('probe','probe-token',30000,1)");
        let probe = client
            .query(&probe_sql, &[])
            .await
            .expect("direct promoter claim function");
        assert_eq!(probe.len(), 1);
        client.execute(&format!("UPDATE {schema}.upload_intents SET state='committed',lease_token=NULL,lease_until=NULL,lease_epoch=1,attempts=0"), &[]).await.unwrap();
        let (runtime_client, runtime_driver) =
            admin_client(&required_postgres_url("SMESH_TEST_POSTGRES_RUNTIME_URL")).await;
        runtime_client
            .batch_execute(&format!("SET ROLE {schema}_runtime"))
            .await
            .unwrap();
        let runtime_probe = runtime_client
            .query(&probe_sql, &[])
            .await
            .expect("runtime promoter claim function");
        assert_eq!(runtime_probe.len(), 1);
        drop(runtime_client);
        runtime_driver.abort();
        client.execute(&format!("UPDATE {schema}.upload_intents SET state='committed',lease_token=NULL,lease_until=NULL,lease_epoch=1,attempts=0"), &[]).await.unwrap();
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let left = {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .claim_artifact_promotion("promoter-left", 30_000, 2)
                    .await
                    .unwrap()
            })
        };
        let right = {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .claim_artifact_promotion("promoter-right", 30_000, 2)
                    .await
                    .unwrap()
            })
        };
        barrier.wait().await;
        let left = left.await.unwrap();
        let right = right.await.unwrap();
        assert_eq!(left.len(), 2);
        assert_eq!(right.len(), 2);
        let left_ids = left
            .iter()
            .map(|claim| claim.upload_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let right_ids = right
            .iter()
            .map(|claim| claim.upload_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert!(left_ids.is_disjoint(&right_ids));
        let mut stale = left[0].clone();
        stale.lease_token =
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into();
        assert!(
            !store
                .fail_artifact_promotion(
                    &stale,
                    "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                )
                .await
                .unwrap()
        );
        assert!(
            store
                .fail_artifact_promotion(
                    &left[0],
                    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                )
                .await
                .unwrap()
        );

        client.execute(&format!("UPDATE {schema}.content_objects SET state='available',available_at=1,retain_until=1"), &[]).await.unwrap();
        let gc_barrier = Arc::new(tokio::sync::Barrier::new(3));
        let gc_left = {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&gc_barrier);
            tokio::spawn(async move {
                barrier.wait().await;
                store.claim_artifact_gc("gc-left", 30_000, 2).await.unwrap()
            })
        };
        let gc_right = {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&gc_barrier);
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .claim_artifact_gc("gc-right", 30_000, 2)
                    .await
                    .unwrap()
            })
        };
        gc_barrier.wait().await;
        let gc_left = gc_left.await.unwrap();
        let gc_right = gc_right.await.unwrap();
        assert_eq!(gc_left.len() + gc_right.len(), 4);
        let gc_left_ids = gc_left
            .iter()
            .map(|claim| claim.object_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let gc_right_ids = gc_right
            .iter()
            .map(|claim| claim.object_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert!(gc_left_ids.is_disjoint(&gc_right_ids));
        let winner = gc_left.first().or_else(|| gc_right.first()).unwrap();
        let mut stale_generation = winner.clone();
        stale_generation.tombstone_generation += 1;
        assert!(
            !store
                .fail_artifact_gc(
                    &stale_generation,
                    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                )
                .await
                .unwrap()
        );
        assert!(
            store
                .fail_artifact_gc(
                    winner,
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                )
                .await
                .unwrap()
        );
        drop(client);
        driver.abort();
        store.shutdown().await.unwrap();
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
);

postgres_test!(
    artifact_claim_terminalization_is_bounded_fair_and_eventual,
    60,
    {
        let Some(url) = admin_url() else { return };
        let config = config(url, "art_term");
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        let schema = config.schema_name();
        let (left, left_driver) = admin_client(&superuser_url()).await;
        let (right, right_driver) = admin_client(&superuser_url()).await;
        for tenant in ["terminal-a", "terminal-b"] {
            let zeros = "0".repeat(64);
            left.batch_execute(&format!("INSERT INTO {schema}.retained_authority_usage VALUES('{tenant}','tenant','{tenant}',0,1),('{tenant}','account','owner',0,1),('{tenant}','principal','account:owner',0,1); INSERT INTO {schema}.artifact_key_generations VALUES('{tenant}','{tenant}/confidential','old','active',1,NULL),('{tenant}','{tenant}/confidential','new','active',1,NULL); INSERT INTO {schema}.artifact_key_rotation_plans VALUES('{tenant}','rotation-terminal','{tenant}/confidential','old','new','sha256:{zeros}','sha256:{zeros}',2,'active',1,NULL);")).await.unwrap();
            for index in 0..4_i32 {
                for kind in ["upload", "gc", "reencrypt"] {
                    let object_id = format!("{kind}-{tenant}-{index}");
                    let digest = format!(
                        "sha256:{:064x}",
                        index
                            + match kind {
                                "upload" => 100,
                                "gc" => 200,
                                _ => 300,
                            }
                    );
                    let (state, generation) = match (kind, index) {
                        ("upload", _) => ("staged", 0_i64),
                        ("gc", 0) => ("quarantined", 1),
                        ("gc", _) => ("tombstoned", 1),
                        _ => ("available", 0),
                    };
                    left.execute(&format!("INSERT INTO {schema}.content_objects(tenant_scope,owner_account_id,object_id,content_digest,classification,encryption_domain,key_generation,plaintext_length,ciphertext_length,ciphertext_digest,backend_locator,nonce,state,reference_count,retain_until,tombstone_generation,created_at,available_at) VALUES($1,'owner',$2,$3,'confidential',$4,'old',1,16,$3,$5,$6,$7,0,9999999999999,$8,1,1)"), &[&tenant,&object_id,&digest,&format!("{tenant}/confidential"),&format!("objects/{kind}-{tenant}-{index}.blob"),&vec![0_u8;12],&state,&generation]).await.unwrap();
                    let attempts = if index < 3 { 1000_i32 } else { 0 };
                    match kind {
                        "upload" => {
                            left.execute(&format!("INSERT INTO {schema}.upload_intents(tenant_scope,upload_id,artifact_id,object_id,state,stage_locator,final_locator,ciphertext_digest,ciphertext_length,lease_epoch,attempts,created_at,updated_at) VALUES($1,$2,$3,$4,'committed',$5,$6,$7,16,1,$8,1,$9)"), &[&tenant,&format!("upload-{tenant}-{index}"),&format!("artifact-{tenant}-{index}"),&object_id,&format!("stage/{tenant}-{index}.blob"),&format!("objects/upload-{tenant}-{index}.blob"),&digest,&attempts,&i64::from(index)]).await.unwrap();
                        }
                        "gc" => {
                            left.execute(&format!("INSERT INTO {schema}.artifact_gc_jobs(tenant_scope,job_id,object_id,tombstone_generation,state,lease_epoch,available_at,attempts) VALUES($1,$2,$3,1,'pending',1,1,$4)"), &[&tenant,&format!("gc-{tenant}-{index}"),&object_id,&attempts]).await.unwrap();
                        }
                        _ => {
                            left.execute(&format!("INSERT INTO {schema}.artifact_reencryption_jobs(tenant_scope,job_id,rotation_id,object_id,old_generation,new_generation,old_locator,state,lease_epoch,attempts,created_at,updated_at) VALUES($1,$2,'rotation-terminal',$3,'old','new',$4,'pending',1,$5,1,$6)"), &[&tenant,&format!("reencrypt-{tenant}-{index}"),&object_id,&format!("objects/reencrypt-{tenant}-{index}.blob"),&attempts,&i64::from(index)]).await.unwrap();
                        }
                    }
                }
            }
        }
        let cases = [
            (
                "upload_intents",
                "failed",
                format!(
                    "SELECT * FROM {schema}.claim_artifact_upload('owner','token-left',30000,2)"
                ),
                format!(
                    "UPDATE {schema}.upload_intents SET state='committed',lease_token=NULL,lease_until=NULL WHERE state IN ('failed','promoting')"
                ),
            ),
            (
                "artifact_gc_jobs",
                "dead",
                format!("SELECT * FROM {schema}.claim_artifact_gc('owner','token-left',30000,2)"),
                format!(
                    "UPDATE {schema}.artifact_gc_jobs SET state='pending',lease_owner=NULL,lease_token=NULL,lease_until=NULL WHERE state IN ('dead','leased'); UPDATE {schema}.content_objects SET state='tombstoned' WHERE object_id LIKE 'gc-%' AND state='deleting'"
                ),
            ),
            (
                "artifact_reencryption_jobs",
                "failed",
                format!(
                    "SELECT * FROM {schema}.claim_artifact_reencryption('rotation-terminal','old','new','owner','token-left',30000,2)"
                ),
                format!(
                    "UPDATE {schema}.artifact_reencryption_jobs SET state='pending',lease_owner=NULL,lease_token=NULL,lease_until=NULL WHERE state IN ('failed','leased')"
                ),
            ),
        ];
        for (table, terminal, sql, reset) in cases {
            let right_sql = sql.replace("token-left", "token-right");
            let (a, b) = tokio::join!(left.query(&sql, &[]), right.query(&right_sql, &[]));
            a.unwrap();
            b.unwrap();
            let count: i64 = left
                .query_one(
                    &format!("SELECT count(*) FROM {schema}.{table} WHERE state='{terminal}'"),
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            assert!(
                (2..=4).contains(&count),
                "concurrent {table} terminalizers made unbounded or zero progress: {count}"
            );
            left.batch_execute(&reset).await.unwrap();
            for expected in [2_i64, 4, 6] {
                left.query(&sql, &[]).await.unwrap();
                let rows = left.query(&format!("SELECT tenant_scope,count(*) FROM {schema}.{table} WHERE state='{terminal}' GROUP BY tenant_scope ORDER BY tenant_scope"), &[]).await.unwrap();
                let total: i64 = rows.iter().map(|row| row.get::<_, i64>(1)).sum();
                assert_eq!(
                    total, expected,
                    "{table} exceeded its terminal batch or stalled"
                );
                assert!(
                    rows.iter().all(|row| row.get::<_, i64>(1) == expected / 2),
                    "{table} was not tenant-fair"
                );
            }
        }
        store.shutdown().await.unwrap();
        drop(left);
        drop(right);
        left_driver.abort();
        right_driver.abort();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    }
);

postgres_test!(
    exhausted_artifact_claims_preserve_active_leases_until_db_time_expiry,
    60,
    {
        let Some(url) = admin_url() else { return };
        let config = config(url, "art_lease_term");
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        let schema = config.schema_name();
        let (client, driver) = admin_client(&superuser_url()).await;
        let zeros = "0".repeat(64);
        client
            .batch_execute(&format!(
                "CREATE TABLE {schema}.artifact_claim_test_clock(now_ms bigint NOT NULL); \
                 INSERT INTO {schema}.artifact_claim_test_clock VALUES(100); \
                 GRANT SELECT ON {schema}.artifact_claim_test_clock TO PUBLIC; \
                 CREATE OR REPLACE FUNCTION {schema}.db_millis() RETURNS bigint \
                 LANGUAGE sql VOLATILE SET search_path=pg_catalog AS \
                 $clock$ SELECT now_ms FROM {schema}.artifact_claim_test_clock $clock$; \
                 INSERT INTO {schema}.retained_authority_usage VALUES \
                 ('lease-tenant','tenant','lease-tenant',0,1), \
                 ('lease-tenant','account','owner',0,1), \
                 ('lease-tenant','principal','account:owner',0,1); \
                 INSERT INTO {schema}.artifact_key_generations VALUES \
                 ('lease-tenant','lease-tenant/confidential','old','active',1,NULL), \
                 ('lease-tenant','lease-tenant/confidential','new','active',1,NULL); \
                 INSERT INTO {schema}.artifact_key_rotation_plans VALUES \
                 ('lease-tenant','rotation-lease','lease-tenant/confidential','old','new', \
                  'sha256:{zeros}','sha256:{zeros}',10,'active',1,NULL);"
            ))
            .await
            .unwrap();

        for (index, kind, object_state, generation) in [
            (0_i32, "upload", "staged", 0_i64),
            (1, "upload", "staged", 0),
            (2, "upload", "staged", 0),
            (3, "gc", "tombstoned", 1),
            (4, "gc", "tombstoned", 1),
            (5, "gc", "quarantined", 1),
            (6, "gc", "tombstoned", 1),
            (7, "reencrypt", "available", 0),
            (8, "reencrypt", "available", 0),
            (9, "reencrypt", "available", 0),
            (10, "gc", "tombstoned", 1),
        ] {
            let object_id = format!("lease-object-{index}");
            let digest = format!("sha256:{:064x}", index + 1);
            client.execute(&format!("INSERT INTO {schema}.content_objects(tenant_scope,owner_account_id,object_id,content_digest,classification,encryption_domain,key_generation,plaintext_length,ciphertext_length,ciphertext_digest,backend_locator,nonce,state,reference_count,retain_until,tombstone_generation,created_at,available_at) VALUES('lease-tenant','owner',$1,$2,'confidential','lease-tenant/confidential','old',1,16,$2,$3,$4,$5,0,9999999999999,$6,1,1)"), &[&object_id,&digest,&format!("objects/{kind}-{index}.blob"),&vec![0_u8;12],&object_state,&generation]).await.unwrap();
        }
        client.batch_execute(&format!(
            "INSERT INTO {schema}.upload_intents(tenant_scope,upload_id,artifact_id,object_id,state,stage_locator,final_locator,ciphertext_digest,ciphertext_length,lease_epoch,attempts,created_at,updated_at) VALUES \
             ('lease-tenant','upload-fail','artifact-upload-fail','lease-object-0','committed','stage/upload-fail.tmp','objects/upload-0.blob','sha256:{:064x}',16,1,999,1,1), \
             ('lease-tenant','upload-expire','artifact-upload-expire','lease-object-1','committed','stage/upload-expire.tmp','objects/upload-1.blob','sha256:{:064x}',16,1,999,1,2), \
             ('lease-tenant','upload-healthy','artifact-upload-healthy','lease-object-2','committed','stage/upload-healthy.tmp','objects/upload-2.blob','sha256:{:064x}',16,1,0,1,3); \
             INSERT INTO {schema}.artifact_gc_jobs(tenant_scope,job_id,object_id,tombstone_generation,state,lease_epoch,available_at,attempts) VALUES \
             ('lease-tenant','gc-fail','lease-object-3',1,'pending',1,1,999), \
             ('lease-tenant','gc-expire','lease-object-4',1,'pending',1,1,999), \
             ('lease-tenant','gc-quarantined','lease-object-5',1,'leased',2,1,1000), \
             ('lease-tenant','gc-healthy','lease-object-6',1,'pending',1,1,0), \
             ('lease-tenant','gc-mixed-expired','lease-object-10',1,'leased',2,1,1000); \
             UPDATE {schema}.artifact_gc_jobs SET lease_owner='current-gc',lease_token='gc-quarantine-token',lease_until=200 WHERE job_id='gc-quarantined'; \
             UPDATE {schema}.artifact_gc_jobs SET lease_owner='expired-gc',lease_token='gc-expired-token',lease_until=100 WHERE job_id='gc-mixed-expired'; \
             INSERT INTO {schema}.artifact_reencryption_jobs(tenant_scope,job_id,rotation_id,object_id,old_generation,new_generation,old_locator,state,lease_epoch,attempts,created_at,updated_at) VALUES \
             ('lease-tenant','reencrypt-fail','rotation-lease','lease-object-7','old','new','objects/reencrypt-7.blob','pending',1,999,1,1), \
             ('lease-tenant','reencrypt-expire','rotation-lease','lease-object-8','old','new','objects/reencrypt-8.blob','pending',1,999,1,2), \
             ('lease-tenant','reencrypt-healthy','rotation-lease','lease-object-9','old','new','objects/reencrypt-9.blob','pending',1,0,1,3);",
            1, 2, 3
        )).await.unwrap();

        let uploads = client.query(&format!("SELECT * FROM {schema}.claim_artifact_upload('current-upload','upload-token',100,10)"), &[]).await.unwrap();
        assert_eq!(
            uploads.len(),
            3,
            "exhaustion-boundary and healthy uploads claim"
        );
        let gc = client
            .query(
                &format!(
                    "SELECT * FROM {schema}.claim_artifact_gc('current-gc','gc-token',100,10)"
                ),
                &[],
            )
            .await
            .unwrap();
        assert_eq!(gc.len(), 3, "exhaustion-boundary and healthy GC jobs claim");
        let reencryption = client.query(&format!("SELECT * FROM {schema}.claim_artifact_reencryption('rotation-lease','old','new','current-reencrypt','reencrypt-token',100,10)"), &[]).await.unwrap();
        assert_eq!(
            reencryption.len(),
            3,
            "exhaustion-boundary and healthy reencryption jobs claim"
        );
        let mixed_gc = client
            .query_one(
                &format!(
                    "SELECT state,lease_owner,lease_token,lease_until FROM {schema}.artifact_gc_jobs WHERE job_id='gc-mixed-expired'"
                ),
                &[],
            )
            .await
            .unwrap();
        assert_eq!(mixed_gc.get::<_, String>(0), "dead");
        assert_eq!(mixed_gc.get::<_, Option<String>>(1), None);
        assert_eq!(mixed_gc.get::<_, Option<String>>(2), None);
        assert_eq!(mixed_gc.get::<_, Option<i64>>(3), None);

        for sql in [
            format!(
                "SELECT * FROM {schema}.claim_artifact_upload('other-upload','other-upload-token',100,10)"
            ),
            format!("SELECT * FROM {schema}.claim_artifact_gc('other-gc','other-gc-token',100,10)"),
            format!(
                "SELECT * FROM {schema}.claim_artifact_reencryption('rotation-lease','old','new','other-reencrypt','other-reencrypt-token',100,10)"
            ),
        ] {
            assert!(client.query(&sql, &[]).await.unwrap().is_empty());
        }
        let protected = client.query(&format!(
            "SELECT 'upload',upload_id,state,NULL::text,lease_token,lease_epoch,lease_until FROM {schema}.upload_intents WHERE upload_id IN ('upload-fail','upload-expire') \
             UNION ALL SELECT 'gc',job_id,state,lease_owner,lease_token,lease_epoch,lease_until FROM {schema}.artifact_gc_jobs WHERE job_id IN ('gc-fail','gc-expire','gc-quarantined') \
             UNION ALL SELECT 'reencrypt',job_id,state,lease_owner,lease_token,lease_epoch,lease_until FROM {schema}.artifact_reencryption_jobs WHERE job_id IN ('reencrypt-fail','reencrypt-expire') ORDER BY 1,2"
        ), &[]).await.unwrap();
        assert_eq!(protected.len(), 7);
        assert!(
            protected.iter().all(|row| {
                let state: String = row.get(2);
                state != "failed" && state != "dead" && row.get::<_, i64>(6) == 200
            }),
            "a contender terminalized or mutated a future active lease"
        );
        let quarantine = protected
            .iter()
            .find(|row| row.get::<_, String>(1) == "gc-quarantined")
            .unwrap();
        assert_eq!(
            quarantine.get::<_, Option<String>>(3).as_deref(),
            Some("current-gc")
        );
        assert_eq!(
            quarantine.get::<_, Option<String>>(4).as_deref(),
            Some("gc-quarantine-token")
        );
        assert_eq!(quarantine.get::<_, i64>(5), 2);

        for (table, id_column, id, terminal) in [
            ("upload_intents", "upload_id", "upload-fail", "failed"),
            ("artifact_gc_jobs", "job_id", "gc-fail", "dead"),
            (
                "artifact_reencryption_jobs",
                "job_id",
                "reencrypt-fail",
                "failed",
            ),
        ] {
            let owner_fence = if table == "upload_intents" {
                "lease_token='upload-token' AND lease_epoch=2"
            } else if table == "artifact_gc_jobs" {
                "lease_owner='current-gc' AND lease_token='gc-token' AND lease_epoch=2"
            } else {
                "lease_owner='current-reencrypt' AND lease_token='reencrypt-token' AND lease_epoch=2"
            };
            let changed = client.execute(&format!("UPDATE {schema}.{table} SET state='{terminal}',lease_token=NULL,lease_until=NULL{} WHERE {id_column}='{id}' AND {owner_fence} AND lease_until>{schema}.db_millis()", if table == "upload_intents" { "" } else { ",lease_owner=NULL" }), &[]).await.unwrap();
            assert_eq!(changed, 1, "the current worker lost its {table} fence");
        }

        client
            .execute(
                &format!("UPDATE {schema}.artifact_claim_test_clock SET now_ms=200"),
                &[],
            )
            .await
            .unwrap();
        let upload_after_expiry = client.query(&format!("SELECT * FROM {schema}.claim_artifact_upload('after-expiry','after-upload',100,2)"), &[]).await.unwrap();
        assert_eq!(upload_after_expiry.len(), 1);
        assert_eq!(upload_after_expiry[0].get::<_, String>(1), "upload-healthy");
        let gc_after_expiry = client
            .query(
                &format!(
                    "SELECT * FROM {schema}.claim_artifact_gc('after-expiry','after-gc',100,2)"
                ),
                &[],
            )
            .await
            .unwrap();
        assert_eq!(gc_after_expiry.len(), 1);
        assert_eq!(gc_after_expiry[0].get::<_, String>(1), "gc-healthy");
        let reencryption_after_expiry = client.query(&format!("SELECT * FROM {schema}.claim_artifact_reencryption('rotation-lease','old','new','after-expiry','after-reencrypt',100,2)"), &[]).await.unwrap();
        assert_eq!(reencryption_after_expiry.len(), 1);
        assert_eq!(
            reencryption_after_expiry[0].get::<_, String>(1),
            "reencrypt-healthy"
        );

        let terminal = client.query(&format!(
            "SELECT 'upload',upload_id,state,lease_token,lease_until FROM {schema}.upload_intents WHERE upload_id='upload-expire' \
             UNION ALL SELECT 'gc',job_id,state,lease_token,lease_until FROM {schema}.artifact_gc_jobs WHERE job_id IN ('gc-expire','gc-quarantined') \
             UNION ALL SELECT 'reencrypt',job_id,state,lease_token,lease_until FROM {schema}.artifact_reencryption_jobs WHERE job_id='reencrypt-expire' ORDER BY 1,2"
        ), &[]).await.unwrap();
        assert_eq!(terminal.len(), 4);
        assert!(
            terminal.iter().all(|row| {
                matches!(row.get::<_, String>(2).as_str(), "failed" | "dead")
                    && row.get::<_, Option<String>>(3).is_none()
                    && row.get::<_, Option<i64>>(4).is_none()
            }),
            "exact-expiry claim did not terminalize the bounded exhausted set"
        );

        let healthy = client.query_one(&format!(
            "SELECT \
             (SELECT state FROM {schema}.upload_intents WHERE upload_id='upload-healthy'), \
             (SELECT state FROM {schema}.artifact_gc_jobs WHERE job_id='gc-healthy'), \
             (SELECT state FROM {schema}.artifact_reencryption_jobs WHERE job_id='reencrypt-healthy')"
        ), &[]).await.unwrap();
        assert_eq!(healthy.get::<_, String>(0), "promoting");
        assert_eq!(healthy.get::<_, String>(1), "leased");
        assert_eq!(healthy.get::<_, String>(2), "leased");

        store.shutdown().await.unwrap();
        drop(client);
        driver.abort();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    }
);

postgres_test!(
    artifact_receiver_publication_faults_roll_back_and_retry_exactly_once,
    {
        use smesh_a2a::{ReceiverAdmission, ReceiverLease};
        let Some(url) = admin_url() else { return };
        let root = ArtifactTestRoot::new("artifact-pg-faults");
        let keyring = root.join("keys.json");
        fs::write(&keyring, r#"{"activeGeneration":"key-a","generations":{"key-a":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"}}"#).unwrap();
        fs::set_permissions(&keyring, fs::Permissions::from_mode(0o600)).unwrap();
        let artifact = ArtifactStoreConfig::new(&root, &keyring).unwrap();
        let config = config(url, "art_fault")
            .with_test_only_trust_injected_time(true)
            .with_artifact_store(artifact);
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        let (client, driver) = admin_client(&superuser_url()).await;
        let schema = config.schema_name();
        let faults = [
            ArtifactPublicationTestFault::BeforeContentObject,
            ArtifactPublicationTestFault::AfterContentObject,
            ArtifactPublicationTestFault::BeforeManifest,
            ArtifactPublicationTestFault::AfterManifest,
            ArtifactPublicationTestFault::BeforeChunkBatch,
            ArtifactPublicationTestFault::AfterChunkBatch,
            ArtifactPublicationTestFault::BeforeProvenanceBatch,
            ArtifactPublicationTestFault::AfterProvenanceBatch,
            ArtifactPublicationTestFault::BeforeReference,
            ArtifactPublicationTestFault::AfterReference,
            ArtifactPublicationTestFault::BeforeUploadIntent,
            ArtifactPublicationTestFault::AfterUploadIntent,
            ArtifactPublicationTestFault::BeforeReceiverEffect,
            ArtifactPublicationTestFault::AfterReceiverEffect,
            ArtifactPublicationTestFault::BeforeReceiverFrames,
            ArtifactPublicationTestFault::AfterReceiverFrames,
            ArtifactPublicationTestFault::BeforeReceiverCompletion,
            ArtifactPublicationTestFault::AfterReceiverCompletion,
        ];
        assert_eq!(faults.len(), 18);
        for (index, fault) in faults.into_iter().enumerate() {
            let suffix = format!("{index:02}");
            let tenant = format!("tenant-fault-{suffix}");
            let task_id = format!("task-fault-{suffix}");
            let context_id = format!("context-fault-{suffix}");
            let message_id = format!("message-fault-{suffix}");
            let dispatch_id = format!("dispatch-fault-{suffix}");
            let submitted = a2a::Task {
                id: task_id.clone(),
                context_id: context_id.clone(),
                status: a2a::TaskStatus {
                    state: a2a::TaskState::Submitted,
                    message: None,
                    timestamp: None,
                },
                artifacts: None,
                history: None,
                metadata: None,
            };
            let request = smesh_a2a::MeshRequest {
                protocol: "a2a-v1".into(),
                task_id: task_id.clone(),
                context_id: context_id.clone(),
                text: format!("artifact publication fault {suffix}"),
            };
            let task_json = serde_json::to_string(&submitted).unwrap();
            let task_state = serde_json::to_string(&submitted.status.state).unwrap();
            let request_json = serde_json::to_string(&request).unwrap();
            let payload_digest = smesh_a2a::content_digest(request_json.as_bytes());
            let admission =
                serde_json::to_string(&a2a::SendMessageResponse::Task(submitted)).unwrap();
            let now = 10_000 + i64::try_from(index).unwrap() * 100;
            client.execute(&format!("INSERT INTO {schema}.tasks(tenant_scope,task_id,context_id,state,revision,task_json,owner_account_id) VALUES($1,$2,$3,$4,1,$5,'owner')"), &[&tenant,&task_id,&context_id,&task_state,&task_json]).await.unwrap();
            client.execute(&format!("INSERT INTO {schema}.task_events(tenant_scope,task_id,event_seq,task_revision,event_kind,from_state,to_state,event_json,created_at) VALUES($1,$2,1,1,'admitted',NULL,$3,$4,$5)"), &[&tenant,&task_id,&task_state,&task_json,&now]).await.unwrap();
            client.execute(&format!("INSERT INTO {schema}.idempotency_records(tenant_scope,message_id,request_digest,task_id,state,admission_result_json,created_at,updated_at,digest_version,actor_account_id) VALUES($1,$2,$3,$4,'in_progress',$5,$6,$6,2,'owner')"), &[&tenant,&message_id,&payload_digest,&task_id,&admission,&now]).await.unwrap();
            client.execute(&format!("INSERT INTO {schema}.outbox(tenant_scope,dispatch_id,task_id,message_id,causative_revision,payload_json,payload_digest,state,max_attempts,available_at,created_at,updated_at,dispatch_identity_version) VALUES($1,$2,$3,$4,1,$5,$6,'pending',1,$7,$7,$7,2)"), &[&tenant,&dispatch_id,&task_id,&message_id,&request_json,&payload_digest,&now]).await.unwrap();
            client.execute(&format!("INSERT INTO {schema}.stream_transcripts(tenant_scope,message_id,dispatch_id,task_id,transcript_version,state,frame_count,transcript_digest,created_at,updated_at) VALUES($1,$2,$3,$4,1,'open',0,$5,$6,$6)"), &[&tenant,&message_id,&dispatch_id,&task_id,&smesh_a2a::content_digest(b"[]"),&now]).await.unwrap();
            let sender = store
                .claim_outbox("fault-sender", now, 50)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(sender.dispatch_id, dispatch_id);
            let envelope = smesh_a2a::DurableDispatchEnvelope {
                tenant_scope: tenant.clone(),
                dispatch_id: dispatch_id.clone(),
                payload_digest: payload_digest.clone(),
                request,
                execution_reservation: sender.execution_reservation.clone(),
            };
            let ReceiverAdmission::Execute(receiver): ReceiverAdmission = store
                .begin_receive(envelope, "fault-receiver", now, 50)
                .await
                .unwrap()
            else {
                panic!("receiver lease expected")
            };
            let receiver: ReceiverLease = receiver;
            let events = vec![
                smesh_a2a::MeshEvent::Artifact {
                    name: format!("result-{suffix}.bin"),
                    media_type: "application/octet-stream".into(),
                    content: format!("unique-fault-payload-{suffix}"),
                },
                smesh_a2a::MeshEvent::Completed {
                    summary: "done".into(),
                },
            ];
            let before = client.query_one(&format!("SELECT (SELECT count(*) FROM {schema}.content_objects),(SELECT count(*) FROM {schema}.artifact_manifests),(SELECT count(*) FROM {schema}.artifact_chunks),(SELECT count(*) FROM {schema}.provenance_edges),(SELECT count(*) FROM {schema}.artifact_references),(SELECT count(*) FROM {schema}.upload_intents)"), &[]).await.unwrap();
            let before: Vec<i64> = (0..6).map(|column| before.get(column)).collect();
            store.set_artifact_publication_test_fault(fault).unwrap();
            let error = store
                .complete_loopback_receive(&receiver, &events, now + 1)
                .await
                .unwrap_err();
            assert!(
                error
                    .message
                    .contains("injected artifact publication fault")
            );
            let after = client.query_one(&format!("SELECT (SELECT count(*) FROM {schema}.content_objects),(SELECT count(*) FROM {schema}.artifact_manifests),(SELECT count(*) FROM {schema}.artifact_chunks),(SELECT count(*) FROM {schema}.provenance_edges),(SELECT count(*) FROM {schema}.artifact_references),(SELECT count(*) FROM {schema}.upload_intents),(SELECT count(*) FROM {schema}.loopback_effects WHERE dispatch_id=$1),(SELECT count(*) FROM {schema}.receiver_frames WHERE dispatch_id=$1),(SELECT state FROM {schema}.receiver_inbox WHERE dispatch_id=$1)"), &[&dispatch_id]).await.unwrap();
            let after_counts: Vec<i64> = (0..6).map(|column| after.get(column)).collect();
            assert_eq!(after_counts, before, "rollback failed at {fault:?}");
            assert_eq!(after.get::<_, i64>(6), 0, "effect escaped at {fault:?}");
            assert_eq!(after.get::<_, i64>(7), 0, "frames escaped at {fault:?}");
            assert_eq!(after.get::<_, String>(8), "processing");
            store
                .complete_loopback_receive(&receiver, &events, now + 1)
                .await
                .unwrap();
            let exact = client.query_one(&format!("SELECT (SELECT count(*) FROM {schema}.artifact_manifests WHERE dispatch_id=$1),(SELECT count(*) FROM {schema}.artifact_chunks c JOIN {schema}.artifact_manifests m USING(tenant_scope,artifact_id) WHERE m.dispatch_id=$1),(SELECT count(*) FROM {schema}.artifact_references r JOIN {schema}.artifact_manifests m USING(tenant_scope,artifact_id) WHERE m.dispatch_id=$1),(SELECT count(*) FROM {schema}.upload_intents u JOIN {schema}.artifact_manifests m USING(tenant_scope,artifact_id) WHERE m.dispatch_id=$1),(SELECT count(*) FROM {schema}.loopback_effects WHERE dispatch_id=$1),(SELECT count(*) FROM {schema}.receiver_frames WHERE dispatch_id=$1),(SELECT state FROM {schema}.receiver_inbox WHERE dispatch_id=$1)"), &[&dispatch_id]).await.unwrap();
            assert_eq!(
                (
                    exact.get::<_, i64>(0),
                    exact.get::<_, i64>(1),
                    exact.get::<_, i64>(2),
                    exact.get::<_, i64>(3),
                    exact.get::<_, i64>(4),
                    exact.get::<_, i64>(5),
                    exact.get::<_, String>(6)
                ),
                (1, 1, 1, 1, 1, 2, "completed".into()),
                "retry not exact at {fault:?}"
            );
            client.execute(&format!("UPDATE {schema}.outbox SET state='delivered',lease_owner=NULL,lease_token=NULL,lease_until=NULL,updated_at=$1 WHERE tenant_scope=$2 AND dispatch_id=$3"), &[&(now+2),&tenant,&dispatch_id]).await.unwrap();
            drop(sender);
        }
        store.shutdown().await.unwrap();
        let reopened = PostgresTaskStore::open(config.clone()).await.unwrap();
        reopened.shutdown().await.unwrap();
        drop(client);
        driver.abort();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
        fs::remove_dir_all(root).unwrap();
    }
);

// Baseline helper for isolated startup-tamper schemas.
#[allow(clippy::too_many_lines)]
async fn create_artifact_tamper_baseline(
    url: &str,
    prefix: &str,
    with_quota_policy: bool,
) -> (
    PostgresStoreConfig,
    ArtifactTestRoot,
    smesh_a2a::ArtifactStageRegistration,
) {
    let root = ArtifactTestRoot::new(&format!("artifact-{prefix}"));
    let keyring = root.join("keys.json");
    fs::write(&keyring,r#"{"activeGeneration":"key-a","generations":{"key-a":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"}}"#).unwrap();
    fs::set_permissions(&keyring, fs::Permissions::from_mode(0o600)).unwrap();
    let quota=Arc::new(smesh_a2a::QuotaPolicy::from_json(br#"{"schemaVersion":"smesh-quota-policy/v1","policyId":"tamper-quota","revision":1,"requestWindowMillis":60000,"reconnectWindowMillis":60000,"limits":{"requestCount":{"tenant":1000,"account":1000,"principal":1000},"concurrentActiveWork":{"tenant":100,"account":100,"principal":100},"inputBytes":{"tenant":67108864,"account":67108864,"principal":67108864},"outputBytes":{"tenant":67108864,"account":67108864,"principal":67108864},"eventCount":{"tenant":10000,"account":10000,"principal":10000},"concurrentStreams":{"tenant":100,"account":100,"principal":100},"concurrentSubscriptions":{"tenant":100,"account":100,"principal":100},"reconnectCount":{"tenant":100,"account":100,"principal":100},"retainedAuthorityBytes":{"tenant":67108864,"account":67108864,"principal":67108864}},"overrides":[]}"#).unwrap());
    let mut cfg = config(url.to_owned(), prefix)
        .with_artifact_store(ArtifactStoreConfig::new(&root, &keyring).unwrap());
    if with_quota_policy {
        cfg = cfg.with_quota_policy(quota);
    }
    let store = PostgresTaskStore::open(cfg.clone()).await.unwrap();
    let (client, driver) = admin_client(&superuser_url()).await;
    let schema = cfg.schema_name();
    let tenant = "tenant-tamper";
    let now = chrono::Utc::now().timestamp_millis();
    let task = a2a::Task {
        id: "task-tamper".into(),
        context_id: "context-tamper".into(),
        status: a2a::TaskStatus {
            state: a2a::TaskState::Completed,
            message: None,
            timestamp: chrono::DateTime::from_timestamp_millis(now),
        },
        artifacts: None,
        history: None,
        metadata: None,
    };
    let task_json = serde_json::to_string(&task).unwrap();
    let task_state = serde_json::to_string(&a2a::TaskState::Completed).unwrap();
    let task_timestamp = task.status.timestamp.unwrap().to_rfc3339();
    client.execute(&format!("INSERT INTO {schema}.tasks(tenant_scope,task_id,context_id,state,status_timestamp,revision,task_json,owner_account_id) VALUES($1,'task-tamper','context-tamper',$2,$3,1,$4,'owner')"),&[&tenant,&task_state,&task_timestamp,&task_json]).await.unwrap();
    client.execute(&format!("INSERT INTO {schema}.task_events(tenant_scope,task_id,event_seq,task_revision,event_kind,from_state,to_state,event_json,created_at) VALUES($1,'task-tamper',1,1,'admitted',NULL,$2,$3,$4)"),&[&tenant,&task_state,&task_json,&now]).await.unwrap();
    let bytes = b"tamper baseline bytes".to_vec();
    let policy_digest = smesh_a2a::ContentDigestV1::of(b"tamper-policy");
    let manifest = smesh_a2a::ArtifactManifestV1::new(
        "artifact-tamper",
        "tamper.bin",
        None,
        "application/octet-stream",
        smesh_a2a::ArtifactClassification::Confidential,
        smesh_a2a::EncryptionDomain::new("tenant-tamper/confidential").unwrap(),
        "key-a",
        smesh_a2a::ArtifactProducer::new(
            tenant,
            "owner",
            "task-tamper",
            "context-tamper",
            "message-tamper",
            "dispatch-tamper",
        )
        .unwrap(),
        Vec::<smesh_a2a::DerivedFrom>::new(),
        smesh_a2a::ArtifactPolicySnapshot::new(
            "artifact-default",
            1,
            policy_digest,
            now,
            now + 60_000,
        )
        .unwrap(),
        now,
        &bytes,
    )
    .unwrap();
    let registration = smesh_a2a::ArtifactStageRegistration {
        tenant_scope: tenant.into(),
        account_id: "owner".into(),
        owner_account_id: "owner".into(),
        task_id: "task-tamper".into(),
        context_id: "context-tamper".into(),
        message_id: "message-tamper".into(),
        dispatch_id: "dispatch-tamper".into(),
        upload_id: "upload-tamper".into(),
        artifact_id: "artifact-tamper".into(),
        object_id: smesh_a2a::content_digest(
            format!(
                "{tenant}\0confidential\0key-a\0{}",
                manifest.content_digest()
            )
            .as_bytes(),
        ),
        content_digest: manifest.content_digest().to_string(),
        manifest_digest: manifest.manifest_digest().to_string(),
        ciphertext_digest: String::new(),
        plaintext_length: manifest.plaintext_length(),
        ciphertext_length: 0,
        classification: "confidential".into(),
        encryption_domain: "tenant-tamper/confidential".into(),
        key_generation: "key-a".into(),
        canonical_manifest_json: manifest.canonical_json().into(),
        chunks: manifest
            .chunks()
            .iter()
            .map(|c| smesh_a2a::ArtifactChunkRegistration {
                ordinal: c.ordinal(),
                byte_offset: c.offset(),
                plaintext_length: c.length(),
                content_digest: c.digest().to_string(),
            })
            .collect(),
        provenance: Vec::new(),
        media_type: "application/octet-stream".into(),
        reference_id: "reference-tamper".into(),
        task_revision: 1,
        policy_id: "artifact-default".into(),
        policy_revision: 1,
        policy_digest: policy_digest.to_string(),
        created_at: now,
        stage_locator: String::new(),
        final_locator: String::new(),
        nonce: [0; 12],
        retain_until: now + 60_000,
        quota_binding_digest: None,
        receiver_lease_epoch: 1,
        receiver_lease_token: "receiver-token".into(),
    };
    let staged = store.stage_artifact(registration, bytes).await.unwrap();
    store.register_artifact(&staged, now).await.unwrap();
    let claim = store
        .claim_artifact_promotion("tamper-promoter", 30_000, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert!(store.commit_artifact_promotion(&claim).await.unwrap());
    store.shutdown().await.unwrap();
    drop(client);
    driver.abort();
    (cfg, root, staged)
}

postgres_test!(
    artifact_gc_blocker_row_lock_races_cover_both_orderings_on_two_stores,
    90,
    {
        use smesh_a2a::ArtifactHold;
        let Some(url) = admin_url() else { return };
        for blocker in ["read", "backup", "hold"] {
            for blocker_first in [true, false] {
                let prefix = format!(
                    "gc_{}_{}",
                    blocker,
                    if blocker_first { "first" } else { "second" }
                );
                let (cfg, root, staged) =
                    create_artifact_tamper_baseline(&url, &prefix, false).await;
                let left = PostgresTaskStore::open(cfg.clone()).await.unwrap();
                let right = PostgresTaskStore::open(cfg.clone()).await.unwrap();
                let (client, driver) = admin_client(&superuser_url()).await;
                let scope = OwnedTaskScope::new(
                    &staged.tenant_scope,
                    &staged.owner_account_id,
                    VisibilityScope::Own,
                )
                .unwrap();
                let audit = || {
                    AuthorizationAuditInput::new(
                        format!("gc-race-{blocker}-{blocker_first}"),
                        &staged.tenant_scope,
                        &staged.owner_account_id,
                        "gc-race-policy",
                        1,
                        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                        "artifactResolve",
                        AuthorizationDecisionEffect::Allow,
                        "gc race",
                        "artifact",
                        smesh_a2a::content_digest(staged.artifact_id.as_bytes()),
                        Some(staged.task_id.clone()),
                        chrono::Utc::now().timestamp_millis(),
                    )
                    .unwrap()
                };
                if blocker_first {
                    let mut read = None;
                    let mut backup = None;
                    let mut hold = None;
                    let mut reference_released = false;
                    let mut retention_expired = false;
                    match blocker {
                        "read" => {
                            read = left
                                .begin_artifact_resolution(
                                    &scope,
                                    &staged.artifact_id,
                                    Some(&staged.task_id),
                                    &smesh_a2a::content_digest(b"owner"),
                                    30_000,
                                    None,
                                    audit(),
                                    chrono::Utc::now().timestamp_millis(),
                                )
                                .await
                                .unwrap();
                        }
                        "backup" => {
                            assert!(
                                left.release_artifact_reference(
                                    &staged.tenant_scope,
                                    &staged.reference_id,
                                    &staged.owner_account_id,
                                    &staged.task_id,
                                    &staged.artifact_id,
                                    chrono::Utc::now().timestamp_millis()
                                )
                                .await
                                .unwrap()
                            );
                            reference_released = true;
                            client.execute(&format!("UPDATE {}.content_objects SET retain_until={}.db_millis()+200 WHERE object_id=$1",cfg.schema_name(),cfg.schema_name()),&[&staged.object_id]).await.unwrap();
                            backup = Some(
                                left.acquire_artifact_backup_lease(
                                    &staged.tenant_scope,
                                    &staged.object_id,
                                    "race-backup",
                                    30_000,
                                )
                                .await
                                .unwrap(),
                            );
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            retention_expired = true;
                        }
                        "hold" => {
                            let value = ArtifactHold {
                                tenant_scope: staged.tenant_scope.clone(),
                                artifact_id: staged.artifact_id.clone(),
                                hold_id: "race-hold".into(),
                                actor_digest: smesh_a2a::content_digest(b"actor"),
                                reason_digest: smesh_a2a::content_digest(b"reason"),
                                expires_at: None,
                            };
                            left.place_artifact_hold(&value, chrono::Utc::now().timestamp_millis())
                                .await
                                .unwrap();
                            hold = Some(value);
                        }
                        _ => unreachable!(),
                    }
                    if !reference_released {
                        assert!(
                            left.release_artifact_reference(
                                &staged.tenant_scope,
                                &staged.reference_id,
                                &staged.owner_account_id,
                                &staged.task_id,
                                &staged.artifact_id,
                                chrono::Utc::now().timestamp_millis()
                            )
                            .await
                            .unwrap()
                        );
                    }
                    if !retention_expired {
                        client
                            .execute(
                                &format!(
                                    "UPDATE {}.content_objects SET retain_until=1 WHERE object_id=$1",
                                    cfg.schema_name()
                                ),
                                &[&staged.object_id],
                            )
                            .await
                            .unwrap();
                    }
                    assert!(
                        right
                            .claim_artifact_gc("race-gc", 30_000, 1)
                            .await
                            .unwrap()
                            .is_empty(),
                        "{blocker} did not fence GC when acquired first"
                    );
                    if let Some(lease) = read {
                        assert!(
                            left.finish_artifact_resolution(&lease, 0, true)
                                .await
                                .unwrap()
                        );
                    }
                    if let Some(lease) = backup {
                        assert!(left.release_artifact_backup_lease(&lease).await.unwrap());
                    }
                    if let Some(value) = hold {
                        assert!(
                            left.release_artifact_hold(
                                &value,
                                chrono::Utc::now().timestamp_millis()
                            )
                            .await
                            .unwrap()
                        );
                    }
                    assert_eq!(
                        right
                            .claim_artifact_gc("race-gc-after", 30_000, 1)
                            .await
                            .unwrap()
                            .len(),
                        1
                    );
                } else {
                    assert!(
                        left.release_artifact_reference(
                            &staged.tenant_scope,
                            &staged.reference_id,
                            &staged.owner_account_id,
                            &staged.task_id,
                            &staged.artifact_id,
                            chrono::Utc::now().timestamp_millis()
                        )
                        .await
                        .unwrap()
                    );
                    client
                        .execute(
                            &format!(
                                "UPDATE {}.content_objects SET retain_until=1 WHERE object_id=$1",
                                cfg.schema_name()
                            ),
                            &[&staged.object_id],
                        )
                        .await
                        .unwrap();
                    assert_eq!(
                        left.claim_artifact_gc("race-gc-first", 30_000, 1)
                            .await
                            .unwrap()
                            .len(),
                        1
                    );
                    match blocker {
                        "read" => assert!(
                            right
                                .begin_artifact_resolution(
                                    &scope,
                                    &staged.artifact_id,
                                    Some(&staged.task_id),
                                    &smesh_a2a::content_digest(b"owner"),
                                    30_000,
                                    None,
                                    audit(),
                                    chrono::Utc::now().timestamp_millis()
                                )
                                .await
                                .unwrap()
                                .is_none()
                        ),
                        "backup" => assert!(
                            right
                                .acquire_artifact_backup_lease(
                                    &staged.tenant_scope,
                                    &staged.object_id,
                                    "late-backup",
                                    30_000
                                )
                                .await
                                .is_err()
                        ),
                        "hold" => {
                            let value = ArtifactHold {
                                tenant_scope: staged.tenant_scope.clone(),
                                artifact_id: staged.artifact_id.clone(),
                                hold_id: "late-hold".into(),
                                actor_digest: smesh_a2a::content_digest(b"actor"),
                                reason_digest: smesh_a2a::content_digest(b"reason"),
                                expires_at: None,
                            };
                            assert!(
                                right
                                    .place_artifact_hold(
                                        &value,
                                        chrono::Utc::now().timestamp_millis()
                                    )
                                    .await
                                    .is_err()
                            );
                        }
                        _ => unreachable!(),
                    }
                }
                left.shutdown().await.unwrap();
                right.shutdown().await.unwrap();
                drop(client);
                driver.abort();
                PostgresTaskStore::drop_test_schema(&cfg).await.unwrap();
                fs::remove_dir_all(root).unwrap();
            }
        }
    }
);

postgres_test!(artifact_authenticated_socket_wire_matrix, {
    use smesh_a2a::auth::{
        AuthenticationError, BearerVerifier, PresentedBearer, Principal, PrincipalLimits,
    };
    use smesh_a2a::{
        ArtifactManifestV1, AuthorizationPolicy, ContentDigestV1, DurableLoopbackEndpoint,
        GatewayConfig, InjectedClock, build_authorized_durable_loopback_gateway,
    };
    use tokio::io::AsyncWriteExt as _;
    struct FixedVerifier;
    #[async_trait::async_trait]
    impl BearerVerifier for FixedVerifier {
        async fn verify(
            &self,
            token: PresentedBearer<'_>,
        ) -> Result<Principal, AuthenticationError> {
            let subject = match token.as_str() {
                "owner-token" => "owner",
                "foreign-token" => "foreign",
                _ => return Err(AuthenticationError::InvalidToken),
            };
            Principal::bearer_for_verifier(
                "test:artifact".into(),
                subject.into(),
                PrincipalLimits::default(),
            )
            .map_err(|_| AuthenticationError::InvalidToken)
        }
    }
    let Some(url) = admin_url() else { return };
    let root = ArtifactTestRoot::new("artifact-wire");
    let keyring = root.join("keys.json");
    fs::write(&keyring, r#"{"activeGeneration":"key-a","generations":{"key-a":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"}}"#).unwrap();
    fs::set_permissions(&keyring, fs::Permissions::from_mode(0o600)).unwrap();
    let bytes = b"authenticated artifact bytes\0with binary".to_vec();
    let quota_json = format!(
        r#"{{
      "schemaVersion":"smesh-quota-policy/v1","policyId":"wire-quota","revision":1,
      "requestWindowMillis":60000,"reconnectWindowMillis":60000,
      "limits":{{
        "requestCount":{{"tenant":100,"account":100,"principal":100}},
        "concurrentActiveWork":{{"tenant":10,"account":10,"principal":10}},
        "inputBytes":{{"tenant":1048576,"account":1048576,"principal":1048576}},
        "outputBytes":{{"tenant":{0},"account":{0},"principal":{0}}},
        "eventCount":{{"tenant":1024,"account":1024,"principal":1024}},
        "concurrentStreams":{{"tenant":4,"account":4,"principal":4}},
        "concurrentSubscriptions":{{"tenant":4,"account":4,"principal":4}},
        "reconnectCount":{{"tenant":12,"account":12,"principal":12}},
        "retainedAuthorityBytes":{{"tenant":67108864,"account":67108864,"principal":67108864}}
      }},"overrides":[]
    }}"#,
        bytes.len() * 4
    );
    let quota = Arc::new(smesh_a2a::QuotaPolicy::from_json(quota_json.as_bytes()).unwrap());
    let config = config(url, "art_wire")
        .with_quota_policy(Arc::clone(&quota))
        .with_artifact_store(ArtifactStoreConfig::new(&root, &keyring).unwrap());
    let store = Arc::new(PostgresTaskStore::open(config.clone()).await.unwrap());
    let (client, driver) = admin_client(&superuser_url()).await;
    let schema = config.schema_name();
    let tenant = "tenant-wire";
    let artifact_id = "artifact-wire";
    let now = chrono::Utc::now().timestamp_millis();
    let task = a2a::Task {
        id: "task-wire".into(),
        context_id: "context-wire".into(),
        status: a2a::TaskStatus {
            state: a2a::TaskState::Completed,
            message: None,
            timestamp: chrono::DateTime::from_timestamp_millis(now),
        },
        artifacts: None,
        history: None,
        metadata: None,
    };
    client.execute(&format!("INSERT INTO {schema}.tasks(tenant_scope,task_id,context_id,state,revision,task_json,owner_account_id) VALUES($1,'task-wire','context-wire',$2,1,$3,'owner')"), &[&tenant,&serde_json::to_string(&a2a::TaskState::Completed).unwrap(),&serde_json::to_string(&task).unwrap()]).await.unwrap();
    let policy_digest = ContentDigestV1::of(b"wire-policy");
    let manifest = ArtifactManifestV1::new(
        artifact_id,
        "wire.bin",
        None,
        "application/octet-stream",
        smesh_a2a::ArtifactClassification::Confidential,
        smesh_a2a::EncryptionDomain::new("tenant-wire/confidential").unwrap(),
        "key-a",
        smesh_a2a::ArtifactProducer::new(
            tenant,
            "owner",
            "task-wire",
            "context-wire",
            "message-wire",
            "dispatch-wire",
        )
        .unwrap(),
        Vec::<smesh_a2a::DerivedFrom>::new(),
        smesh_a2a::ArtifactPolicySnapshot::new(
            "artifact-default",
            1,
            policy_digest,
            now,
            now + 60_000,
        )
        .unwrap(),
        now,
        &bytes,
    )
    .unwrap();
    let registration = smesh_a2a::ArtifactStageRegistration {
        tenant_scope: tenant.into(),
        account_id: "owner".into(),
        owner_account_id: "owner".into(),
        task_id: "task-wire".into(),
        context_id: "context-wire".into(),
        message_id: "message-wire".into(),
        dispatch_id: "dispatch-wire".into(),
        upload_id: "upload-wire".into(),
        artifact_id: artifact_id.into(),
        object_id: smesh_a2a::content_digest(
            format!(
                "{tenant}\0confidential\0key-a\0{}",
                manifest.content_digest()
            )
            .as_bytes(),
        ),
        content_digest: manifest.content_digest().to_string(),
        manifest_digest: manifest.manifest_digest().to_string(),
        ciphertext_digest: String::new(),
        plaintext_length: manifest.plaintext_length(),
        ciphertext_length: 0,
        classification: "confidential".into(),
        encryption_domain: "tenant-wire/confidential".into(),
        key_generation: "key-a".into(),
        canonical_manifest_json: manifest.canonical_json().into(),
        chunks: manifest
            .chunks()
            .iter()
            .map(|chunk| smesh_a2a::ArtifactChunkRegistration {
                ordinal: chunk.ordinal(),
                byte_offset: chunk.offset(),
                plaintext_length: chunk.length(),
                content_digest: chunk.digest().to_string(),
            })
            .collect(),
        provenance: Vec::new(),
        media_type: "application/octet-stream".into(),
        reference_id: "reference-wire".into(),
        task_revision: 1,
        policy_id: "artifact-default".into(),
        policy_revision: 1,
        policy_digest: policy_digest.to_string(),
        created_at: now,
        stage_locator: String::new(),
        final_locator: String::new(),
        nonce: [0; 12],
        retain_until: now + 60_000,
        quota_binding_digest: None,
        receiver_lease_epoch: 1,
        receiver_lease_token: "receiver-token".into(),
    };
    let staged = store
        .stage_artifact(registration, bytes.clone())
        .await
        .unwrap();
    store.register_artifact(&staged, now).await.unwrap();
    tokio::time::sleep(Duration::from_millis(5)).await;
    let protected = store.scan_artifact_stage_orphans(1, 100).await.unwrap();
    assert_eq!((protected.deleted, protected.refunded_bytes), (0, 0));
    assert!(root.join(&staged.stage_locator).is_file());
    let claim = store
        .claim_artifact_promotion("wire-promoter", 30_000, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert!(store.commit_artifact_promotion(&claim).await.unwrap());
    let scope = OwnedTaskScope::new(tenant, "owner", VisibilityScope::Own).unwrap();
    let audit = AuthorizationAuditInput::new(
        "audit-wire-direct",
        tenant,
        "owner",
        "wire-policy",
        1,
        "wire-policy-digest",
        "artifactResolve",
        AuthorizationDecisionEffect::Allow,
        "test",
        "artifact",
        smesh_a2a::content_digest(artifact_id.as_bytes()),
        None,
        now,
    )
    .unwrap();
    let direct_quota = quota
        .operation_intent(
            &smesh_a2a::QuotaSubject::new(tenant, "owner", "direct-principal").unwrap(),
            smesh_a2a::QuotaOperation::TaskGet,
            "artifact-wire-direct",
            0,
        )
        .unwrap();
    let direct_lease = store
        .begin_artifact_resolution(
            &scope,
            artifact_id,
            None,
            &smesh_a2a::content_digest(b"owner"),
            30_000,
            Some(&direct_quota),
            audit,
            now,
        )
        .await
        .unwrap()
        .unwrap();
    let direct = store.read_artifact_resolution(&direct_lease).await;
    assert!(direct.is_ok(), "direct artifact read failed: {direct:?}");
    assert!(
        store
            .finish_artifact_resolution(&direct_lease, bytes.len() as u64, true)
            .await
            .unwrap()
    );
    let policy = Arc::new(AuthorizationPolicy::from_json(br#"{"schemaVersion":"smesh-authz-policy/v1","policyId":"wire-policy","revision":1,"tenants":[{"id":"tenant-wire","enabled":true}],"accounts":[{"id":"owner","kind":"serviceAccount","memberships":[{"tenantId":"tenant-wire","roles":["taskAgent"]}]},{"id":"foreign","kind":"serviceAccount","memberships":[{"tenantId":"tenant-wire","roles":["taskAgent"]}]}],"principalBindings":[{"principal":{"issuer":"test:artifact","subject":"owner"},"accountId":"owner"},{"principal":{"issuer":"test:artifact","subject":"foreign"},"accountId":"foreign"}]}"#).unwrap());
    let auth = smesh_a2a::auth::AuthState::new(Arc::new(FixedVerifier), [3; 32]);
    let authority: Arc<dyn DurableAuthority> = store.clone();
    let gateway = build_authorized_durable_loopback_gateway(
        GatewayConfig::new("http://127.0.0.1", "wire"),
        authority,
        DurableLoopbackEndpoint::new(),
        InjectedClock::new(now),
        auth,
        policy,
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let cancel = tokio_util::sync::CancellationToken::new();
    let server_cancel = cancel.clone();
    let app = gateway.router();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(server_cancel.cancelled_owned())
            .await
            .unwrap();
    });
    let http = reqwest::Client::new();
    let endpoint = format!("http://{address}/artifacts/v1/{artifact_id}");
    assert_eq!(
        http.get(&endpoint).send().await.unwrap().status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        http.get(&endpoint)
            .bearer_auth("foreign-token")
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );
    assert_eq!(
        http.get(format!("http://{address}/artifacts/v1/missing"))
            .bearer_auth("owner-token")
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );
    let range = http
        .get(&endpoint)
        .bearer_auth("owner-token")
        .header(reqwest::header::RANGE, "bytes=0-2")
        .send()
        .await
        .unwrap();
    assert_eq!(range.status(), reqwest::StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        range.headers().get(reqwest::header::ACCEPT_RANGES).unwrap(),
        "none"
    );
    let head = http
        .head(&endpoint)
        .bearer_auth("owner-token")
        .send()
        .await
        .unwrap();
    assert_eq!(head.status(), reqwest::StatusCode::OK);
    assert_eq!(
        head.headers().get(reqwest::header::CONTENT_LENGTH).unwrap(),
        bytes.len().to_string().as_str()
    );
    assert_eq!(head.bytes().await.unwrap().len(), 0);
    let get = http
        .get(&endpoint)
        .bearer_auth("owner-token")
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), reqwest::StatusCode::OK);
    assert_eq!(
        get.headers()
            .get(reqwest::header::CONTENT_DISPOSITION)
            .unwrap(),
        "attachment"
    );
    assert_eq!(get.bytes().await.unwrap().as_ref(), bytes.as_slice());
    let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
    socket.write_all(format!("GET /artifacts/v1/{artifact_id} HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer owner-token\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    drop(socket);
    tokio::task::yield_now().await;
    assert_eq!(
        client
            .query_one(
                &format!("SELECT count(*) FROM {schema}.artifact_read_leases WHERE state='active'"),
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    let blob = root.join(&staged.final_locator);
    let mut corrupted = fs::read(&blob).unwrap();
    corrupted[0] ^= 0xff;
    fs::write(&blob, corrupted).unwrap();
    assert_eq!(
        http.get(&endpoint)
            .bearer_auth("owner-token")
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR
    );
    let blob_reads_at_boundary = store.artifact_blob_read_count();
    let denied = http
        .get(&endpoint)
        .bearer_auth("owner-token")
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        denied.headers().get(reqwest::header::RETRY_AFTER).unwrap(),
        "1"
    );
    for forbidden in [
        reqwest::header::ETAG,
        reqwest::header::CONTENT_TYPE,
        reqwest::header::CONTENT_DISPOSITION,
    ] {
        assert!(!denied.headers().contains_key(forbidden));
    }
    assert!(denied.bytes().await.unwrap().is_empty());
    assert_eq!(store.artifact_blob_read_count(), blob_reads_at_boundary);
    assert_eq!(
        client
            .query_one(
                &format!("SELECT count(*) FROM {schema}.artifact_read_leases WHERE state='active'"),
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    let denial = client.query_one(&format!("SELECT count(*),COALESCE(bool_and(retry_after_seconds=1),false),COALESCE(string_agg(to_jsonb(d)::text,''),'') FROM {schema}.quota_denial_audits d WHERE tenant_scope=$1"), &[&tenant]).await.unwrap();
    assert_eq!(denial.get::<_, i64>(0), 1);
    assert!(denial.get::<_, bool>(1));
    assert!(!denial.get::<_, String>(2).contains(artifact_id));
    store.close_owned_sync();
    assert_eq!(
        http.get(&endpoint)
            .bearer_auth("owner-token")
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
    cancel.cancel();
    server.await.unwrap();
    gateway.shutdown().await.unwrap();

    // Startup semantic-seal tamper cases run in `artifact_tamper_reopen_matrix`,
    // which mutates each authority row in an isolated schema.

    drop(client);
    driver.abort();
    drop(store);
    PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    fs::remove_dir_all(root).unwrap();
});

postgres_test!(artifact_tamper_baseline_reopens, {
    let Some(url) = admin_url() else { return };
    let (config, root, _staged) =
        create_artifact_tamper_baseline(&url, "art_tamper_control", true).await;
    let reopened = PostgresTaskStore::open(config.clone()).await.unwrap();
    reopened.shutdown().await.unwrap();
    PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    fs::remove_dir_all(root).unwrap();
});

postgres_test!(artifact_tamper_reopen_matrix, 60, {
    let Some(url) = admin_url() else { return };
    let names = [
        "object-content-digest",
        "object-ciphertext-digest",
        "object-plaintext-length",
        "object-ciphertext-length",
        "object-state",
        "object-locator",
        "object-key-generation",
        "object-encryption-domain",
        "object-classification",
        "object-reference-count",
        "manifest-canonical",
        "manifest-digest",
        "manifest-producer",
        "manifest-task",
        "manifest-context",
        "manifest-policy",
        "manifest-retention",
        "chunk-order",
        "chunk-digest",
        "chunk-length",
        "chunk-object-binding",
        "provenance-self",
        "provenance-cycle",
        "provenance-cross-domain",
        "upload-lease-fence",
        "read-lease-fence",
        "backup-lease-fence",
        "retention-hold",
        "tombstone",
        "gc-job",
    ];
    for (index, name) in names.into_iter().enumerate() {
        eprintln!("artifact isolated tamper case: {name}");
        let prefix = format!("art_tm_{index:02}");
        let (config, root, staged) = create_artifact_tamper_baseline(&url, &prefix, true).await;
        let schema = config.schema_name();
        let zero = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let (table, mutation) = match name {
            "object-content-digest" => (
                "content_objects",
                format!("UPDATE {schema}.content_objects SET content_digest='{zero}'"),
            ),
            "object-ciphertext-digest" => (
                "content_objects",
                format!("UPDATE {schema}.content_objects SET ciphertext_digest='{zero}'"),
            ),
            "object-plaintext-length" => (
                "content_objects",
                format!("UPDATE {schema}.content_objects SET plaintext_length=plaintext_length+1"),
            ),
            "object-ciphertext-length" => (
                "content_objects",
                format!(
                    "UPDATE {schema}.content_objects SET ciphertext_length=ciphertext_length+1"
                ),
            ),
            "object-state" => (
                "content_objects",
                format!("UPDATE {schema}.content_objects SET state='staged'"),
            ),
            "object-locator" => (
                "content_objects",
                format!(
                    "UPDATE {schema}.content_objects SET backend_locator='objects/tampered/locator'"
                ),
            ),
            "object-key-generation" => (
                "content_objects",
                format!("UPDATE {schema}.content_objects SET key_generation='key-tampered'"),
            ),
            "object-encryption-domain" | "provenance-cross-domain" => (
                "content_objects",
                format!(
                    "UPDATE {schema}.content_objects SET encryption_domain='tenant-tamper/cross-domain'"
                ),
            ),
            "object-classification" => (
                "content_objects",
                format!("UPDATE {schema}.content_objects SET classification='public'"),
            ),
            "object-reference-count" => (
                "content_objects",
                format!("UPDATE {schema}.content_objects SET reference_count=2"),
            ),
            "manifest-canonical" => (
                "artifact_manifests",
                format!("UPDATE {schema}.artifact_manifests SET canonical_json='{{}}'"),
            ),
            "manifest-digest" => (
                "artifact_manifests",
                format!("UPDATE {schema}.artifact_manifests SET manifest_digest='{zero}'"),
            ),
            "manifest-producer" => (
                "artifact_manifests",
                format!("UPDATE {schema}.artifact_manifests SET owner_account_id='tampered'"),
            ),
            "manifest-task" => (
                "artifact_manifests",
                format!("UPDATE {schema}.artifact_manifests SET task_id='tampered'"),
            ),
            "manifest-context" => (
                "artifact_manifests",
                format!("UPDATE {schema}.artifact_manifests SET context_id='tampered'"),
            ),
            "manifest-policy" => (
                "artifact_manifests",
                format!("UPDATE {schema}.artifact_manifests SET policy_id='tampered'"),
            ),
            "manifest-retention" => (
                "artifact_manifests",
                format!("UPDATE {schema}.artifact_manifests SET retain_until=retain_until+1"),
            ),
            "chunk-order" => (
                "artifact_chunks",
                format!("UPDATE {schema}.artifact_chunks SET ordinal=1"),
            ),
            "chunk-digest" => (
                "artifact_chunks",
                format!("UPDATE {schema}.artifact_chunks SET content_digest='{zero}'"),
            ),
            "chunk-length" => (
                "artifact_chunks",
                format!("UPDATE {schema}.artifact_chunks SET plaintext_length=plaintext_length+1"),
            ),
            "chunk-object-binding" => (
                "artifact_chunks",
                format!("UPDATE {schema}.artifact_chunks SET artifact_id='tampered'"),
            ),
            "provenance-self" | "provenance-cycle" => (
                "artifact_manifests",
                format!(
                    "UPDATE {schema}.artifact_manifests SET canonical_json=replace(canonical_json,'\"derivedFrom\":[]','\"derivedFrom\":[{{\"artifactId\":\"artifact-tamper\",\"relation\":\"summary\"}}]')"
                ),
            ),
            "upload-lease-fence" => (
                "upload_intents",
                format!(
                    "UPDATE {schema}.upload_intents SET state='promoting',lease_token=NULL,lease_until=NULL"
                ),
            ),
            "read-lease-fence" => (
                "artifact_read_leases",
                format!(
                    "INSERT INTO {schema}.artifact_read_leases VALUES('tenant-tamper','tamper-read','artifact-tamper',1,'','owner','active',1,1)"
                ),
            ),
            "backup-lease-fence" => (
                "artifact_backup_leases",
                format!(
                    "INSERT INTO {schema}.artifact_backup_leases VALUES('tenant-tamper','tamper-backup','{}','',1,'','active',1,1)",
                    staged.object_id
                ),
            ),
            "retention-hold" => (
                "artifact_retention_holds",
                format!(
                    "INSERT INTO {schema}.artifact_retention_holds VALUES('tenant-tamper','tamper-hold','artifact-tamper','','','active',1,NULL,NULL)"
                ),
            ),
            "tombstone" => (
                "artifact_tombstones",
                format!(
                    "INSERT INTO {schema}.artifact_tombstones VALUES('tenant-tamper','{}',1,'reason','locator',NULL,1,NULL)",
                    staged.object_id
                ),
            ),
            "gc-job" => (
                "artifact_gc_jobs",
                format!(
                    "INSERT INTO {schema}.artifact_gc_jobs VALUES('tenant-tamper','tamper-gc','{}',1,'leased',1,NULL,NULL,1,NULL,0,NULL)",
                    staged.object_id
                ),
            ),
            _ => unreachable!(),
        };
        let (client, driver) = admin_client(&superuser_url()).await;
        client.batch_execute(&format!("ALTER TABLE {schema}.{table} DISABLE TRIGGER ALL; {mutation}; ALTER TABLE {schema}.{table} ENABLE TRIGGER ALL")).await.unwrap_or_else(|error|panic!("mutation failed {name}: {error}"));
        assert!(
            matches!(
                PostgresTaskStore::open(config.clone()).await,
                Err(smesh_a2a::PostgresStoreError::InvalidSchema)
            ),
            "tamper case reopened: {name}"
        );
        drop(client);
        driver.abort();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
        fs::remove_dir_all(root).unwrap();
    }
});

postgres_test!(artifact_populated_default_plans_and_batch_bound, {
    let Some(url) = admin_url() else { return };
    let (config, root, staged) = create_artifact_tamper_baseline(&url, "art_plans", true).await;
    let schema = config.schema_name();
    let (client, driver) = admin_client(&superuser_url()).await;
    for table in [
        "content_objects",
        "artifact_manifests",
        "artifact_references",
        "artifact_chunks",
        "upload_intents",
        "artifact_read_leases",
        "artifact_backup_leases",
        "artifact_retention_holds",
        "provenance_edges",
    ] {
        client
            .batch_execute(&format!("ALTER TABLE {schema}.{table} DISABLE TRIGGER ALL"))
            .await
            .unwrap();
    }
    let digest = "'sha256:'||encode(sha256(convert_to(g::text,'UTF8')),'hex')";
    client.batch_execute(&format!(r"
      INSERT INTO {schema}.content_objects SELECT 'tenant-plan','owner','obj-'||g,{digest},'confidential','tenant-plan/confidential','key-a',1,17,{digest},'objects/plan/obj-'||g,decode('000000000000000000000000','hex'),'available',0,0,1,1,0 FROM generate_series(1,2000) g;
      INSERT INTO {schema}.artifact_manifests SELECT 'tenant-plan','artifact-'||g,{digest},'obj-'||g,1,'{{}}','owner','task-tamper','context-tamper','message','dispatch','application/octet-stream',1,'confidential','tenant-plan/confidential','policy',1,{digest},1,1 FROM generate_series(1,2000) g;
      INSERT INTO {schema}.artifact_references SELECT 'tenant-plan','ref-'||g,'artifact-'||g,'task-tamper','context-tamper','owner',1,'active',1,1 FROM generate_series(1,2000) g;
      INSERT INTO {schema}.artifact_chunks SELECT 'tenant-plan','artifact-'||g,0,0,1,{digest} FROM generate_series(1,2000) g;
      INSERT INTO {schema}.upload_intents(tenant_scope,upload_id,artifact_id,object_id,state,stage_locator,final_locator,ciphertext_digest,ciphertext_length,lease_epoch,created_at,updated_at) SELECT 'tenant-plan','upload-'||g,'artifact-'||g,'obj-'||g,'committed','stage/0123456789abcdefghijklmnopqrstuv.tmp','objects/plan/obj-'||g,{digest},17,1,1,g FROM generate_series(1,2000) g;
      INSERT INTO {schema}.artifact_read_leases SELECT 'tenant-plan','read-'||g,'artifact-'||g,1,'token','owner','active',10000,1 FROM generate_series(1,2000) g;
      INSERT INTO {schema}.artifact_backup_leases SELECT 'tenant-plan','backup-'||g,'obj-'||g,'worker',1,'token','active',10000,1 FROM generate_series(1,2000) g;
      INSERT INTO {schema}.artifact_retention_holds SELECT 'tenant-plan','hold-'||g,'artifact-'||g,'actor','reason','active',1,NULL,NULL FROM generate_series(1,2000) g;
      INSERT INTO {schema}.provenance_edges SELECT 'tenant-plan','artifact-'||g,0,'artifact-tamper','summary' FROM generate_series(1,2000) g;
      ANALYZE {schema}.content_objects; ANALYZE {schema}.artifact_manifests; ANALYZE {schema}.artifact_references; ANALYZE {schema}.artifact_chunks; ANALYZE {schema}.upload_intents; ANALYZE {schema}.artifact_read_leases; ANALYZE {schema}.artifact_backup_leases; ANALYZE {schema}.artifact_retention_holds; ANALYZE {schema}.provenance_edges;
    ")).await.unwrap();
    let plans = [
        (
            format!(
                "SELECT r.reference_id FROM {schema}.artifact_references r WHERE r.tenant_scope='tenant-plan' AND r.task_id='task-tamper' AND r.artifact_id='artifact-1999' AND r.owner_account_id='owner' AND r.state='active'"
            ),
            "artifact_references_resolve",
        ),
        (
            format!(
                "SELECT upload_id FROM {schema}.upload_intents WHERE tenant_scope='tenant-plan' AND state IN ('committed','promoting') AND updated_at<=2 ORDER BY updated_at,tenant_scope,upload_id LIMIT 100"
            ),
            "upload_intents_due",
        ),
        (
            format!(
                "SELECT object_id FROM {schema}.content_objects WHERE state='available' AND reference_count=0 AND retain_until<=2 ORDER BY state,retain_until,tenant_scope,object_id LIMIT 100"
            ),
            "content_objects_gc_due",
        ),
        (
            format!(
                "SELECT lease_id FROM {schema}.artifact_read_leases WHERE tenant_scope='tenant-plan' AND artifact_id='artifact-1999' AND state='active' AND lease_until>2"
            ),
            "artifact_read_leases_active",
        ),
        (
            format!(
                "SELECT lease_id FROM {schema}.artifact_backup_leases WHERE tenant_scope='tenant-plan' AND object_id='obj-1999' AND state='active' AND lease_until>2"
            ),
            "artifact_backup_leases_active",
        ),
        (
            format!(
                "SELECT hold_id FROM {schema}.artifact_retention_holds WHERE tenant_scope='tenant-plan' AND artifact_id='artifact-1999' AND state='active' AND (expires_at IS NULL OR expires_at>2)"
            ),
            "artifact_retention_holds_active",
        ),
        (
            format!(
                "SELECT child_artifact_id FROM {schema}.provenance_edges WHERE tenant_scope='tenant-plan' AND parent_artifact_id='artifact-tamper' AND child_artifact_id='artifact-1999'"
            ),
            "provenance_edges_parent",
        ),
    ];
    for (sql, index) in plans {
        let plan = client
            .query(&format!("EXPLAIN (COSTS OFF) {sql}"), &[])
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.get::<_, String>(0))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!plan.contains("Seq Scan"), "{sql}\n{plan}");
        assert!(!plan.contains("Sort"), "{sql}\n{plan}");
        assert!(plan.contains(index), "expected {index}\n{sql}\n{plan}");
    }
    let functions=client.query(&format!("SELECT pg_get_functiondef(p.oid) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='{schema}' AND p.proname IN ('claim_artifact_upload','claim_artifact_gc','artifact_stage_locator_live') ORDER BY p.proname"),&[]).await.unwrap().into_iter().map(|r|r.get::<_,String>(0).replace(schema,"__SCHEMA__")).collect::<Vec<_>>().join("\n");
    let function_hash = smesh_a2a::content_digest(functions.as_bytes());
    eprintln!("artifact canonical function SQL hash: {function_hash}");
    assert!(function_hash.starts_with("sha256:"));
    assert!(
        client
            .query(
                &format!(
                    "SELECT * FROM {schema}.claim_artifact_upload('owner','token',30000,1001)"
                ),
                &[]
            )
            .await
            .is_err()
    );
    let claimed = client
        .query(
            &format!("SELECT * FROM {schema}.claim_artifact_upload('owner','token',30000,1000)"),
            &[],
        )
        .await
        .unwrap();
    assert!(claimed.len() <= 1000);
    drop(client);
    driver.abort();
    PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    fs::remove_dir_all(root).unwrap();
    let _ = staged;
});

postgres_test!(artifact_claims_are_fair_across_active_tenants, {
    let Some(url) = admin_url() else { return };
    let (config, root, staged) =
        create_artifact_tamper_baseline(&url, "art_claim_fair", true).await;
    let left = Arc::new(PostgresTaskStore::open(config.clone()).await.unwrap());
    let right = Arc::new(PostgresTaskStore::open(config.clone()).await.unwrap());
    let schema = config.schema_name();
    let (client, driver) = admin_client(&superuser_url()).await;
    client
        .batch_execute(&format!(
            "ALTER TABLE {schema}.upload_intents DISABLE TRIGGER ALL"
        ))
        .await
        .unwrap();
    for (tenant, count, updated) in [
        ("tenant-a", 4, 0_i64),
        ("tenant-b", 1, 1_i64),
        ("tenant-c", 1, 1_i64),
    ] {
        for n in 0..count {
            let id = format!("{tenant}-{n}");
            client.execute(&format!("INSERT INTO {schema}.upload_intents(tenant_scope,upload_id,artifact_id,object_id,state,stage_locator,final_locator,ciphertext_digest,ciphertext_length,lease_epoch,created_at,updated_at) VALUES($1,$2,$2,$3,'committed',$4,$5,$6,$7,1,$8,$8)"),&[&tenant,&id,&staged.object_id,&staged.stage_locator,&staged.final_locator,&staged.ciphertext_digest,&i64::try_from(staged.ciphertext_length).unwrap(),&updated]).await.unwrap();
        }
    }
    // Keep accounting disabled for these intentionally FK-free synthetic rows.
    let (a, b) = tokio::join!(
        left.claim_artifact_promotion("fair-left", 30_000, 3),
        right.claim_artifact_promotion("fair-right", 30_000, 3)
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert!(a.len() <= 3 && b.len() <= 3);
    let tenants: std::collections::BTreeSet<String> =
        a.into_iter().chain(b).map(|r| r.tenant_scope).collect();
    assert_eq!(
        tenants,
        std::collections::BTreeSet::from(["tenant-a".into(), "tenant-b".into(), "tenant-c".into()])
    );
    left.shutdown().await.unwrap();
    right.shutdown().await.unwrap();
    drop(client);
    driver.abort();
    PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    fs::remove_dir_all(root).unwrap();
});

postgres_test!(artifact_two_scanners_delete_and_refund_once, {
    let Some(url) = admin_url() else { return };
    let root = ArtifactTestRoot::new("artifact-scanners");
    let keyring = root.join("keys.json");
    fs::write(&keyring, r#"{"activeGeneration":"key-a","generations":{"key-a":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"}}"#).unwrap();
    fs::set_permissions(&keyring, fs::Permissions::from_mode(0o600)).unwrap();
    let config = config(url, "art_scan")
        .with_artifact_store(ArtifactStoreConfig::new(&root, &keyring).unwrap());
    let store = Arc::new(PostgresTaskStore::open(config.clone()).await.unwrap());
    let stage = root
        .join("stage")
        .join("0123456789abcdefghijklmnopqrstuv.tmp");
    let bytes = vec![0x5a; 4096];
    fs::write(&stage, &bytes).unwrap();
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o600)).unwrap();
    tokio::time::sleep(Duration::from_millis(5)).await;
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let left = {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        tokio::spawn(async move {
            barrier.wait().await;
            store.scan_artifact_stage_orphans(1, 100).await.unwrap()
        })
    };
    let right = {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        tokio::spawn(async move {
            barrier.wait().await;
            store.scan_artifact_stage_orphans(1, 100).await.unwrap()
        })
    };
    barrier.wait().await;
    let left = left.await.unwrap();
    let right = right.await.unwrap();
    assert_eq!(left.deleted + right.deleted, 1);
    assert_eq!(
        left.refunded_bytes + right.refunded_bytes,
        bytes.len() as u64
    );
    assert!(!stage.exists());
    let (client, driver) = admin_client(&superuser_url()).await;
    let rows: i64 = client
        .query_one(
            &format!(
                "SELECT count(*) FROM {}.artifact_orphan_audits",
                config.schema_name()
            ),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(rows, 1);
    let candidate_rows: i64 = client
        .query_one(
            &format!(
                "SELECT count(*) FROM {}.artifact_orphan_candidates WHERE state='finalized' AND ciphertext_length=$1 AND finalized_at IS NOT NULL",
                config.schema_name()
            ),
            &[&i64::try_from(bytes.len()).unwrap()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        candidate_rows, 1,
        "unlink ownership must be durable before audit"
    );

    // Model SIGKILL after unlink but before database finalization.  The next
    // scanner must take over the expired generation and emit one refund/audit.
    let crashed_locator = "stage/abcdefghij0123456789ABCDEFGHIJKL.tmp";
    let crashed_path = root.join(crashed_locator);
    fs::write(&crashed_path, vec![0x33; 2048]).unwrap();
    client
        .execute(
            &format!("INSERT INTO {}.artifact_orphan_candidates(stage_locator,locator_digest,ciphertext_length,state,claim_token,claim_generation,claim_until,claimed_at) VALUES($1,$2,2048,'claimed',$3,1,0,0)",
                config.schema_name()),
            &[&crashed_locator, &smesh_a2a::content_digest(crashed_locator.as_bytes()), &smesh_a2a::content_digest(b"dead-scanner")],
        )
        .await
        .unwrap();
    fs::remove_file(&crashed_path).unwrap();
    let recovered = store.scan_artifact_stage_orphans(1, 100).await.unwrap();
    assert_eq!((recovered.deleted, recovered.refunded_bytes), (1, 2048));
    let replay = store.scan_artifact_stage_orphans(1, 100).await.unwrap();
    assert_eq!((replay.deleted, replay.refunded_bytes), (0, 0));
    let recovered_rows: i64 = client
        .query_one(
            &format!("SELECT count(*) FROM {}.artifact_orphan_candidates c JOIN {}.artifact_orphan_audits a USING(locator_digest) WHERE c.stage_locator=$1 AND c.state='finalized' AND c.claim_generation=2", config.schema_name(), config.schema_name()),
            &[&crashed_locator],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(recovered_rows, 1);

    // Scanner ownership wins the opposite ordering. Registration observes the
    // durable claim under the same advisory fence, fails closed, and cannot
    // publish metadata for a stage that cleanup may unlink.
    let registration = smesh_a2a::ArtifactStageRegistration {
        tenant_scope: "tenant-owned-stage".into(),
        account_id: "owner".into(),
        owner_account_id: "owner".into(),
        task_id: "task".into(),
        context_id: "context".into(),
        message_id: "message".into(),
        dispatch_id: "dispatch".into(),
        upload_id: "upload-owned".into(),
        artifact_id: "artifact-owned".into(),
        object_id: smesh_a2a::content_digest(b"owned-object"),
        content_digest: smesh_a2a::content_digest(b"owned"),
        manifest_digest: smesh_a2a::content_digest(b"owned-manifest"),
        ciphertext_digest: String::new(),
        plaintext_length: 5,
        ciphertext_length: 0,
        classification: "confidential".into(),
        encryption_domain: "tenant-owned-stage/confidential".into(),
        key_generation: "key-a".into(),
        canonical_manifest_json: "{}".into(),
        chunks: Vec::new(),
        provenance: Vec::new(),
        media_type: "application/octet-stream".into(),
        reference_id: "reference-owned".into(),
        task_revision: 1,
        policy_id: "artifact-default".into(),
        policy_revision: 1,
        policy_digest: smesh_a2a::content_digest(b"policy"),
        created_at: 1,
        stage_locator: String::new(),
        final_locator: String::new(),
        nonce: [0; 12],
        retain_until: i64::MAX,
        quota_binding_digest: None,
        receiver_lease_epoch: 1,
        receiver_lease_token: "receiver-token".into(),
    };
    let owned = store
        .stage_artifact(registration, b"owned".to_vec())
        .await
        .unwrap();
    client.execute(&format!("INSERT INTO {}.artifact_orphan_candidates(stage_locator,locator_digest,ciphertext_length,state,claim_token,claim_generation,claim_until,claimed_at) VALUES($1,$2,$3,'claimed',$4,1,9223372036854775807,0)", config.schema_name()), &[&owned.stage_locator,&smesh_a2a::content_digest(owned.stage_locator.as_bytes()),&i64::try_from(owned.ciphertext_length).unwrap(),&smesh_a2a::content_digest(b"scanner-owner")]).await.unwrap();
    assert!(store.register_artifact(&owned, 1).await.is_err());
    assert!(root.join(&owned.stage_locator).is_file());
    let escaped: i64 = client
        .query_one(
            &format!(
                "SELECT count(*) FROM {}.upload_intents WHERE upload_id='upload-owned'",
                config.schema_name()
            ),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(escaped, 0);
    store.shutdown().await.unwrap();
    drop(client);
    driver.abort();
    drop(store);
    PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    fs::remove_dir_all(root).unwrap();
});
