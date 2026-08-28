#![allow(clippy::match_wild_err_arm)]

mod support;

use std::{env, fs, os::unix::fs::PermissionsExt as _, sync::Arc, time::Duration};

use smesh_a2a::{
    AuthorityDiagnostics, AuthorityIdentity, AuthorityShutdown, AuthorizationAuditInput,
    AuthorizationAuditSink, AuthorizationDecisionEffect, AuthorizedMutation, AuthorizedTaskRead,
    DurableAuthority, OutboxAuthority, OwnedTaskScope, PostgresStoreConfig, PostgresTaskStore,
    PostgresTransactionTestFault, QuotaReservationInput, ReceiverAuthority, SqliteTaskStore,
    TaskAdmission, TaskLifecycle, TranscriptAuthority, VisibilityScope,
};
#[cfg(debug_assertions)]
use smesh_a2a::{
    DurableLoopbackEndpoint, GatewayConfig, InjectedClock, SendMessageAdmission,
    build_durable_loopback_gateway,
};
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
    ($name:ident, $body:block) => {
        #[tokio::test]
        async fn $name() {
            tokio::time::timeout(Duration::from_secs(30), async move $body)
                .await
                .unwrap_or_else(|_| panic!("PostgreSQL test {} exceeded 30s watchdog", stringify!($name)));
        }
    };
}

fn admin_url() -> Option<String> {
    match env::var("SMESH_TEST_POSTGRES_ADMIN_URL") {
        Ok(url) => Some(url),
        Err(_) if env::var("SMESH_POSTGRES_TEST_REQUIRED").as_deref() == Ok("1") => {
            panic!("SMESH_TEST_POSTGRES_ADMIN_URL is required")
        }
        Err(_) => {
            eprintln!("skipping PostgreSQL test: SMESH_TEST_POSTGRES_ADMIN_URL is absent");
            None
        }
    }
}

fn superuser_url() -> String {
    env::var("SMESH_TEST_POSTGRES_SUPERUSER_URL").unwrap_or_else(|_| {
        "postgresql://postgres:smesh_test_password@127.0.0.1:55432/smesh_test".into()
    })
}

fn config(url: String, suffix: &str) -> PostgresStoreConfig {
    let runtime_url = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL").unwrap_or_else(|_| {
        "postgresql://smesh_test_runtime:smesh_runtime_password@127.0.0.1:55432/smesh_test".into()
    });
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
fn every_retryable_growth_transaction_is_capacity_locked_and_checked() {
    let source = include_str!("../src/postgres_store.rs");
    let runner = &source[source.find("async fn run_retryable_transaction").unwrap()
        ..source.find("fn q(&self").unwrap()];
    assert!(runner.contains("self.lock_capacity(&tx).await?;"));
    assert!(runner.contains("self.ensure_capacity(&tx, tenant).await?;"));
    assert!(
        source.contains("store.ensure_all_tenant_capacity(tx).await?;"),
        "global outbox expiry/attempt growth must be checked for every tenant"
    );
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
        source.matches(".transaction()").count(),
        8,
        "new direct transaction site must be routed through the bounded runner or explicitly reviewed"
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
        let sqlite = Arc::new(SqliteTaskStore::open(&sqlite_path, 64).await.unwrap());
        let sqlite_key = sqlite.completion_receipt_key();

        let pg_config = config(url.clone(), "row_parity");
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
        let postgres_dump = dump_postgres(&client, pg_config.schema_name()).await;
        assert_eq!(sqlite_dump.counts.len(), AUTHORITY_TABLES.len());
        assert_eq!(postgres_dump.counts.len(), AUTHORITY_TABLES.len());
        assert_eq!(sqlite_dump, postgres_dump);
        for table in AUTHORITY_TABLES {
            assert!(
                sqlite_dump.counts[table] > 0,
                "row-parity scenario did not populate {table}"
            );
        }

        let sqlite_reopened = SqliteTaskStore::open(&sqlite_path, 64).await.unwrap();
        assert_eq!(sqlite_reopened.completion_receipt_key(), sqlite_key);
        sqlite_reopened.shutdown().await.unwrap();
        let postgres_reopened = PostgresTaskStore::open(pg_config.clone()).await.unwrap();
        assert_eq!(
            postgres_reopened.completion_receipt_key(),
            Some(postgres_key)
        );
        postgres_reopened.shutdown().await.unwrap();

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
            "ANALYZE {0}.outbox; ANALYZE {0}.cancellation_intents; SET enable_seqscan=off",
            config.schema_name()
        ))
        .await
        .unwrap();
    let cancellation = client.query(&format!("EXPLAIN SELECT 1 FROM {0}.cancellation_intents WHERE dispatch_id='missing' AND state='requested'", config.schema_name()), &[]).await.unwrap().into_iter().map(|row| row.get::<_,String>(0)).collect::<Vec<_>>().join("\n");
    assert!(
        cancellation.contains("cancellation_intents_dispatch_requested"),
        "{cancellation}"
    );
    let claim = client.query(&format!("EXPLAIN SELECT tenant_scope,outbox_id FROM {0}.outbox WHERE ((state='pending' AND available_at<=0) OR (state='leased' AND lease_until<=0)) AND attempt_count<max_attempts ORDER BY available_at,outbox_id LIMIT 1", config.schema_name()), &[]).await.unwrap().into_iter().map(|row| row.get::<_,String>(0)).collect::<Vec<_>>().join("\n");
    assert!(claim.contains("outbox_due"), "{claim}");
    for function in [
        "claim_outbox_bounded(0,'owner','token',1)",
        "cancellation_requested_bounded('missing')",
    ] {
        let plan = client
            .query(
                &format!("EXPLAIN SELECT * FROM {}.{function}", config.schema_name()),
                &[],
            )
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            plan.contains("Function Scan") || plan.contains("Result"),
            "{plan}"
        );
    }
    drop(client);
    driver.abort();
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
            .authorize_and_admit_mutation(
                &scope,
                AuthorizedMutation::without_quota(admitted.clone()),
                audit("missing-replay"),
            )
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
        let frozen_bytes = 64 * 1024 * 1024 - audit_bytes - snapshot_overhead - entry_overhead;
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
        assert_eq!(row.get::<_, i64>(1), 64 * 1024 * 1024);
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
