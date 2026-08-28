#![allow(clippy::match_wild_err_arm)]

mod support;

use std::{env, fs, os::unix::fs::PermissionsExt as _, sync::Arc, time::Duration};

use smesh_a2a::{
    AuthorityDiagnostics, AuthorityIdentity, AuthorityShutdown, AuthorizationAuditInput,
    AuthorizationAuditSink, AuthorizationDecisionEffect, AuthorizedTaskRead, DurableAuthority,
    OutboxAuthority, OwnedTaskScope, PostgresStoreConfig, PostgresTaskStore,
    PostgresTransactionTestFault, ReceiverAuthority, SqliteTaskStore, TaskAdmission,
    VisibilityScope,
};
use support::authority_row_parity::{AUTHORITY_TABLES, dump_postgres, dump_sqlite};
use support::durable_authority_conformance::{
    run_continuation_cancellation_conformance, run_durable_authority_command_conformance,
    run_durable_authority_command_conformance_open,
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
        "postgresql://smesh_test_runtime:smesh_test_runtime@127.0.0.1:55432/smesh_test".into()
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
        populate_pagination_and_active_cancellation(sqlite_authority).await;
        let postgres_authority: Arc<dyn DurableAuthority> = postgres;
        run_durable_authority_command_conformance_open(postgres_authority.clone()).await;
        populate_pagination_and_active_cancellation(postgres_authority).await;

        let sqlite_dump = dump_sqlite(&sqlite_path);
        let (client, driver) = admin_client(&superuser_url()).await;
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
        "postgresql://smesh_test_runtime:***@127.0.0.1:55432/smesh_test".into()
    });
    let runtime = Url::parse(&runtime_url).unwrap().username().to_owned();
    let config = config(url, "runtime_member");
    let (client, driver) = admin_client(&superuser_url()).await;
    client
        .batch_execute(&format!("GRANT {migrator} TO {runtime}"))
        .await
        .unwrap();
    assert!(matches!(
        PostgresTaskStore::open(config).await,
        Err(smesh_a2a::PostgresStoreError::InvalidSchema)
    ));
    client
        .batch_execute(&format!("REVOKE {migrator} FROM {runtime}"))
        .await
        .unwrap();
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
        "postgresql://smesh_test_runtime:smesh_test_runtime@127.0.0.1:55432/smesh_test".into()
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
        "postgresql://smesh_test_runtime:***@127.0.0.1:55432/smesh_test".into()
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
    populate_pagination_and_active_cancellation(authority).await;
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

postgres_test!(expired_final_attempt_is_atomically_dead_lettered, {
    let Some(url) = admin_url() else { return };
    let config = config(url.clone(), "final_expiry");
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
    client.execute(&format!("INSERT INTO {}.tasks(tenant_scope,task_id,context_id,state,revision,task_json,owner_account_id) VALUES($1,$2,$3,$4,1,$5,$6)",config.schema_name()), &[&"tenant-expiry",&task.id,&task.context_id,&state,&task_json,&"owner"]).await.unwrap();
    client.execute(&format!("INSERT INTO {}.task_events(tenant_scope,task_id,event_seq,task_revision,event_kind,from_state,to_state,event_json,created_at) VALUES($1,$2,1,1,'admitted',NULL,$3,$4,1)",config.schema_name()), &[&"tenant-expiry",&task.id,&state,&task_json]).await.unwrap();
    client.execute(&format!("INSERT INTO {}.outbox(tenant_scope,dispatch_id,task_id,message_id,causative_revision,payload_json,payload_digest,state,max_attempts,available_at,created_at,updated_at,dispatch_identity_version) VALUES($1,$2,$3,$4,1,$5,$6,'pending',1,100,100,100,2)",config.schema_name()), &[&"tenant-expiry",&"dispatch-expiry",&task.id,&"message-expiry",&payload,&digest]).await.unwrap();
    let lease = store
        .claim_outbox("expiry-owner", 100, 10)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lease.attempt_no, 1);
    assert!(
        store
            .claim_outbox("next-owner", 111, 10)
            .await
            .unwrap()
            .is_none()
    );
    let row=client.query_one(&format!("SELECT o.state,o.lease_token,a.finished_at,a.outcome FROM {0}.outbox o JOIN {0}.outbox_attempts a USING(tenant_scope,outbox_id) WHERE o.dispatch_id='dispatch-expiry'",config.schema_name()),&[]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "dead");
    assert!(row.get::<_, Option<String>>(1).is_none());
    assert_eq!(row.get::<_, Option<i64>>(2), Some(111));
    assert_eq!(
        row.get::<_, Option<String>>(3).as_deref(),
        Some("permanent")
    );
    store.shutdown().await.unwrap();
    drop(client);
    driver.abort();
    PostgresTaskStore::drop_test_schema(&config).await.unwrap();
});

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
