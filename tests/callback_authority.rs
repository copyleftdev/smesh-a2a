use std::sync::Arc;

use a2a::{Task, TaskState, TaskStatus};
use a2a_server::TaskStore;
use async_trait::async_trait;
use smesh_a2a::{
    AuditProjectionAuthority, AuthorityCapabilities, AuthorityIdentity, CallbackAuthority,
    CallbackCapabilities, CallbackConfigId, CallbackConfigState, CallbackDeliveryCategory,
    CallbackDeliveryDisposition, CallbackDeliveryState, CallbackFailCommand, CallbackLease,
    CallbackPolicySnapshot, CallbackReadiness, ConfigCreateCommand, ConfigDeleteCommand,
    ConfigGetCommand, ConfigListCommand, ConfigPageSize, DeliveryClaimCommand, DeliveryFence,
    LeaseDurationMillis, OwnedTaskScope, VisibilityScope,
};

fn postgres_urls() -> Option<(String, String)> {
    let admin = std::env::var("SMESH_TEST_POSTGRES_ADMIN_URL");
    let runtime = std::env::var("SMESH_TEST_POSTGRES_RUNTIME_URL");
    if std::env::var("SMESH_POSTGRES_TEST_REQUIRED").as_deref() == Ok("1") {
        return Some((
            admin.unwrap_or_else(|error| {
                panic!("SMESH_TEST_POSTGRES_ADMIN_URL is required: {error}")
            }),
            runtime.unwrap_or_else(|error| {
                panic!("SMESH_TEST_POSTGRES_RUNTIME_URL is required: {error}")
            }),
        ));
    }
    Some((admin.ok()?, runtime.ok()?))
}

#[tokio::test]
async fn postgres_v7_enabled_policy_is_persisted_before_runtime_pool_and_exposed() {
    let Some((admin, runtime)) = postgres_urls() else {
        return;
    };
    let schema = format!("smesh_callback_{:016x}", rand::random::<u64>());
    let config = smesh_a2a::PostgresStoreConfig::new(admin, runtime, schema)
        .unwrap()
        .with_test_only_insecure_loopback(true)
        .with_push_policy(enabled_policy());
    let store = smesh_a2a::PostgresTaskStore::open(config).await.unwrap();
    assert_eq!(store.callback_readiness(), CallbackReadiness::Ready);
    assert_eq!(
        store.callback_capabilities(),
        CallbackCapabilities::postgres_production()
    );
    assert_eq!(
        store.callback_policy_snapshot().unwrap().policy_digest(),
        enabled_policy().policy_digest()
    );
}

fn enabled_policy() -> smesh_a2a::push::PushPolicy {
    smesh_a2a::push::PushPolicy::parse_bytes(
        br#"
schema = "smesh-push/1"
enabled = true
policy_id = "push-policy"
policy_revision = 1
policy_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
max_pending = 100
max_configs_per_task = 4
max_configs_per_tenant = 20
worker_count = 1
claim_batch = 8
claim_lease_ms = 30000
dns_timeout_ms = 1000
max_dns_answers = 4
connect_timeout_ms = 1000
request_timeout_ms = 2000
max_response_bytes = 4096
max_attempts = 8
base_retry_ms = 100
max_retry_ms = 1000
max_delivery_age_ms = 10000
[[enrollments]]
tenant = "smesh-dev-only-tenant"
endpoint_id = "endpoint"
url = "https://example.com:443/events"
event = "terminal"
auth = "hmac-sha256"
key_generation = "key-1"
secret_file = "/tmp/callback-secret"
"#,
    )
    .unwrap()
}

fn versioned_policy(
    revision: u64,
    endpoint: &str,
    url: &str,
    digest_digit: char,
) -> smesh_a2a::push::PushPolicy {
    let digest = std::iter::repeat_n(digest_digit, 64).collect::<String>();
    smesh_a2a::push::PushPolicy::parse_bytes(
        format!(
            r#"
schema = "smesh-push/1"
enabled = true
policy_id = "push-policy"
policy_revision = {revision}
policy_digest = "sha256:{digest}"
max_pending = 100
max_configs_per_task = 4
max_configs_per_tenant = 20
worker_count = 1
claim_batch = 8
claim_lease_ms = 30000
dns_timeout_ms = 1000
max_dns_answers = 4
connect_timeout_ms = 1000
request_timeout_ms = 2000
max_response_bytes = 4096
max_attempts = 8
base_retry_ms = 100
max_retry_ms = 1000
max_delivery_age_ms = 10000
[[enrollments]]
tenant = "smesh-dev-only-tenant"
endpoint_id = "{endpoint}"
url = "{url}"
event = "terminal"
auth = "hmac-sha256"
key_generation = "key-{revision}"
secret_file = "/tmp/callback-secret"
"#
        )
        .as_bytes(),
    )
    .unwrap()
}

#[tokio::test]
async fn sqlite_higher_policy_removal_revokes_config_and_cancels_pending_atomically() {
    let root = std::env::temp_dir().join(format!(
        "smesh-callback-reconcile-{}",
        rand::random::<u64>()
    ));
    std::fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = root.join("store.db");
    let old = versioned_policy(1, "endpoint", "https://example.com:443/events", '1');
    let store = smesh_a2a::SqliteTaskStore::open_with_push_policy(&path, 10, &old)
        .await
        .unwrap();
    let mut task = Task {
        id: "reconcile-task".into(),
        context_id: "reconcile-context".into(),
        status: TaskStatus {
            state: TaskState::Working,
            message: None,
            timestamp: Some(chrono::Utc::now()),
        },
        artifacts: None,
        history: None,
        metadata: None,
    };
    store.create(task.clone()).await.unwrap();
    let scope = OwnedTaskScope::new(
        "smesh-dev-only-tenant",
        "smesh-dev-only-account",
        VisibilityScope::Tenant,
    )
    .unwrap();
    let url = "https://example.com:443/events";
    store
        .create_callback_config(
            ConfigCreateCommand::new(
                scope,
                "reconcile-task",
                Some(CallbackConfigId::new("reconcile-config").unwrap()),
                "endpoint",
                1,
                url,
                smesh_a2a::content_digest(url.as_bytes()),
                1,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    task.status.state = TaskState::Completed;
    store.update(task).await.unwrap();
    drop(store);

    let replacement = versioned_policy(
        2,
        "replacement",
        "https://replacement.example:443/events",
        '2',
    );
    let reopened = smesh_a2a::SqliteTaskStore::open_with_push_policy(&path, 10, &replacement)
        .await
        .unwrap();
    drop(reopened);
    let db = rusqlite::Connection::open(&path).unwrap();
    let state: String = db
        .query_row(
            "SELECT state FROM callback_configs WHERE config_id='reconcile-config'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let delivery: String = db
        .query_row(
            "SELECT state FROM callback_deliveries WHERE config_id='reconcile-config'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!((state.as_str(), delivery.as_str()), ("revoked", "canceled"));
    drop(db);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn sqlite_removed_enrollment_future_lease_blocks_without_mutation_until_exact_db_expiry() {
    let root = std::env::temp_dir().join(format!(
        "smesh-callback-lease-reconcile-{}",
        rand::random::<u64>()
    ));
    std::fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = root.join("store.db");
    let old = versioned_policy(1, "endpoint", "https://example.com:443/events", '1');
    let store = smesh_a2a::SqliteTaskStore::open_with_push_policy(&path, 10, &old)
        .await
        .unwrap();
    let mut task = Task {
        id: "lease-task".into(),
        context_id: "lease-context".into(),
        status: TaskStatus {
            state: TaskState::Working,
            message: None,
            timestamp: Some(chrono::Utc::now()),
        },
        artifacts: None,
        history: None,
        metadata: None,
    };
    store.create(task.clone()).await.unwrap();
    let scope = OwnedTaskScope::new(
        "smesh-dev-only-tenant",
        "smesh-dev-only-account",
        VisibilityScope::Tenant,
    )
    .unwrap();
    let url = "https://example.com:443/events";
    store
        .create_callback_config(
            ConfigCreateCommand::new(
                scope,
                "lease-task",
                Some(CallbackConfigId::new("lease-config").unwrap()),
                "endpoint",
                1,
                url,
                smesh_a2a::content_digest(url.as_bytes()),
                1,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    task.status.state = TaskState::Completed;
    store.update(task).await.unwrap();
    assert_eq!(
        store
            .claim_callback_deliveries(
                DeliveryClaimCommand::new(
                    "lease-worker",
                    LeaseDurationMillis::new(30_000).unwrap(),
                    1
                )
                .unwrap()
            )
            .await
            .unwrap()
            .len(),
        1
    );
    drop(store);
    let replacement = versioned_policy(
        2,
        "replacement",
        "https://replacement.example:443/events",
        '2',
    );
    assert!(
        smesh_a2a::SqliteTaskStore::open_with_push_policy(&path, 10, &replacement)
            .await
            .is_err()
    );
    let db = rusqlite::Connection::open(&path).unwrap();
    let before:(String,String,i64)=db.query_row("SELECT c.state,d.state,(SELECT count(*) FROM callback_policy_snapshots) FROM callback_configs c JOIN callback_deliveries d USING(tenant_scope,task_id,config_id) WHERE c.config_id='lease-config'",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
    assert_eq!(before, ("terminal_closed".into(), "leased".into(), 1));
    db.execute(
        "UPDATE callback_deliveries SET lease_until=CAST(unixepoch('subsec')*1000 AS INTEGER)",
        [],
    )
    .unwrap();
    drop(db);
    let reopened = smesh_a2a::SqliteTaskStore::open_with_push_policy(&path, 10, &replacement)
        .await
        .unwrap();
    drop(reopened);
    let db = rusqlite::Connection::open(&path).unwrap();
    let after:(String,String,i64)=db.query_row("SELECT c.state,d.state,(SELECT count(*) FROM callback_policy_snapshots) FROM callback_configs c JOIN callback_deliveries d USING(tenant_scope,task_id,config_id) WHERE c.config_id='lease-config'",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
    assert_eq!(after, ("revoked".into(), "canceled".into(), 2));
    drop(db);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
#[cfg(debug_assertions)]
async fn sqlite_terminal_callback_fault_matrix_rolls_back_and_retries_exactly_once() {
    use smesh_a2a::CallbackTerminalTestFault as F;
    for state in [
        TaskState::Completed,
        TaskState::Failed,
        TaskState::Canceled,
        TaskState::Rejected,
    ] {
        for fault in [
            F::BeforeEventInsert,
            F::BeforeDeliveryInsert,
            F::AfterDeliveryInsert,
            F::BeforeConfigTerminalClose,
            F::AfterCallbackRows,
        ] {
            let root = std::env::temp_dir()
                .join(format!("smesh-callback-fault-{}", rand::random::<u64>()));
            std::fs::create_dir(&root).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            let path = root.join("store.db");
            let policy = versioned_policy(1, "endpoint", "https://example.com:443/events", '1');
            let store = smesh_a2a::SqliteTaskStore::open_with_push_policy(&path, 10, &policy)
                .await
                .unwrap();
            let mut task = Task {
                id: format!("fault-{state:?}").to_ascii_lowercase(),
                context_id: "fault-context".into(),
                status: TaskStatus {
                    state: TaskState::Working,
                    message: None,
                    timestamp: Some(chrono::Utc::now()),
                },
                artifacts: None,
                history: None,
                metadata: None,
            };
            store.create(task.clone()).await.unwrap();
            let scope = OwnedTaskScope::new(
                "smesh-dev-only-tenant",
                "smesh-dev-only-account",
                VisibilityScope::Tenant,
            )
            .unwrap();
            let url = "https://example.com:443/events";
            store
                .create_callback_config(
                    ConfigCreateCommand::new(
                        scope,
                        &task.id,
                        Some(CallbackConfigId::new("fault-config").unwrap()),
                        "endpoint",
                        1,
                        url,
                        smesh_a2a::content_digest(url.as_bytes()),
                        1,
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            task.status.state = state.clone();
            store.set_callback_terminal_test_fault(fault).unwrap();
            assert!(
                store.update(task.clone()).await.is_err(),
                "{state:?} {fault:?}"
            );
            let db = rusqlite::Connection::open(&path).unwrap();
            let rolled:(String,i64,i64,String)=db.query_row("SELECT state,(SELECT count(*) FROM callback_events),(SELECT count(*) FROM callback_deliveries),(SELECT state FROM callback_configs WHERE config_id='fault-config') FROM tasks",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
            assert_eq!(
                rolled,
                (
                    serde_json::to_string(&TaskState::Working).unwrap(),
                    0,
                    0,
                    "active".into()
                ),
                "{state:?} {fault:?}"
            );
            drop(db);
            store.update(task).await.unwrap();
            let db = rusqlite::Connection::open(&path).unwrap();
            let committed:(i64,i64,String)=db.query_row("SELECT (SELECT count(*) FROM callback_events),(SELECT count(*) FROM callback_deliveries),(SELECT state FROM callback_configs WHERE config_id='fault-config')",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
            assert_eq!(committed, (1, 1, "terminal_closed".into()));
            drop(db);
            drop(store);
            std::fs::remove_dir_all(root).unwrap();
        }
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn postgres_terminal_callback_fault_matrix_rolls_back_and_retries_exactly_once() {
    use smesh_a2a::CallbackTerminalTestFault as F;
    let Some((admin, runtime)) = postgres_urls() else {
        return;
    };
    let schema = format!("smesh_callback_fault_{:016x}", rand::random::<u64>());
    let config = smesh_a2a::PostgresStoreConfig::new(&admin, &runtime, &schema)
        .unwrap()
        .with_test_only_insecure_loopback(true)
        .with_test_only_parent_managed_cleanup()
        .with_test_only_trust_injected_time(true)
        .with_push_policy(versioned_policy(
            1,
            "endpoint",
            "https://example.com:443/events",
            '1',
        ));
    let store = smesh_a2a::PostgresTaskStore::open(config.clone())
        .await
        .unwrap();
    let superuser =
        std::env::var("SMESH_TEST_POSTGRES_SUPERUSER_URL").unwrap_or_else(|_| admin.clone());
    let (mut db, connection) = tokio_postgres::connect(&superuser, tokio_postgres::NoTls)
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    db.batch_execute("SELECT set_config('smesh.internal_global','claim-v1',false); SELECT set_config('smesh.tenant_scope','smesh-dev-only-tenant',false); SELECT set_config('smesh.account_id','smesh-dev-only-account',false)").await.unwrap();
    for (index, fault) in [
        F::BeforeEventInsert,
        F::BeforeDeliveryInsert,
        F::AfterDeliveryInsert,
        F::BeforeConfigTerminalClose,
        F::AfterCallbackRows,
    ]
    .into_iter()
    .enumerate()
    {
        let mut task = Task {
            id: format!("pg-fault-{index}"),
            context_id: "pg-fault-context".into(),
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: Some(chrono::Utc::now()),
            },
            artifacts: None,
            history: None,
            metadata: None,
        };
        let working = serde_json::to_string(&TaskState::Working).unwrap();
        db.execute(&format!("INSERT INTO {schema}.tasks(tenant_scope,task_id,context_id,state,status_timestamp,revision,task_json,owner_account_id) VALUES('smesh-dev-only-tenant',$1,$2,$3,NULL,1,$4,'smesh-dev-only-account')"),&[&task.id,&task.context_id,&working,&serde_json::to_string(&task).unwrap()]).await.unwrap();
        let scope = OwnedTaskScope::new(
            "smesh-dev-only-tenant",
            "smesh-dev-only-account",
            VisibilityScope::Tenant,
        )
        .unwrap();
        let url = "https://example.com:443/events";
        store
            .create_callback_config(
                ConfigCreateCommand::new(
                    scope,
                    &task.id,
                    Some(CallbackConfigId::new(format!("pg-fault-config-{index}")).unwrap()),
                    "endpoint",
                    1,
                    url,
                    smesh_a2a::content_digest(url.as_bytes()),
                    1,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        task.status.state = TaskState::Completed;
        let payload = b"{}".to_vec();
        let digest = smesh_a2a::content_digest(&payload);
        let event = format!("pg-fault-event-{index}");
        let tx = db.transaction().await.unwrap();
        tx.batch_execute("SELECT set_config('smesh.internal_global','claim-v1',true); SELECT set_config('smesh.tenant_scope','smesh-dev-only-tenant',true)").await.unwrap();
        tx.execute(
            &format!("UPDATE {schema}.tasks SET state=$1,revision=2,task_json=$2 WHERE task_id=$3"),
            &[
                &serde_json::to_string(&TaskState::Completed).unwrap(),
                &serde_json::to_string(&task).unwrap(),
                &task.id,
            ],
        )
        .await
        .unwrap();
        tx.query_one(
            "SELECT set_config('smesh.test_callback_terminal_fault',$1,true)",
            &[&fault.as_str()],
        )
        .await
        .unwrap();
        assert!(tx.query_one(&format!("SELECT {schema}.enqueue_terminal_callbacks('smesh-dev-only-tenant',$1,2,$2,$3,$4,2,{schema}.db_millis())"),&[&task.id,&event,&payload,&digest]).await.is_err(),"{fault:?}");
        drop(tx);
        let rolled=db.query_one(&format!("SELECT state,(SELECT count(*) FROM {schema}.callback_events WHERE task_id=$1),(SELECT count(*) FROM {schema}.callback_deliveries WHERE task_id=$1),(SELECT COALESCE(max(state),'missing') FROM {schema}.callback_configs WHERE task_id=$1) FROM {schema}.tasks WHERE task_id=$1"),&[&task.id]).await.unwrap();
        assert_eq!(
            (
                rolled.get::<_, String>(0),
                rolled.get::<_, i64>(1),
                rolled.get::<_, i64>(2),
                rolled.get::<_, String>(3)
            ),
            (working, 0, 0, "active".into())
        );
        let tx = db.transaction().await.unwrap();
        tx.batch_execute("SELECT set_config('smesh.internal_global','claim-v1',true); SELECT set_config('smesh.tenant_scope','smesh-dev-only-tenant',true)").await.unwrap();
        tx.execute(
            &format!("UPDATE {schema}.tasks SET state=$1,revision=2,task_json=$2 WHERE task_id=$3"),
            &[
                &serde_json::to_string(&TaskState::Completed).unwrap(),
                &serde_json::to_string(&task).unwrap(),
                &task.id,
            ],
        )
        .await
        .unwrap();
        tx.query_one(&format!("SELECT {schema}.enqueue_terminal_callbacks('smesh-dev-only-tenant',$1,2,$2,$3,$4,2,{schema}.db_millis())"),&[&task.id,&event,&payload,&digest]).await.unwrap();
        tx.commit().await.unwrap();
    }
    drop(db);
    driver.abort();
    drop(store);
    smesh_a2a::PostgresTaskStore::drop_test_schema(&config)
        .await
        .unwrap();
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Two-task PostgreSQL fence fixture is intentionally auditable end to end.
async fn postgres_drain_finalization_is_scoped_by_task_for_reused_config_ids() {
    let Some((admin, runtime)) = postgres_urls() else {
        return;
    };
    let schema = format!("smesh_callback_drain_scope_{:016x}", rand::random::<u64>());
    let config = smesh_a2a::PostgresStoreConfig::new(&admin, &runtime, &schema)
        .unwrap()
        .with_test_only_insecure_loopback(true)
        .with_test_only_parent_managed_cleanup()
        .with_push_policy(enabled_policy());
    let store = smesh_a2a::PostgresTaskStore::open(config.clone())
        .await
        .unwrap();
    let (db, driver) = tokio_postgres::connect(&admin, tokio_postgres::NoTls)
        .await
        .unwrap();
    let driver = tokio::spawn(driver);
    db.batch_execute("SELECT set_config('smesh.internal_global','claim-v1',false); SELECT set_config('smesh.tenant_scope','smesh-dev-only-tenant',false)").await.unwrap();
    let scope = OwnedTaskScope::new(
        "smesh-dev-only-tenant",
        "smesh-dev-only-account",
        VisibilityScope::Tenant,
    )
    .unwrap();
    for task_id in ["pg-drain-a", "pg-drain-b"] {
        let mut task = Task {
            id: task_id.into(),
            context_id: format!("context-{task_id}"),
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: Some(chrono::Utc::now()),
            },
            artifacts: None,
            history: None,
            metadata: None,
        };
        db.execute(&format!("INSERT INTO {schema}.tasks(tenant_scope,task_id,context_id,state,status_timestamp,revision,task_json,owner_account_id) VALUES($1,$2,$3,$4,NULL,1,$5,$6)"), &[&"smesh-dev-only-tenant", &task.id, &task.context_id, &serde_json::to_string(&TaskState::Working).unwrap(), &serde_json::to_string(&task).unwrap(), &"smesh-dev-only-account"]).await.unwrap();
        store
            .create_callback_config(
                ConfigCreateCommand::new(
                    scope.clone(),
                    task_id,
                    Some(CallbackConfigId::new("shared-config").unwrap()),
                    "endpoint",
                    1,
                    "https://example.com:443/events",
                    smesh_a2a::content_digest(b"https://example.com:443/events"),
                    1,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        task.status.state = TaskState::Completed;
        db.execute(&format!("UPDATE {schema}.tasks SET state=$1,revision=2,task_json=$2 WHERE tenant_scope=$3 AND task_id=$4"), &[&serde_json::to_string(&TaskState::Completed).unwrap(), &serde_json::to_string(&task).unwrap(), &"smesh-dev-only-tenant", &task_id]).await.unwrap();
        let payload = b"{}".to_vec();
        db.query_one(&format!("SELECT {schema}.enqueue_terminal_callbacks($1,$2,2,$3,$4,$5,2,{schema}.db_millis())"), &[&"smesh-dev-only-tenant", &task_id, &format!("event-{task_id}"), &payload, &smesh_a2a::content_digest(&payload)]).await.unwrap();
    }
    let leases = store
        .claim_callback_deliveries(
            DeliveryClaimCommand::new(
                "pg-drain-worker",
                LeaseDurationMillis::new(30_000).unwrap(),
                2,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(leases.len(), 2);
    for task_id in ["pg-drain-a", "pg-drain-b"] {
        assert_eq!(
            store
                .delete_callback_config(
                    ConfigDeleteCommand::new(
                        scope.clone(),
                        task_id,
                        CallbackConfigId::new("shared-config").unwrap(),
                        2
                    )
                    .unwrap()
                )
                .await
                .unwrap(),
            smesh_a2a::CallbackDeleteOutcome::Draining
        );
    }
    store
        .commit_callback_delivery(leases[0].fence())
        .await
        .unwrap();
    let first = store
        .get_callback_config(
            ConfigGetCommand::new(
                scope.clone(),
                "pg-drain-a",
                CallbackConfigId::new("shared-config").unwrap(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let second = store
        .get_callback_config(
            ConfigGetCommand::new(
                scope.clone(),
                "pg-drain-b",
                CallbackConfigId::new("shared-config").unwrap(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        first.is_none(),
        "the completed task's draining config must be revoked"
    );
    assert_eq!(
        second.map(|config| config.state()),
        Some(CallbackConfigState::Draining),
        "the sibling task's same-named config must remain draining"
    );
    store
        .commit_callback_delivery(leases[1].fence())
        .await
        .unwrap();
    drop(db);
    driver.abort();
    let _ = driver.await;
    drop(store);
    smesh_a2a::PostgresTaskStore::drop_test_schema(&config)
        .await
        .unwrap();
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Startup tamper cases share one isolated PostgreSQL authority fixture.
async fn postgres_startup_rejects_callback_audit_substitution_and_nonrevoked_cap_tamper() {
    let Some((admin, runtime)) = postgres_urls() else {
        return;
    };
    let superuser =
        std::env::var("SMESH_TEST_POSTGRES_SUPERUSER_URL").unwrap_or_else(|_| admin.clone());
    let policy = enabled_policy();

    let audit_schema = format!("smesh_callback_audit_tamper_{:016x}", rand::random::<u64>());
    let audit_config = smesh_a2a::PostgresStoreConfig::new(&admin, &runtime, &audit_schema)
        .unwrap()
        .with_test_only_insecure_loopback(true)
        .with_test_only_parent_managed_cleanup()
        .with_push_policy(policy.clone());
    let audit_store = smesh_a2a::PostgresTaskStore::open(audit_config.clone())
        .await
        .unwrap();

    let task = Task {
        id: "audit-tamper-task".into(),
        context_id: "audit-tamper-context".into(),
        status: TaskStatus {
            state: TaskState::Working,
            message: None,
            timestamp: Some(chrono::Utc::now()),
        },
        artifacts: None,
        history: None,
        metadata: None,
    };
    let (seed_db, seed_driver) = tokio_postgres::connect(&superuser, tokio_postgres::NoTls)
        .await
        .unwrap();
    let seed_driver = tokio::spawn(seed_driver);
    seed_db.execute(&format!("INSERT INTO {audit_schema}.tasks(tenant_scope,task_id,context_id,state,status_timestamp,revision,task_json,owner_account_id) VALUES($1,$2,$3,$4,NULL,1,$5,$6)"), &[&"smesh-dev-only-tenant", &task.id, &task.context_id, &serde_json::to_string(&TaskState::Working).unwrap(), &serde_json::to_string(&task).unwrap(), &"smesh-dev-only-account"]).await.unwrap();
    drop(seed_db);
    seed_driver.abort();
    let _ = seed_driver.await;
    let scope = OwnedTaskScope::new(
        "smesh-dev-only-tenant",
        "smesh-dev-only-account",
        VisibilityScope::Tenant,
    )
    .unwrap();
    audit_store
        .create_callback_config(
            ConfigCreateCommand::new(
                scope,
                "audit-tamper-task",
                Some(CallbackConfigId::new("shared-config").unwrap()),
                "endpoint",
                1,
                "https://example.com:443/events",
                smesh_a2a::content_digest(b"https://example.com:443/events"),
                1,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    drop(audit_store);
    let (audit_db, audit_driver) = tokio_postgres::connect(&superuser, tokio_postgres::NoTls)
        .await
        .unwrap();
    let audit_driver = tokio::spawn(audit_driver);
    audit_db
        .batch_execute("SET session_replication_role=replica")
        .await
        .unwrap();
    audit_db.execute(&format!("UPDATE {audit_schema}.callback_audits SET source_pk_digest='sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' WHERE audit_order=(SELECT min(audit_order) FROM {audit_schema}.callback_audits)"), &[]).await.unwrap();
    drop(audit_db);
    audit_driver.abort();
    let _ = audit_driver.await;
    assert!(
        smesh_a2a::PostgresTaskStore::open(audit_config.clone())
            .await
            .is_err()
    );

    smesh_a2a::PostgresTaskStore::drop_test_schema(&audit_config)
        .await
        .unwrap();

    let cap_schema = format!("smesh_callback_cap_tamper_{:016x}", rand::random::<u64>());
    let cap_config = smesh_a2a::PostgresStoreConfig::new(&admin, &runtime, &cap_schema)
        .unwrap()
        .with_test_only_insecure_loopback(true)
        .with_test_only_parent_managed_cleanup()
        .with_push_policy(policy);
    drop(
        smesh_a2a::PostgresTaskStore::open(cap_config.clone())
            .await
            .unwrap(),
    );

    let (cap_db, cap_driver) = tokio_postgres::connect(&superuser, tokio_postgres::NoTls)
        .await
        .unwrap();
    let cap_driver = tokio::spawn(cap_driver);
    cap_db
        .batch_execute("SET session_replication_role=replica")
        .await
        .unwrap();
    for index in 0..21 {
        let task_id = format!("cap-task-{index}");
        let task = Task {
            id: task_id.clone(),
            context_id: format!("cap-context-{index}"),
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: Some(chrono::Utc::now()),
            },
            artifacts: None,
            history: None,
            metadata: None,
        };
        cap_db.execute(&format!("INSERT INTO {cap_schema}.tasks(tenant_scope,task_id,context_id,state,status_timestamp,revision,task_json,owner_account_id) VALUES($1,$2,$3,$4,NULL,1,$5,$6)"), &[&"smesh-dev-only-tenant", &task_id, &task.context_id, &serde_json::to_string(&TaskState::Working).unwrap(), &serde_json::to_string(&task).unwrap(), &"smesh-dev-only-account"]).await.unwrap();
        cap_db.execute(&format!("INSERT INTO {cap_schema}.callback_configs(tenant_scope,task_id,config_id,owner_account_id,principal_scope,enrollment_id,enrollment_generation,canonical_url,url_digest,state,created_at,updated_at) VALUES($1,$2,$3,$4,$4,'endpoint',1,'https://example.com:443/events',$5,'active',1,1)"), &[&"smesh-dev-only-tenant", &task_id, &format!("cap-config-{index}"), &"smesh-dev-only-account", &smesh_a2a::content_digest(b"https://example.com:443/events")]).await.unwrap();
    }
    drop(cap_db);
    cap_driver.abort();
    let _ = cap_driver.await;
    assert!(
        smesh_a2a::PostgresTaskStore::open(cap_config.clone())
            .await
            .is_err()
    );

    smesh_a2a::PostgresTaskStore::drop_test_schema(&cap_config)
        .await
        .unwrap();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn postgres_callback_crud_uses_scope_first_rls_paths() {
    let Some((admin, runtime)) = postgres_urls() else {
        return;
    };
    let schema = format!("smesh_callback_crud_{:016x}", rand::random::<u64>());
    let admin_insert = admin.clone();
    let schema_insert = schema.clone();
    let store = smesh_a2a::PostgresTaskStore::open(
        smesh_a2a::PostgresStoreConfig::new(admin, runtime, schema)
            .unwrap()
            .with_test_only_insecure_loopback(true)
            .with_audit_projection(true)
            .with_push_policy(enabled_policy()),
    )
    .await
    .unwrap();
    let mut task = Task {
        id: "pg-task".into(),
        context_id: "pg-context".into(),
        status: TaskStatus {
            state: TaskState::Working,
            message: None,
            timestamp: Some(chrono::Utc::now()),
        },
        artifacts: None,
        history: None,
        metadata: None,
    };
    let (client, connection) = tokio_postgres::connect(&admin_insert, tokio_postgres::NoTls)
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    client
        .batch_execute("SELECT set_config('smesh.internal_global','claim-v1',false)")
        .await
        .unwrap();
    client.execute(&format!("INSERT INTO {schema_insert}.tasks(tenant_scope,task_id,context_id,state,status_timestamp,revision,task_json,owner_account_id) VALUES('smesh-dev-only-tenant','pg-task','pg-context',$1,NULL,1,$2,'smesh-dev-only-account')"), &[&serde_json::to_string(&TaskState::Working).unwrap(),&serde_json::to_string(&task).unwrap()]).await.unwrap();
    drop(client);
    driver.abort();
    let scope = OwnedTaskScope::new(
        "smesh-dev-only-tenant",
        "smesh-dev-only-account",
        VisibilityScope::Tenant,
    )
    .unwrap();
    let url = "https://example.com:443/events";
    let created = store
        .create_callback_config(
            ConfigCreateCommand::new(
                scope.clone(),
                "pg-task",
                Some(CallbackConfigId::new("pg-config").unwrap()),
                "endpoint",
                1,
                url,
                smesh_a2a::content_digest(url.as_bytes()),
                1,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.config_id().as_str(), "pg-config");
    assert_eq!(
        store
            .list_callback_configs(
                ConfigListCommand::new(
                    scope.clone(),
                    "pg-task",
                    ConfigPageSize::new(10).unwrap(),
                    None
                )
                .unwrap()
            )
            .await
            .unwrap()
            .configs()
            .len(),
        1
    );
    task.status.state = TaskState::Completed;
    let (client, connection) = tokio_postgres::connect(&admin_insert, tokio_postgres::NoTls)
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    client.batch_execute("SELECT set_config('smesh.internal_global','claim-v1',false),set_config('smesh.tenant_scope','smesh-dev-only-tenant',false)").await.unwrap();
    client.execute(&format!("UPDATE {schema_insert}.tasks SET state=$1,revision=2,task_json=$2 WHERE tenant_scope='smesh-dev-only-tenant' AND task_id='pg-task'"),&[&serde_json::to_string(&TaskState::Completed).unwrap(),&serde_json::to_string(&task).unwrap()]).await.unwrap();
    let payload = b"{}".to_vec();
    let digest = smesh_a2a::content_digest(&payload);
    client.query_one(&format!("SELECT {schema_insert}.enqueue_terminal_callbacks($1,$2,2,$3,$4,$5,2,{schema_insert}.db_millis())"),&[&"smesh-dev-only-tenant",&"pg-task",&"callback-event-test",&payload,&digest]).await.unwrap();
    drop(client);
    driver.abort();
    let leases = store
        .claim_callback_deliveries(
            DeliveryClaimCommand::new("pg-worker", LeaseDurationMillis::new(30_000).unwrap(), 1)
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(leases.len(), 1);
    assert!(
        store
            .commit_callback_delivery(leases[0].fence())
            .await
            .unwrap()
    );
    let superuser = std::env::var("SMESH_TEST_POSTGRES_SUPERUSER_URL").unwrap_or(admin_insert);
    let (plan_db, plan_connection) = tokio_postgres::connect(&superuser, tokio_postgres::NoTls)
        .await
        .unwrap();
    let plan_driver = tokio::spawn(plan_connection);
    plan_db.batch_execute(&format!("INSERT INTO {schema_insert}.tasks(tenant_scope,task_id,context_id,state,status_timestamp,revision,task_json,owner_account_id) SELECT 'smesh-dev-only-tenant','plan-task-'||g,'plan-context','\\\"TASK_STATE_WORKING\\\"',NULL,1,'{{}}','smesh-dev-only-account' FROM generate_series(1,2000) g; INSERT INTO {schema_insert}.callback_configs(tenant_scope,task_id,config_id,owner_account_id,principal_scope,enrollment_id,enrollment_generation,canonical_url,url_digest,state,created_at,updated_at) SELECT 'smesh-dev-only-tenant','plan-task-'||g,'plan-config-'||g,'smesh-dev-only-account','smesh-dev-only-account','endpoint',1,'https://example.com:443/events','{}','active',g,g FROM generate_series(1,2000) g; INSERT INTO {schema_insert}.callback_events(tenant_scope,event_id,task_id,causative_revision,payload,payload_digest,public_egress_bytes,created_at,expires_at) SELECT 'smesh-dev-only-tenant','plan-event-'||g,'plan-task-'||g,1,'{{}}'::bytea,'{}',2,g,9999999999999 FROM generate_series(1,2000) g; INSERT INTO {schema_insert}.callback_deliveries(tenant_scope,event_id,task_id,config_id,state,available_at,created_at,updated_at) SELECT 'smesh-dev-only-tenant','plan-event-'||g,'plan-task-'||g,'plan-config-'||g,'pending',g,g,g FROM generate_series(1,2000) g; ANALYZE {schema_insert}.callback_configs; ANALYZE {schema_insert}.callback_deliveries;",smesh_a2a::content_digest(url.as_bytes()),smesh_a2a::content_digest(b"{}"))).await.unwrap();
    for (name, sql, expected) in [
        (
            "get",
            format!(
                "EXPLAIN (FORMAT TEXT) SELECT * FROM {schema_insert}.callback_configs WHERE tenant_scope='smesh-dev-only-tenant' AND task_id='plan-task-1000' AND config_id='plan-config-1000'"
            ),
            "callback_configs_task_state",
        ),
        (
            "list",
            format!(
                "EXPLAIN (FORMAT TEXT) SELECT * FROM {schema_insert}.callback_configs WHERE tenant_scope='smesh-dev-only-tenant' AND task_id='plan-task-1000' AND state<>'revoked' ORDER BY created_at,config_id LIMIT 100"
            ),
            "callback_configs_task_list",
        ),
        (
            "claim",
            format!(
                "EXPLAIN (FORMAT TEXT) SELECT tenant_scope,event_id,config_id FROM {schema_insert}.callback_deliveries WHERE tenant_scope='smesh-dev-only-tenant' AND state IN ('pending','retry') AND available_at<=9999999999999 ORDER BY available_at,event_id,config_id LIMIT 100"
            ),
            "callback_deliveries_claim",
        ),
    ] {
        let plan = plan_db
            .query(&sql, &[])
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.get::<_, String>(0))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(plan.contains(expected), "{name} missing {expected}: {plan}");
        assert!(
            !plan.contains("Seq Scan") && !plan.contains("Sort"),
            "{name} unbounded plan: {plan}"
        );
    }
    drop(plan_db);
    plan_driver.abort();
    assert_eq!(
        store
            .delete_callback_config(
                ConfigDeleteCommand::new(
                    scope,
                    "pg-task",
                    CallbackConfigId::new("pg-config").unwrap(),
                    2,
                )
                .unwrap()
            )
            .await
            .unwrap(),
        smesh_a2a::CallbackDeleteOutcome::Revoked
    );
    let projected = store
        .claim_audit_projection("pg-projector", 30_000, 16)
        .await
        .unwrap();
    let kinds = projected
        .iter()
        .map(smesh_a2a::AuditProjectionLease::event_kind)
        .collect::<Vec<_>>();
    for expected in [
        smesh_a2a::AuditProjectionEventKind::CallbackPolicyReconciled,
        smesh_a2a::AuditProjectionEventKind::CallbackConfigCreated,
        smesh_a2a::AuditProjectionEventKind::CallbackConfigDeleted,
        smesh_a2a::AuditProjectionEventKind::CallbackDeliveryAttempted,
        smesh_a2a::AuditProjectionEventKind::CallbackDelivered,
    ] {
        assert!(kinds.contains(&expected), "missing {expected:?}: {kinds:?}");
    }
}

#[tokio::test]
async fn sqlite_v8_open_persists_enabled_policy_and_reopens() {
    let root = std::env::temp_dir().join(format!("smesh-callback-{}", rand::random::<u64>()));
    std::fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = root.join("store.db");
    let policy = enabled_policy();
    let store = smesh_a2a::SqliteTaskStore::open_with_push_policy(&path, 10, &policy)
        .await
        .unwrap();
    assert_eq!(store.callback_readiness(), CallbackReadiness::Ready);
    assert_eq!(
        store.callback_policy_snapshot().unwrap().policy_digest(),
        policy.policy_digest()
    );
    drop(store);
    let reopened = smesh_a2a::SqliteTaskStore::open_with_push_policy(&path, 10, &policy)
        .await
        .unwrap();
    assert_eq!(reopened.callback_readiness(), CallbackReadiness::Ready);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn sqlite_callback_crud_and_terminal_enqueue_are_durable() {
    let root = std::env::temp_dir().join(format!("smesh-callback-crud-{}", rand::random::<u64>()));
    std::fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let store = smesh_a2a::SqliteTaskStore::open_with_push_policy_and_audit_projection(
        root.join("store.db"),
        10,
        &enabled_policy(),
    )
    .await
    .unwrap();
    let task = Task {
        id: "task".into(),
        context_id: "context".into(),
        status: TaskStatus {
            state: TaskState::Working,
            message: None,
            timestamp: Some(chrono::Utc::now()),
        },
        artifacts: None,
        history: None,
        metadata: None,
    };
    store.create(task.clone()).await.unwrap();
    let scope = OwnedTaskScope::new(
        "smesh-dev-only-tenant",
        "smesh-dev-only-account",
        VisibilityScope::Tenant,
    )
    .unwrap();
    let url = "https://example.com:443/events";
    let digest = smesh_a2a::content_digest(url.as_bytes());
    let created = store
        .create_callback_config(
            ConfigCreateCommand::new(
                scope.clone(),
                "task",
                Some(CallbackConfigId::new("config").unwrap()),
                "endpoint",
                1,
                url,
                &digest,
                1,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.config_id().as_str(), "config");
    let other_task = Task {
        id: "task-two".into(),
        context_id: "context-two".into(),
        status: TaskStatus {
            state: TaskState::Working,
            message: None,
            timestamp: Some(chrono::Utc::now()),
        },
        artifacts: None,
        history: None,
        metadata: None,
    };
    store.create(other_task).await.unwrap();
    store
        .create_callback_config(
            ConfigCreateCommand::new(
                scope.clone(),
                "task-two",
                Some(CallbackConfigId::new("config").unwrap()),
                "endpoint",
                1,
                url,
                &digest,
                2,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .list_callback_configs(
                ConfigListCommand::new(
                    scope.clone(),
                    "task",
                    ConfigPageSize::new(1).unwrap(),
                    None
                )
                .unwrap()
            )
            .await
            .unwrap()
            .configs()
            .len(),
        1
    );
    let mut terminal = task;
    terminal.status.state = TaskState::Completed;
    store.update(terminal).await.unwrap();
    let leases = store
        .claim_callback_deliveries(
            DeliveryClaimCommand::new("worker", LeaseDurationMillis::new(30_000).unwrap(), 1)
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(leases.len(), 1);
    assert!(leases[0].payload().len() < 256 * 1024);
    assert!(
        store
            .commit_callback_delivery(leases[0].fence())
            .await
            .unwrap()
    );
    let projected = store
        .claim_audit_projection("projector", 30_000, 16)
        .await
        .unwrap();
    let kinds = projected
        .iter()
        .map(smesh_a2a::AuditProjectionLease::event_kind)
        .collect::<Vec<_>>();
    for expected in [
        smesh_a2a::AuditProjectionEventKind::CallbackPolicyReconciled,
        smesh_a2a::AuditProjectionEventKind::CallbackConfigCreated,
        smesh_a2a::AuditProjectionEventKind::CallbackEventEnqueued,
        smesh_a2a::AuditProjectionEventKind::CallbackDeliveryAttempted,
        smesh_a2a::AuditProjectionEventKind::CallbackDelivered,
    ] {
        assert!(kinds.contains(&expected), "missing {expected:?}: {kinds:?}");
    }
    let config_create_ids = projected
        .iter()
        .filter(|row| {
            row.event_kind() == smesh_a2a::AuditProjectionEventKind::CallbackConfigCreated
        })
        .map(smesh_a2a::AuditProjectionLease::event_id)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        config_create_ids.len(),
        2,
        "same config id on distinct tasks must not collide"
    );
    assert!(projected.iter().all(|row| {
        row.event_id().starts_with("sha256:")
            && !row.event_id().contains("example.com")
            && !row.source_pk_digest().contains("example.com")
    }));
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // SQLite and PostgreSQL drain regressions intentionally mirror each other.
async fn sqlite_drain_finalization_is_scoped_by_task_for_reused_config_ids() {
    let root = std::env::temp_dir().join(format!(
        "smesh-callback-drain-scope-{}",
        rand::random::<u64>()
    ));
    std::fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = root.join("store.db");
    let policy = enabled_policy();
    let store = smesh_a2a::SqliteTaskStore::open_with_push_policy(&path, 10, &policy)
        .await
        .unwrap();
    let scope = OwnedTaskScope::new(
        "smesh-dev-only-tenant",
        "smesh-dev-only-account",
        VisibilityScope::Tenant,
    )
    .unwrap();
    let url = "https://example.com:443/events";
    for task_id in ["drain-a", "drain-b"] {
        let mut task = Task {
            id: task_id.into(),
            context_id: format!("context-{task_id}"),
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: Some(chrono::Utc::now()),
            },
            artifacts: None,
            history: None,
            metadata: None,
        };
        store.create(task.clone()).await.unwrap();
        store
            .create_callback_config(
                ConfigCreateCommand::new(
                    scope.clone(),
                    task_id,
                    Some(CallbackConfigId::new("shared-config").unwrap()),
                    "endpoint",
                    1,
                    url,
                    smesh_a2a::content_digest(url.as_bytes()),
                    1,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        task.status.state = TaskState::Completed;
        store.update(task).await.unwrap();
    }
    let leases = store
        .claim_callback_deliveries(
            DeliveryClaimCommand::new("worker", LeaseDurationMillis::new(30_000).unwrap(), 2)
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(leases.len(), 2);
    for task_id in ["drain-a", "drain-b"] {
        assert_eq!(
            store
                .delete_callback_config(
                    ConfigDeleteCommand::new(
                        scope.clone(),
                        task_id,
                        CallbackConfigId::new("shared-config").unwrap(),
                        2
                    )
                    .unwrap()
                )
                .await
                .unwrap(),
            smesh_a2a::CallbackDeleteOutcome::Draining
        );
    }
    let first = &leases[0];
    let second = &leases[1];
    assert!(store.commit_callback_delivery(first.fence()).await.unwrap());
    let first_config = store
        .get_callback_config(
            smesh_a2a::ConfigGetCommand::new(
                scope.clone(),
                first.task_id(),
                CallbackConfigId::new("shared-config").unwrap(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let second_config = store
        .get_callback_config(
            smesh_a2a::ConfigGetCommand::new(
                scope.clone(),
                second.task_id(),
                CallbackConfigId::new("shared-config").unwrap(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        first_config.is_none(),
        "finished task must finalize independently"
    );
    assert_eq!(
        second_config.unwrap().state(),
        CallbackConfigState::Draining
    );
    assert!(
        store
            .commit_callback_delivery(second.fence())
            .await
            .unwrap()
    );
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn sqlite_startup_rejects_missing_callback_audit_obligations_and_policy_caps() {
    async fn seed(path: &std::path::Path, policy: &smesh_a2a::push::PushPolicy) {
        let store = smesh_a2a::SqliteTaskStore::open_with_push_policy(path, 10, policy)
            .await
            .unwrap();
        let scope = OwnedTaskScope::new(
            "smesh-dev-only-tenant",
            "smesh-dev-only-account",
            VisibilityScope::Tenant,
        )
        .unwrap();
        for task_id in ["audit-a", "audit-b"] {
            store
                .create(Task {
                    id: task_id.into(),
                    context_id: format!("context-{task_id}"),
                    status: TaskStatus {
                        state: TaskState::Working,
                        message: None,
                        timestamp: Some(chrono::Utc::now()),
                    },
                    artifacts: None,
                    history: None,
                    metadata: None,
                })
                .await
                .unwrap();
            store
                .create_callback_config(
                    ConfigCreateCommand::new(
                        scope.clone(),
                        task_id,
                        Some(CallbackConfigId::new("shared-config").unwrap()),
                        "endpoint",
                        1,
                        "https://example.com:443/events",
                        smesh_a2a::content_digest(b"https://example.com:443/events"),
                        1,
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
        }
        drop(store);
    }
    let policy = enabled_policy();
    let root = std::env::temp_dir().join(format!(
        "smesh-callback-audit-tamper-{}",
        rand::random::<u64>()
    ));
    std::fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    for kind in ["callback_policy_reconciled", "callback_config_created"] {
        let audit_path = root.join(format!("missing-{kind}.db"));
        seed(&audit_path, &policy).await;
        let db = rusqlite::Connection::open(&audit_path).unwrap();
        db.execute_batch("DROP TRIGGER callback_audits_no_delete;")
            .unwrap();
        assert_eq!(
            db.execute(
                "DELETE FROM callback_audits WHERE audit_order=(SELECT min(audit_order) FROM callback_audits WHERE event_kind=?1)",
                [kind],
            )
            .unwrap(),
            1
        );
        drop(db);
        assert!(
            smesh_a2a::SqliteTaskStore::open_with_push_policy(&audit_path, 10, &policy)
                .await
                .is_err(),
            "missing {kind} obligation must fail closed"
        );
    }

    let cap_path = root.join("cap.db");
    seed(&cap_path, &policy).await;
    let db = rusqlite::Connection::open(&cap_path).unwrap();
    db.execute_batch("DROP TRIGGER callback_policy_no_update; UPDATE callback_policy_snapshots SET max_configs_per_tenant=1;").unwrap();
    drop(db);
    assert!(
        smesh_a2a::SqliteTaskStore::open_with_push_policy(&cap_path, 10, &policy)
            .await
            .is_err()
    );
    std::fs::remove_dir_all(root).unwrap();
}

struct LegacyAuthority;
impl AuthorityIdentity for LegacyAuthority {
    fn capabilities(&self) -> AuthorityCapabilities {
        AuthorityCapabilities {
            lease_renewal: false,
            quota_reservations: false,
        }
    }
    fn completion_receipt_key(&self) -> Option<[u8; 32]> {
        None
    }
    fn authorization_resource_digest(&self, _: &str) -> Result<String, a2a::A2AError> {
        Ok("sha256:0000000000000000000000000000000000000000000000000000000000000000".into())
    }
}

#[test]
fn legacy_authorities_remain_callback_disabled() {
    let authority: Arc<dyn AuthorityIdentity> = Arc::new(LegacyAuthority);
    assert!(authority.callback_authority().is_none());
}

#[test]
fn callback_commands_are_closed_bounded_and_publicly_inspectable() {
    assert!(CallbackConfigId::new("").is_err());
    assert!(CallbackConfigId::new("x".repeat(129)).is_err());
    let id = CallbackConfigId::new("opaque-config").unwrap();
    assert_eq!(id.as_str(), "opaque-config");

    assert!(ConfigPageSize::new(0).is_err());
    assert!(ConfigPageSize::new(101).is_err());
    assert_eq!(ConfigPageSize::new(100).unwrap().get(), 100);
    assert!(LeaseDurationMillis::new(999).is_err());
    assert!(LeaseDurationMillis::new(300_001).is_err());

    let scope = OwnedTaskScope::new("tenant", "actor", VisibilityScope::Tenant).unwrap();
    let create = ConfigCreateCommand::new(
        scope.clone(),
        "task",
        Some(id.clone()),
        "enrollment",
        7,
        "https://example.com:443/events",
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        123,
    )
    .unwrap();
    assert_eq!(create.scope(), &scope);
    assert_eq!(create.scope().principal_scope(), "actor");
    let exact_scope = OwnedTaskScope::new_with_principal(
        "tenant",
        "actor",
        "oidc:issuer:subject",
        VisibilityScope::Tenant,
    )
    .unwrap();
    assert_eq!(exact_scope.principal_scope(), "oidc:issuer:subject");
    assert_eq!(create.task_id(), "task");
    assert_eq!(create.config_id(), Some(&id));
    assert_eq!(create.enrollment_generation(), 7);
    assert_eq!(create.canonical_url(), "https://example.com:443/events");

    let list = ConfigListCommand::new(
        scope.clone(),
        "task",
        ConfigPageSize::new(50).unwrap(),
        None,
    )
    .unwrap();
    assert_eq!(list.page_size().get(), 50);
    let delete = ConfigDeleteCommand::new(scope, "task", id.clone(), 456).unwrap();
    assert_eq!(delete.config_id(), &id);

    assert_eq!(CallbackConfigState::Active.as_str(), "active");
    assert_eq!(CallbackConfigState::Draining.as_str(), "draining");
    assert_eq!(CallbackDeliveryState::Dead.as_str(), "dead");
}

#[test]
fn policy_snapshot_rejects_revision_digest_ambiguity() {
    let snapshot = CallbackPolicySnapshot::new(
        "policy",
        3,
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        32,
        1000,
        256 * 1024,
        16,
    )
    .unwrap();
    assert_eq!(snapshot.policy_revision(), 3);
    assert_eq!(snapshot.max_payload_bytes(), 256 * 1024);
    assert!(
        CallbackPolicySnapshot::new("policy", 0, snapshot.policy_digest(), 1, 1, 1, 1).is_err()
    );
}

#[test]
fn parsed_push_policy_exposes_persistable_non_secret_snapshot() {
    let policy = smesh_a2a::push::PushPolicy::parse_bytes(
        br#"
schema = "smesh-push/1"
enabled = true
policy_id = "push-policy"
policy_revision = 9
policy_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
max_pending = 100
max_configs_per_task = 4
max_configs_per_tenant = 20
worker_count = 2
claim_batch = 8
claim_lease_ms = 30000
dns_timeout_ms = 1000
max_dns_answers = 4
connect_timeout_ms = 1000
request_timeout_ms = 2000
max_response_bytes = 4096
max_attempts = 8
base_retry_ms = 100
max_retry_ms = 1000
max_delivery_age_ms = 10000
[[enrollments]]
tenant = "tenant"
endpoint_id = "endpoint"
url = "https://example.com:443/events"
event = "terminal"
auth = "hmac-sha256"
key_generation = "key-1"
secret_file = "/tmp/callback-secret"
"#,
    )
    .unwrap();
    assert_eq!(policy.policy_id(), "push-policy");
    assert_eq!(policy.policy_revision(), 9);
    assert_eq!(policy.max_pending(), 100);
    assert_eq!(policy.max_configs_per_task(), 4);
    assert_eq!(policy.claim_batch(), 8);
    assert_eq!(policy.enrollments().len(), 1);
    assert_eq!(policy.enrollments()[0].tenant(), "tenant");
    assert_eq!(policy.enrollments()[0].endpoint_id(), "endpoint");
}

#[test]
fn delivery_commands_expose_fence_and_digest_only_failure() {
    let claim =
        DeliveryClaimCommand::new("worker", LeaseDurationMillis::new(30_000).unwrap(), 32).unwrap();
    assert!(
        DeliveryClaimCommand::new("worker", LeaseDurationMillis::new(30_000).unwrap(), 1).is_ok()
    );
    assert!(
        DeliveryClaimCommand::new("worker", LeaseDurationMillis::new(30_000).unwrap(), 1_000)
            .is_ok()
    );
    assert!(
        DeliveryClaimCommand::new("worker", LeaseDurationMillis::new(30_000).unwrap(), 1_001)
            .is_err()
    );
    assert_eq!(claim.owner(), "worker");
    assert_eq!(claim.batch_limit(), 32);
    let fence = DeliveryFence::new("tenant", "event", "config", "worker", "token", 2).unwrap();
    let lease = CallbackLease::new(
        fence.clone(),
        "task",
        "config",
        "https://example.com:443/events",
        "enrollment",
        1,
        b"{}".to_vec(),
        "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
        1,
        9999,
    )
    .unwrap();
    let scoped_lease = CallbackLease::new_scoped(
        fence.clone(),
        "task",
        "config",
        "https://example.com:443/events",
        "enrollment",
        1,
        b"{}".to_vec(),
        "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
        1,
        9000,
        9999,
        "account-a",
        "principal-a",
    )
    .unwrap();
    assert_eq!(scoped_lease.owner_account_id(), "account-a");
    assert_eq!(scoped_lease.principal_scope(), "principal-a");
    assert_eq!(scoped_lease.created_at(), 9000);
    assert_eq!(scoped_lease.expires_at(), 9999);
    assert_eq!(lease.payload(), b"{}");
    assert_eq!(lease.fence(), &fence);
    let fail = CallbackFailCommand::new(
        fence,
        CallbackDeliveryDisposition::Retry,
        CallbackDeliveryCategory::Transport,
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        Some(12_345),
    )
    .unwrap();
    assert_eq!(fail.retry_at(), Some(12_345));
    assert!(
        CallbackFailCommand::new(
            DeliveryFence::new("tenant", "event", "config", "worker", "token", 2).unwrap(),
            CallbackDeliveryDisposition::Dead,
            CallbackDeliveryCategory::Policy,
            "raw secret error",
            None,
        )
        .is_err()
    );
}

struct Fake;
#[async_trait]
impl CallbackAuthority for Fake {
    fn callback_capabilities(&self) -> CallbackCapabilities {
        CallbackCapabilities::sqlite_conformance()
    }
    fn callback_readiness(&self) -> CallbackReadiness {
        CallbackReadiness::Ready
    }
    fn callback_policy_snapshot(&self) -> Option<Arc<CallbackPolicySnapshot>> {
        None
    }
    async fn callback_database_time(&self) -> Result<i64, a2a::A2AError> {
        Ok(1)
    }
    async fn resolve_callback_enrollment(
        &self,
        _: &OwnedTaskScope,
        _: &str,
    ) -> Result<Option<smesh_a2a::CallbackEnrollmentBinding>, a2a::A2AError> {
        unimplemented!()
    }
    async fn create_callback_config(
        &self,
        _: ConfigCreateCommand,
    ) -> Result<smesh_a2a::CallbackConfig, a2a::A2AError> {
        unimplemented!()
    }
    async fn get_callback_config(
        &self,
        _: smesh_a2a::ConfigGetCommand,
    ) -> Result<Option<smesh_a2a::CallbackConfig>, a2a::A2AError> {
        unimplemented!()
    }
    async fn list_callback_configs(
        &self,
        _: ConfigListCommand,
    ) -> Result<smesh_a2a::CallbackConfigPage, a2a::A2AError> {
        unimplemented!()
    }
    async fn delete_callback_config(
        &self,
        _: ConfigDeleteCommand,
    ) -> Result<smesh_a2a::CallbackDeleteOutcome, a2a::A2AError> {
        unimplemented!()
    }
    async fn claim_callback_deliveries(
        &self,
        _: DeliveryClaimCommand,
    ) -> Result<Vec<CallbackLease>, a2a::A2AError> {
        unimplemented!()
    }
    async fn renew_callback_delivery(
        &self,
        _: &DeliveryFence,
        duration: LeaseDurationMillis,
    ) -> Result<Option<i64>, a2a::A2AError> {
        Ok(Some(duration.get()))
    }
    async fn commit_callback_delivery(&self, _: &DeliveryFence) -> Result<bool, a2a::A2AError> {
        unimplemented!()
    }
    async fn fail_callback_delivery(
        &self,
        _: CallbackFailCommand,
    ) -> Result<CallbackDeliveryState, a2a::A2AError> {
        unimplemented!()
    }
    async fn revoke_callback_delivery(
        &self,
        _: &DeliveryFence,
    ) -> Result<CallbackDeliveryState, a2a::A2AError> {
        unimplemented!()
    }
}

#[test]
fn fake_must_implement_complete_object_safe_surface() {
    let fake: &dyn CallbackAuthority = &Fake;
    assert_eq!(
        fake.callback_capabilities(),
        CallbackCapabilities::sqlite_conformance()
    );
}

#[tokio::test]
async fn callback_delivery_fence_validation_is_source_compatible_and_authoritative() {
    let fake = Fake;
    let fence = DeliveryFence::new("tenant", "event", "config", "worker", "token", 2).unwrap();
    assert!(
        fake.validate_callback_delivery_fence(&fence, LeaseDurationMillis::new(30_000).unwrap())
            .await
            .unwrap()
    );
}
