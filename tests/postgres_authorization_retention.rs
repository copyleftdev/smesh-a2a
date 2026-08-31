mod support;

use std::{env, str::FromStr as _, time::Duration};

use smesh_a2a::{
    AuditProjectionAuthority, AuthorityShutdown, PostgresStoreConfig, PostgresTaskStore,
};
use tokio_postgres::NoTls;

fn postgres_urls() -> Option<(String, String)> {
    let required = env::var("SMESH_POSTGRES_TEST_REQUIRED").as_deref() == Ok("1")
        || env::var("SMESH_TEST_POSTGRES_REQUIRED").as_deref() == Ok("1");
    let admin = match env::var("SMESH_TEST_POSTGRES_ADMIN_URL") {
        Ok(value) => value,
        Err(error) if required => panic!("SMESH_TEST_POSTGRES_ADMIN_URL is required: {error}"),
        Err(_) => return None,
    };
    let runtime = match env::var("SMESH_TEST_POSTGRES_RUNTIME_URL") {
        Ok(value) => value,
        Err(error) if required => panic!("SMESH_TEST_POSTGRES_RUNTIME_URL is required: {error}"),
        Err(_) => return None,
    };
    Some((admin, runtime))
}

fn config(admin: &str, runtime: &str, suffix: &str) -> PostgresStoreConfig {
    PostgresStoreConfig::new(
        admin,
        runtime,
        format!(
            "smesh_auth_retention_{suffix}_{:016x}",
            rand::random::<u64>()
        ),
    )
    .unwrap()
    .with_test_only_insecure_loopback(true)
    .with_test_only_parent_managed_cleanup()
    .with_pool_size(4)
    .unwrap()
    .with_timeouts(Duration::from_secs(5), Duration::from_secs(5))
    .unwrap()
}

#[test]
fn revision_nine_is_narrow_fixed_path_and_explicitly_privileged() {
    let sql = include_str!("../migrations/postgres/0009_authorization_audit_retention.sql");
    assert!(sql.contains("SECURITY DEFINER SET search_path=pg_catalog"));
    assert!(sql.contains("retention_ms IS NULL"));
    assert!(sql.contains("max_rows IS NULL"));
    assert!(sql.contains("max_rows>1000"));
    assert!(sql.contains("projection_required boolean NOT NULL"));
    assert!(sql.contains("CREATE POLICY authorization_projection_migration"));
    assert!(sql.contains("DROP POLICY authorization_projection_migration"));
    assert!(!sql.to_ascii_lowercase().contains("min(decided_at)"));
    assert!(sql.contains("LIMIT max_rows"));
    assert!(sql.contains("authorization_retention_diagnostics"));
    assert!(sql.contains("REVOKE ALL ON FUNCTION"));
    assert!(sql.contains("GRANT EXECUTE ON FUNCTION __SCHEMA__.cleanup_authorization_decisions(text,bigint,integer) TO __MIGRATOR__"));
    assert!(!sql.contains("cleanup_authorization_decisions(text,bigint,integer) TO __ROLE__"));
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One real lifecycle matrix owns setup, retention, and restart.
async fn bounded_cleanup_is_tenant_projection_and_live_window_safe_across_restart() {
    let Some((admin, runtime)) = postgres_urls() else {
        return;
    };
    tokio::time::timeout(Duration::from_secs(45), async move {
        let config = config(&admin, &runtime, "matrix").with_audit_projection(true);
        let schema = config.schema_name().to_owned();
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        let (client, connection) = tokio_postgres::connect(&admin, NoTls).await.unwrap();
        let driver = tokio::spawn(connection);
        let mut seed_config = tokio_postgres::Config::from_str(&runtime).unwrap();
        seed_config.options(format!("-c role={schema}_runtime"));
        let (seed_client, seed_connection) = seed_config.connect(NoTls).await.unwrap();
        let seed_driver = tokio::spawn(seed_connection);
        let projection_proof: String = client.query_one(
            &format!("SELECT proof FROM {schema}.audit_projection_session_secret WHERE singleton=1"),
            &[],
        ).await.unwrap().get(0);
        seed_client.query_one(
            &format!("SELECT {schema}.register_audit_projection_session($1)"),
            &[&projection_proof],
        ).await.unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        let old = now - 100_000;
        let live = now - 1_000;

        for tenant_no in 0..8 {
            let tenant = format!("tenant-{tenant_no}");
            client.execute("SELECT set_config('smesh.internal_global','audit-projector-v1',false),set_config('smesh.tenant_scope',$1,false)", &[&tenant]).await.unwrap();
            seed_client.execute("SELECT set_config('smesh.tenant_scope',$1,false)", &[&tenant]).await.unwrap();
            for (kind, decided_at) in [
                ("pending", old - 1),
                ("terminal", old),
                ("absent", old),
                ("dead", old),
                ("live", live),
            ] {
                let projection_required = matches!(kind, "terminal" | "dead" | "pending");
                client.execute(
                    &format!("UPDATE {schema}.audit_projection_control SET enabled=$1 WHERE singleton=1"),
                    &[&projection_required],
                ).await.unwrap();
                let decision = format!("decision-{tenant_no}-{kind}");
                seed_client.execute(
                    &format!("INSERT INTO {schema}.authorization_decisions(decision_id,tenant_scope,actor_account_id,policy_id,policy_revision,policy_digest,operation,effect,reason,resource_kind,resource_digest,task_id,decided_at) VALUES($1,$2,'actor','policy',1,'sha256:policy','TaskGet','allow','fixture','task','sha256:resource',NULL,$3)"),
                    &[&decision, &tenant, &decided_at],
                ).await.unwrap();
                if projection_required && matches!(kind, "terminal" | "dead") {
                        let state = if kind == "terminal" { "delivered" } else { "dead" };
                        let delivered_at = (kind == "terminal").then_some(old);
                        let dead_at = (kind == "dead").then_some(old);
                        let changed = client.execute(
                            &format!("UPDATE {schema}.audit_projection_outbox SET state=$1,delivered_at=$2,dead_at=$3 WHERE tenant_scope=$4 AND source='authorization_decisions' AND source_pk_digest=(SELECT projection_source_pk_digest FROM {schema}.authorization_decisions WHERE tenant_scope=$4 AND decision_id=$5)"),
                            &[&state, &delivered_at, &dead_at, &tenant, &decision],
                        ).await.unwrap();
                        assert_eq!(changed, 1);
                }
            }
        }
        client.execute(&format!("UPDATE {schema}.audit_projection_control SET enabled=true WHERE singleton=1"), &[]).await.unwrap();
        let generic_event = smesh_a2a::content_digest(b"retention-generic-terminal");
        let generic_source = smesh_a2a::content_digest(b"retention-generic-source");
        client.execute(
            &format!("INSERT INTO {schema}.audit_projection_outbox(tenant_scope,event_id,source,source_pk_digest,event_kind,occurred_at,state,available_at,delivered_at) VALUES('tenant-7',$1,'task_events',$2,'task_terminal',$3,'delivered',$3,$3)"),
            &[&generic_event, &generic_source, &old],
        ).await.unwrap();
        assert_eq!(store.cleanup_audit_projection(0, 1).await.unwrap(), 1,
            "a protected authorization prefix must not starve later generic projection cleanup");
        assert_eq!(store.cleanup_audit_projection(0, 1_000).await.unwrap(), 0,
            "generic projection retention must preserve terminal authorization evidence");

        for tenant_no in 0..8 {
            let tenant = format!("tenant-{tenant_no}");
            client.execute("SELECT set_config('smesh.tenant_scope',$1,false),set_config('smesh.internal_global','diag-v1',false),set_config('smesh.authorization_retention','cleanup-v1',false)", &[&tenant]).await.unwrap();
            let obligation_row = client.query_one(
                &format!("SELECT sum(projection_required::int)::bigint,sum(projection_terminal::int)::bigint,sum((p.event_id IS NOT NULL)::int)::bigint FROM {schema}.authorization_decisions d LEFT JOIN {schema}.audit_projection_outbox p ON p.tenant_scope=d.tenant_scope AND p.source='authorization_decisions' AND p.source_pk_digest=d.projection_source_pk_digest WHERE d.tenant_scope=$1"),
                &[&tenant],
            ).await.unwrap();
            assert_eq!((obligation_row.get::<_, i64>(0), obligation_row.get::<_, i64>(1), obligation_row.get::<_, i64>(2)), (3, 2, 3));
            let before_other_tenants: i64 = client.query_one(
                &format!("SELECT count(*) FROM {schema}.authorization_decisions WHERE tenant_scope<>$1"),
                &[&tenant],
            ).await.unwrap().get(0);
            let first = PostgresTaskStore::cleanup_authorization_decisions(&config, &tenant, 50_000, 1).await.unwrap();
            assert_eq!(first.deleted, 1, "each call must honor its bound");
            assert_eq!(first.projection_blocked, 1, "an older blocked prefix must not starve eligible rows");
            assert!(first.has_more);
            let second = PostgresTaskStore::cleanup_authorization_decisions(&config, &tenant, 50_000, 1).await.unwrap();
            assert_eq!(second.deleted, 1);
            let third = PostgresTaskStore::cleanup_authorization_decisions(&config, &tenant, 50_000, 1).await.unwrap();
            assert_eq!(third.deleted, 1);
            let done = PostgresTaskStore::cleanup_authorization_decisions(&config, &tenant, 50_000, 1).await.unwrap();
            assert_eq!(done.deleted, 0);
            assert_eq!(done.projection_blocked, 1);
            assert!(!done.has_more);
            let projection_states: Vec<String> = client.query(
                &format!("SELECT state FROM {schema}.audit_projection_outbox WHERE tenant_scope=$1 AND source='authorization_decisions' ORDER BY state"),
                &[&tenant],
            ).await.unwrap().into_iter().map(|row| row.get(0)).collect();
            assert_eq!(projection_states, ["pending"]);
            let after_other_tenants: i64 = client.query_one(
                &format!("SELECT count(*) FROM {schema}.authorization_decisions WHERE tenant_scope<>$1"),
                &[&tenant],
            ).await.unwrap().get(0);
            assert_eq!(after_other_tenants, before_other_tenants);
        }

        store.shutdown().await.unwrap();
        drop(store);
        let reopened = PostgresTaskStore::open(config.clone()).await.unwrap();
        for tenant_no in 0..8 {
            let tenant = format!("tenant-{tenant_no}");
            let result = PostgresTaskStore::cleanup_authorization_decisions(&config, &tenant, 50_000, 1000).await.unwrap();
            assert_eq!(result.deleted, 0);
            assert!(!result.has_more);
        }
        client.execute("SELECT set_config('smesh.authorization_retention','cleanup-v1',false)", &[]).await.unwrap();
        let diagnostics: Vec<(String, i64, i64)> = client.query(
            &format!("SELECT tenant_scope,total_deleted,last_deleted::bigint FROM {schema}.authorization_retention_diagnostics ORDER BY tenant_scope"),
            &[],
        ).await.unwrap().into_iter().map(|row| (row.get(0), row.get(1), row.get(2))).collect();
        assert_eq!(diagnostics.len(), 8);
        assert!(diagnostics.iter().all(|(_, total, last)| *total == 3 && *last == 0));

        drop(seed_client);
        seed_driver.abort();
        drop(client);
        driver.abort();
        drop(reopened);
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    }).await.expect("PostgreSQL authorization retention watchdog");
}

#[tokio::test]
async fn runtime_cannot_bypass_retention_authority_and_catalog_tamper_fails_closed() {
    let Some((admin, runtime)) = postgres_urls() else {
        return;
    };
    tokio::time::timeout(Duration::from_secs(60), async move {
        let base_config = config(&admin, &runtime, "privilege");
        let schema = base_config.schema_name().to_owned();
        let store = PostgresTaskStore::open(base_config.clone()).await.unwrap();
        let (admin_client, admin_connection) = tokio_postgres::connect(&admin, NoTls).await.unwrap();
        let admin_driver = tokio::spawn(admin_connection);

        let mut raw = tokio_postgres::Config::from_str(&runtime).unwrap();
        raw.options(format!("-c role={schema}_runtime -c smesh.tenant_scope=tenant-a"));
        let (runtime_client, runtime_connection) = raw.connect(NoTls).await.unwrap();
        let runtime_driver = tokio::spawn(runtime_connection);
        runtime_client.execute(
            &format!("INSERT INTO {schema}.authorization_decisions(decision_id,tenant_scope,actor_account_id,policy_id,policy_revision,policy_digest,operation,effect,reason,resource_kind,resource_digest,task_id,decided_at) VALUES('privileged-row','tenant-a','actor','policy',1,'digest','TaskGet','allow','fixture','task','resource',NULL,1)"),
            &[],
        ).await.unwrap();
        for forged in [
            format!("SELECT * FROM {schema}.cleanup_authorization_decisions('tenant-a',0,1)"),
            format!("SELECT set_config('smesh.authorization_retention','cleanup-v1',false); SELECT * FROM {schema}.cleanup_authorization_decisions('tenant-a',0,1)"),
        ] {
            assert!(runtime_client.batch_execute(&forged).await.is_err(), "runtime forged cleanup capability");
        }
        for invalid in [
            format!("SELECT * FROM {schema}.cleanup_authorization_decisions('tenant-a',NULL,1)"),
            format!("SELECT * FROM {schema}.cleanup_authorization_decisions('tenant-a',0,NULL)"),
            format!("SELECT * FROM {schema}.cleanup_authorization_decisions('tenant-a',0,1001)"),
        ] {
            assert!(admin_client.batch_execute(&invalid).await.is_err(), "invalid cleanup input was accepted");
        }
        assert!(runtime_client.execute(&format!("DELETE FROM {schema}.authorization_decisions"), &[]).await.is_err());
        assert!(runtime_client.execute(&format!("UPDATE {schema}.authorization_decisions SET reason='tampered'"), &[]).await.is_err());
        assert!(runtime_client.execute(&format!("UPDATE {schema}.authorization_retention_diagnostics SET total_deleted=0"), &[]).await.is_err());
        drop(runtime_client);
        runtime_driver.abort();

        store.shutdown().await.unwrap();
        admin_client.batch_execute(&format!("ALTER FUNCTION {schema}.cleanup_authorization_decisions(text,bigint,integer) SET search_path={schema},pg_catalog")).await.unwrap();
        assert!(matches!(
            PostgresTaskStore::open(base_config.clone()).await,
            Err(smesh_a2a::PostgresStoreError::InvalidSchema)
        ));
        PostgresTaskStore::drop_test_schema(&base_config).await.unwrap();

        let constraint_config = config(&admin, &runtime, "ctamper");
        let constraint_schema = constraint_config.schema_name().to_owned();
        let constraint_store = PostgresTaskStore::open(constraint_config.clone()).await.unwrap();
        constraint_store.shutdown().await.unwrap();
        admin_client.batch_execute(&format!("ALTER TABLE {constraint_schema}.authorization_decisions DROP CONSTRAINT authorization_decisions_projection_digest_check")).await.unwrap();
        assert!(matches!(PostgresTaskStore::open(constraint_config.clone()).await,
            Err(smesh_a2a::PostgresStoreError::InvalidSchema)));
        PostgresTaskStore::drop_test_schema(&constraint_config).await.unwrap();

        let grant_config = config(&admin, &runtime, "gtamper");
        let grant_schema = grant_config.schema_name().to_owned();
        let grant_store = PostgresTaskStore::open(grant_config.clone()).await.unwrap();
        grant_store.shutdown().await.unwrap();
        admin_client.batch_execute(&format!("GRANT EXECUTE ON FUNCTION {grant_schema}.cleanup_authorization_decisions(text,bigint,integer) TO {grant_schema}_runtime")).await.unwrap();
        assert!(matches!(PostgresTaskStore::open(grant_config.clone()).await,
            Err(smesh_a2a::PostgresStoreError::InvalidSchema)));
        PostgresTaskStore::drop_test_schema(&grant_config).await.unwrap();
        drop(admin_client);
        admin_driver.abort();
    }).await.expect("PostgreSQL authorization retention privilege watchdog");
}
