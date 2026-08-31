mod support;

use std::{env, str::FromStr as _, time::Duration};

use smesh_a2a::{AuthorityShutdown, PostgresStoreConfig, PostgresTaskStore};
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
    assert!(sql.contains("max_rows>1000"));
    assert!(sql.contains("current_setting('smesh.tenant_scope',true)"));
    assert!(sql.contains("state NOT IN ('delivered','dead')"));
    assert!(sql.contains("authorization_retention_diagnostics"));
    assert!(sql.contains("REVOKE ALL ON FUNCTION"));
    assert!(sql.contains("GRANT EXECUTE ON FUNCTION"));
}

#[tokio::test]
async fn bounded_cleanup_is_tenant_projection_and_live_window_safe_across_restart() {
    let Some((admin, runtime)) = postgres_urls() else {
        return;
    };
    tokio::time::timeout(Duration::from_secs(45), async move {
        let config = config(&admin, &runtime, "matrix");
        let schema = config.schema_name().to_owned();
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        let (client, connection) = tokio_postgres::connect(&admin, NoTls).await.unwrap();
        let driver = tokio::spawn(connection);
        let mut seed_config = tokio_postgres::Config::from_str(&runtime).unwrap();
        seed_config.options(format!("-c role={schema}_runtime"));
        let (seed_client, seed_connection) = seed_config.connect(NoTls).await.unwrap();
        let seed_driver = tokio::spawn(seed_connection);
        let now = chrono::Utc::now().timestamp_millis();
        let old = now - 100_000;
        let live = now - 1_000;

        for tenant_no in 0..8 {
            let tenant = format!("tenant-{tenant_no}");
            client.execute("SELECT set_config('smesh.internal_global','audit-projector-v1',false)", &[]).await.unwrap();
            seed_client.execute("SELECT set_config('smesh.tenant_scope',$1,false)", &[&tenant]).await.unwrap();
            for (kind, decided_at) in [
                ("terminal", old),
                ("absent", old),
                ("pending", old),
                ("live", live),
            ] {
                let decision = format!("decision-{tenant_no}-{kind}");
                seed_client.execute(
                    &format!("INSERT INTO {schema}.authorization_decisions(decision_id,tenant_scope,actor_account_id,policy_id,policy_revision,policy_digest,operation,effect,reason,resource_kind,resource_digest,task_id,decided_at) VALUES($1,$2,'actor','policy',1,'sha256:policy','TaskGet','allow','fixture','task','sha256:resource',NULL,$3)"),
                    &[&decision, &tenant, &decided_at],
                ).await.unwrap();
                if matches!(kind, "terminal" | "pending") {
                    let material = format!("smesh-audit-projection/v1\u{1f}authorization_decisions\u{1f}{tenant}\u{1f}{decision}\u{1f}1");
                    let source_pk = smesh_a2a::content_digest(format!("pk\u{1f}{material}").as_bytes());
                    let event_id = smesh_a2a::content_digest(format!("event-{tenant_no}-{kind}").as_bytes());
                    let state = if kind == "terminal" { "delivered" } else { "pending" };
                    let delivered_at = (state == "delivered").then_some(old);
                    client.execute(
                        &format!("INSERT INTO {schema}.audit_projection_outbox(tenant_scope,event_id,source,source_pk_digest,event_kind,occurred_at,state,available_at,delivered_at) VALUES($1,$2,'authorization_decisions',$3,'authorization_decided',$4,$5,$4,$6)"),
                        &[&tenant, &event_id, &source_pk, &old, &state, &delivered_at],
                    ).await.unwrap();
                }
            }
        }

        for tenant_no in 0..8 {
            let tenant = format!("tenant-{tenant_no}");
            let before_other_tenants: i64 = client.query_one(
                &format!("SELECT count(*) FROM {schema}.authorization_decisions WHERE tenant_scope<>$1"),
                &[&tenant],
            ).await.unwrap().get(0);
            let first = store.cleanup_authorization_decisions(&tenant, 50_000, 1).await.unwrap();
            assert_eq!(first.deleted, 1, "each call must honor its bound");
            assert!(first.projection_blocked >= 1);
            let second = store.cleanup_authorization_decisions(&tenant, 50_000, 1).await.unwrap();
            assert_eq!(second.deleted, 1);
            let done = store.cleanup_authorization_decisions(&tenant, 50_000, 1).await.unwrap();
            assert_eq!(done.deleted, 0);
            assert_eq!(done.live_rows, 2);
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
            let result = reopened.cleanup_authorization_decisions(&tenant, 50_000, 1000).await.unwrap();
            assert_eq!(result.deleted, 0);
            assert_eq!(result.live_rows, 2);
        }
        client.execute("SELECT set_config('smesh.authorization_retention','cleanup-v1',false)", &[]).await.unwrap();
        let diagnostics: Vec<(String, i64, i64)> = client.query(
            &format!("SELECT tenant_scope,total_deleted,last_deleted::bigint FROM {schema}.authorization_retention_diagnostics ORDER BY tenant_scope"),
            &[],
        ).await.unwrap().into_iter().map(|row| (row.get(0), row.get(1), row.get(2))).collect();
        assert_eq!(diagnostics.len(), 8);
        assert!(diagnostics.iter().all(|(_, total, last)| *total == 2 && *last == 0));

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
    tokio::time::timeout(Duration::from_secs(30), async move {
        let config = config(&admin, &runtime, "privilege");
        let schema = config.schema_name().to_owned();
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
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
        assert!(runtime_client.execute(&format!("DELETE FROM {schema}.authorization_decisions"), &[]).await.is_err());
        assert!(runtime_client.execute(&format!("UPDATE {schema}.authorization_decisions SET reason='tampered'"), &[]).await.is_err());
        assert!(runtime_client.execute(&format!("UPDATE {schema}.authorization_retention_diagnostics SET total_deleted=0"), &[]).await.is_err());
        drop(runtime_client);
        runtime_driver.abort();

        store.shutdown().await.unwrap();
        admin_client.batch_execute(&format!("ALTER FUNCTION {schema}.cleanup_authorization_decisions(bigint,integer) SET search_path={schema},pg_catalog")).await.unwrap();
        assert!(matches!(
            PostgresTaskStore::open(config.clone()).await,
            Err(smesh_a2a::PostgresStoreError::InvalidSchema)
        ));
        drop(admin_client);
        admin_driver.abort();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    }).await.expect("PostgreSQL authorization retention privilege watchdog");
}
