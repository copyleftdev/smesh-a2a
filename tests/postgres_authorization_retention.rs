mod support;

use std::{env, str::FromStr as _, time::Duration};

use smesh_a2a::{
    AuditProjectionAuthority, AuthorityShutdown, PostgresStoreConfig, PostgresStoreError,
    PostgresTaskStore, content_digest,
};
use tokio_postgres::NoTls;

const REVISION_EIGHT_MIGRATIONS: [(&str, i64, &str, &str); 8] = [
    (
        "0001_authority_schema_v6",
        6,
        include_str!("../migrations/postgres/0001_authority_schema_v6.sql"),
        "1",
    ),
    (
        "0002_quota_reservation_seam",
        6,
        include_str!("../migrations/postgres/0002_quota_reservation_seam.sql"),
        "2",
    ),
    (
        "0003_receiver_sender_fence",
        6,
        include_str!("../migrations/postgres/0003_receiver_sender_fence.sql"),
        "3",
    ),
    (
        "0004_distributed_quota_authority",
        6,
        include_str!("../migrations/postgres/0004_distributed_quota_authority.sql"),
        "4",
    ),
    (
        "0005_artifact_authority",
        6,
        include_str!("../migrations/postgres/0005_artifact_authority.sql"),
        "5",
    ),
    (
        "0006_audit_projection",
        6,
        include_str!("../migrations/postgres/0006_audit_projection.sql"),
        "6",
    ),
    (
        "0007_callback_authority",
        7,
        include_str!("../migrations/postgres/0007_callback_authority.sql"),
        "7",
    ),
    (
        "0008_callback_policy_fence",
        8,
        include_str!("../migrations/postgres/0008_callback_policy_fence.sql"),
        "8",
    ),
];

async fn test_catalog_digest<C>(client: &C, schema: &str) -> String
where
    C: tokio_postgres::GenericClient + Sync,
{
    // This intentionally duplicates the production catalog seal. A revision-8
    // fixture must be indistinguishable from one created by the old executable.
    let queries = [
        "SELECT concat_ws('|','relation',c.relname,c.relkind,c.relrowsecurity,c.relforcerowsecurity,c.relpersistence) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 ORDER BY 1",
        "SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,a.attgenerated,COALESCE(pg_get_expr(d.adbin,d.adrelid),'')) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE n.nspname=$1 AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum",
        "SELECT concat_ws('|','constraint',c.relname,x.conname,x.contype,pg_get_constraintdef(x.oid,true)) FROM pg_constraint x JOIN pg_class c ON c.oid=x.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 ORDER BY c.relname,x.conname",
        "SELECT concat_ws('|','index',i.relname,pg_get_indexdef(i.oid)) FROM pg_class i JOIN pg_namespace n ON n.oid=i.relnamespace WHERE n.nspname=$1 AND i.relkind='i' ORDER BY i.relname",
        "SELECT concat_ws('|','trigger',c.relname,t.tgname,pg_get_triggerdef(t.oid,true)) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND NOT t.tgisinternal ORDER BY c.relname,t.tgname",
        "SELECT concat_ws('|','function',p.proname,pg_get_function_identity_arguments(p.oid),owner.rolname,pg_get_functiondef(p.oid)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles owner ON owner.oid=p.proowner WHERE n.nspname=$1 ORDER BY p.proname,pg_get_function_identity_arguments(p.oid)",
        "SELECT concat_ws('|','policy',c.relname,p.polname,p.polcmd,p.polpermissive,COALESCE(pg_get_expr(p.polqual,p.polrelid),''),COALESCE(pg_get_expr(p.polwithcheck,p.polrelid),''),p.polroles::text) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 ORDER BY c.relname,p.polname",
        "SELECT concat_ws('|','grant',table_name,grantee,privilege_type,is_grantable) FROM information_schema.role_table_grants WHERE table_schema=$1 ORDER BY table_name,grantee,privilege_type",
        "SELECT concat_ws('|','sequence-grant',object_name,grantee,privilege_type,is_grantable) FROM information_schema.usage_privileges WHERE object_schema=$1 ORDER BY object_name,grantee,privilege_type",
        "SELECT concat_ws('|','routine-grant',routine_name,grantee,privilege_type,is_grantable) FROM information_schema.role_routine_grants WHERE routine_schema=$1 ORDER BY routine_name,grantee,privilege_type",
        "SELECT concat_ws('|','role',rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls) FROM pg_roles WHERE rolname=$1||'_runtime' ORDER BY rolname",
        "SELECT concat_ws('|','membership',member.rolname,parent.rolname,am.admin_option) FROM pg_auth_members am JOIN pg_roles member ON member.oid=am.member JOIN pg_roles parent ON parent.oid=am.roleid WHERE member.rolname=$1||'_runtime' OR parent.rolname=$1||'_runtime' ORDER BY member.rolname,parent.rolname",
    ];
    let mut manifest = Vec::new();
    for query in queries {
        manifest.extend(
            client
                .query(query, &[&schema])
                .await
                .unwrap()
                .into_iter()
                .map(|row| row.get::<_, String>(0)),
        );
    }
    content_digest(manifest.join("\n").replace(schema, "__SCHEMA__").as_bytes())
}

async fn install_revision_eight(admin: &str, runtime: &str, schema: &str) {
    let (client, connection) = tokio_postgres::connect(admin, NoTls).await.unwrap();
    let driver = tokio::spawn(connection);
    let (runtime_identity, runtime_connection) =
        tokio_postgres::connect(runtime, NoTls).await.unwrap();
    let runtime_driver = tokio::spawn(runtime_connection);
    let migrator: String = client
        .query_one("SELECT current_user", &[])
        .await
        .unwrap()
        .get(0);
    let runtime_user: String = runtime_identity
        .query_one("SELECT current_user", &[])
        .await
        .unwrap()
        .get(0);
    assert_ne!(migrator, runtime_user);
    let quoted_runtime: String = client
        .query_one("SELECT quote_ident($1)", &[&runtime_user])
        .await
        .unwrap()
        .get(0);

    for (_, _, migration, _) in REVISION_EIGHT_MIGRATIONS {
        let rendered = migration
            .replace("__SCHEMA__", schema)
            .replace("__ROLE__", &format!("{schema}_runtime"))
            .replace("__MIGRATOR__", &migrator.replace('\'', "''"));
        client.batch_execute(&rendered).await.unwrap();
        if migration == REVISION_EIGHT_MIGRATIONS[0].2 {
            client
                .batch_execute(&format!(
                    "GRANT {schema}_runtime TO {quoted_runtime} WITH ADMIN FALSE, INHERIT FALSE, SET TRUE"
                ))
                .await
                .unwrap();
        }
    }

    for (name, logical_version, migration, revision) in REVISION_EIGHT_MIGRATIONS {
        client
            .execute(
                &format!("INSERT INTO {schema}.schema_migrations VALUES({revision},$1,$2,$3,{schema}.db_millis())"),
                &[&logical_version, &name, &content_digest(migration.as_bytes())],
            )
            .await
            .unwrap();
    }
    let catalog = test_catalog_digest(&client, schema).await;
    client
        .execute(
            &format!("INSERT INTO {schema}.store_metadata VALUES(1,8,$1,$2,$3,$4)"),
            &[
                &content_digest(REVISION_EIGHT_MIGRATIONS[0].2.as_bytes()),
                &catalog,
                &&[17_u8; 32][..],
                &&[29_u8; 32][..],
            ],
        )
        .await
        .unwrap();
    client
        .execute(
            &format!("INSERT INTO {schema}.store_identity VALUES(1,$1,{schema}.db_millis())"),
            &[&&[43_u8; 32][..]],
        )
        .await
        .unwrap();

    drop(runtime_identity);
    runtime_driver.abort();
    drop(client);
    driver.abort();
}

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

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn populated_revision_eight_upgrades_authorization_projection_evidence_transactionally() {
    let Some((admin, runtime)) = postgres_urls() else {
        return;
    };
    let poisoned = config(&admin, &runtime, "v8p");
    let poisoned_schema = poisoned.schema_name().to_owned();
    let mut poisoned_task = {
        let admin = admin.clone();
        let runtime = runtime.clone();
        let poisoned = poisoned.clone();
        tokio::spawn(async move {
            install_revision_eight(&admin, &runtime, &poisoned_schema).await;
            let (client, connection) = tokio_postgres::connect(&admin, NoTls).await.unwrap();
            let driver = tokio::spawn(connection);
            client.batch_execute(&format!("CREATE INDEX issue_72_catalog_poison ON {poisoned_schema}.authorization_decisions(decision_id)")).await.unwrap();
            assert!(matches!(
                PostgresTaskStore::open(poisoned).await,
                Err(PostgresStoreError::InvalidSchema)
            ));
            let state = client.query_one(
                    &format!("SELECT (SELECT schema_version FROM {poisoned_schema}.store_metadata WHERE singleton=1),EXISTS(SELECT 1 FROM {poisoned_schema}.schema_migrations WHERE revision=9),EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=$1 AND table_name='authorization_decisions' AND column_name='projection_required')"),
                    &[&poisoned_schema],
                ).await.unwrap();
            assert_eq!(state.get::<_, i64>(0), 8);
            assert!(!state.get::<_, bool>(1));
            assert!(
                !state.get::<_, bool>(2),
                "revision-9 DDL ran before catalog validation"
            );
            drop(client);
            driver.abort();
        })
    };
    let poisoned_result = tokio::time::timeout(Duration::from_secs(40), &mut poisoned_task).await;
    if poisoned_result.is_err() {
        poisoned_task.abort();
        let _ = poisoned_task.await;
    }
    PostgresTaskStore::drop_test_schema(&poisoned)
        .await
        .unwrap();
    poisoned_result
        .expect("poisoned revision-8 watchdog")
        .unwrap();

    let upgrade = config(&admin, &runtime, "v8u");
    let upgrade_schema = upgrade.schema_name().to_owned();
    let mut upgrade_task = {
        let admin = admin.clone();
        let runtime = runtime.clone();
        let upgrade = upgrade.clone();
        tokio::spawn(async move {
            install_revision_eight(&admin, &runtime, &upgrade_schema).await;
            let (client, connection) = tokio_postgres::connect(&admin, NoTls).await.unwrap();
            let driver = tokio::spawn(connection);
            let proof: String = client.query_one(
                    &format!("SELECT proof FROM {upgrade_schema}.audit_projection_session_secret WHERE singleton=1"), &[]
                ).await.unwrap().get(0);
            let mut runtime_config = tokio_postgres::Config::from_str(&runtime).unwrap();
            runtime_config.options(format!("-c role={upgrade_schema}_runtime"));
            let (runtime_client, runtime_connection) = runtime_config.connect(NoTls).await.unwrap();
            let runtime_driver = tokio::spawn(runtime_connection);
            runtime_client
                .query_one(
                    &format!("SELECT {upgrade_schema}.register_audit_projection_session($1)"),
                    &[&proof],
                )
                .await
                .unwrap();
            runtime_client
                .execute(
                    "SELECT set_config('smesh.tenant_scope','tenant-v8',false)",
                    &[],
                )
                .await
                .unwrap();
            let insert = format!(
                "INSERT INTO {upgrade_schema}.authorization_decisions(decision_id,tenant_scope,actor_account_id,policy_id,policy_revision,policy_digest,operation,effect,reason,resource_kind,resource_digest,task_id,decided_at) VALUES($1,'tenant-v8','actor-v8','policy-v8',8,'sha256:policy-v8','TaskGet',$2,$3,'task','sha256:resource-v8',NULL,$4)"
            );
            runtime_client
                .execute(&insert, &[&"absent", &"deny", &"disabled", &101_i64])
                .await
                .unwrap();
            client.execute(&format!("UPDATE {upgrade_schema}.audit_projection_control SET enabled=true WHERE singleton=1"), &[]).await.unwrap();
            for (decision, effect, reason, decided_at) in [
                ("pending", "deny", "pending projection", 102_i64),
                ("delivered", "allow", "delivered projection", 103_i64),
                ("dead", "deny", "dead projection", 104_i64),
            ] {
                runtime_client
                    .execute(&insert, &[&decision, &effect, &reason, &decided_at])
                    .await
                    .unwrap();
            }
            client.execute("SELECT set_config('smesh.internal_global','audit-projector-v1',false),set_config('smesh.tenant_scope','tenant-v8',false)", &[]).await.unwrap();
            for (decision, state) in [("delivered", "delivered"), ("dead", "dead")] {
                let delivered_at = (state == "delivered").then_some(200_i64);
                let dead_at = (state == "dead").then_some(201_i64);
                assert_eq!(client.execute(
                        &format!("UPDATE {upgrade_schema}.audit_projection_outbox p SET state=$1,delivered_at=$2,dead_at=$3 WHERE p.tenant_scope='tenant-v8' AND p.source='authorization_decisions' AND p.source_pk_digest=(SELECT 'sha256:'||encode(sha256(convert_to('pk'||chr(31)||'smesh-audit-projection/v1'||chr(31)||'authorization_decisions'||chr(31)||tenant_scope||chr(31)||decision_id||chr(31)||policy_revision::text,'UTF8')),'hex') FROM {upgrade_schema}.authorization_decisions WHERE tenant_scope='tenant-v8' AND decision_id=$4)"),
                        &[&state, &delivered_at, &dead_at, &decision],
                    ).await.unwrap(), 1);
            }
            let before: Vec<(String, String, String, i64)> = client.query(
                    &format!("SELECT decision_id,effect,reason,decided_at FROM {upgrade_schema}.authorization_decisions WHERE tenant_scope='tenant-v8' ORDER BY decided_at"), &[]
                ).await.unwrap().into_iter().map(|row| (row.get(0), row.get(1), row.get(2), row.get(3))).collect();
            assert_eq!(before.len(), 4);

            drop(runtime_client);
            runtime_driver.abort();
            let store = PostgresTaskStore::open(upgrade.clone()).await.unwrap();
            let rows: Vec<(String, bool, bool, bool, bool)> = client.query(
                    &format!("SELECT d.decision_id,d.projection_required,d.projection_terminal,d.projection_source_pk_digest=('sha256:'||encode(sha256(convert_to('pk'||chr(31)||'smesh-audit-projection/v1'||chr(31)||'authorization_decisions'||chr(31)||d.tenant_scope||chr(31)||d.decision_id||chr(31)||d.policy_revision::text,'UTF8')),'hex')),EXISTS(SELECT 1 FROM {upgrade_schema}.audit_projection_outbox p WHERE p.tenant_scope=d.tenant_scope AND p.source='authorization_decisions' AND p.source_pk_digest=d.projection_source_pk_digest) FROM {upgrade_schema}.authorization_decisions d WHERE d.tenant_scope='tenant-v8' ORDER BY d.decided_at"), &[]
                ).await.unwrap().into_iter().map(|row| (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4))).collect();
            assert_eq!(
                rows,
                vec![
                    ("absent".into(), false, false, true, false),
                    ("pending".into(), true, false, true, true),
                    ("delivered".into(), true, true, true, true),
                    ("dead".into(), true, true, true, true),
                ]
            );
            let after: Vec<(String, String, String, i64)> = client.query(
                    &format!("SELECT decision_id,effect,reason,decided_at FROM {upgrade_schema}.authorization_decisions WHERE tenant_scope='tenant-v8' ORDER BY decided_at"), &[]
                ).await.unwrap().into_iter().map(|row| (row.get(0), row.get(1), row.get(2), row.get(3))).collect();
            assert_eq!(after, before, "revision-9 changed historical source fields");

            client.execute("SELECT set_config('smesh.internal_global','diag-v1',false),set_config('smesh.tenant_scope','tenant-v8',false)", &[]).await.unwrap();
            let counters = client.query_one(
                    &format!("SELECT (SELECT retained_bytes FROM {upgrade_schema}.retained_authority_usage WHERE tenant_scope='tenant-v8' AND scope_kind='tenant' AND scope_id='tenant-v8'),{upgrade_schema}.retained_authority_oracle('tenant-v8',NULL),(SELECT retained_bytes FROM {upgrade_schema}.retained_authority_usage WHERE tenant_scope='tenant-v8' AND scope_kind='account' AND scope_id='actor-v8'),{upgrade_schema}.retained_authority_account_oracle('tenant-v8','actor-v8'),(SELECT retained_bytes FROM {upgrade_schema}.retained_authority_usage WHERE tenant_scope='tenant-v8' AND scope_kind='principal' AND scope_id='account:actor-v8'),{upgrade_schema}.retained_authority_oracle('tenant-v8','account:actor-v8')"), &[]
                ).await.unwrap();
            assert_eq!(counters.get::<_, i64>(0), counters.get::<_, i64>(1));
            assert_eq!(counters.get::<_, i64>(2), counters.get::<_, i64>(3));
            assert_eq!(counters.get::<_, i64>(4), counters.get::<_, i64>(5));

            let ledger = client.query_one(
                    &format!("SELECT m.schema_version,l.logical_schema_version,l.name,l.checksum FROM {upgrade_schema}.store_metadata m JOIN {upgrade_schema}.schema_migrations l ON l.revision=9 WHERE m.singleton=1"), &[]
                ).await.unwrap();
            assert_eq!(ledger.get::<_, i64>(0), 9);
            assert_eq!(ledger.get::<_, i64>(1), 9);
            assert_eq!(
                ledger.get::<_, &str>(2),
                "0009_authorization_audit_retention"
            );
            assert_eq!(
                ledger.get::<_, String>(3),
                content_digest(
                    include_str!("../migrations/postgres/0009_authorization_audit_retention.sql")
                        .as_bytes()
                )
            );
            store.shutdown().await.unwrap();
            drop(store);
            let reopened = PostgresTaskStore::open(upgrade).await.unwrap();
            reopened.shutdown().await.unwrap();
            drop(reopened);
            drop(client);
            driver.abort();
        })
    };
    let upgrade_result = tokio::time::timeout(Duration::from_secs(45), &mut upgrade_task).await;
    if upgrade_result.is_err() {
        upgrade_task.abort();
        let _ = upgrade_task.await;
    }
    PostgresTaskStore::drop_test_schema(&upgrade).await.unwrap();
    upgrade_result
        .expect("populated revision-8 upgrade watchdog")
        .unwrap();
}
