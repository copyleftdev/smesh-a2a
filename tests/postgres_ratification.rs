use std::{env, str::FromStr, time::Duration};

use smesh_a2a::{
    AuthoritativeReviewCandidate, AuthorityIdentity as _, AuthorizationAuditInput,
    AuthorizationDecisionEffect, AuthorizedMutation, CallbackAuthority as _, CallbackConfigId,
    CallbackTerminalTestFault, CancellationAuthority as _, ConfigCreateCommand, HumanDecision,
    OutboxAuthority as _, OwnedTaskScope, PostgresStoreConfig, PostgresStoreError,
    PostgresTaskStore, QuotaOperation, QuotaPolicy, QuotaSubject, RatificationAuthority as _,
    RatificationCommand, ReceiverAdmission, ReceiverAuthority as _, ReviewAcknowledgement,
    SendMessageAdmission, SqliteTaskStore, TaskAdmission as _, VisibilityScope,
};
use tokio_postgres::NoTls;

const REVISION_TEN_MIGRATIONS: [(&str, i64, &str, i64); 10] = [
    (
        "0001_authority_schema_v6",
        6,
        include_str!("../migrations/postgres/0001_authority_schema_v6.sql"),
        1,
    ),
    (
        "0002_quota_reservation_seam",
        6,
        include_str!("../migrations/postgres/0002_quota_reservation_seam.sql"),
        2,
    ),
    (
        "0003_receiver_sender_fence",
        6,
        include_str!("../migrations/postgres/0003_receiver_sender_fence.sql"),
        3,
    ),
    (
        "0004_distributed_quota_authority",
        6,
        include_str!("../migrations/postgres/0004_distributed_quota_authority.sql"),
        4,
    ),
    (
        "0005_artifact_authority",
        6,
        include_str!("../migrations/postgres/0005_artifact_authority.sql"),
        5,
    ),
    (
        "0006_audit_projection",
        6,
        include_str!("../migrations/postgres/0006_audit_projection.sql"),
        6,
    ),
    (
        "0007_callback_authority",
        7,
        include_str!("../migrations/postgres/0007_callback_authority.sql"),
        7,
    ),
    (
        "0008_callback_policy_fence",
        8,
        include_str!("../migrations/postgres/0008_callback_policy_fence.sql"),
        8,
    ),
    (
        "0009_authorization_audit_retention",
        9,
        include_str!("../migrations/postgres/0009_authorization_audit_retention.sql"),
        9,
    ),
    (
        "0010_human_ratification",
        10,
        include_str!("../migrations/postgres/0010_human_ratification.sql"),
        10,
    ),
];

async fn test_catalog_digest<C>(client: &C, schema: &str) -> String
where
    C: tokio_postgres::GenericClient + Sync,
{
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
    smesh_a2a::content_digest(manifest.join("\n").replace(schema, "__SCHEMA__").as_bytes())
}

async fn install_revision_ten(admin: &str, runtime: &str, schema: &str) {
    let (client, connection) = tokio_postgres::connect(admin, NoTls).await.unwrap();
    let driver = tokio::spawn(connection);
    let (runtime_client, runtime_connection) =
        tokio_postgres::connect(runtime, NoTls).await.unwrap();
    let runtime_driver = tokio::spawn(runtime_connection);
    let migrator: String = client
        .query_one("SELECT current_user", &[])
        .await
        .unwrap()
        .get(0);
    let runtime_user: String = runtime_client
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
    for (_, _, migration, revision) in REVISION_TEN_MIGRATIONS {
        let rendered = migration
            .replace("__SCHEMA__", schema)
            .replace("__ROLE__", &format!("{schema}_runtime"))
            .replace("__MIGRATOR__", &migrator.replace('\'', "''"));
        client.batch_execute(&rendered).await.unwrap();
        if revision == 1 {
            client.batch_execute(&format!("GRANT {schema}_runtime TO {quoted_runtime} WITH ADMIN FALSE, INHERIT FALSE, SET TRUE")).await.unwrap();
        }
    }
    for (name, logical, migration, revision) in REVISION_TEN_MIGRATIONS {
        client.execute(&format!("INSERT INTO {schema}.schema_migrations VALUES($1,$2,$3,$4,{schema}.db_millis())"), &[&revision, &logical, &name, &smesh_a2a::content_digest(migration.as_bytes())]).await.unwrap();
    }
    let catalog = test_catalog_digest(&client, schema).await;
    client
        .execute(
            &format!("INSERT INTO {schema}.store_metadata VALUES(1,10,$1,$2,$3,$4)"),
            &[
                &smesh_a2a::content_digest(REVISION_TEN_MIGRATIONS[0].2.as_bytes()),
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
    drop(runtime_client);
    runtime_driver.abort();
    drop(client);
    driver.abort();
}

async fn clone_ratification_rows_into_revision_ten(
    admin: &str,
    runtime: &str,
    source_schema: &str,
    target_schema: &str,
) {
    install_revision_ten(admin, runtime, target_schema).await;
    let (client, connection) = tokio_postgres::connect(admin, NoTls).await.unwrap();
    let driver = tokio::spawn(connection);
    client.batch_execute(&format!(
        "ALTER TABLE {source_schema}.tasks DISABLE ROW LEVEL SECURITY;
         ALTER TABLE {source_schema}.idempotency_records DISABLE ROW LEVEL SECURITY;
         ALTER TABLE {source_schema}.outbox DISABLE ROW LEVEL SECURITY;
         ALTER TABLE {source_schema}.task_events DISABLE ROW LEVEL SECURITY;
         ALTER TABLE {source_schema}.outbox_attempts DISABLE ROW LEVEL SECURITY;
         ALTER TABLE {source_schema}.outbox_tenant_scheduler DISABLE ROW LEVEL SECURITY;
         ALTER TABLE {source_schema}.stream_transcripts DISABLE ROW LEVEL SECURITY;
         ALTER TABLE {source_schema}.stream_frames DISABLE ROW LEVEL SECURITY;
         ALTER TABLE {source_schema}.authorization_decisions DISABLE ROW LEVEL SECURITY;
         ALTER TABLE {source_schema}.ratification_packets DISABLE ROW LEVEL SECURITY;
         ALTER TABLE {source_schema}.ratification_events DISABLE ROW LEVEL SECURITY;
         ALTER TABLE {target_schema}.tasks DISABLE ROW LEVEL SECURITY;
         ALTER TABLE {target_schema}.idempotency_records DISABLE ROW LEVEL SECURITY;
         ALTER TABLE {target_schema}.outbox DISABLE ROW LEVEL SECURITY;
         ALTER TABLE {target_schema}.task_events DISABLE ROW LEVEL SECURITY;
         ALTER TABLE {target_schema}.outbox_attempts DISABLE ROW LEVEL SECURITY;
         ALTER TABLE {target_schema}.outbox_tenant_scheduler DISABLE ROW LEVEL SECURITY;
         ALTER TABLE {target_schema}.stream_transcripts DISABLE ROW LEVEL SECURITY;
         ALTER TABLE {target_schema}.stream_frames DISABLE ROW LEVEL SECURITY;
         ALTER TABLE {target_schema}.authorization_decisions DISABLE ROW LEVEL SECURITY;
         ALTER TABLE {target_schema}.quota_policy_versions DISABLE ROW LEVEL SECURITY;
         ALTER TABLE {target_schema}.retained_authority_usage DISABLE ROW LEVEL SECURITY;
         ALTER TABLE {target_schema}.ratification_packets DISABLE ROW LEVEL SECURITY;
         ALTER TABLE {target_schema}.ratification_events DISABLE ROW LEVEL SECURITY;
         INSERT INTO {target_schema}.tasks OVERRIDING SYSTEM VALUE SELECT * FROM {source_schema}.tasks WHERE tenant_scope='tenant-ratification' AND task_id='postgres-ratification-task';
         INSERT INTO {target_schema}.idempotency_records OVERRIDING SYSTEM VALUE SELECT * FROM {source_schema}.idempotency_records WHERE tenant_scope='tenant-ratification' AND task_id='postgres-ratification-task';
         INSERT INTO {target_schema}.outbox OVERRIDING SYSTEM VALUE SELECT * FROM {source_schema}.outbox WHERE tenant_scope='tenant-ratification' AND task_id='postgres-ratification-task';
         INSERT INTO {target_schema}.task_events OVERRIDING SYSTEM VALUE SELECT * FROM {source_schema}.task_events WHERE tenant_scope='tenant-ratification';
         INSERT INTO {target_schema}.outbox_attempts OVERRIDING SYSTEM VALUE SELECT * FROM {source_schema}.outbox_attempts WHERE tenant_scope='tenant-ratification';
         INSERT INTO {target_schema}.stream_transcripts OVERRIDING SYSTEM VALUE SELECT * FROM {source_schema}.stream_transcripts WHERE tenant_scope='tenant-ratification';
         INSERT INTO {target_schema}.stream_frames OVERRIDING SYSTEM VALUE SELECT * FROM {source_schema}.stream_frames WHERE tenant_scope='tenant-ratification';
         INSERT INTO {target_schema}.authorization_decisions OVERRIDING SYSTEM VALUE SELECT * FROM {source_schema}.authorization_decisions WHERE tenant_scope='tenant-ratification';
         INSERT INTO {target_schema}.ratification_packets SELECT * FROM {source_schema}.ratification_packets WHERE tenant_scope='tenant-ratification' AND task_id='postgres-ratification-task';
         INSERT INTO {target_schema}.ratification_events SELECT * FROM {source_schema}.ratification_events WHERE tenant_scope='tenant-ratification' AND task_id='postgres-ratification-task';
         ALTER TABLE {source_schema}.tasks ENABLE ROW LEVEL SECURITY; ALTER TABLE {source_schema}.tasks FORCE ROW LEVEL SECURITY;
         ALTER TABLE {source_schema}.idempotency_records ENABLE ROW LEVEL SECURITY; ALTER TABLE {source_schema}.idempotency_records FORCE ROW LEVEL SECURITY;
         ALTER TABLE {source_schema}.outbox ENABLE ROW LEVEL SECURITY; ALTER TABLE {source_schema}.outbox FORCE ROW LEVEL SECURITY;
         ALTER TABLE {source_schema}.task_events ENABLE ROW LEVEL SECURITY; ALTER TABLE {source_schema}.task_events FORCE ROW LEVEL SECURITY;
         ALTER TABLE {source_schema}.outbox_attempts ENABLE ROW LEVEL SECURITY; ALTER TABLE {source_schema}.outbox_attempts FORCE ROW LEVEL SECURITY;
         ALTER TABLE {source_schema}.outbox_tenant_scheduler ENABLE ROW LEVEL SECURITY; ALTER TABLE {source_schema}.outbox_tenant_scheduler FORCE ROW LEVEL SECURITY;
         ALTER TABLE {source_schema}.stream_transcripts ENABLE ROW LEVEL SECURITY; ALTER TABLE {source_schema}.stream_transcripts FORCE ROW LEVEL SECURITY;
         ALTER TABLE {source_schema}.stream_frames ENABLE ROW LEVEL SECURITY; ALTER TABLE {source_schema}.stream_frames FORCE ROW LEVEL SECURITY;
         ALTER TABLE {source_schema}.authorization_decisions ENABLE ROW LEVEL SECURITY; ALTER TABLE {source_schema}.authorization_decisions FORCE ROW LEVEL SECURITY;
         ALTER TABLE {source_schema}.ratification_packets ENABLE ROW LEVEL SECURITY; ALTER TABLE {source_schema}.ratification_packets FORCE ROW LEVEL SECURITY;
         ALTER TABLE {source_schema}.ratification_events ENABLE ROW LEVEL SECURITY; ALTER TABLE {source_schema}.ratification_events FORCE ROW LEVEL SECURITY;
         ALTER TABLE {target_schema}.tasks ENABLE ROW LEVEL SECURITY; ALTER TABLE {target_schema}.tasks FORCE ROW LEVEL SECURITY;
         ALTER TABLE {target_schema}.idempotency_records ENABLE ROW LEVEL SECURITY; ALTER TABLE {target_schema}.idempotency_records FORCE ROW LEVEL SECURITY;
         ALTER TABLE {target_schema}.outbox ENABLE ROW LEVEL SECURITY; ALTER TABLE {target_schema}.outbox FORCE ROW LEVEL SECURITY;
         ALTER TABLE {target_schema}.task_events ENABLE ROW LEVEL SECURITY; ALTER TABLE {target_schema}.task_events FORCE ROW LEVEL SECURITY;
         ALTER TABLE {target_schema}.outbox_attempts ENABLE ROW LEVEL SECURITY; ALTER TABLE {target_schema}.outbox_attempts FORCE ROW LEVEL SECURITY;
         ALTER TABLE {target_schema}.outbox_tenant_scheduler ENABLE ROW LEVEL SECURITY; ALTER TABLE {target_schema}.outbox_tenant_scheduler FORCE ROW LEVEL SECURITY;
         ALTER TABLE {target_schema}.stream_transcripts ENABLE ROW LEVEL SECURITY; ALTER TABLE {target_schema}.stream_transcripts FORCE ROW LEVEL SECURITY;
         ALTER TABLE {target_schema}.stream_frames ENABLE ROW LEVEL SECURITY; ALTER TABLE {target_schema}.stream_frames FORCE ROW LEVEL SECURITY;
         ALTER TABLE {target_schema}.authorization_decisions ENABLE ROW LEVEL SECURITY; ALTER TABLE {target_schema}.authorization_decisions FORCE ROW LEVEL SECURITY;
         ALTER TABLE {target_schema}.quota_policy_versions ENABLE ROW LEVEL SECURITY; ALTER TABLE {target_schema}.quota_policy_versions FORCE ROW LEVEL SECURITY;
         ALTER TABLE {target_schema}.retained_authority_usage ENABLE ROW LEVEL SECURITY; ALTER TABLE {target_schema}.retained_authority_usage FORCE ROW LEVEL SECURITY;
         ALTER TABLE {target_schema}.ratification_packets ENABLE ROW LEVEL SECURITY; ALTER TABLE {target_schema}.ratification_packets FORCE ROW LEVEL SECURITY;
         ALTER TABLE {target_schema}.ratification_events ENABLE ROW LEVEL SECURITY; ALTER TABLE {target_schema}.ratification_events FORCE ROW LEVEL SECURITY"
    )).await.unwrap();
    drop(client);
    driver.abort();
}

fn retained_limit_policy(tenant: u64, account: u64, principal: u64) -> QuotaPolicy {
    QuotaPolicy::from_json(
        format!(r#"{{
          "schemaVersion":"smesh-quota-policy/v1","policyId":"migration-boundary","revision":1,
          "requestWindowMillis":1000,"reconnectWindowMillis":60000,
          "limits":{{
            "requestCount":{{"tenant":20,"account":20,"principal":20}},
            "concurrentActiveWork":{{"tenant":4,"account":4,"principal":4}},
            "inputBytes":{{"tenant":1048576,"account":1048576,"principal":1048576}},
            "outputBytes":{{"tenant":1048576,"account":1048576,"principal":1048576}},
            "eventCount":{{"tenant":1024,"account":1024,"principal":1024}},
            "concurrentStreams":{{"tenant":4,"account":4,"principal":4}},
            "concurrentSubscriptions":{{"tenant":4,"account":4,"principal":4}},
            "reconnectCount":{{"tenant":12,"account":12,"principal":12}},
            "retainedAuthorityBytes":{{"tenant":{tenant},"account":{account},"principal":{principal}}}
          }},"overrides":[]
        }}"#).as_bytes(),
    ).unwrap()
}

async fn write_revision_ten_limits(
    client: &tokio_postgres::Client,
    schema: &str,
    tenant: u64,
    account: u64,
    principal: u64,
) {
    let policy = retained_limit_policy(tenant, account, principal);
    client
        .batch_execute(&format!(
            "ALTER TABLE {schema}.quota_policy_versions DISABLE ROW LEVEL SECURITY;
         ALTER TABLE {schema}.retained_authority_usage DISABLE ROW LEVEL SECURITY"
        ))
        .await
        .unwrap();
    client.execute(
        &format!("INSERT INTO {schema}.quota_policy_versions(tenant_scope,policy_id,policy_revision,policy_digest,canonical_json,lifecycle,created_at) VALUES('tenant-ratification',$1,$2,$3,$4,'active',1) ON CONFLICT(tenant_scope,policy_id,policy_revision) DO UPDATE SET policy_digest=EXCLUDED.policy_digest,canonical_json=EXCLUDED.canonical_json"),
        &[&policy.policy_id(), &i64::try_from(policy.revision()).unwrap(), &policy.digest(), &policy.canonical_json()],
    ).await.unwrap();
    client.batch_execute(&format!(
        "ALTER TABLE {schema}.quota_policy_versions ENABLE ROW LEVEL SECURITY; ALTER TABLE {schema}.quota_policy_versions FORCE ROW LEVEL SECURITY;
         ALTER TABLE {schema}.retained_authority_usage ENABLE ROW LEVEL SECURITY; ALTER TABLE {schema}.retained_authority_usage FORCE ROW LEVEL SECURITY"
    )).await.unwrap();
}

async fn revision_ten_final_totals(
    client: &tokio_postgres::Client,
    schema: &str,
    owner_principal: &str,
) -> (u64, u64, u64) {
    client
        .batch_execute(&format!(
            "ALTER TABLE {schema}.ratification_packets DISABLE ROW LEVEL SECURITY;
         ALTER TABLE {schema}.ratification_events DISABLE ROW LEVEL SECURITY;
         SET smesh.internal_global='diag-v1'"
        ))
        .await
        .unwrap();
    let row = client.query_one(
        &format!("SELECT ({schema}.retained_authority_oracle('tenant-ratification',NULL)+(SELECT COALESCE(sum({schema}.row_retained_bytes(p)),0) FROM {schema}.ratification_packets p)+(SELECT COALESCE(sum({schema}.row_retained_bytes(e)),0) FROM {schema}.ratification_events e))::bigint,({schema}.retained_authority_account_oracle('tenant-ratification','owner-ratification')+(SELECT COALESCE(sum({schema}.row_retained_bytes(p)),0) FROM {schema}.ratification_packets p)+(SELECT COALESCE(sum({schema}.row_retained_bytes(e)),0) FROM {schema}.ratification_events e))::bigint,({schema}.retained_authority_oracle('tenant-ratification',$1)+(SELECT COALESCE(sum({schema}.row_retained_bytes(p)),0) FROM {schema}.ratification_packets p))::bigint"),
        &[&owner_principal],
    ).await.unwrap();
    client.batch_execute(&format!(
        "ALTER TABLE {schema}.ratification_packets ENABLE ROW LEVEL SECURITY; ALTER TABLE {schema}.ratification_packets FORCE ROW LEVEL SECURITY;
         ALTER TABLE {schema}.ratification_events ENABLE ROW LEVEL SECURITY; ALTER TABLE {schema}.ratification_events FORCE ROW LEVEL SECURITY"
    )).await.unwrap();
    (
        u64::try_from(row.get::<_, i64>(0)).unwrap(),
        u64::try_from(row.get::<_, i64>(1)).unwrap(),
        u64::try_from(row.get::<_, i64>(2)).unwrap(),
    )
}

async fn seed_revision_ten_artifact_and_callback_authority(
    client: &tokio_postgres::Client,
    schema: &str,
    principal: &str,
) {
    let zero = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let callback_policy = ratification_push_policy();
    let callback_enrollment = &callback_policy.enrollments()[0];
    let callback_url = callback_enrollment.url().as_str();
    let callback_url_digest = smesh_a2a::content_digest(callback_url.as_bytes());
    let callback_policy_id = callback_policy.policy_id();
    let callback_policy_digest = callback_policy.policy_digest();
    let callback_enrollment_id = callback_enrollment.endpoint_id();
    let callback_key_generation = callback_enrollment.key_generation();
    let sql = format!(
        "ALTER TABLE {schema}.artifact_key_generations DISABLE ROW LEVEL SECURITY;
         ALTER TABLE {schema}.content_objects DISABLE ROW LEVEL SECURITY;
         ALTER TABLE {schema}.callback_enrollments DISABLE ROW LEVEL SECURITY;
         ALTER TABLE {schema}.callback_configs DISABLE ROW LEVEL SECURITY;
         ALTER TABLE {schema}.retained_authority_usage DISABLE ROW LEVEL SECURITY;
         INSERT INTO {schema}.retained_authority_usage VALUES
          ('tenant-ratification','principal','account:owner-ratification',0,1)
          ON CONFLICT DO NOTHING;
         INSERT INTO {schema}.artifact_key_generations VALUES('tenant-ratification','tenant-ratification/confidential','migration-key','active',1,NULL);
         INSERT INTO {schema}.content_objects(tenant_scope,owner_account_id,object_id,content_digest,classification,encryption_domain,key_generation,plaintext_length,ciphertext_length,ciphertext_digest,backend_locator,nonce,state,retain_until,created_at,available_at)
          VALUES('tenant-ratification','owner-ratification','migration-object','{zero}','confidential','tenant-ratification/confidential','migration-key',1,16,'{zero}','objects/migration/object',decode('000000000000000000000000','hex'),'available',1,1,1);
         INSERT INTO {schema}.callback_policy_snapshots VALUES('{callback_policy_id}',1,'{callback_policy_digest}',4,20,100,262144,8,10000,1);
         INSERT INTO {schema}.callback_enrollments(policy_id,policy_revision,tenant_scope,enrollment_id,enrollment_generation,canonical_url,url_digest,key_generation,secret_reference)
          VALUES('{callback_policy_id}',1,'tenant-ratification','{callback_enrollment_id}',1,'{callback_url}','{callback_url_digest}','{callback_key_generation}','/tmp/smesh-ratification-callback-secret');
         INSERT INTO {schema}.callback_configs VALUES('tenant-ratification','postgres-ratification-task','migration-config','owner-ratification',$$__PRINCIPAL__$$,'{callback_enrollment_id}',1,'{callback_url}','{callback_url_digest}','active',NULL,1,1);
         UPDATE {schema}.retained_authority_usage u SET retained_bytes=CASE u.scope_kind
          WHEN 'tenant' THEN {schema}.retained_authority_oracle(u.tenant_scope,NULL)+{schema}.artifact_retained_oracle(u.tenant_scope,NULL)+{schema}.callback_retained_oracle(u.tenant_scope,NULL)
          WHEN 'account' THEN {schema}.retained_authority_account_oracle(u.tenant_scope,u.scope_id)+{schema}.artifact_retained_account_oracle(u.tenant_scope,u.scope_id)+{schema}.callback_retained_account_oracle(u.tenant_scope,u.scope_id)
          ELSE {schema}.retained_authority_oracle(u.tenant_scope,u.scope_id)+{schema}.artifact_retained_oracle(u.tenant_scope,u.scope_id)+{schema}.callback_retained_oracle(u.tenant_scope,u.scope_id) END;
         ALTER TABLE {schema}.artifact_key_generations ENABLE ROW LEVEL SECURITY; ALTER TABLE {schema}.artifact_key_generations FORCE ROW LEVEL SECURITY;
         ALTER TABLE {schema}.content_objects ENABLE ROW LEVEL SECURITY; ALTER TABLE {schema}.content_objects FORCE ROW LEVEL SECURITY;
         ALTER TABLE {schema}.callback_enrollments ENABLE ROW LEVEL SECURITY; ALTER TABLE {schema}.callback_enrollments FORCE ROW LEVEL SECURITY;
         ALTER TABLE {schema}.callback_configs ENABLE ROW LEVEL SECURITY; ALTER TABLE {schema}.callback_configs FORCE ROW LEVEL SECURITY;
         ALTER TABLE {schema}.retained_authority_usage ENABLE ROW LEVEL SECURITY; ALTER TABLE {schema}.retained_authority_usage FORCE ROW LEVEL SECURITY;"
    )
    .replace("__PRINCIPAL__", principal);
    client.batch_execute(&sql).await.unwrap();
}

async fn migration_rollback_snapshot(
    client: &tokio_postgres::Client,
    schema: &str,
) -> (String, Vec<(String, String)>) {
    let catalog = test_catalog_digest(client, schema).await;
    let mut state = Vec::new();
    for (name, query) in [
        (
            "retained_authority_usage",
            format!(
                "SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY tenant_scope,scope_kind,scope_id),'[]'::jsonb)::text FROM {schema}.retained_authority_usage r"
            ),
        ),
        (
            "active_quota_policies",
            format!(
                "SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY tenant_scope,policy_id,policy_revision),'[]'::jsonb)::text FROM {schema}.quota_policy_versions r WHERE lifecycle='active'"
            ),
        ),
        (
            "schema_migrations",
            format!(
                "SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY revision),'[]'::jsonb)::text FROM {schema}.schema_migrations r"
            ),
        ),
        (
            "store_metadata",
            format!(
                "SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY singleton),'[]'::jsonb)::text FROM {schema}.store_metadata r"
            ),
        ),
    ] {
        state.push((
            name.to_owned(),
            client.query_one(&query, &[]).await.unwrap().get(0),
        ));
    }
    (catalog, state)
}

fn postgres_urls() -> Option<(String, String)> {
    let required = env::var("SMESH_POSTGRES_TEST_REQUIRED").as_deref() == Ok("1");
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

async fn postgres_ratification_state(
    client: &tokio_postgres::Client,
    schema: &str,
) -> Vec<(String, String)> {
    let mut snapshot = Vec::new();
    for table in [
        "tasks",
        "ratification_packets",
        "ratification_events",
        "idempotency_records",
        "stream_transcripts",
        "stream_frames",
        "task_events",
        "outbox",
        "callback_configs",
        "callback_events",
        "callback_deliveries",
        "outbox_tenant_scheduler",
        "retained_authority_usage",
        "audit_projection_outbox",
        "authorization_decisions",
    ] {
        client
            .batch_execute(&format!(
                "ALTER TABLE {schema}.{table} DISABLE ROW LEVEL SECURITY"
            ))
            .await
            .unwrap();
        let sql = format!(
            "SELECT COALESCE(jsonb_agg(to_jsonb(rows) ORDER BY to_jsonb(rows)::text), '[]'::jsonb)::text FROM {schema}.{table} rows"
        );
        let value = client.query_one(&sql, &[]).await.unwrap().get(0);
        client
            .batch_execute(&format!(
                "ALTER TABLE {schema}.{table} ENABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.{table} FORCE ROW LEVEL SECURITY"
            ))
            .await
            .unwrap();
        snapshot.push((table.to_owned(), value));
    }
    snapshot
}

async fn clone_postgres_task_row(
    client: &tokio_postgres::Client,
    schema: &str,
    table: &str,
    task_id: &str,
    state: &str,
    replacements: &[(&str, &str)],
) -> u64 {
    let relation = format!("{schema}.{table}");
    let columns = client
        .query(
            "SELECT attname FROM pg_attribute
             WHERE attrelid=to_regclass($1) AND attnum>0 AND NOT attisdropped
               AND attidentity='' AND attgenerated=''
             ORDER BY attnum",
            &[&relation],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>();
    let projection = columns
        .iter()
        .map(|column| {
            replacements
                .iter()
                .find_map(|(name, value)| {
                    (*name == column).then(|| format!("'{}'::text", value.replace('\'', "''")))
                })
                .unwrap_or_else(|| format!("\"{column}\""))
        })
        .collect::<Vec<_>>()
        .join(",");
    let names = columns
        .iter()
        .map(|column| format!("\"{column}\""))
        .collect::<Vec<_>>()
        .join(",");
    client
        .execute(
            &format!(
                "INSERT INTO {relation}({names})
                 SELECT {projection} FROM {relation}
                 WHERE task_id=$1 AND state=$2 LIMIT 1"
            ),
            &[&task_id, &state],
        )
        .await
        .unwrap()
}

fn unkeyed_config(admin: &str, runtime: &str, suffix: &str) -> PostgresStoreConfig {
    let suffix_digest = smesh_a2a::content_digest(suffix.as_bytes());
    PostgresStoreConfig::new(
        admin,
        runtime,
        format!(
            "smesh_rat_{}_{:016x}",
            &suffix_digest[7..15],
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

fn config(admin: &str, runtime: &str, suffix: &str) -> PostgresStoreConfig {
    unkeyed_config(admin, runtime, suffix)
        .with_ratification_key(zeroize::Zeroizing::new([0x60; 32]))
}

#[test]
fn postgres_ci_serializes_ratification_authority_and_exact_binary_qualification() {
    let workflow = include_str!("../.github/workflows/ci.yml");
    assert!(workflow.contains("# Command watchdogs total 100 minutes"));
    assert!(workflow.contains("timeout-minutes: 120"));
    assert!(workflow.contains("timeout --signal=TERM --kill-after=15s 15m cargo test --locked --test postgres_ratification -- --test-threads=1"));
    assert!(workflow.contains("timeout --signal=TERM --kill-after=15s 10m cargo test --locked --test human_ratification_process production_postgres_binary_qualifies_ratification_routes -- --exact --test-threads=1"));
}

#[test]
fn revision_ten_declares_the_ratification_boundary() {
    let sql = include_str!("../migrations/postgres/0010_human_ratification.sql");
    for required in [
        "principal_scope",
        "authentication_method",
        "ratification_packets",
        "ratification_events",
        "FORCE ROW LEVEL SECURITY",
        "ratification packet identity is immutable",
        "ratification event is immutable",
        "REVOKE DELETE",
    ] {
        assert!(sql.contains(required), "missing {required}");
    }
    assert!(sql.contains("legacy-principal"));
    assert!(sql.contains("trusted-local"));
    let adapter = include_str!("../src/postgres_store.rs");
    let sqlite = include_str!("../src/sqlite_store.rs");
    for backend in [adapter, sqlite] {
        assert!(backend.contains("prepare_authoritative_review_candidate("));
    }
    assert!(adapter.contains("fn ratification_authority(&self)"));
    assert!(!adapter.contains("PostgreSQL ratification review is not implemented"));
    assert!(!adapter.contains("PostgreSQL ratification decisions are not implemented"));
    assert!(adapter.contains("FOR UPDATE OF t"));
    assert!(adapter.contains("FOR UPDATE OF p"));
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn populated_revision_ten_upgrade_attributes_packet_and_receipt_principals_exactly() {
    let Some((admin, runtime)) = postgres_urls() else {
        return;
    };
    tokio::time::timeout(Duration::from_secs(120), async move {
        let source = integrated_postgres_ratification(&admin, &runtime, "v10_source", false, false).await;
        let ratifier_scope = OwnedTaskScope::new_with_principal_and_authentication(
            source.scope.tenant_scope(),
            source.scope.owner_account_id(),
            smesh_a2a::content_digest(b"independent-ratifier-principal"),
            VisibilityScope::Own,
            "bearer-jwt",
        ).unwrap();
        source.store.acknowledge_ratification_review(
            &ratifier_scope,
            review(&source.packet, &ratifier_scope, &source.task_id),
            ratification_audit(&source.packet, &ratifier_scope, &source.task_id, "v10-source-review-audit", "ratificationReview", 1_700_000_010_003),
        ).await.unwrap();

        let target = config(&admin, &runtime, "populated_v10")
            .with_push_policy(ratification_push_policy());
        let target_schema = target.schema_name().to_owned();
        let source_schema = source.config.schema_name().to_owned();
        clone_ratification_rows_into_revision_ten(
            &admin,
            &runtime,
            &source_schema,
            &target_schema,
        )
        .await;
        let (client, connection) = tokio_postgres::connect(&admin, NoTls).await.unwrap();
        let driver = tokio::spawn(connection);
        client
            .batch_execute("SET smesh.internal_global='diag-v1'")
            .await
            .unwrap();
        let owner_principal = source.scope.principal_scope().to_owned();
        let ratifier_principal = ratifier_scope.principal_scope().to_owned();
        seed_revision_ten_artifact_and_callback_authority(
            &client,
            &target_schema,
            &owner_principal,
        )
        .await;
        let before_owner: i64 = client.query_one(
            &format!("SELECT retained_bytes FROM {target_schema}.retained_authority_usage WHERE tenant_scope='tenant-ratification' AND scope_kind='principal' AND scope_id=$1"),
            &[&owner_principal],
        ).await.unwrap().get(0);
        drop(source.store);
        PostgresTaskStore::drop_test_schema(&source.config).await.unwrap();

        let upgraded = PostgresTaskStore::open(target.clone()).await.unwrap();
        let attribution = client.query_one(
            &format!("SELECT {target_schema}.retained_principal(to_jsonb(p)),{target_schema}.retained_principal(to_jsonb(e)),{target_schema}.row_retained_bytes(p),{target_schema}.row_retained_bytes(e) FROM {target_schema}.ratification_packets p JOIN {target_schema}.ratification_events e USING(tenant_scope,task_id,generation)"),
            &[],
        ).await.unwrap();
        assert_eq!(attribution.get::<_, String>(0), owner_principal);
        assert_eq!(attribution.get::<_, String>(1), ratifier_principal);
        let packet_bytes: i64 = attribution.get(2);
        let event_bytes: i64 = attribution.get(3);
        let mut scoped_runtime = tokio_postgres::Config::from_str(&runtime).unwrap();
        scoped_runtime.options(format!(
            "-c role={target_schema}_runtime -c smesh.tenant_scope=tenant-ratification"
        ));
        let (runtime_client, runtime_connection) = scoped_runtime.connect(NoTls).await.unwrap();
        let runtime_driver = tokio::spawn(runtime_connection);
        let counters = runtime_client.query_one(
            &format!("SELECT (SELECT retained_bytes FROM {target_schema}.retained_authority_usage WHERE tenant_scope='tenant-ratification' AND scope_kind='principal' AND scope_id=$1),(SELECT retained_bytes FROM {target_schema}.retained_authority_usage WHERE tenant_scope='tenant-ratification' AND scope_kind='principal' AND scope_id=$2),{target_schema}.retained_authority_oracle('tenant-ratification',$1)+{target_schema}.artifact_retained_oracle('tenant-ratification',$1)+{target_schema}.callback_retained_oracle('tenant-ratification',$1),{target_schema}.retained_authority_oracle('tenant-ratification',$2)+{target_schema}.artifact_retained_oracle('tenant-ratification',$2)+{target_schema}.callback_retained_oracle('tenant-ratification',$2)"),
            &[&owner_principal, &ratifier_principal],
        ).await.unwrap();
        assert_eq!(counters.get::<_, i64>(0), before_owner + packet_bytes);
        assert_eq!(counters.get::<_, i64>(1), event_bytes);
        assert_eq!(counters.get::<_, i64>(0), counters.get::<_, i64>(2));
        assert_eq!(counters.get::<_, i64>(1), counters.get::<_, i64>(3));
        let visible: Vec<String> = client.query(
            &format!("SELECT * FROM {target_schema}.authority_retained_scopes_bounded('tenant-ratification','principal') ORDER BY 1"),
            &[],
        ).await.unwrap().into_iter().map(|row| row.get(0)).collect();
        assert!(visible.contains(&owner_principal));
        assert!(visible.contains(&ratifier_principal));
        drop(runtime_client);
        runtime_driver.abort();
        drop(upgraded);
        drop(client);
        driver.abort();
        PostgresTaskStore::drop_test_schema(&target).await.unwrap();
    }).await.expect("populated revision-10 upgrade watchdog");
}

#[tokio::test]
async fn tampered_revision_ten_counter_rolls_revision_eleven_back_completely() {
    let Some((admin, runtime)) = postgres_urls() else {
        return;
    };
    tokio::time::timeout(Duration::from_secs(120), async move {
        let source =
            integrated_postgres_ratification(&admin, &runtime, "v10_tamper_source", false, false)
                .await;
        let ratifier_scope = OwnedTaskScope::new_with_principal_and_authentication(
            source.scope.tenant_scope(),
            source.scope.owner_account_id(),
            smesh_a2a::content_digest(b"tamper-ratifier-principal"),
            VisibilityScope::Own,
            "bearer-jwt",
        )
        .unwrap();
        source
            .store
            .acknowledge_ratification_review(
                &ratifier_scope,
                review(&source.packet, &ratifier_scope, &source.task_id),
                ratification_audit(
                    &source.packet,
                    &ratifier_scope,
                    &source.task_id,
                    "v10-tamper-review-audit",
                    "ratificationReview",
                    1_700_000_010_003,
                ),
            )
            .await
            .unwrap();
        let target = config(&admin, &runtime, "tampered_v10");
        let schema = target.schema_name().to_owned();
        clone_ratification_rows_into_revision_ten(
            &admin,
            &runtime,
            source.config.schema_name(),
            &schema,
        )
        .await;
        let (client, connection) = tokio_postgres::connect(&admin, NoTls).await.unwrap();
        let driver = tokio::spawn(connection);
        client
            .batch_execute(&format!(
                "ALTER TABLE {schema}.retained_authority_usage DISABLE ROW LEVEL SECURITY;
             UPDATE {schema}.retained_authority_usage SET retained_bytes=retained_bytes+1
              WHERE tenant_scope='tenant-ratification' AND scope_kind='tenant';
             ALTER TABLE {schema}.retained_authority_usage ENABLE ROW LEVEL SECURITY;
             ALTER TABLE {schema}.retained_authority_usage FORCE ROW LEVEL SECURITY"
            ))
            .await
            .unwrap();
        let before = migration_rollback_snapshot(&client, &schema).await;
        drop(source.store);
        PostgresTaskStore::drop_test_schema(&source.config)
            .await
            .unwrap();
        let Err(error) = PostgresTaskStore::open(target.clone()).await else {
            panic!("tampered revision-10 authority migrated")
        };
        assert_eq!(
            error,
            PostgresStoreError::RetainedAuthorityMaterializationMismatch,
        );
        assert_eq!(migration_rollback_snapshot(&client, &schema).await, before);
        drop(client);
        driver.abort();
        PostgresTaskStore::drop_test_schema(&target).await.unwrap();
    })
    .await
    .expect("tampered revision-10 rollback watchdog");
}

#[tokio::test]
async fn artifact_only_revision_ten_scopes_require_every_usage_row() {
    let Some((admin, runtime)) = postgres_urls() else {
        return;
    };
    tokio::time::timeout(Duration::from_secs(120), async move {
        for (index, (scope_kind, scope_id)) in [
            ("tenant", "artifact-only-tenant"),
            ("account", "artifact-only-owner"),
            ("principal", "account:artifact-only-owner"),
        ]
        .into_iter()
        .enumerate()
        {
            let target = config(&admin, &runtime, &format!("artifact_only_v10_{index}"));
            let schema = target.schema_name().to_owned();
            install_revision_ten(&admin, &runtime, &schema).await;
            let (client, connection) = tokio_postgres::connect(&admin, NoTls).await.unwrap();
            let driver = tokio::spawn(connection);
            client
                .batch_execute(&format!(
                    "SET smesh.internal_global='claim-v1';
                     ALTER TABLE {schema}.artifact_key_generations DISABLE ROW LEVEL SECURITY;
                     ALTER TABLE {schema}.content_objects DISABLE ROW LEVEL SECURITY;
                     ALTER TABLE {schema}.retained_authority_usage DISABLE ROW LEVEL SECURITY;
                     INSERT INTO {schema}.artifact_key_generations VALUES('artifact-only-tenant','artifact-only-tenant/confidential','artifact-only-key','active',1,NULL);
                     INSERT INTO {schema}.content_objects(tenant_scope,owner_account_id,object_id,content_digest,classification,encryption_domain,key_generation,plaintext_length,ciphertext_length,ciphertext_digest,backend_locator,nonce,state,retain_until,created_at,available_at)
                      VALUES('artifact-only-tenant','artifact-only-owner','artifact-only-object','sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','confidential','artifact-only-tenant/confidential','artifact-only-key',16,32,'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','artifact-only-locator',decode('000000000000000000000000','hex'),'available',999,1,1);
                     DELETE FROM {schema}.retained_authority_usage WHERE tenant_scope='artifact-only-tenant' AND scope_kind='{scope_kind}' AND scope_id='{scope_id}';
                     ALTER TABLE {schema}.artifact_key_generations ENABLE ROW LEVEL SECURITY; ALTER TABLE {schema}.artifact_key_generations FORCE ROW LEVEL SECURITY;
                     ALTER TABLE {schema}.content_objects ENABLE ROW LEVEL SECURITY; ALTER TABLE {schema}.content_objects FORCE ROW LEVEL SECURITY;
                     ALTER TABLE {schema}.retained_authority_usage ENABLE ROW LEVEL SECURITY; ALTER TABLE {schema}.retained_authority_usage FORCE ROW LEVEL SECURITY"
                ))
                .await
                .unwrap();
            let before = migration_rollback_snapshot(&client, &schema).await;
            let Err(error) = PostgresTaskStore::open(target.clone()).await else {
                panic!("artifact-only missing usage row migrated")
            };
            assert_eq!(error, PostgresStoreError::RetainedAuthorityMaterializationMismatch);
            assert_eq!(migration_rollback_snapshot(&client, &schema).await, before);
            drop(client);
            driver.abort();
            PostgresTaskStore::drop_test_schema(&target).await.unwrap();
        }
    })
    .await
    .expect("artifact-only revision-10 scope watchdog");
}

#[test]
fn revision_eleven_permanently_exposes_only_tenant_discovery_rows_to_migrator() {
    let migration = include_str!("../migrations/postgres/0011_ratification_retained_authority.sql");
    for table in [
        "artifact_key_generations",
        "content_objects",
        "callback_configs",
        "callback_events",
        "callback_deliveries",
        "callback_attempts",
        "callback_tenant_scheduler",
    ] {
        assert!(
            migration.contains(&format!(
                "UNION SELECT tenant_scope FROM __SCHEMA__.{table}"
            )),
            "missing tenant discovery for {table}"
        );
    }
    assert!(migration.contains("CREATE POLICY retained_diagnostics ON __SCHEMA__.%I FOR SELECT TO __MIGRATOR__ USING(current_setting(''smesh.internal_global'',true)=''diag-v1'')"));
}

#[tokio::test]
async fn post_v11_artifact_and_callback_only_tenants_require_usage_rows_on_restart() {
    let Some((admin, runtime)) = postgres_urls() else {
        return;
    };
    tokio::time::timeout(Duration::from_secs(120), async move {
        for (index, setup) in [
            "INSERT INTO __SCHEMA__.artifact_key_generations VALUES('artifact-post-v11','artifact-post-v11/confidential','artifact-key','active',1,NULL);",
            "INSERT INTO __SCHEMA__.callback_tenant_scheduler VALUES('callback-post-v11',1);",
        ].into_iter().enumerate() {
            let target=config(&admin,&runtime,&format!("post_v11_discovery_{index}"));
            let store=PostgresTaskStore::open(target.clone()).await.unwrap();
            let schema=target.schema_name().to_owned();
            let (client,connection)=tokio_postgres::connect(&admin,NoTls).await.unwrap();
            let driver=tokio::spawn(connection);
            let tenant=if index==0 { "artifact-post-v11" } else { "callback-post-v11" };
            let table=if index==0 { "artifact_key_generations" } else { "callback_tenant_scheduler" };
            client.batch_execute(&format!("ALTER TABLE {schema}.{table} DISABLE ROW LEVEL SECURITY; ALTER TABLE {schema}.retained_authority_usage DISABLE ROW LEVEL SECURITY; {} DELETE FROM {schema}.retained_authority_usage WHERE tenant_scope='{tenant}'; ALTER TABLE {schema}.{table} ENABLE ROW LEVEL SECURITY; ALTER TABLE {schema}.{table} FORCE ROW LEVEL SECURITY; ALTER TABLE {schema}.retained_authority_usage ENABLE ROW LEVEL SECURITY; ALTER TABLE {schema}.retained_authority_usage FORCE ROW LEVEL SECURITY;",setup.replace("__SCHEMA__",&schema))).await.unwrap();
            drop(store);
            let Err(error)=PostgresTaskStore::open(target.clone()).await else { panic!("post-v11 {table}-only tenant escaped discovery") };
            assert_eq!(error,PostgresStoreError::InvalidSchema);
            drop(client); driver.abort();
            PostgresTaskStore::drop_test_schema(&target).await.unwrap();
        }
    }).await.expect("post-v11 tenant discovery watchdog");
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn populated_revision_ten_enforces_each_retained_scope_at_exact_boundary() {
    let Some((admin, runtime)) = postgres_urls() else {
        return;
    };
    tokio::time::timeout(Duration::from_secs(300), async move {
        let source =
            integrated_postgres_ratification(&admin, &runtime, "v10_boundary_source", false, false)
                .await;
        let ratifier_scope = OwnedTaskScope::new_with_principal_and_authentication(
            source.scope.tenant_scope(),
            source.scope.owner_account_id(),
            smesh_a2a::content_digest(b"boundary-ratifier-principal"),
            VisibilityScope::Own,
            "bearer-jwt",
        )
        .unwrap();
        source
            .store
            .acknowledge_ratification_review(
                &ratifier_scope,
                review(&source.packet, &ratifier_scope, &source.task_id),
                ratification_audit(
                    &source.packet,
                    &ratifier_scope,
                    &source.task_id,
                    "v10-boundary-review-audit",
                    "ratificationReview",
                    1_700_000_010_003,
                ),
            )
            .await
            .unwrap();
        let owner_principal = source.scope.principal_scope().to_owned();
        for (kind, expected_error) in [
            (
                "tenant",
                PostgresStoreError::RetainedAuthorityTenantQuotaExceeded,
            ),
            (
                "account",
                PostgresStoreError::RetainedAuthorityAccountQuotaExceeded,
            ),
            (
                "principal",
                PostgresStoreError::RetainedAuthorityPrincipalQuotaExceeded,
            ),
        ] {
            for over in [false, true] {
                let target = config(&admin, &runtime, &format!("boundary_{kind}_{over}"));
                let schema = target.schema_name().to_owned();
                clone_ratification_rows_into_revision_ten(
                    &admin,
                    &runtime,
                    source.config.schema_name(),
                    &schema,
                )
                .await;
                let (client, connection) = tokio_postgres::connect(&admin, NoTls).await.unwrap();
                let driver = tokio::spawn(connection);
                let mut limits = (67_108_864_u64, 67_108_864_u64, 67_108_864_u64);
                for _ in 0..8 {
                    write_revision_ten_limits(&client, &schema, limits.0, limits.1, limits.2).await;
                    let totals =
                        revision_ten_final_totals(&client, &schema, &owner_principal).await;
                    let next = (
                        totals.0 - u64::from(over && kind == "tenant"),
                        totals.1 - u64::from(over && kind == "account"),
                        totals.2 - u64::from(over && kind == "principal"),
                    );
                    if next == limits {
                        break;
                    }
                    limits = next;
                }
                write_revision_ten_limits(&client, &schema, limits.0, limits.1, limits.2).await;
                let totals = revision_ten_final_totals(&client, &schema, &owner_principal).await;
                assert_eq!(
                    match kind {
                        "tenant" => limits.0,
                        "account" => limits.1,
                        _ => limits.2,
                    },
                    match kind {
                        "tenant" => totals.0,
                        "account" => totals.1,
                        _ => totals.2,
                    } - u64::from(over)
                );
                let before = migration_rollback_snapshot(&client, &schema).await;
                let result = PostgresTaskStore::open(target.clone()).await;
                if over {
                    let Err(error) = result else {
                        panic!("over-limit {kind} migration succeeded")
                    };
                    assert_eq!(error, expected_error, "wrong {kind} migration denial");
                    assert_eq!(migration_rollback_snapshot(&client, &schema).await, before);
                } else {
                    let store = result.unwrap_or_else(|error| {
                        panic!("exact-boundary {kind} migration failed: {error}")
                    });
                    drop(store);
                }
                drop(client);
                driver.abort();
                PostgresTaskStore::drop_test_schema(&target).await.unwrap();
            }
        }
        drop(source.store);
        PostgresTaskStore::drop_test_schema(&source.config)
            .await
            .unwrap();
    })
    .await
    .expect("revision-10 retained-scope boundary watchdog");
}

#[tokio::test]
async fn external_key_binds_an_empty_postgres_ratification_authority() {
    let Some((admin, runtime)) = postgres_urls() else {
        return;
    };
    tokio::time::timeout(Duration::from_secs(45), async move {
        let base = config(&admin, &runtime, "external_key");
        let store = PostgresTaskStore::open(
            base.clone()
                .with_ratification_key(zeroize::Zeroizing::new([0x61; 32])),
        )
        .await
        .unwrap();
        assert!(store.ratification_authority().is_some());
        drop(store);
        assert!(
            PostgresTaskStore::open(
                base.clone()
                    .with_ratification_key(zeroize::Zeroizing::new([0x62; 32])),
            )
            .await
            .is_err()
        );
        let store = PostgresTaskStore::open(
            base.clone()
                .with_ratification_key(zeroize::Zeroizing::new([0x61; 32])),
        )
        .await
        .unwrap();
        drop(store);
        PostgresTaskStore::drop_test_schema(&base).await.unwrap();
    })
    .await
    .expect("PostgreSQL external ratification key watchdog");
}

#[tokio::test]
async fn fresh_catalog_is_v11_rls_forced_and_runtime_least_privileged() {
    let Some((admin, runtime)) = postgres_urls() else {
        return;
    };
    tokio::time::timeout(Duration::from_secs(45), async move {
        let config = unkeyed_config(&admin, &runtime, "catalog");
        let schema = config.schema_name().to_owned();
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        assert!(store.ratification_authority().is_none());

        let (client, connection) = tokio_postgres::connect(&admin, NoTls).await.unwrap();
        let driver = tokio::spawn(connection);
        let metadata = client
            .query_one(
                &format!("SELECT schema_version FROM {schema}.store_metadata WHERE singleton=1"),
                &[],
            )
            .await
            .unwrap();
        assert_eq!(metadata.get::<_, i64>(0), 11);
        let migration = client
            .query_one(
                &format!("SELECT logical_schema_version,name FROM {schema}.schema_migrations WHERE revision=10"),
                &[],
            )
            .await
            .unwrap();
        assert_eq!(migration.get::<_, i64>(0), 10);
        assert_eq!(migration.get::<_, &str>(1), "0010_human_ratification");
        let retained_migration = client
            .query_one(
                &format!("SELECT logical_schema_version,name FROM {schema}.schema_migrations WHERE revision=11"),
                &[],
            )
            .await
            .unwrap();
        assert_eq!(retained_migration.get::<_, i64>(0), 11);
        assert_eq!(
            retained_migration.get::<_, &str>(1),
            "0011_ratification_retained_authority"
        );
        let tables = client
            .query(
                "SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname IN ('ratification_packets','ratification_events') ORDER BY c.relname",
                &[&schema],
            )
            .await
            .unwrap();
        assert_eq!(tables.len(), 2);
        assert!(tables.iter().all(|row| row.get::<_, bool>(1) && row.get::<_, bool>(2)));
        let grants = client
            .query(
                "SELECT table_name,privilege_type FROM information_schema.role_table_grants WHERE table_schema=$1 AND grantee=$1||'_runtime' AND table_name IN ('ratification_packets','ratification_events') ORDER BY table_name,privilege_type",
                &[&schema],
            )
            .await
            .unwrap()
            .into_iter()
            .map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)))
            .collect::<Vec<_>>();
        assert_eq!(grants, [
            ("ratification_events".into(), "INSERT".into()),
            ("ratification_events".into(), "SELECT".into()),
            ("ratification_packets".into(), "INSERT".into()),
            ("ratification_packets".into(), "SELECT".into()),
            ("ratification_packets".into(), "UPDATE".into()),
        ]);

        drop(store);
        drop(client);
        driver.abort();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    })
    .await
    .expect("PostgreSQL ratification catalog watchdog");
}

#[test]
fn runtime_url_parser_remains_available_for_fixture_contract() {
    if let Ok(url) = env::var("SMESH_TEST_POSTGRES_RUNTIME_URL") {
        tokio_postgres::Config::from_str(&url).unwrap();
    }
}

fn admission(now: i64) -> SendMessageAdmission {
    let mut message = a2a::Message::new(a2a::Role::User, vec![a2a::Part::text("build release")]);
    message.message_id = "postgres-ratification-message".into();
    let request = a2a::SendMessageRequest {
        message: message.clone(),
        configuration: None,
        metadata: None,
        tenant: None,
    };
    let task = a2a::Task {
        id: "postgres-ratification-task".into(),
        context_id: "postgres-ratification-context".into(),
        status: a2a::TaskStatus {
            state: a2a::TaskState::Submitted,
            message: None,
            timestamp: chrono::DateTime::from_timestamp_millis(now),
        },
        artifacts: None,
        history: Some(vec![message]),
        metadata: None,
    };
    SendMessageAdmission {
        request,
        streaming: false,
        task: task.clone(),
        original_result: a2a::SendMessageResponse::Task(task),
        input_limits: smesh_a2a::InputLimits::default(),
        now,
        max_attempts: 8,
    }
}

fn admission_audit(task: &str, now: i64) -> AuthorizationAuditInput {
    AuthorizationAuditInput::new(
        format!("postgres-ratification-admission-{task}"),
        "tenant-ratification",
        "owner-ratification",
        "smesh-dev-only-policy",
        1,
        smesh_a2a::content_digest(b"smesh-dev-only-policy/v1"),
        "TaskSend",
        AuthorizationDecisionEffect::Allow,
        "ratification fixture admission",
        "task",
        smesh_a2a::content_digest(task.as_bytes()),
        Some(task.into()),
        now,
    )
    .unwrap()
}

fn ratification_audit(
    packet: &smesh_a2a::ReviewPacket,
    scope: &OwnedTaskScope,
    task: &str,
    id: &str,
    operation: &str,
    now: i64,
) -> AuthorizationAuditInput {
    AuthorizationAuditInput::new(
        id,
        scope.tenant_scope(),
        scope.owner_account_id(),
        packet.authorization_policy_id.clone(),
        packet.authorization_policy_revision,
        packet.authorization_policy_digest.clone(),
        operation,
        AuthorizationDecisionEffect::Allow,
        "authorized",
        "ratification",
        packet.packet_hash.clone(),
        Some(task.into()),
        now,
    )
    .unwrap()
}

fn review(
    packet: &smesh_a2a::ReviewPacket,
    scope: &OwnedTaskScope,
    task: &str,
) -> ReviewAcknowledgement {
    ReviewAcknowledgement {
        tenant_id: scope.tenant_scope().into(),
        task_id: task.into(),
        generation: packet.generation,
        account_id: scope.owner_account_id().into(),
        authorization_policy_id: packet.authorization_policy_id.clone(),
        authorization_policy_revision: packet.authorization_policy_revision,
        authorization_policy_digest: packet.authorization_policy_digest.clone(),
        principal_scope: scope.principal_scope().into(),
        authentication_method: scope.authentication_method().into(),
        context_id: packet.context_id.clone(),
        request_digest: packet.request_digest.clone(),
        ratification_key_generation: packet.ratification_key_generation.clone(),
        expected_revision: 0,
        checkpoint_hash: packet.checkpoint_hash.clone(),
        packet_hash: packet.packet_hash.clone(),
        evidence_hashes: packet.evidence_hashes.clone(),
        artifact_hashes: packet.artifacts.iter().map(|a| a.digest.clone()).collect(),
        artifact_manifest_digest: packet.artifact_set_digest.clone(),
        uncertainty_acknowledged: true,
        idempotency_key: "postgres-review".into(),
        reviewed_at_millis: 1_700_000_010_003,
    }
}

fn approve(
    packet: &smesh_a2a::ReviewPacket,
    scope: &OwnedTaskScope,
    task: &str,
) -> RatificationCommand {
    RatificationCommand {
        tenant_id: scope.tenant_scope().into(),
        task_id: task.into(),
        generation: packet.generation,
        account_id: scope.owner_account_id().into(),
        authorization_policy_id: packet.authorization_policy_id.clone(),
        authorization_policy_revision: packet.authorization_policy_revision,
        authorization_policy_digest: packet.authorization_policy_digest.clone(),
        principal_scope: scope.principal_scope().into(),
        authentication_method: scope.authentication_method().into(),
        context_id: packet.context_id.clone(),
        request_digest: packet.request_digest.clone(),
        ratification_key_generation: packet.ratification_key_generation.clone(),
        expected_revision: 1,
        checkpoint_hash: packet.checkpoint_hash.clone(),
        packet_hash: packet.packet_hash.clone(),
        artifact_manifest_digest: packet.artifact_set_digest.clone(),
        idempotency_key: "postgres-approve".into(),
        decision: smesh_a2a::HumanDecision::Approve,
        rationale: "approved exact candidate".into(),
        decided_at_millis: 1_700_000_010_004,
    }
}

fn decision(
    packet: &smesh_a2a::ReviewPacket,
    scope: &OwnedTaskScope,
    task: &str,
    key: &str,
    value: HumanDecision,
) -> RatificationCommand {
    RatificationCommand {
        idempotency_key: key.into(),
        decision: value,
        ..approve(packet, scope, task)
    }
}

fn ratification_push_policy() -> smesh_a2a::push::PushPolicy {
    smesh_a2a::push::PushPolicy::parse_bytes(
        br#"
 schema = "smesh-push/1"
 enabled = true
 policy_id = "ratification-push-policy"
 policy_revision = 1
 policy_digest = "sha256:7777777777777777777777777777777777777777777777777777777777777777"
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
 tenant = "tenant-ratification"
 endpoint_id = "ratification-endpoint"
 url = "https://example.com:443/ratification"
 event = "terminal"
 auth = "hmac-sha256"
 key_generation = "key-1"
 secret_file = "/tmp/smesh-ratification-callback-secret"
 "#,
    )
    .unwrap()
}

fn ratification_quota_policy() -> std::sync::Arc<QuotaPolicy> {
    std::sync::Arc::new(
        QuotaPolicy::from_json(
            br#"{
      "schemaVersion":"smesh-quota-policy/v1","policyId":"ratification-quota","revision":1,
      "requestWindowMillis":1000,"reconnectWindowMillis":60000,
      "limits":{
        "requestCount":{"tenant":20,"account":20,"principal":20},
        "concurrentActiveWork":{"tenant":4,"account":4,"principal":4},
        "inputBytes":{"tenant":1048576,"account":1048576,"principal":1048576},
        "outputBytes":{"tenant":1048576,"account":1048576,"principal":1048576},
        "eventCount":{"tenant":1024,"account":1024,"principal":1024},
        "concurrentStreams":{"tenant":4,"account":4,"principal":4},
        "concurrentSubscriptions":{"tenant":4,"account":4,"principal":4},
        "reconnectCount":{"tenant":12,"account":12,"principal":12},
        "retainedAuthorityBytes":{"tenant":16777216,"account":16777216,"principal":16777216}
      },"overrides":[]
    }"#,
        )
        .unwrap(),
    )
}

struct IntegratedPostgresRatification {
    config: PostgresStoreConfig,
    store: PostgresTaskStore,
    task_id: String,
    approved: a2a::Task,
    transcript: Vec<a2a::StreamResponse>,
    scope: OwnedTaskScope,
    packet: smesh_a2a::ReviewPacket,
}

async fn scoped_postgres_task(runtime: &str, schema: &str, task_id: &str) -> a2a::Task {
    let mut scoped_runtime = tokio_postgres::Config::from_str(runtime).unwrap();
    scoped_runtime.options(format!(
        "-c role={schema}_runtime -c smesh.tenant_scope=tenant-ratification"
    ));
    let (client, connection) = scoped_runtime.connect(NoTls).await.unwrap();
    let driver = tokio::spawn(connection);
    let encoded: String = client
        .query_one(
            &format!("SELECT task_json FROM {schema}.tasks WHERE task_id=$1"),
            &[&task_id],
        )
        .await
        .unwrap()
        .get(0);
    drop(client);
    driver.abort();
    serde_json::from_str(&encoded).unwrap()
}

#[allow(clippy::too_many_lines)]
async fn integrated_postgres_ratification(
    admin: &str,
    runtime: &str,
    suffix: &str,
    callbacks: bool,
    quotas: bool,
) -> IntegratedPostgresRatification {
    let mut config = config(admin, runtime, suffix);
    if callbacks {
        config = config.with_push_policy(ratification_push_policy());
    }
    let quota_policy = ratification_quota_policy();
    if quotas {
        config = config.with_quota_policy(std::sync::Arc::clone(&quota_policy));
    }
    let store = PostgresTaskStore::open(config.clone()).await.unwrap();
    let now = 1_700_000_010_000;
    let mut command = admission(now);
    command.streaming = true;
    let task_id = command.task.id.clone();
    let scope = OwnedTaskScope::new_with_principal_and_authentication(
        "tenant-ratification",
        "owner-ratification",
        smesh_a2a::content_digest(b"principal-ratification"),
        VisibilityScope::Own,
        "bearer-jwt",
    )
    .unwrap();
    if quotas {
        let subject = QuotaSubject::new(
            scope.tenant_scope(),
            scope.owner_account_id(),
            scope.principal_scope(),
        )
        .unwrap();
        let input_bytes = serde_json::to_vec(&command.request).unwrap().len() as u64;
        let intent = quota_policy
            .admission_intent(
                &subject,
                &command.request.message.message_id,
                input_bytes,
                command.streaming,
            )
            .unwrap();
        store
            .authorize_and_admit_mutation(
                &scope,
                AuthorizedMutation::with_quota_intent(command, intent),
                admission_audit(&task_id, now),
            )
            .await
            .unwrap();
    } else {
        store
            .authorize_and_admit(&scope, command, admission_audit(&task_id, now))
            .await
            .unwrap();
    }
    let lease = store
        .claim_outbox(&format!("ratification-worker-{suffix}"), now + 1, 60_000)
        .await
        .unwrap()
        .unwrap();
    if quotas {
        let payload = serde_json::to_vec(&lease.request).unwrap();
        let envelope = smesh_a2a::DurableDispatchEnvelope {
            tenant_scope: lease.tenant_scope.clone(),
            dispatch_id: lease.dispatch_id.clone(),
            payload_digest: smesh_a2a::content_digest(&payload),
            request: lease.request.clone(),
            execution_reservation: lease.execution_reservation.clone(),
        };
        let ReceiverAdmission::Execute(receiver) = store
            .begin_receive(envelope, "ratification-receiver", now + 1, 60_000)
            .await
            .unwrap()
        else {
            panic!("ratification receiver lease was not executable")
        };
        store
            .complete_loopback_receive(
                &receiver,
                &[smesh_a2a::MeshEvent::Completed {
                    summary: "sealed candidate result canary".into(),
                }],
                now + 2,
            )
            .await
            .unwrap();
    }
    let initial = store.task_for_outbox(&lease).await.unwrap().unwrap();
    let mut approved = initial.clone();
    approved.status = a2a::TaskStatus {
        state: a2a::TaskState::Completed,
        message: Some(a2a::Message::new(
            a2a::Role::Agent,
            vec![a2a::Part::text("sealed candidate result canary")],
        )),
        timestamp: chrono::DateTime::from_timestamp_millis(now + 2),
    };
    approved.artifacts = Some(vec![a2a::Artifact {
        artifact_id: "sealed-candidate-artifact".into(),
        name: Some("release.txt".into()),
        description: None,
        parts: vec![a2a::Part::text("sealed candidate artifact canary")],
        metadata: None,
        extensions: None,
    }]);
    let transcript = vec![
        a2a::StreamResponse::Task(initial),
        a2a::StreamResponse::Task(approved.clone()),
    ];
    store
        .commit_delivery_for_ratification(
            &lease,
            approved.clone(),
            a2a::SendMessageResponse::Task(approved.clone()),
            &transcript,
            AuthoritativeReviewCandidate::new(
                "release-policy",
                7,
                smesh_a2a::content_digest(b"release-policy-v7"),
                format!("sealed-checkpoint-{suffix}").into_bytes(),
                vec![b"tests passed".to_vec()],
                "bounded uncertainty",
            )
            .unwrap(),
            now + 2,
        )
        .await
        .unwrap();
    let packet = store
        .ratification_view(&scope, &task_id)
        .await
        .unwrap()
        .unwrap()
        .packet;
    IntegratedPostgresRatification {
        config,
        store,
        task_id,
        approved,
        transcript,
        scope,
        packet,
    }
}

#[tokio::test]
async fn postgres_terminal_state_swap_fails_live_view_and_restart_without_mutation() {
    let Some((admin, runtime)) = postgres_urls() else {
        return;
    };
    tokio::time::timeout(Duration::from_secs(45), async move {
        let fixture = integrated_postgres_ratification(&admin, &runtime, "terminal_swap", false, false).await;
        let IntegratedPostgresRatification { config, store, task_id, scope, packet, .. } = fixture;
        store.acknowledge_ratification_review(
            &scope,
            review(&packet, &scope, &task_id),
            ratification_audit(&packet, &scope, &task_id, "terminal-swap-review", "ratificationReview", 1_700_000_010_003),
        ).await.unwrap();
        store.decide_ratification(
            &scope,
            decision(&packet, &scope, &task_id, "terminal-swap-approve", HumanDecision::Approve),
            ratification_audit(&packet, &scope, &task_id, "terminal-swap-decision", "ratificationDecide", 1_700_000_010_004),
        ).await.unwrap();
        let (client, connection) = tokio_postgres::connect(&admin, NoTls).await.unwrap();
        let driver = tokio::spawn(connection);
        client.batch_execute("SET smesh.internal_global='diag-v1'").await.unwrap();
        client
            .batch_execute(&format!(
                "ALTER TABLE {}.ratification_packets DISABLE ROW LEVEL SECURITY;
                 ALTER TABLE {}.ratification_packets DISABLE TRIGGER ratification_packets_identity_immutable;
                 ALTER TABLE {}.ratification_packets DISABLE TRIGGER retained_authority_accounting",
                config.schema_name(),
                config.schema_name(),
                config.schema_name()
            ))
            .await
            .unwrap();
        assert_eq!(
            client
                .execute(
                    &format!(
                        "UPDATE {}.ratification_packets SET state='amended' WHERE tenant_scope=$1 AND task_id=$2",
                        config.schema_name()
                    ),
                    &[&"tenant-ratification", &task_id],
                )
                .await
                .unwrap(),
            1
        );
        client
            .batch_execute(&format!(
                "ALTER TABLE {}.ratification_packets ENABLE TRIGGER ratification_packets_identity_immutable;
                 ALTER TABLE {}.ratification_packets ENABLE TRIGGER retained_authority_accounting;
                 ALTER TABLE {}.ratification_packets ENABLE ROW LEVEL SECURITY;
                 ALTER TABLE {}.ratification_packets FORCE ROW LEVEL SECURITY",
                config.schema_name(),
                config.schema_name(),
                config.schema_name(),
                config.schema_name()
            ))
            .await
            .unwrap();
        let before = postgres_ratification_state(&client, config.schema_name()).await;
        assert!(store.ratification_view(&scope, &task_id).await.is_err());
        assert_eq!(postgres_ratification_state(&client, config.schema_name()).await, before);
        drop(store);
        let Err(error) = PostgresTaskStore::open(config.clone()).await else {
            panic!("terminal state swap survived restart")
        };
        assert_eq!(error, PostgresStoreError::InvalidSchema);
        assert_eq!(postgres_ratification_state(&client, config.schema_name()).await, before);
        drop(client);
        driver.abort();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    }).await.expect("PostgreSQL terminal-state swap watchdog");
}

#[tokio::test]
async fn postgres_replay_rejects_duplicate_delivered_causative_identity_without_mutation() {
    let Some((admin, runtime)) = postgres_urls() else {
        return;
    };
    let fixture =
        integrated_postgres_ratification(&admin, &runtime, "duplicate_cause", false, false).await;
    let IntegratedPostgresRatification {
        config,
        store,
        task_id,
        scope,
        packet,
        ..
    } = fixture;
    let mut command = review(&packet, &scope, &task_id);
    store
        .acknowledge_ratification_review(
            &scope,
            command.clone(),
            ratification_audit(
                &packet,
                &scope,
                &task_id,
                "duplicate-cause-initial-audit",
                "ratificationReview",
                1_700_000_010_003,
            ),
        )
        .await
        .unwrap();

    let (admin_client, admin_connection) = tokio_postgres::connect(&admin, NoTls).await.unwrap();
    let admin_driver = tokio::spawn(admin_connection);
    let schema = config.schema_name();
    admin_client
        .batch_execute(&format!(
            "ALTER TABLE {schema}.idempotency_records DISABLE ROW LEVEL SECURITY;
             ALTER TABLE {schema}.idempotency_records DISABLE TRIGGER USER;
             ALTER TABLE {schema}.outbox DISABLE ROW LEVEL SECURITY;
             ALTER TABLE {schema}.outbox DISABLE TRIGGER USER"
        ))
        .await
        .unwrap();
    assert_eq!(
        clone_postgres_task_row(
            &admin_client,
            schema,
            "idempotency_records",
            &task_id,
            "completed",
            &[("message_id", "duplicate-cause-message")],
        )
        .await,
        1
    );
    assert_eq!(
        clone_postgres_task_row(
            &admin_client,
            schema,
            "outbox",
            &task_id,
            "delivered",
            &[
                ("dispatch_id", "duplicate-cause-dispatch"),
                ("message_id", "duplicate-cause-message"),
            ],
        )
        .await,
        1
    );
    let before = postgres_ratification_state(&admin_client, schema).await;
    command.reviewed_at_millis += 99;
    let error = store
        .acknowledge_ratification_review(
            &scope,
            command,
            ratification_audit(
                &packet,
                &scope,
                &task_id,
                "duplicate-cause-replay-audit",
                "ratificationReview",
                1_700_000_010_102,
            ),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, a2a::error_code::INTERNAL_ERROR);
    assert_eq!(
        postgres_ratification_state(&admin_client, schema).await,
        before
    );
    drop(store);
    drop(admin_client);
    admin_driver.abort();
    PostgresTaskStore::drop_test_schema(&config).await.unwrap();
}

async fn prepare_additional_postgres_ratification(
    store: &PostgresTaskStore,
    scope: &OwnedTaskScope,
    suffix: &str,
    now: i64,
) -> (String, smesh_a2a::ReviewPacket) {
    let mut command = admission(now);
    command.task.id = format!("task-ratification-{suffix}");
    command.task.context_id = format!("context-ratification-{suffix}");
    command.request.message.message_id = format!("message-ratification-{suffix}");
    command.task.history = Some(vec![command.request.message.clone()]);
    command.original_result = a2a::SendMessageResponse::Task(command.task.clone());
    let task_id = command.task.id.clone();
    store
        .authorize_and_admit(scope, command, admission_audit(&task_id, now))
        .await
        .unwrap();
    let worker = format!("{suffix}-worker");
    let lease = store
        .claim_outbox(&worker, now + 1, 60_000)
        .await
        .unwrap()
        .unwrap();
    let initial = store.task_for_outbox(&lease).await.unwrap().unwrap();
    let mut approved = initial.clone();
    approved.status = a2a::TaskStatus {
        state: a2a::TaskState::Completed,
        message: Some(a2a::Message::new(
            a2a::Role::Agent,
            vec![a2a::Part::text("concurrent candidate")],
        )),
        timestamp: chrono::DateTime::from_timestamp_millis(now + 2),
    };
    approved.artifacts = Some(vec![a2a::Artifact {
        artifact_id: format!("{suffix}-artifact"),
        name: Some("release.txt".into()),
        description: None,
        parts: vec![a2a::Part::text("concurrent artifact")],
        metadata: None,
        extensions: None,
    }]);
    store
        .commit_delivery_for_ratification(
            &lease,
            approved.clone(),
            a2a::SendMessageResponse::Task(approved.clone()),
            &[
                a2a::StreamResponse::Task(initial),
                a2a::StreamResponse::Task(approved),
            ],
            AuthoritativeReviewCandidate::new(
                "release-policy",
                7,
                smesh_a2a::content_digest(b"release-policy-v7"),
                format!("{suffix}-checkpoint").into_bytes(),
                vec![format!("{suffix}-evidence").into_bytes()],
                "bounded uncertainty",
            )
            .unwrap(),
            now + 2,
        )
        .await
        .unwrap();
    let packet = store
        .ratification_view(scope, &task_id)
        .await
        .unwrap()
        .unwrap()
        .packet;
    (task_id, packet)
}

#[tokio::test]
async fn concurrent_cross_task_global_idempotency_is_one_success_one_typed_conflict() {
    let Some((admin, runtime)) = postgres_urls() else {
        return;
    };
    tokio::time::timeout(Duration::from_secs(45), async move {
        let fixture = integrated_postgres_ratification(
            &admin,
            &runtime,
            "concurrent_global_key",
            false,
            false,
        )
        .await;
        let (second_task, second_packet) = prepare_additional_postgres_ratification(
            &fixture.store,
            &fixture.scope,
            "concurrent-global-two",
            1_700_000_012_000,
        )
        .await;
        let (client, connection) = tokio_postgres::connect(&admin, NoTls).await.unwrap();
        let driver = tokio::spawn(connection);
        let schema = fixture.config.schema_name();
        client
            .batch_execute("SET smesh.internal_global='diag-v1'")
            .await
            .unwrap();
        let before: i64 = client
            .query_one(
                &format!("SELECT count(*) FROM {schema}.ratification_events"),
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let first_review = review(&fixture.packet, &fixture.scope, &fixture.task_id);
        let second_review = review(&second_packet, &fixture.scope, &second_task);
        let first_audit = ratification_audit(
            &fixture.packet,
            &fixture.scope,
            &fixture.task_id,
            "concurrent-global-first-audit",
            "ratificationReview",
            1_700_000_012_003,
        );
        let second_audit = ratification_audit(
            &second_packet,
            &fixture.scope,
            &second_task,
            "concurrent-global-second-audit",
            "ratificationReview",
            1_700_000_012_003,
        );
        let (first, second) = tokio::join!(
            fixture.store.acknowledge_ratification_review(
                &fixture.scope,
                first_review,
                first_audit
            ),
            fixture.store.acknowledge_ratification_review(
                &fixture.scope,
                second_review,
                second_audit
            )
        );
        let results = [first, second];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        let conflicts = results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .collect::<Vec<_>>();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].code, -32_621);
        let after: i64 = client
            .query_one(
                &format!("SELECT count(*) FROM {schema}.ratification_events"),
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(after, before + 1);
        let states = client
            .query(
                &format!("SELECT state,revision FROM {schema}.ratification_packets WHERE task_id IN ($1,$2) ORDER BY task_id"),
                &[&fixture.task_id, &second_task],
            )
            .await
            .unwrap();
        assert_eq!(states.iter().filter(|row| row.get::<_, i64>(1) == 1).count(), 1);
        assert_eq!(states.iter().filter(|row| row.get::<_, i64>(1) == 0).count(), 1);
        drop(fixture.store);
        drop(client);
        driver.abort();
        PostgresTaskStore::drop_test_schema(&fixture.config)
            .await
            .unwrap();
    })
    .await
    .expect("PostgreSQL concurrent global idempotency watchdog");
}

#[tokio::test]
#[allow(clippy::too_many_lines, clippy::large_futures)]
async fn postgres_cross_task_ratification_idempotency_conflict_is_authenticated_and_atomic() {
    let Some((admin, runtime)) = postgres_urls() else {
        return;
    };
    tokio::time::timeout(Duration::from_secs(45), async move {
        let first =
            integrated_postgres_ratification(&admin, &runtime, "cross_task", false, false).await;
        let IntegratedPostgresRatification {
            config,
            store,
            task_id: first_task,
            scope,
            packet: first_packet,
            ..
        } = first;
        store
            .acknowledge_ratification_review(
                &scope,
                review(&first_packet, &scope, &first_task),
                ratification_audit(
                    &first_packet,
                    &scope,
                    &first_task,
                    "cross-task-first-audit",
                    "ratificationReview",
                    1_700_000_010_003,
                ),
            )
            .await
            .unwrap();

        let now = 1_700_000_011_000;
        let mut command = admission(now);
        command.task.id = "task-ratification-cross-task-two".into();
        command.task.context_id = "context-ratification-cross-task-two".into();
        command.request.message.message_id = "message-ratification-cross-task-two".into();
        command.task.history = Some(vec![command.request.message.clone()]);
        command.original_result = a2a::SendMessageResponse::Task(command.task.clone());
        let second_task = command.task.id.clone();
        store
            .authorize_and_admit(&scope, command, admission_audit(&second_task, now))
            .await
            .unwrap();
        let lease = store
            .claim_outbox("cross-task-worker", now + 1, 60_000)
            .await
            .unwrap()
            .unwrap();
        let initial = store.task_for_outbox(&lease).await.unwrap().unwrap();
        let mut approved = initial.clone();
        approved.status = a2a::TaskStatus {
            state: a2a::TaskState::Completed,
            message: Some(a2a::Message::new(
                a2a::Role::Agent,
                vec![a2a::Part::text("cross task candidate")],
            )),
            timestamp: chrono::DateTime::from_timestamp_millis(now + 2),
        };
        approved.artifacts = Some(vec![a2a::Artifact {
            artifact_id: "cross-task-artifact".into(),
            name: Some("release.txt".into()),
            description: None,
            parts: vec![a2a::Part::text("cross task artifact")],
            metadata: None,
            extensions: None,
        }]);
        store
            .commit_delivery_for_ratification(
                &lease,
                approved.clone(),
                a2a::SendMessageResponse::Task(approved.clone()),
                &[
                    a2a::StreamResponse::Task(initial),
                    a2a::StreamResponse::Task(approved),
                ],
                AuthoritativeReviewCandidate::new(
                    "release-policy",
                    7,
                    smesh_a2a::content_digest(b"release-policy-v7"),
                    b"cross-task-checkpoint".to_vec(),
                    vec![b"cross task evidence".to_vec()],
                    "bounded uncertainty",
                )
                .unwrap(),
                now + 2,
            )
            .await
            .unwrap();
        let second_packet = store
            .ratification_view(&scope, &second_task)
            .await
            .unwrap()
            .unwrap()
            .packet;
        let (snapshot_client, snapshot_connection) =
            tokio_postgres::connect(&admin, NoTls).await.unwrap();
        let snapshot_driver = tokio::spawn(snapshot_connection);
        let before = postgres_ratification_state(&snapshot_client, config.schema_name()).await;
        let error = store
            .acknowledge_ratification_review(
                &scope,
                review(&second_packet, &scope, &second_task),
                ratification_audit(
                    &second_packet,
                    &scope,
                    &second_task,
                    "cross-task-second-audit",
                    "ratificationReview",
                    now + 3,
                ),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, -32_621);
        assert_eq!(
            postgres_ratification_state(&snapshot_client, config.schema_name()).await,
            before
        );
        snapshot_client
            .batch_execute(&format!(
                "ALTER TABLE {}.idempotency_records DISABLE ROW LEVEL SECURITY;
                 ALTER TABLE {}.idempotency_records DISABLE TRIGGER USER",
                config.schema_name(),
                config.schema_name()
            ))
            .await
            .unwrap();
        assert_eq!(
            snapshot_client
                .execute(
                    &format!(
                        "UPDATE {}.idempotency_records SET actor_account_id='forged-conflict-owner' WHERE task_id=$1",
                        config.schema_name()
                    ),
                    &[&first_task],
                )
                .await
                .unwrap(),
            1,
        );
        let owner_tampered_before =
            postgres_ratification_state(&snapshot_client, config.schema_name()).await;
        let error = store
            .acknowledge_ratification_review(
                &scope,
                review(&second_packet, &scope, &second_task),
                ratification_audit(
                    &second_packet,
                    &scope,
                    &second_task,
                    "cross-task-tampered-owner-audit",
                    "ratificationReview",
                    now + 4,
                ),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, a2a::error_code::INTERNAL_ERROR);
        assert_eq!(
            postgres_ratification_state(&snapshot_client, config.schema_name()).await,
            owner_tampered_before
        );
        snapshot_client
            .batch_execute(&format!(
                "ALTER TABLE {}.idempotency_records DISABLE ROW LEVEL SECURITY",
                config.schema_name()
            ))
            .await
            .unwrap();
        assert_eq!(
            snapshot_client
                .execute(
                    &format!(
                        "UPDATE {}.idempotency_records SET actor_account_id='owner-ratification' WHERE task_id=$1",
                        config.schema_name()
                    ),
                    &[&first_task],
                )
                .await
                .unwrap(),
            1,
        );
        snapshot_client
            .batch_execute(&format!(
                "ALTER TABLE {}.ratification_events DISABLE ROW LEVEL SECURITY;
                 ALTER TABLE {}.ratification_events DISABLE TRIGGER USER",
                config.schema_name(),
                config.schema_name()
            ))
            .await
            .unwrap();
        assert_eq!(
            snapshot_client
                .execute(
                    &format!(
                        "UPDATE {}.ratification_events SET receipt_json='{{}}' WHERE task_id=$1",
                        config.schema_name()
                    ),
                    &[&first_task],
                )
                .await
                .unwrap(),
            1,
        );
        let tampered_before =
            postgres_ratification_state(&snapshot_client, config.schema_name()).await;
        let error = store
            .acknowledge_ratification_review(
                &scope,
                review(&second_packet, &scope, &second_task),
                ratification_audit(
                    &second_packet,
                    &scope,
                    &second_task,
                    "cross-task-tampered-chain-audit",
                    "ratificationReview",
                    now + 4,
                ),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, a2a::error_code::INTERNAL_ERROR);
        assert_eq!(
            postgres_ratification_state(&snapshot_client, config.schema_name()).await,
            tampered_before
        );
        drop(snapshot_client);
        snapshot_driver.abort();
        drop(store);
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    })
    .await
    .expect("PostgreSQL cross-task idempotency watchdog");
}

#[tokio::test]
async fn ratification_event_capacity_denial_is_atomic_at_all_retained_scopes() {
    let Some((admin, runtime)) = postgres_urls() else {
        return;
    };
    tokio::time::timeout(Duration::from_secs(45), async move {
        let fixture = integrated_postgres_ratification(
            &admin,
            &runtime,
            "retained_event_denial",
            false,
            false,
        )
        .await;
        let schema = fixture.config.schema_name();
        let (client, connection) = tokio_postgres::connect(&admin, NoTls).await.unwrap();
        let driver = tokio::spawn(connection);
        client
            .execute(
                "SELECT set_config('smesh.tenant_scope','tenant-ratification',false)",
                &[],
            )
            .await
            .unwrap();
        client
            .batch_execute(&format!(
                "ALTER TABLE {schema}.retained_authority_usage DISABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.ratification_packets DISABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.ratification_events DISABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.authorization_decisions DISABLE ROW LEVEL SECURITY"
            ))
            .await
            .unwrap();
        assert_eq!(
            client
                .execute(
                    &format!("UPDATE {schema}.retained_authority_usage SET retained_bytes=67108864 WHERE tenant_scope='tenant-ratification'"),
                    &[],
                )
                .await
                .unwrap(),
            4,
        );

        let denied = fixture
            .store
            .acknowledge_ratification_review(
                &fixture.scope,
                review(&fixture.packet, &fixture.scope, &fixture.task_id),
                ratification_audit(
                    &fixture.packet,
                    &fixture.scope,
                    &fixture.task_id,
                    "retained-event-denial-audit",
                    "ratificationReview",
                    1_700_000_010_003,
                ),
            )
            .await;
        assert!(denied.is_err());
        let state = client
            .query_one(
                &format!("SELECT p.state,p.revision,(SELECT count(*) FROM {schema}.ratification_events),(SELECT count(*) FROM {schema}.authorization_decisions WHERE decision_id='retained-event-denial-audit') FROM {schema}.ratification_packets p WHERE p.task_id=$1"),
                &[&fixture.task_id],
            )
            .await
            .unwrap();
        assert_eq!(state.get::<_, &str>(0), "awaiting_review");
        assert_eq!(state.get::<_, i64>(1), 0);
        assert_eq!(state.get::<_, i64>(2), 0);
        assert_eq!(state.get::<_, i64>(3), 0);

        let cleanup = fixture.config.clone();
        drop(fixture.store);
        drop(client);
        driver.abort();
        PostgresTaskStore::drop_test_schema(&cleanup).await.unwrap();
    })
    .await
    .expect("PostgreSQL ratification retained-event denial watchdog");
}

#[tokio::test]
#[allow(clippy::too_many_lines, clippy::large_futures)] // One real transaction fixture covers fencing, RLS, restart, tamper, and byte parity.
async fn delivery_atomically_freezes_packet_and_scoped_verified_view() {
    let Some((admin, runtime)) = postgres_urls() else {
        return;
    };
    tokio::time::timeout(Duration::from_secs(45), async move {
        let config = config(&admin, &runtime, "delivery");
        let fixed_receipt_key = [0x5a; 32];
        let bootstrap = PostgresTaskStore::open(config.clone()).await.unwrap();
        drop(bootstrap);
        let (key_client, key_connection) = tokio_postgres::connect(&admin, NoTls).await.unwrap();
        let key_driver = tokio::spawn(key_connection);
        key_client
            .batch_execute(&format!(
                "ALTER TABLE {}.store_metadata DISABLE TRIGGER store_metadata_immutable",
                config.schema_name()
            ))
            .await
            .unwrap();
        key_client
            .execute(
                &format!(
                    "UPDATE {}.store_metadata SET receipt_key=$1 WHERE singleton=1",
                    config.schema_name()
                ),
                &[&fixed_receipt_key.as_slice()],
            )
            .await
            .unwrap();
        key_client
            .batch_execute(&format!(
                "ALTER TABLE {}.store_metadata ENABLE TRIGGER store_metadata_immutable",
                config.schema_name()
            ))
            .await
            .unwrap();
        drop(key_client);
        key_driver.abort();
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        let now = 1_700_000_010_000;
        let command = admission(now);
        let task_id = command.task.id.clone();
        let scope = OwnedTaskScope::new_with_principal_and_authentication(
            "tenant-ratification",
            "owner-ratification",
            smesh_a2a::content_digest(b"principal-ratification"),
            VisibilityScope::Own,
            "bearer-jwt",
        )
        .unwrap();
        store
            .authorize_and_admit(&scope, command, admission_audit(&task_id, now))
            .await
            .unwrap();
        let lease = store
            .claim_outbox("ratification-worker", now + 1, 60_000)
            .await
            .unwrap()
            .unwrap();
        let initial = store.task_for_outbox(&lease).await.unwrap().unwrap();
        let mut completed = initial.clone();
        completed.status = a2a::TaskStatus {
            state: a2a::TaskState::Completed,
            message: Some(a2a::Message::new(
                a2a::Role::Agent,
                vec![a2a::Part::text("ready")],
            )),
            timestamp: chrono::DateTime::from_timestamp_millis(now + 2),
        };
        completed.artifacts = Some(vec![a2a::Artifact {
            artifact_id: "artifact-ratified".into(),
            name: Some("release.txt".into()),
            description: None,
            parts: vec![a2a::Part::text("private candidate")],
            metadata: None,
            extensions: None,
        }]);
        let transcript = vec![
            a2a::StreamResponse::Task(initial),
            a2a::StreamResponse::StatusUpdate(a2a::TaskStatusUpdateEvent {
                task_id: completed.id.clone(),
                context_id: completed.context_id.clone(),
                status: completed.status.clone(),
                metadata: None,
            }),
        ];
        let candidate = AuthoritativeReviewCandidate::new(
            "release-policy",
            7,
            smesh_a2a::content_digest(b"release-policy-v7"),
            b"sealed-checkpoint-v7".to_vec(),
            vec![b"tests passed".to_vec()],
            "bounded uncertainty",
        )
        .unwrap();
        let mut wrong_lease = lease.clone();
        wrong_lease.lease_token = smesh_a2a::content_digest(b"wrong-ratification-fence");
        assert_eq!(
            store
                .commit_delivery_for_ratification(
                    &wrong_lease,
                    completed.clone(),
                    a2a::SendMessageResponse::Task(completed.clone()),
                    &transcript,
                    candidate.clone(),
                    now + 2,
                )
                .await
                .unwrap(),
            smesh_a2a::TransitionOutcome::Stale
        );
        assert!(store.ratification_view(&scope, &task_id).await.unwrap().is_none());
        assert_eq!(
            store.task_for_outbox(&lease).await.unwrap().unwrap().status.state,
            a2a::TaskState::Submitted
        );

        // Force the final packet insert to fail after all preceding delivery writes. The
        // fenced transaction must roll every task/event/idempotency/transcript/outbox effect
        // back, leaving the same lease usable for the real commit.
        let schema = config.schema_name();
        let (rollback_client, rollback_connection) =
            tokio_postgres::connect(&admin, NoTls).await.unwrap();
        let rollback_driver = tokio::spawn(rollback_connection);
        rollback_client
            .batch_execute(&format!(
                "CREATE FUNCTION {schema}.reject_ratification_packet() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced ratification rollback'; END $$;
                 CREATE TRIGGER reject_ratification_packet BEFORE INSERT ON {schema}.ratification_packets FOR EACH ROW EXECUTE FUNCTION {schema}.reject_ratification_packet();"
            ))
            .await
            .unwrap();
        assert!(store
            .commit_delivery_for_ratification(
                &lease,
                completed.clone(),
                a2a::SendMessageResponse::Task(completed.clone()),
                &transcript,
                candidate.clone(),
                now + 2,
            )
            .await
            .is_err());
        assert!(store.ratification_view(&scope, &task_id).await.unwrap().is_none());
        assert_eq!(
            store.task_for_outbox(&lease).await.unwrap().unwrap().status.state,
            a2a::TaskState::Submitted
        );
        rollback_client
            .batch_execute(&format!(
                "DROP TRIGGER reject_ratification_packet ON {schema}.ratification_packets;
                 DROP FUNCTION {schema}.reject_ratification_packet();"
            ))
            .await
            .unwrap();
        drop(rollback_client);
        rollback_driver.abort();

        assert_eq!(
            store
                .commit_delivery_for_ratification(
                    &lease,
                    completed.clone(),
                    a2a::SendMessageResponse::Task(completed.clone()),
                    &transcript,
                    candidate.clone(),
                    now + 2,
                )
                .await
                .unwrap(),
            smesh_a2a::TransitionOutcome::Applied
        );
        let view = store
            .ratification_view(&scope, &task_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            store
                .commit_delivery_for_ratification(
                    &lease,
                    completed.clone(),
                    a2a::SendMessageResponse::Task(completed.clone()),
                    &transcript,
                    candidate.clone(),
                    now + 3,
                )
                .await
                .unwrap(),
            smesh_a2a::TransitionOutcome::Stale
        );
        assert_eq!(
            store
                .ratification_view(&scope, &task_id)
                .await
                .unwrap()
                .unwrap(),
            view
        );
        assert_eq!(view.packet.generation, 1);
        assert_eq!(view.packet.task_revision, 2);
        assert_eq!(view.packet.principal_scope, scope.principal_scope());
        assert_eq!(view.packet.authentication_method, "bearer-jwt");
        assert!(
            serde_json::to_string(&view.packet)
                .unwrap()
                .contains("private candidate")
        );

        // With identical key material, timestamps, admission bindings, and candidate bytes,
        // PostgreSQL must persist the exact same canonical packet bytes as SQLite.
        let sqlite_root = env::temp_dir().join(format!(
            "smesh-postgres-ratification-parity-{:016x}",
            rand::random::<u64>()
        ));
        std::fs::create_dir(&sqlite_root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&sqlite_root, std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let sqlite_path = sqlite_root.join("ratification.sqlite3");
        let sqlite_bootstrap = SqliteTaskStore::open_with_ratification_key(
            &sqlite_path,
            16,
            zeroize::Zeroizing::new([0x60; 32]),
            false,
        )
        .await
        .unwrap();
        drop(sqlite_bootstrap);
        let sqlite_connection = rusqlite::Connection::open(&sqlite_path).unwrap();
        sqlite_connection
            .execute(
                "UPDATE store_metadata SET receipt_key=?1 WHERE singleton=1",
                [fixed_receipt_key.as_slice()],
            )
            .unwrap();
        drop(sqlite_connection);
        let sqlite = SqliteTaskStore::open_with_ratification_key(
            &sqlite_path,
            16,
            zeroize::Zeroizing::new([0x60; 32]),
            false,
        )
        .await
        .unwrap();
        sqlite
            .authorize_and_admit(
                &scope,
                admission(now),
                admission_audit(&task_id, now),
            )
            .await
            .unwrap();
        let sqlite_lease = sqlite
            .claim_outbox("ratification-worker", now + 1, 60_000)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            sqlite
                .commit_delivery_for_ratification(
                    &sqlite_lease,
                    completed.clone(),
                    a2a::SendMessageResponse::Task(completed.clone()),
                    &transcript,
                    candidate.clone(),
                    now + 2,
                )
                .await
                .unwrap(),
            smesh_a2a::TransitionOutcome::Applied
        );
        let sqlite_view = sqlite
            .ratification_view(&scope, &task_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::to_vec(&sqlite_view.packet).unwrap(),
            serde_json::to_vec(&view.packet).unwrap()
        );
        let review_command = review(&view.packet, &scope, &task_id);
        let sqlite_reviewed = sqlite
            .acknowledge_ratification_review(
                &scope,
                review_command.clone(),
                ratification_audit(&view.packet, &scope, &task_id, "postgres-review-audit", "ratificationReview", now + 3),
            )
            .await
            .unwrap();
        let decision = approve(&view.packet, &scope, &task_id);
        let sqlite_approved = sqlite
            .decide_ratification(
                &scope,
                decision.clone(),
                ratification_audit(&view.packet, &scope, &task_id, "postgres-approve-audit", "ratificationDecide", now + 5),
            )
            .await
            .unwrap();
        let sqlite_approved_view = sqlite.ratification_view(&scope, &task_id).await.unwrap().unwrap();
        drop(sqlite);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", sqlite_path.display()));
        }
        let _ = std::fs::remove_dir(sqlite_root);

        let reviewed = store
            .acknowledge_ratification_review(
                &scope,
                review_command.clone(),
                ratification_audit(&view.packet, &scope, &task_id, "postgres-review-audit", "ratificationReview", now + 3),
            )
            .await
            .unwrap();
        assert_eq!(serde_json::to_vec(&reviewed).unwrap(), serde_json::to_vec(&sqlite_reviewed).unwrap());
        let replayed = store
            .acknowledge_ratification_review(
                &scope,
                review_command,
                ratification_audit(&view.packet, &scope, &task_id, "postgres-review-replay-audit", "ratificationReview", now + 4),
            )
            .await
            .unwrap();
        assert_eq!(reviewed, replayed);
        let approved_receipt = store
            .decide_ratification(
                &scope,
                decision.clone(),
                ratification_audit(&view.packet, &scope, &task_id, "postgres-approve-audit", "ratificationDecide", now + 5),
            )
            .await
            .unwrap();
        assert_eq!(serde_json::to_vec(&approved_receipt).unwrap(), serde_json::to_vec(&sqlite_approved).unwrap());
        assert_eq!(
            approved_receipt,
            store.decide_ratification(
                &scope,
                decision,
                ratification_audit(&view.packet, &scope, &task_id, "postgres-approve-replay-audit", "ratificationDecide", now + 6),
            ).await.unwrap()
        );
        let approved_view = store.ratification_view(&scope, &task_id).await.unwrap().unwrap();
        assert_eq!(approved_view.state, smesh_a2a::RatificationState::Approved);
        assert_eq!(approved_view.history.len(), 2);
        assert_eq!(approved_view, sqlite_approved_view);

        let foreign =
            OwnedTaskScope::new("tenant-ratification", "another-owner", VisibilityScope::Own)
                .unwrap();
        assert!(
            store
                .ratification_view(&foreign, &task_id)
                .await
                .unwrap()
                .is_none()
        );
        let schema = config.schema_name();
        let mut wrong_runtime = tokio_postgres::Config::from_str(&runtime).unwrap();
        wrong_runtime.options(format!("-c role={schema}_runtime -c smesh.tenant_scope=wrong-tenant"));
        let (wrong_client, wrong_connection) = wrong_runtime.connect(NoTls).await.unwrap();
        let wrong_driver = tokio::spawn(wrong_connection);
        assert_eq!(
            wrong_client
                .query_one(&format!("SELECT count(*) FROM {schema}.ratification_packets"), &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
        drop(wrong_client);
        wrong_driver.abort();
        let mut right_runtime = tokio_postgres::Config::from_str(&runtime).unwrap();
        right_runtime.options(format!("-c role={schema}_runtime -c smesh.tenant_scope=tenant-ratification"));
        let (right_client, right_connection) = right_runtime.connect(NoTls).await.unwrap();
        let right_driver = tokio::spawn(right_connection);
        assert_eq!(
            right_client
                .query_one(&format!("SELECT count(*) FROM {schema}.ratification_packets"), &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            1
        );
        assert!(right_client.execute(
            &format!("UPDATE {schema}.ratification_packets SET packet_hash=$1"),
            &[&smesh_a2a::content_digest(b"forged-packet")],
        ).await.is_err());
        assert!(right_client.execute(
            &format!("DELETE FROM {schema}.ratification_packets"), &[],
        ).await.is_err());
        drop(right_client);
        right_driver.abort();
        drop(store);
        let reopened = PostgresTaskStore::open(config.clone()).await.unwrap();
        assert!(reopened.ratification_view(&scope, &task_id).await.unwrap().is_some());
        drop(reopened);
        let (admin_client, admin_connection) = tokio_postgres::connect(&admin, NoTls).await.unwrap();
        let admin_driver = tokio::spawn(admin_connection);
        let schema = config.schema_name();
        admin_client
            .batch_execute(&format!(
                "ALTER TABLE {schema}.ratification_packets DISABLE TRIGGER ratification_packets_identity_immutable;
                 ALTER TABLE {schema}.ratification_packets DISABLE TRIGGER retained_authority_accounting;"
            ))
            .await
            .unwrap();
        let mut runtime_config = tokio_postgres::Config::from_str(&runtime).unwrap();
        runtime_config.options(format!(
            "-c role={schema}_runtime -c smesh.tenant_scope=tenant-ratification"
        ));
        let (runtime_client, runtime_connection) = runtime_config.connect(NoTls).await.unwrap();
        let runtime_driver = tokio::spawn(runtime_connection);
        assert_eq!(
            runtime_client
                .execute(
                    &format!("UPDATE {schema}.ratification_packets SET packet_json='{{}}'"),
                    &[],
                )
                .await
                .unwrap(),
            1
        );
        drop(runtime_client);
        runtime_driver.abort();
        admin_client
            .batch_execute(&format!(
                "ALTER TABLE {schema}.ratification_packets ENABLE TRIGGER ratification_packets_identity_immutable;
                 ALTER TABLE {schema}.ratification_packets ENABLE TRIGGER retained_authority_accounting;"
            ))
            .await
            .unwrap();
        match PostgresTaskStore::open(config.clone()).await {
            Err(smesh_a2a::PostgresStoreError::InvalidSchema) => {}
            Err(error) => panic!("unexpected tamper classification: {error}"),
            Ok(_) => panic!("tampered ratification packet reopened"),
        }
        drop(admin_client);
        admin_driver.abort();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    })
    .await
    .expect("PostgreSQL ratification delivery watchdog");
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn postgres_exact_replay_rejects_corrupt_packet_and_event_columns() {
    let Some((admin, runtime)) = postgres_urls() else {
        return;
    };
    for (index, (suffix, table, _trigger, mutation)) in [
        (
            "replay_task_state",
            "tasks",
            "tasks_identity_immutable",
            "state='TASK_STATE_COMPLETED'",
        ),
        (
            "replay_task_revision",
            "tasks",
            "tasks_identity_immutable",
            "revision=revision+1",
        ),
        (
            "replay_task_json",
            "tasks",
            "tasks_identity_immutable",
            "task_json='{}'",
        ),
        (
            "replay_task_owner",
            "tasks",
            "tasks_identity_immutable",
            "owner_account_id='forged-owner'",
        ),
        (
            "replay_task_context",
            "tasks",
            "tasks_identity_immutable",
            "context_id='forged-context'",
        ),
        (
            "replay_task_timestamp",
            "tasks",
            "tasks_identity_immutable",
            "status_timestamp='2099-01-01T00:00:00+00:00'",
        ),
        (
            "replay_task_policy",
            "tasks",
            "tasks_identity_immutable",
            "authorization_policy_id='forged-policy'",
        ),
        (
            "replay_task_policy_revision",
            "tasks",
            "tasks_identity_immutable",
            "authorization_policy_revision=authorization_policy_revision+1",
        ),
        (
            "replay_task_policy_digest",
            "tasks",
            "tasks_identity_immutable",
            "authorization_policy_digest='sha256:0000000000000000000000000000000000000000000000000000000000000000'",
        ),
        (
            "replay_task_principal",
            "tasks",
            "tasks_identity_immutable",
            "principal_scope='forged-principal'",
        ),
        (
            "replay_task_auth",
            "tasks",
            "tasks_identity_immutable",
            "authentication_method='forged-authentication'",
        ),
        (
            "replay_cause_revision",
            "outbox",
            "outbox_identity_immutable",
            "causative_revision=causative_revision+1",
        ),
        (
            "replay_cause_state",
            "outbox",
            "outbox_identity_immutable",
            "state='dead'",
        ),
        (
            "replay_cause_message",
            "outbox",
            "outbox_identity_immutable",
            "message_id='forged-cause-message'",
        ),
        (
            "replay_identity_actor",
            "idempotency_records",
            "idempotency_identity_immutable",
            "actor_account_id='forged-cause-actor'",
        ),
        (
            "replay_identity_legacy_null_actor",
            "idempotency_records",
            "idempotency_identity_immutable",
            "actor_account_id=NULL",
        ),
        (
            "replay_identity_request",
            "idempotency_records",
            "idempotency_identity_immutable",
            "request_digest='sha256:0000000000000000000000000000000000000000000000000000000000000000'",
        ),

        (
            "replay_packet_json",
            "ratification_packets",
            "ratification_packets_identity_immutable",
            "packet_json='{}'",
        ),
        (
            "replay_packet_hash",
            "ratification_packets",
            "ratification_packets_identity_immutable",
            "packet_hash='sha256:0000000000000000000000000000000000000000000000000000000000000000'",
        ),
        (
            "replay_packet_seal",
            "ratification_packets",
            "ratification_packets_identity_immutable",
            "packet_seal='forged'",
        ),
        (
            "replay_checkpoint",
            "ratification_packets",
            "ratification_packets_identity_immutable",
            "checkpoint_hash='sha256:0000000000000000000000000000000000000000000000000000000000000000'",
        ),
        (
            "replay_candidate_task",
            "ratification_packets",
            "ratification_packets_identity_immutable",
            "approved_task_json='{}'",
        ),
        (
            "replay_candidate_result",
            "ratification_packets",
            "ratification_packets_identity_immutable",
            "approved_result_json='{}'",
        ),
        (
            "replay_candidate_transcript",
            "ratification_packets",
            "ratification_packets_identity_immutable",
            "approved_transcript_json='[]'",
        ),
        (
            "replay_event_action",
            "ratification_events",
            "ratification_events_no_update",
            "action='approve'",
        ),
        (
            "replay_event_digest",
            "ratification_events",
            "ratification_events_no_update",
            "command_digest='sha256:0000000000000000000000000000000000000000000000000000000000000000'",
        ),
        (
            "replay_event_receipt",
            "ratification_events",
            "ratification_events_no_update",
            "receipt_json='{}'",
        ),
        (
            "replay_event_hash",
            "ratification_events",
            "ratification_events_no_update",
            "receipt_hash='sha256:0000000000000000000000000000000000000000000000000000000000000000'",
        ),
        (
            "replay_event_seal",
            "ratification_events",
            "ratification_events_no_update",
            "receipt_seal='forged'",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = integrated_postgres_ratification(
            &admin,
            &runtime,
            &format!("r{index}"),
            false,
            false,
        )
        .await;
        let IntegratedPostgresRatification {
            config,
            store,
            task_id,
            scope,
            packet,
            ..
        } = fixture;
        let mut command = review(&packet, &scope, &task_id);
        let receipt = store
            .acknowledge_ratification_review(
                &scope,
                command.clone(),
                ratification_audit(
                    &packet,
                    &scope,
                    &task_id,
                    &format!("{suffix}-initial-audit"),
                    "ratificationReview",
                    1_700_000_010_003,
                ),
            )
            .await
            .unwrap();
        assert_eq!(receipt.revision, 1);

        let (admin_client, admin_connection) =
            tokio_postgres::connect(&admin, NoTls).await.unwrap();
        let admin_driver = tokio::spawn(admin_connection);
        let schema = config.schema_name();
        admin_client
            .batch_execute(&format!(
                "ALTER TABLE {schema}.{table} DISABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.{table} DISABLE TRIGGER USER"
            ))
            .await
            .unwrap();
        admin_client
            .execute(&format!("UPDATE {schema}.{table} SET {mutation}"), &[])
            .await
            .unwrap();
        let before = postgres_ratification_state(&admin_client, schema).await;

        command.reviewed_at_millis += 99;
        let error = store
            .acknowledge_ratification_review(
                &scope,
                command,
                ratification_audit(
                    &packet,
                    &scope,
                    &task_id,
                    &format!("{suffix}-replay-audit"),
                    "ratificationReview",
                    1_700_000_010_102,
                ),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, a2a::error_code::INTERNAL_ERROR, "{mutation}");
        assert_eq!(
            postgres_ratification_state(&admin_client, schema).await,
            before,
            "failed PostgreSQL replay mutated durable state: {mutation}"
        );
        drop(store);
        drop(admin_client);
        admin_driver.abort();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    }
}

#[tokio::test]
async fn postgres_revision_zero_packet_rejects_orphan_receipt_without_mutation() {
    let Some((admin, runtime)) = postgres_urls() else {
        return;
    };
    let fixture =
        integrated_postgres_ratification(&admin, &runtime, "revision_zero_orphan", false, false)
            .await;
    let IntegratedPostgresRatification {
        config,
        store,
        task_id,
        scope,
        packet,
        ..
    } = fixture;
    store
        .acknowledge_ratification_review(
            &scope,
            review(&packet, &scope, &task_id),
            ratification_audit(
                &packet,
                &scope,
                &task_id,
                "orphan-initial-audit",
                "ratificationReview",
                1_700_000_010_003,
            ),
        )
        .await
        .unwrap();
    let (admin_client, admin_connection) = tokio_postgres::connect(&admin, NoTls).await.unwrap();
    let admin_driver = tokio::spawn(admin_connection);
    let schema = config.schema_name();
    admin_client
        .batch_execute(&format!(
            "ALTER TABLE {schema}.ratification_events DISABLE ROW LEVEL SECURITY;
             ALTER TABLE {schema}.ratification_packets DISABLE ROW LEVEL SECURITY;
             ALTER TABLE {schema}.ratification_events DISABLE TRIGGER USER;
             ALTER TABLE {schema}.ratification_packets DISABLE TRIGGER USER;
             UPDATE {schema}.ratification_events SET revision=2;
             UPDATE {schema}.ratification_packets SET state='awaiting_review',revision=0,
                 reviewer_account_id=NULL,head_receipt_hash=NULL;"
        ))
        .await
        .unwrap();
    let before = postgres_ratification_state(&admin_client, schema).await;
    let mut replacement = review(&packet, &scope, &task_id);
    replacement.idempotency_key = "replacement-review".into();
    let error = store
        .acknowledge_ratification_review(
            &scope,
            replacement,
            ratification_audit(
                &packet,
                &scope,
                &task_id,
                "orphan-replacement-audit",
                "ratificationReview",
                1_700_000_010_004,
            ),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, a2a::error_code::INTERNAL_ERROR);
    assert_eq!(
        postgres_ratification_state(&admin_client, schema).await,
        before
    );
    drop(store);
    drop(admin_client);
    admin_driver.abort();
    PostgresTaskStore::drop_test_schema(&config).await.unwrap();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn postgres_decision_replay_authenticates_full_chain_without_mutation() {
    let Some((admin, runtime)) = postgres_urls() else {
        return;
    };
    for (index, (suffix, table, _trigger, mutation)) in [
        (
            "decision_cause_revision",
            "outbox",
            "outbox_identity_immutable",
            "UPDATE {schema}.outbox SET causative_revision=causative_revision+1",
        ),
        (
            "decision_cause_state",
            "outbox",
            "outbox_identity_immutable",
            "UPDATE {schema}.outbox SET state='dead'",
        ),
        (
            "decision_cause_message",
            "outbox",
            "outbox_identity_immutable",
            "UPDATE {schema}.outbox SET message_id='forged-cause-message'",
        ),
        (
            "decision_identity_actor",
            "idempotency_records",
            "idempotency_identity_immutable",
            "UPDATE {schema}.idempotency_records SET actor_account_id='forged-cause-actor'",
        ),
        (
            "decision_identity_request",
            "idempotency_records",
            "idempotency_identity_immutable",
            "UPDATE {schema}.idempotency_records SET request_digest='sha256:0000000000000000000000000000000000000000000000000000000000000000'",
        ),

        (
            "decision_review_receipt",
            "ratification_events",
            "ratification_events_no_update",
            "UPDATE {schema}.ratification_events SET receipt_json='{}' WHERE revision=1",
        ),
        (
            "decision_review_digest",
            "ratification_events",
            "ratification_events_no_update",
            "UPDATE {schema}.ratification_events SET command_digest='sha256:0000000000000000000000000000000000000000000000000000000000000000' WHERE revision=1",
        ),
        (
            "decision_review_hash",
            "ratification_events",
            "ratification_events_no_update",
            "UPDATE {schema}.ratification_events SET receipt_hash='sha256:0000000000000000000000000000000000000000000000000000000000000000' WHERE revision=1",
        ),
        (
            "decision_decision_receipt",
            "ratification_events",
            "ratification_events_no_update",
            "UPDATE {schema}.ratification_events SET receipt_json='{}' WHERE revision=2",
        ),
        (
            "decision_decision_digest",
            "ratification_events",
            "ratification_events_no_update",
            "UPDATE {schema}.ratification_events SET command_digest='sha256:0000000000000000000000000000000000000000000000000000000000000000' WHERE revision=2",
        ),
        (
            "decision_decision_seal",
            "ratification_events",
            "ratification_events_no_update",
            "UPDATE {schema}.ratification_events SET receipt_seal='forged' WHERE revision=2",
        ),
        (
            "decision_order",
            "ratification_events",
            "ratification_events_no_update",
            "UPDATE {schema}.ratification_events SET revision=3 WHERE revision=2",
        ),
        (
            "decision_link",
            "ratification_events",
            "ratification_events_no_update",
            "UPDATE {schema}.ratification_events SET previous_receipt_hash=NULL WHERE revision=2",
        ),
        (
            "decision_account",
            "ratification_events",
            "ratification_events_no_update",
            "UPDATE {schema}.ratification_events SET account_id='forged-account' WHERE revision=1",
        ),
        (
            "decision_membership_review",
            "ratification_events",
            "ratification_events_no_delete",
            "DELETE FROM {schema}.ratification_events WHERE revision=1",
        ),
        (
            "decision_membership_decision",
            "ratification_events",
            "ratification_events_no_delete",
            "DELETE FROM {schema}.ratification_events WHERE revision=2",
        ),
        (
            "decision_head",
            "ratification_packets",
            "ratification_packets_identity_immutable",
            "UPDATE {schema}.ratification_packets SET head_receipt_hash='sha256:0000000000000000000000000000000000000000000000000000000000000000'",
        ),
        (
            "decision_revision",
            "ratification_packets",
            "ratification_packets_identity_immutable",
            "UPDATE {schema}.ratification_packets SET revision=1",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = integrated_postgres_ratification(
            &admin,
            &runtime,
            &format!("r{index}"),
            false,
            false,
        )
        .await;
        let IntegratedPostgresRatification {
            config,
            store,
            task_id,
            scope,
            packet,
            ..
        } = fixture;
        store
            .acknowledge_ratification_review(
                &scope,
                review(&packet, &scope, &task_id),
                ratification_audit(
                    &packet,
                    &scope,
                    &task_id,
                    &format!("{suffix}-review-audit"),
                    "ratificationReview",
                    1_700_000_010_003,
                ),
            )
            .await
            .unwrap();
        let mut command = decision(
            &packet,
            &scope,
            &task_id,
            &format!("{suffix}-decision"),
            HumanDecision::Approve,
        );
        store
            .decide_ratification(
                &scope,
                command.clone(),
                ratification_audit(
                    &packet,
                    &scope,
                    &task_id,
                    &format!("{suffix}-decision-audit"),
                    "ratificationDecide",
                    1_700_000_010_004,
                ),
            )
            .await
            .unwrap();

        let (admin_client, admin_connection) =
            tokio_postgres::connect(&admin, NoTls).await.unwrap();
        let admin_driver = tokio::spawn(admin_connection);
        let schema = config.schema_name();
        admin_client
            .batch_execute(&format!(
                "ALTER TABLE {schema}.{table} DISABLE ROW LEVEL SECURITY;
                 ALTER TABLE {schema}.{table} DISABLE TRIGGER USER"
            ))
            .await
            .unwrap();
        admin_client
            .batch_execute(&mutation.replace("{schema}", schema))
            .await
            .unwrap();
        let before = postgres_ratification_state(&admin_client, schema).await;
        command.decided_at_millis += 99;
        let error = store
            .decide_ratification(
                &scope,
                command,
                ratification_audit(
                    &packet,
                    &scope,
                    &task_id,
                    &format!("{suffix}-replay-audit"),
                    "ratificationDecide",
                    1_700_000_010_103,
                ),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, a2a::error_code::INTERNAL_ERROR, "{mutation}");
        assert_eq!(
            postgres_ratification_state(&admin_client, schema).await,
            before,
            "{mutation}"
        );
        drop(store);
        drop(admin_client);
        admin_driver.abort();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines, clippy::large_futures)]
async fn rejection_is_atomic_private_and_exactly_replayable() {
    let Some((admin, runtime)) = postgres_urls() else {
        return;
    };
    tokio::time::timeout(Duration::from_secs(45), async move {
        let fixture = integrated_postgres_ratification(&admin, &runtime, "reject", true, false).await;
        let IntegratedPostgresRatification {
            config,
            store,
            task_id,
            approved,
            transcript,
            scope,
            packet,
        } = fixture;
        assert!(serde_json::to_string(&approved).unwrap().contains("sealed candidate artifact canary"));
        assert!(serde_json::to_string(&transcript).unwrap().contains("sealed candidate result canary"));

        let callback_url = "https://example.com:443/ratification";
        store.create_callback_config(ConfigCreateCommand::new(
            scope.clone(),
            &task_id,
            Some(CallbackConfigId::new("ratification-callback").unwrap()),
            "ratification-endpoint",
            1,
            callback_url,
            smesh_a2a::content_digest(callback_url.as_bytes()),
            1,
        ).unwrap()).await.unwrap();

        let review_command = review(&packet, &scope, &task_id);
        let review_receipt = store.acknowledge_ratification_review(
            &scope,
            review_command.clone(),
            ratification_audit(&packet, &scope, &task_id, "reject-review-audit", "ratificationReview", 1_700_000_030_003),
        ).await.unwrap();
        let mut conflicting_review = review_command.clone();
        conflicting_review.evidence_hashes.clear();
        let conflict_error=store.acknowledge_ratification_review(
            &scope,
            conflicting_review,
            ratification_audit(&packet, &scope, &task_id, "reject-review-conflict-audit", "ratificationReview", 1_700_000_030_004),
        ).await.unwrap_err();
        assert_eq!(conflict_error.code,-32_621);
        let mut stale_review=review_command.clone();
        stale_review.idempotency_key="postgres-stale-review".into();
        let stale_error=store.acknowledge_ratification_review(
            &scope,
            stale_review,
            ratification_audit(&packet, &scope, &task_id, "reject-review-stale-audit", "ratificationReview", 1_700_000_030_004),
        ).await.unwrap_err();
        assert_eq!(stale_error.code,-32_620);
        assert!(store.acknowledge_ratification_review(
            &scope,
            review_command.clone(),
            ratification_audit(&packet, &scope, &task_id, "reject-review-audit", "ratificationReview", 1_700_000_030_004),
        ).await.is_err());
        let replayed_review = store.acknowledge_ratification_review(
            &scope,
            review_command,
            ratification_audit(&packet, &scope, &task_id, "reject-review-replay-audit", "ratificationReview", 1_700_000_030_005),
        ).await.unwrap();
        assert_eq!(serde_json::to_vec(&review_receipt).unwrap(), serde_json::to_vec(&replayed_review).unwrap());

        for (name, stale) in [
            ("actor", { let mut value = decision(&packet, &scope, &task_id, "stale-actor", HumanDecision::Reject); value.account_id = "different-reviewer".into(); value }),
            ("policy", { let mut value = decision(&packet, &scope, &task_id, "stale-policy", HumanDecision::Reject); value.authorization_policy_revision += 1; value }),
            ("context", { let mut value = decision(&packet, &scope, &task_id, "stale-context", HumanDecision::Reject); value.context_id = "stale-context".into(); value }),
            ("request", { let mut value = decision(&packet, &scope, &task_id, "stale-request", HumanDecision::Reject); value.request_digest = smesh_a2a::content_digest(b"stale-request"); value }),
            ("key", { let mut value = decision(&packet, &scope, &task_id, "stale-key", HumanDecision::Reject); value.ratification_key_generation = smesh_a2a::content_digest(b"stale-key"); value }),
        ] {
            assert!(store.decide_ratification(
                &scope,
                stale,
                ratification_audit(&packet, &scope, &task_id, &format!("reject-{name}-audit"), "ratificationDecide", 1_700_000_030_006),
            ).await.is_err(), "accepted stale {name} binding");
        }

        let reject = decision(&packet, &scope, &task_id, "postgres-reject", HumanDecision::Reject);
        store.set_callback_terminal_test_fault(CallbackTerminalTestFault::AfterCallbackRows).unwrap();
        assert!(store.decide_ratification(
            &scope,
            reject.clone(),
            ratification_audit(&packet, &scope, &task_id, "reject-decision-audit", "ratificationDecide", 1_700_000_030_007),
        ).await.is_err());
        let rolled_back = store.ratification_view(&scope, &task_id).await.unwrap().unwrap();
        assert_eq!(rolled_back.state, smesh_a2a::RatificationState::Reviewed);
        assert_eq!(rolled_back.history.len(), 1);

        let schema = config.schema_name();
        let (fault_client, fault_connection) = tokio_postgres::connect(&admin, NoTls).await.unwrap();
        let fault_driver = tokio::spawn(fault_connection);
        fault_client.batch_execute(&format!(
            "CREATE FUNCTION {schema}.reject_ratification_effect() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'duplicate ratification effect injection' USING ERRCODE='unique_violation'; END $$;
             CREATE TRIGGER reject_ratification_effect BEFORE INSERT ON {schema}.task_events FOR EACH ROW WHEN (NEW.event_kind='ratification_rejected') EXECUTE FUNCTION {schema}.reject_ratification_effect();"
        )).await.unwrap();
        assert!(store.decide_ratification(
            &scope,
            reject.clone(),
            ratification_audit(&packet, &scope, &task_id, "reject-decision-audit", "ratificationDecide", 1_700_000_030_007),
        ).await.is_err());
        let effect_rolled_back = store.ratification_view(&scope, &task_id).await.unwrap().unwrap();
        assert_eq!(effect_rolled_back.state, smesh_a2a::RatificationState::Reviewed);
        assert_eq!(effect_rolled_back.history.len(), 1);
        fault_client.batch_execute(&format!(
            "DROP TRIGGER reject_ratification_effect ON {schema}.task_events;
             DROP FUNCTION {schema}.reject_ratification_effect();"
        )).await.unwrap();
        drop(fault_client);
        fault_driver.abort();

        let rejected = store.decide_ratification(
            &scope,
            reject.clone(),
            ratification_audit(&packet, &scope, &task_id, "reject-decision-audit", "ratificationDecide", 1_700_000_030_008),
        ).await.unwrap();
        let rejected_view = store.ratification_view(&scope, &task_id).await.unwrap().unwrap();
        assert_eq!(rejected_view.state, smesh_a2a::RatificationState::Rejected);
        assert_eq!(rejected_view.history.len(), 2);

        let replayed_rejection = store.decide_ratification(
            &scope,
            reject.clone(),
            ratification_audit(&packet, &scope, &task_id, "reject-decision-replay-audit", "ratificationDecide", 1_700_000_030_009),
        ).await.unwrap();
        assert_eq!(serde_json::to_vec(&rejected).unwrap(), serde_json::to_vec(&replayed_rejection).unwrap());
        let mut conflicting = reject;
        conflicting.rationale = "conflicting reuse".into();
        assert!(store.decide_ratification(
            &scope,
            conflicting,
            ratification_audit(&packet, &scope, &task_id, "reject-conflict-audit", "ratificationDecide", 1_700_000_030_010),
        ).await.is_err());
        assert!(store.decide_ratification(
            &scope,
            decision(&packet, &scope, &task_id, "second-terminal", HumanDecision::Approve),
            ratification_audit(&packet, &scope, &task_id, "second-terminal-audit", "ratificationDecide", 1_700_000_030_011),
        ).await.is_err());

        let schema = config.schema_name();
        let mut scoped_runtime = tokio_postgres::Config::from_str(&runtime).unwrap();
        scoped_runtime.options(format!("-c role={schema}_runtime -c smesh.tenant_scope=tenant-ratification"));
        let (client, connection) = scoped_runtime.connect(NoTls).await.unwrap();
        let driver = tokio::spawn(connection);
        let counts = client.query_one(&format!(
            "SELECT
               (SELECT count(*) FROM {schema}.ratification_events WHERE task_id=$1),
               (SELECT count(*) FROM {schema}.authorization_decisions WHERE operation='ratificationDecide'),
               (SELECT count(*) FROM {schema}.task_events WHERE task_id=$1 AND event_kind='ratification_rejected'),
               (SELECT count(*) FROM {schema}.callback_events WHERE task_id=$1),
               (SELECT count(*) FROM {schema}.callback_deliveries WHERE task_id=$1),
               (SELECT state FROM {schema}.callback_configs WHERE task_id=$1),
               (SELECT task_json FROM {schema}.tasks WHERE task_id=$1),
               (SELECT coalesce(final_result_json,'') FROM {schema}.idempotency_records WHERE task_id=$1 LIMIT 1),
               (SELECT coalesce(string_agg(frame_json,''),'') FROM {schema}.stream_frames WHERE message_id IN (SELECT message_id FROM {schema}.idempotency_records WHERE task_id=$1))"
        ), &[&task_id]).await.unwrap();
        assert_eq!(counts.get::<_, i64>(0), 2);
        assert_eq!(counts.get::<_, i64>(1), 2);
        assert_eq!(counts.get::<_, i64>(2), 1);
        assert_eq!(counts.get::<_, i64>(3), 1);
        assert_eq!(counts.get::<_, i64>(4), 1);
        assert_eq!(counts.get::<_, String>(5), "terminal_closed");
        let task: a2a::Task = serde_json::from_str(&counts.get::<_, String>(6)).unwrap();
        assert_eq!(task.status.state, a2a::TaskState::Rejected);
        assert!(task.artifacts.is_none());
        for public_bytes in [counts.get::<_, String>(6), counts.get::<_, String>(7), counts.get::<_, String>(8)] {
            assert!(!public_bytes.contains("sealed candidate"));
        }
        drop(client);
        driver.abort();
        drop(store);
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    })
    .await
    .expect("PostgreSQL rejection watchdog");
}

#[tokio::test]
#[allow(clippy::too_many_lines, clippy::large_futures)]
async fn amendment_is_quota_bound_claimable_and_produces_generation_two() {
    let Some((admin, runtime)) = postgres_urls() else {
        return;
    };
    tokio::time::timeout(Duration::from_secs(45), async move {
        let fixture = integrated_postgres_ratification(&admin, &runtime, "amend", false, true).await;
        let IntegratedPostgresRatification { config, store, task_id, scope, packet, .. } = fixture;
        store.acknowledge_ratification_review(
            &scope,
            review(&packet, &scope, &task_id),
            ratification_audit(&packet, &scope, &task_id, "amend-review-audit", "ratificationReview", 1_700_000_010_003),
        ).await.unwrap();
        let amend = decision(&packet, &scope, &task_id, "postgres-amend", HumanDecision::Amend);
        let subject = QuotaSubject::new(scope.tenant_scope(), scope.owner_account_id(), scope.principal_scope()).unwrap();
        let intent = ratification_quota_policy().operation_intent(
            &subject,
            QuotaOperation::TaskContinue,
            &amend.idempotency_key,
            amend.rationale.len() as u64,
        ).unwrap();
        let amended_receipt = store.decide_ratification_with_quota(
            &scope,
            amend,
            ratification_audit(&packet, &scope, &task_id, "amend-decision-audit", "ratificationDecide", 1_700_000_010_004),
            Some(&intent),
        ).await.unwrap();
        assert_eq!(amended_receipt.revision, 2);
        assert_eq!(store.ratification_view(&scope, &task_id).await.unwrap().unwrap().state, smesh_a2a::RatificationState::Amended);

        let schema = config.schema_name().to_owned();
        let mut scoped_runtime = tokio_postgres::Config::from_str(&runtime).unwrap();
        scoped_runtime.options(format!("-c role={schema}_runtime -c smesh.tenant_scope=tenant-ratification"));
        let (client, connection) = scoped_runtime.connect(NoTls).await.unwrap();
        let driver = tokio::spawn(connection);
        let reservation = client.query_one(&format!(
            "SELECT count(*),count(DISTINCT o.dispatch_id),count(DISTINCT o.quota_reservation_id),bool_and(q.state='reserved')
             FROM {schema}.outbox o JOIN {schema}.quota_execution_reservations q
               ON q.tenant_scope=o.tenant_scope AND q.reservation_id=o.quota_reservation_id
             WHERE o.task_id=$1 AND o.state='pending'"
        ), &[&task_id]).await.unwrap();
        assert_eq!(reservation.get::<_, i64>(0), 1);
        assert_eq!(reservation.get::<_, i64>(1), 1);
        assert_eq!(reservation.get::<_, i64>(2), 1);
        assert!(reservation.get::<_, bool>(3));
        drop(client);
        driver.abort();

        // Restart exactly after the amendment commit and before its claim. Durable polling,
        // not a process-local notification, must make the stable dispatch claimable.
        drop(store);
        let reopened = PostgresTaskStore::open(config.clone()).await.unwrap();
        let amendment_lease = reopened.claim_outbox("amend-worker", 1_700_000_010_005, 60_000).await.unwrap().unwrap();
        assert!(amendment_lease.execution_reservation.is_some());
        let payload = serde_json::to_vec(&amendment_lease.request).unwrap();
        let envelope = smesh_a2a::DurableDispatchEnvelope {
            tenant_scope: amendment_lease.tenant_scope.clone(),
            dispatch_id: amendment_lease.dispatch_id.clone(),
            payload_digest: smesh_a2a::content_digest(&payload),
            request: amendment_lease.request.clone(),
            execution_reservation: amendment_lease.execution_reservation.clone(),
        };
        let ReceiverAdmission::Execute(receiver) = reopened
            .begin_receive(envelope, "amend-receiver", 1_700_000_010_005, 60_000)
            .await
            .unwrap()
        else {
            panic!("amendment receiver lease was not executable")
        };
        reopened
            .complete_loopback_receive(
                &receiver,
                &[smesh_a2a::MeshEvent::Completed { summary: "generation two candidate".into() }],
                1_700_000_010_006,
            )
            .await
            .unwrap();
        let amended_task = reopened.task_for_outbox(&amendment_lease).await.unwrap().unwrap();
        assert_eq!(amended_task.status.state, a2a::TaskState::InputRequired);
        assert!(amended_task.history.as_ref().unwrap().last().unwrap().parts.iter().any(|part| serde_json::to_string(part).unwrap().contains("approved exact candidate")));

        let mut generation_two_candidate = amended_task.clone();
        generation_two_candidate.status = a2a::TaskStatus {
            state: a2a::TaskState::Completed,
            message: Some(a2a::Message::new(a2a::Role::Agent, vec![a2a::Part::text("generation two candidate")])),
            timestamp: chrono::DateTime::from_timestamp_millis(1_700_000_010_006),
        };
        generation_two_candidate.artifacts = Some(vec![a2a::Artifact {
            artifact_id: "generation-two-artifact".into(),
            name: Some("generation-two.txt".into()),
            description: None,
            parts: vec![a2a::Part::text("generation two candidate artifact")],
            metadata: None,
            extensions: None,
        }]);
        let transcript = vec![
            a2a::StreamResponse::Task(amended_task),
            a2a::StreamResponse::ArtifactUpdate(a2a::TaskArtifactUpdateEvent {
                task_id: generation_two_candidate.id.clone(),
                context_id: generation_two_candidate.context_id.clone(),
                artifact: generation_two_candidate.artifacts.as_ref().unwrap()[0].clone(),
                append: None,
                last_chunk: Some(true),
                metadata: None,
            }),
            a2a::StreamResponse::StatusUpdate(a2a::TaskStatusUpdateEvent {
                task_id: generation_two_candidate.id.clone(),
                context_id: generation_two_candidate.context_id.clone(),
                status: generation_two_candidate.status.clone(),
                metadata: None,
            }),
        ];
        assert_eq!(reopened.commit_delivery_for_ratification(
            &amendment_lease,
            generation_two_candidate.clone(),
            a2a::SendMessageResponse::Task(generation_two_candidate),
            &transcript,
            AuthoritativeReviewCandidate::new(
                "release-policy", 7, smesh_a2a::content_digest(b"release-policy-v7"),
                b"sealed-checkpoint-generation-two".to_vec(), vec![b"generation two tests".to_vec()], "bounded uncertainty",
            ).unwrap(),
            1_700_000_010_006,
        ).await.unwrap(), smesh_a2a::TransitionOutcome::Applied);
        let generation_two = reopened.ratification_view(&scope, &task_id).await.unwrap().unwrap();
        assert_eq!(generation_two.packet.generation, 2);
        assert_eq!(generation_two.state, smesh_a2a::RatificationState::AwaitingReview);
        drop(reopened);
        let reopened = PostgresTaskStore::open(config.clone()).await.unwrap();
        assert_eq!(
            reopened
                .ratification_view(&scope, &task_id)
                .await
                .unwrap()
                .unwrap(),
            generation_two
        );
        let (snapshot_client, snapshot_connection) = tokio_postgres::connect(&admin, NoTls).await.unwrap();
        let snapshot_driver = tokio::spawn(snapshot_connection);
        let before = postgres_ratification_state(&snapshot_client, config.schema_name()).await;
        let conflict = reopened.acknowledge_ratification_review(
            &scope,
            review(&generation_two.packet, &scope, &task_id),
            ratification_audit(&generation_two.packet, &scope, &task_id, "generation-two-global-conflict-audit", "ratificationReview", 1_700_000_010_007),
        ).await.unwrap_err();
        assert_eq!(conflict.code, -32_621);
        assert_eq!(postgres_ratification_state(&snapshot_client, config.schema_name()).await, before);
        snapshot_client.batch_execute(&format!(
            "ALTER TABLE {}.ratification_events DISABLE ROW LEVEL SECURITY;
             ALTER TABLE {}.ratification_events DISABLE TRIGGER USER",
            config.schema_name(), config.schema_name(),
        )).await.unwrap();
        assert_eq!(snapshot_client.execute(
            &format!("UPDATE {}.ratification_events SET receipt_json='{{}}' WHERE task_id=$1 AND generation=1 AND revision=1", config.schema_name()),
            &[&task_id],
        ).await.unwrap(), 1);
        let tampered_before = postgres_ratification_state(&snapshot_client, config.schema_name()).await;
        let authenticated_error = reopened.acknowledge_ratification_review(
            &scope,
            review(&generation_two.packet, &scope, &task_id),
            ratification_audit(&generation_two.packet, &scope, &task_id, "generation-two-tampered-conflict-audit", "ratificationReview", 1_700_000_010_008),
        ).await.unwrap_err();
        assert_eq!(authenticated_error.code, -32_011);
        assert_eq!(postgres_ratification_state(&snapshot_client, config.schema_name()).await, tampered_before);
        drop(snapshot_client);
        snapshot_driver.abort();
        drop(reopened);
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    })
    .await
    .expect("PostgreSQL amendment watchdog");
}

#[tokio::test]
#[allow(clippy::too_many_lines, clippy::large_futures)]
async fn restart_and_three_way_decision_race_have_one_task_row_winner() {
    let Some((admin, runtime)) = postgres_urls() else {
        return;
    };
    tokio::time::timeout(Duration::from_secs(45), async move {
        let fixture =
            integrated_postgres_ratification(&admin, &runtime, "race", false, false).await;
        let IntegratedPostgresRatification {
            config,
            store,
            task_id,
            scope,
            packet,
            ..
        } = fixture;
        drop(store);
        let reviewed_store = PostgresTaskStore::open(config.clone()).await.unwrap();
        reviewed_store
            .acknowledge_ratification_review(
                &scope,
                review(&packet, &scope, &task_id),
                ratification_audit(
                    &packet,
                    &scope,
                    &task_id,
                    "race-review-audit",
                    "ratificationReview",
                    1_700_000_010_003,
                ),
            )
            .await
            .unwrap();
        drop(reviewed_store);
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        assert_eq!(
            store
                .ratification_view(&scope, &task_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            smesh_a2a::RatificationState::Reviewed
        );

        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(4));
        let mut contenders = Vec::new();
        for (name, value) in [
            ("approve", HumanDecision::Approve),
            ("reject", HumanDecision::Reject),
            ("amend", HumanDecision::Amend),
        ] {
            let contender = store.clone();
            let contender_scope = scope.clone();
            let contender_packet = packet.clone();
            let contender_task = task_id.clone();
            let contender_barrier = std::sync::Arc::clone(&barrier);
            contenders.push(tokio::spawn(async move {
                contender_barrier.wait().await;
                contender
                    .decide_ratification(
                        &contender_scope,
                        decision(
                            &contender_packet,
                            &contender_scope,
                            &contender_task,
                            &format!("race-{name}"),
                            value,
                        ),
                        ratification_audit(
                            &contender_packet,
                            &contender_scope,
                            &contender_task,
                            &format!("race-{name}-audit"),
                            "ratificationDecide",
                            1_700_000_010_004,
                        ),
                    )
                    .await
            }));
        }
        barrier.wait().await;
        let mut winners = 0;
        for contender in contenders {
            winners += usize::from(contender.await.unwrap().is_ok());
        }
        assert_eq!(winners, 1);
        let final_view = store
            .ratification_view(&scope, &task_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(final_view.history.len(), 2);
        assert!(matches!(
            final_view.state,
            smesh_a2a::RatificationState::Approved
                | smesh_a2a::RatificationState::Rejected
                | smesh_a2a::RatificationState::Amended
        ));
        drop(store);
        let restarted = PostgresTaskStore::open(config.clone()).await.unwrap();
        assert_eq!(
            restarted
                .ratification_view(&scope, &task_id)
                .await
                .unwrap()
                .unwrap(),
            final_view
        );
        drop(restarted);
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    })
    .await
    .expect("PostgreSQL three-way decision race watchdog");
}

#[tokio::test]
#[allow(clippy::too_many_lines, clippy::large_futures)]
async fn cancel_and_continue_races_each_commit_one_packet_outcome() {
    let Some((admin, runtime)) = postgres_urls() else {
        return;
    };
    tokio::time::timeout(Duration::from_secs(45), async move {
        let cancel_fixture =
            integrated_postgres_ratification(&admin, &runtime, "cancel", false, false).await;
        let IntegratedPostgresRatification {
            config: cancel_config,
            store: cancel_store,
            task_id: cancel_task,
            scope: cancel_scope,
            packet: cancel_packet,
            ..
        } = cancel_fixture;
        cancel_store
            .acknowledge_ratification_review(
                &cancel_scope,
                review(&cancel_packet, &cancel_scope, &cancel_task),
                ratification_audit(
                    &cancel_packet,
                    &cancel_scope,
                    &cancel_task,
                    "cancel-race-review-audit",
                    "ratificationReview",
                    1_700_000_010_003,
                ),
            )
            .await
            .unwrap();
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));
        let decision_store = cancel_store.clone();
        let decision_scope = cancel_scope.clone();
        let decision_packet = cancel_packet.clone();
        let decision_task = cancel_task.clone();
        let decision_barrier = std::sync::Arc::clone(&barrier);
        let decision_handle = tokio::spawn(async move {
            decision_barrier.wait().await;
            decision_store
                .decide_ratification(
                    &decision_scope,
                    decision(
                        &decision_packet,
                        &decision_scope,
                        &decision_task,
                        "cancel-race-decision",
                        HumanDecision::Reject,
                    ),
                    ratification_audit(
                        &decision_packet,
                        &decision_scope,
                        &decision_task,
                        "cancel-race-decision-audit",
                        "ratificationDecide",
                        1_700_000_010_004,
                    ),
                )
                .await
        });
        let cancellation_store = cancel_store.clone();
        let cancellation_scope = cancel_scope.clone();
        let cancellation_packet = cancel_packet.clone();
        let cancellation_task = cancel_task.clone();
        let cancellation_barrier = std::sync::Arc::clone(&barrier);
        let cancellation = tokio::spawn(async move {
            cancellation_barrier.wait().await;
            cancellation_store
                .cancel_authorized(
                    &cancellation_scope,
                    &cancellation_task,
                    1_700_000_010_004,
                    ratification_audit(
                        &cancellation_packet,
                        &cancellation_scope,
                        &cancellation_task,
                        "cancel-race-cancel-audit",
                        "TaskCancel",
                        1_700_000_010_004,
                    ),
                )
                .await
        });
        barrier.wait().await;
        assert_eq!(
            usize::from(decision_handle.await.unwrap().is_ok())
                + usize::from(cancellation.await.unwrap().is_ok()),
            1
        );
        let canceled_or_decided = cancel_store
            .ratification_view(&cancel_scope, &cancel_task)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            canceled_or_decided.state,
            smesh_a2a::RatificationState::Canceled | smesh_a2a::RatificationState::Rejected
        ));
        drop(cancel_store);
        PostgresTaskStore::drop_test_schema(&cancel_config)
            .await
            .unwrap();

        let continue_fixture =
            integrated_postgres_ratification(&admin, &runtime, "continue", false, false).await;
        let IntegratedPostgresRatification {
            config: continue_config,
            store: continue_store,
            task_id: continue_task,
            scope: continue_scope,
            packet: continue_packet,
            ..
        } = continue_fixture;
        continue_store
            .acknowledge_ratification_review(
                &continue_scope,
                review(&continue_packet, &continue_scope, &continue_task),
                ratification_audit(
                    &continue_packet,
                    &continue_scope,
                    &continue_task,
                    "continue-race-review-audit",
                    "ratificationReview",
                    1_700_000_010_003,
                ),
            )
            .await
            .unwrap();
        let current_task =
            scoped_postgres_task(&runtime, continue_config.schema_name(), &continue_task).await;
        let mut message = a2a::Message::new(
            a2a::Role::User,
            vec![a2a::Part::text("superseding continuation")],
        );
        message.message_id = "continue-race-message".into();
        message.task_id = Some(current_task.id.clone());
        message.context_id = Some(current_task.context_id.clone());
        let continuation = SendMessageAdmission {
            request: a2a::SendMessageRequest {
                message,
                configuration: None,
                metadata: None,
                tenant: None,
            },
            streaming: false,
            task: current_task.clone(),
            original_result: a2a::SendMessageResponse::Task(current_task),
            input_limits: smesh_a2a::InputLimits::default(),
            now: 1_700_000_010_004,
            max_attempts: 8,
        };
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));
        let decision_store = continue_store.clone();
        let decision_scope = continue_scope.clone();
        let decision_packet = continue_packet.clone();
        let decision_task = continue_task.clone();
        let decision_barrier = std::sync::Arc::clone(&barrier);
        let decision_handle = tokio::spawn(async move {
            decision_barrier.wait().await;
            decision_store
                .decide_ratification(
                    &decision_scope,
                    decision(
                        &decision_packet,
                        &decision_scope,
                        &decision_task,
                        "continue-race-decision",
                        HumanDecision::Approve,
                    ),
                    ratification_audit(
                        &decision_packet,
                        &decision_scope,
                        &decision_task,
                        "continue-race-decision-audit",
                        "ratificationDecide",
                        1_700_000_010_004,
                    ),
                )
                .await
        });
        let continuation_store = continue_store.clone();
        let continuation_scope = continue_scope.clone();
        let continuation_packet = continue_packet.clone();
        let continuation_task = continue_task.clone();
        let continuation_barrier = std::sync::Arc::clone(&barrier);
        let continuation_result = tokio::spawn(async move {
            continuation_barrier.wait().await;
            continuation_store
                .authorize_and_continue(
                    &continuation_scope,
                    continuation,
                    ratification_audit(
                        &continuation_packet,
                        &continuation_scope,
                        &continuation_task,
                        "continue-race-continue-audit",
                        "TaskContinue",
                        1_700_000_010_004,
                    ),
                )
                .await
        });
        barrier.wait().await;
        assert_eq!(
            usize::from(decision_handle.await.unwrap().is_ok())
                + usize::from(continuation_result.await.unwrap().is_ok()),
            1
        );
        let superseded_or_decided = continue_store
            .ratification_view(&continue_scope, &continue_task)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            superseded_or_decided.state,
            smesh_a2a::RatificationState::Superseded | smesh_a2a::RatificationState::Approved
        ));
        drop(continue_store);
        PostgresTaskStore::drop_test_schema(&continue_config)
            .await
            .unwrap();
    })
    .await
    .expect("PostgreSQL lifecycle race watchdog");
}
