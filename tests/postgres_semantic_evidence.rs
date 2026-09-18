const MIGRATION: &str = include_str!("../migrations/postgres/0013_semantic_evidence.sql");

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use smesh_a2a::{
    AuthorityShutdown, IssuerEnrollmentV1, IssuerRoleV1, PostgresStoreConfig, PostgresTaskStore,
};
use tokio_postgres::NoTls;

fn required_url(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent | std::env::VarError::NotUnicode(_))
            if std::env::var("SMESH_POSTGRES_TEST_REQUIRED").as_deref() == Ok("1") =>
        {
            panic!("{name} is required")
        }
        Err(_) => None,
    }
}

#[test]
fn semantic_evidence_migration_is_tenant_scoped_and_fail_closed() {
    for table in [
        "completion_policy_versions",
        "issuer_enrollments",
        "candidate_generations",
        "candidate_artifacts",
        "issuer_evidence",
        "evidence_conflicts",
    ] {
        assert!(
            MIGRATION.contains(&format!("CREATE TABLE __SCHEMA__.{table}")),
            "missing {table}"
        );
        assert!(
            MIGRATION.contains(&format!(
                "ALTER TABLE __SCHEMA__.{table} ENABLE ROW LEVEL SECURITY"
            )),
            "missing RLS for {table}"
        );
        assert!(
            MIGRATION.contains(&format!(
                "ALTER TABLE __SCHEMA__.{table} FORCE ROW LEVEL SECURITY"
            )),
            "missing forced RLS for {table}"
        );
    }
    assert!(MIGRATION.contains("PRIMARY KEY(tenant_scope,candidate_generation_id)"));
    assert!(MIGRATION.contains("CHECK(issuer_role IN ('text-concordance-review/v1','text-concordance-test/v1','text-concordance-contradiction/v1'))"));
    assert!(MIGRATION.contains("CHECK(decision IN ('approve','clear'))"));
    assert!(MIGRATION.contains("CHECK(state IN ('open','sealed','canceled','conflicted'))"));
    assert!(MIGRATION.contains("CREATE TRIGGER candidate_generations_identity"));
    assert!(MIGRATION.contains("CREATE TRIGGER issuer_evidence_immutable"));
    assert!(MIGRATION.contains("CREATE TRIGGER evidence_conflicts_immutable"));
    assert!(!MIGRATION.contains("GRANT UPDATE ON __SCHEMA__.issuer_evidence"));
    assert!(!MIGRATION.contains("GRANT DELETE ON __SCHEMA__.issuer_evidence"));
}

#[tokio::test]
async fn store_open_applies_revision_13_and_seals_catalog() {
    let Some(admin_url) = required_url("SMESH_TEST_POSTGRES_ADMIN_URL") else {
        return;
    };
    let Some(runtime_url) = required_url("SMESH_TEST_POSTGRES_RUNTIME_URL") else {
        return;
    };
    let schema = format!("smesh_semantic_evidence_{:016x}", rand::random::<u64>());
    let config = PostgresStoreConfig::new(&admin_url, &runtime_url, &schema)
        .unwrap()
        .with_test_only_insecure_loopback(true);
    let store = PostgresTaskStore::open(config).await.unwrap();
    store.shutdown().await.unwrap();

    let (client, connection) = tokio_postgres::connect(&admin_url, NoTls).await.unwrap();
    let connection_task = tokio::spawn(connection);
    let row = client
        .query_one(
            &format!(
                "SELECT schema_version,(SELECT logical_schema_version FROM {schema}.schema_migrations WHERE revision=13) FROM {schema}.store_metadata WHERE singleton=1"
            ),
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 13);
    assert_eq!(row.get::<_, i64>(1), 13);
    client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
    drop(client);
    connection_task.await.unwrap().unwrap();
}

fn enrollment(tenant: &str, role: IssuerRoleV1, identity: &str, seed: u8) -> IssuerEnrollmentV1 {
    let signing_key = SigningKey::from_bytes(&[seed; 32]);
    IssuerEnrollmentV1 {
        tenant_scope: tenant.to_owned(),
        issuer_role: role,
        issuer_identity: identity.to_owned(),
        public_key: URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
        valid_from: 100,
        expires_at: 1_000,
        revoked_at: None,
    }
}

#[tokio::test]
async fn authority_initialization_persists_exact_three_distinct_roles() {
    let Some(admin_url) = required_url("SMESH_TEST_POSTGRES_ADMIN_URL") else {
        return;
    };
    let Some(runtime_url) = required_url("SMESH_TEST_POSTGRES_RUNTIME_URL") else {
        return;
    };
    let schema = format!("smesh_semantic_enrollment_{:016x}", rand::random::<u64>());
    let config = PostgresStoreConfig::new(&admin_url, &runtime_url, &schema)
        .unwrap()
        .with_test_only_insecure_loopback(true);
    let store = PostgresTaskStore::open(config).await.unwrap();
    let enrollments = [
        enrollment("tenant-a", IssuerRoleV1::Review, "review-key-1", 1),
        enrollment("tenant-a", IssuerRoleV1::Test, "test-key-1", 2),
        enrollment(
            "tenant-a",
            IssuerRoleV1::Contradiction,
            "contradiction-key-1",
            3,
        ),
    ];
    store
        .initialize_text_concordance_authority(
            "tenant-a",
            "owner-a",
            "principal-a",
            &enrollments,
            100,
        )
        .await
        .unwrap();
    store.shutdown().await.unwrap();

    let mut runtime_config = runtime_url.parse::<tokio_postgres::Config>().unwrap();
    runtime_config.options(format!("-c role={schema}_runtime"));
    let (client, connection) = runtime_config.connect(NoTls).await.unwrap();
    let connection_task = tokio::spawn(connection);
    client
        .query_one(
            "SELECT set_config('smesh.tenant_scope','tenant-a',false)",
            &[],
        )
        .await
        .unwrap();
    let policy_count: i64 = client
        .query_one(
            &format!("SELECT count(*) FROM {schema}.completion_policy_versions"),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let enrollment_count: i64 = client
        .query_one(
            &format!("SELECT count(*) FROM {schema}.issuer_enrollments"),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(policy_count, 1);
    assert_eq!(enrollment_count, 3);
    drop(client);
    connection_task.await.unwrap().unwrap();

    let (admin, admin_connection) = tokio_postgres::connect(&admin_url, NoTls).await.unwrap();
    let admin_task = tokio::spawn(admin_connection);
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
    drop(admin);
    admin_task.await.unwrap().unwrap();
}
