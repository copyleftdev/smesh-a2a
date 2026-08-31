mod support;

use std::fs;
#[cfg(all(unix, debug_assertions))]
use std::io::{BufRead as _, BufReader};
#[cfg(all(unix, debug_assertions))]
use std::process::{Command, Stdio};
#[cfg(all(unix, debug_assertions))]
use std::time::Duration;

use smesh_a2a::{
    ArtifactAuthority, ArtifactBackupPlanFile, ArtifactKeyRotationPlanFile,
    ArtifactMigrationPlanFile, ArtifactRestorePlanFile, ArtifactStoreConfig, AuthorityShutdown,
    AuthorizationAuditInput, AuthorizationDecisionEffect, AuthorizedTaskRead, ContentDigestV1,
    InlineArtifactKind, OwnedTaskScope, PostgresStoreConfig, PostgresStoreError, PostgresTaskStore,
    VisibilityScope, extract_inline_artifacts,
};
use support::artifact_test_root::ArtifactTestRoot;

fn postgres_urls() -> Option<(String, String, String)> {
    let admin = std::env::var("SMESH_TEST_POSTGRES_ADMIN_URL");
    let runtime = std::env::var("SMESH_TEST_POSTGRES_RUNTIME_URL");
    let superuser = std::env::var("SMESH_TEST_POSTGRES_SUPERUSER_URL");
    match (admin, runtime, superuser) {
        (Ok(admin), Ok(runtime), Ok(superuser)) => Some((admin, runtime, superuser)),
        _ if std::env::var("SMESH_POSTGRES_TEST_REQUIRED").as_deref() == Ok("1") => {
            panic!("explicit PostgreSQL superuser, admin, and runtime URLs are required")
        }
        _ => None,
    }
}

#[test]
#[ignore = "invoked as the detached backup signer subprocess"]
fn detached_signature_signer() {
    use std::io::{Read as _, Write as _};
    let mut payload = Vec::new();
    std::io::stdin().read_to_end(&mut payload).unwrap();
    writeln!(
        std::io::stdout(),
        "smesh-test-signer-a:{}",
        smesh_a2a::content_digest(&payload)
    )
    .unwrap();
}

#[test]
#[ignore = "invoked as the detached restore verifier subprocess"]
fn detached_signature_verifier() {
    use std::io::Read as _;
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).unwrap();
    let separator = input.iter().rposition(|byte| *byte == 0).unwrap();
    let payload = &input[..separator];
    assert!(!payload.is_empty());
    let signature = String::from_utf8(input[separator + 1..].to_vec()).unwrap();
    assert!(signature.contains("smesh-test-signer-a:sha256:"));
}

#[test]
#[ignore = "invoked as the wrong detached restore verifier subprocess"]
fn detached_signature_wrong_signer() {
    use std::io::Read as _;
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).unwrap();
    assert!(String::from_utf8_lossy(&input).contains("smesh-test-signer-b:"));
}

#[test]
#[ignore = "invoked as a failing detached restore verifier subprocess"]
fn detached_signature_command_failure() {
    panic!("injected detached verifier command failure");
}

fn write_inventory_and_digest(root: &std::path::Path, value: &serde_json::Value) {
    let bytes = serde_json::to_vec(value).unwrap();
    fs::write(root.join("inventory.json"), &bytes).unwrap();
    let mut domain = b"smesh-artifact-physical-inventory/v1\0".to_vec();
    domain.extend_from_slice(&bytes);
    fs::write(
        root.join("inventory.digest"),
        ContentDigestV1::of(&domain).to_string(),
    )
    .unwrap();
}

fn regular_file_count(root: &std::path::Path) -> usize {
    fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .map(|path| {
            if path.is_dir() {
                regular_file_count(&path)
            } else {
                usize::from(path.is_file())
            }
        })
        .sum()
}

#[test]
fn canonical_extractor_handles_text_raw_data_and_never_url() {
    let canary = "https://127.0.0.1:9/must-never-be-fetched";
    let mut value = serde_json::json!({
        "id": "task-1",
        "artifacts": [{
            "artifactId": "artifact-1",
            "name": "mixed",
            "parts": [
                {"text": "héllo", "mediaType": "text/plain; charset=utf-8"},
                {"raw": "AP8Q", "mediaType": "application/octet-stream"},
                {"data": {"z": 1, "a": [true, null]}, "mediaType": "application/json"},
                {"url": canary, "mediaType": "application/octet-stream"}
            ]
        }]
    });

    let extracted = extract_inline_artifacts(&value).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].artifact_id, "artifact-1");
    assert_eq!(
        extracted[0]
            .parts
            .iter()
            .map(|part| part.kind)
            .collect::<Vec<_>>(),
        vec![
            InlineArtifactKind::Text,
            InlineArtifactKind::Raw,
            InlineArtifactKind::Data
        ]
    );
    assert_eq!(extracted[0].parts[0].bytes, "héllo".as_bytes());
    assert_eq!(extracted[0].parts[1].bytes, [0, 255, 16]);
    assert_eq!(extracted[0].parts[2].bytes, br#"{"a":[true,null],"z":1}"#);
    assert_eq!(extracted[0].inert_urls, vec![canary]);

    let projection = extracted[0].manifest_projection(
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        3,
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    extracted[0].rewrite_all(&mut value, &projection).unwrap();
    assert_eq!(value["artifacts"][0], projection);
    assert!(!value.to_string().contains(canary));
    assert!(extract_inline_artifacts(&value).unwrap().is_empty());
}

#[test]
fn extractor_rejects_ambiguous_parts_and_invalid_base64() {
    for value in [
        serde_json::json!({"artifactId":"a","parts":[{"text":"x","raw":"eA=="}]}),
        serde_json::json!({"artifactId":"a","parts":[{"raw":"***"}]}),
        serde_json::json!({"artifactId":"a","parts":[{"data":1,"url":"https://example.invalid"}]}),
    ] {
        assert!(extract_inline_artifacts(&value).is_err());
    }
}

#[test]
fn extractor_rejects_artifact_ids_that_cannot_be_canonical_resolver_segments() {
    for artifact_id in [
        "a#b", "a?b", "a/b", ".", "..", "a%2fb", "a%2Fb", "%61", "a%25b",
    ] {
        let value = serde_json::json!({
            "artifactId": artifact_id,
            "parts": [{"text": "must not gain a resolver"}]
        });
        assert!(
            extract_inline_artifacts(&value).is_err(),
            "migration accepted ambiguous artifact ID {artifact_id:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn migration_plan_file_is_private_no_follow_and_strict() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let root = ArtifactTestRoot::new("artifact-plan");
    let plan = root.join("plan.json");
    fs::write(&plan, r#"{
      "schema":"smesh-artifact-migration-plan/v1",
      "planId":"migration-1",
      "source":{"schema":"smesh_source","storeId":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
      "sourceSchemaVersion":5,
      "policy":{"id":"artifact-migration","revision":1,"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
      "actor":"operator@example.invalid","reason":"move inline payloads to encrypted CAS","batchSize":1000
    }"#).unwrap();
    fs::set_permissions(&plan, fs::Permissions::from_mode(0o600)).unwrap();
    let loaded = ArtifactMigrationPlanFile::open(&plan).unwrap();
    assert_eq!(loaded.plan().batch_size(), 1000);
    assert_eq!(loaded.source_schema(), "smesh_source");

    let link = root.join("link.json");
    symlink(&plan, &link).unwrap();
    assert!(ArtifactMigrationPlanFile::open(&link).is_err());
    fs::set_permissions(&plan, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(ArtifactMigrationPlanFile::open(&plan).is_err());
}

#[cfg(unix)]
#[tokio::test]
#[allow(clippy::too_many_lines, clippy::format_collect)]
async fn populated_postgres_migration_rewrites_causal_copies_and_exact_rerun_is_zero() {
    use std::os::unix::fs::PermissionsExt as _;
    use std::str::FromStr as _;

    let Some((admin, runtime, superuser)) = postgres_urls() else {
        return;
    };
    let schema = format!("smesh_artifact_migrate_{:016x}", rand::random::<u64>());
    let root = ArtifactTestRoot::new("artifact-migrate");
    let keyring = root.join("keys.json");
    fs::write(&keyring, r#"{"activeGeneration":"key-1","generations":{"key-1":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"}}"#).unwrap();
    fs::set_permissions(&keyring, fs::Permissions::from_mode(0o600)).unwrap();
    let cas = root.join("cas");
    fs::create_dir(&cas).unwrap();
    fs::set_permissions(&cas, fs::Permissions::from_mode(0o700)).unwrap();
    let artifact = ArtifactStoreConfig::new(&cas, &keyring).unwrap();
    let config = PostgresStoreConfig::new(&admin, &runtime, &schema)
        .unwrap()
        .with_test_only_insecure_loopback(true)
        .with_test_only_parent_managed_cleanup()
        .with_artifact_store(artifact.clone());
    let store = PostgresTaskStore::open(config.clone()).await.unwrap();
    drop(store);

    let pg = tokio_postgres::Config::from_str(&superuser).unwrap();
    let (client, connection) = pg.connect(tokio_postgres::NoTls).await.unwrap();
    let driver = tokio::spawn(async move {
        connection.await.unwrap();
    });
    let store_id: Vec<u8> = client
        .query_one(
            &format!("SELECT store_id FROM {schema}.store_identity"),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let store_id = format!(
        "sha256:{}",
        store_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let inline = serde_json::json!({
        "id":"task-1","contextId":"context-1","status":{"state":"TASK_STATE_COMPLETED"},
        "artifacts":[{"artifactId":"artifact-inline","name":"résultat","parts":[{"text":"héllo 🌍"},{"raw":"AP8Q"}]}]
    }).to_string();
    let expected_artifact_bytes =
        extract_inline_artifacts(&serde_json::from_str::<serde_json::Value>(&inline).unwrap())
            .unwrap()[0]
            .canonical_bytes()
            .unwrap();
    client.batch_execute(&format!("SET session_replication_role=replica;
      INSERT INTO {schema}.tasks(tenant_scope,task_id,context_id,state,revision,task_json,owner_account_id) VALUES('tenant-a','task-1','context-1','\"TASK_STATE_COMPLETED\"',1,'{}','account-a');
      INSERT INTO {schema}.task_events(tenant_scope,task_id,event_seq,task_revision,event_kind,to_state,event_json,created_at) VALUES('tenant-a','task-1',1,1,'completed','\"TASK_STATE_COMPLETED\"','{}',1);
      SET session_replication_role=origin;
      INSERT INTO {schema}.retained_authority_usage(tenant_scope,scope_kind,scope_id,retained_bytes,updated_at) VALUES
       ('tenant-a','tenant','tenant-a',0,1),('tenant-a','account','account-a',0,1),('tenant-a','principal','account:account-a',0,1);
      UPDATE {schema}.retained_authority_usage SET retained_bytes=CASE scope_kind
       WHEN 'tenant' THEN {schema}.retained_authority_oracle('tenant-a',NULL)
       WHEN 'account' THEN {schema}.retained_authority_account_oracle('tenant-a','account-a')
       ELSE {schema}.retained_authority_oracle('tenant-a','account:account-a') END;",
      inline.replace('\'', "''"), inline.replace('\'', "''"))).await.unwrap();

    assert!(matches!(
        PostgresTaskStore::open(config.clone()).await,
        Err(PostgresStoreError::ArtifactMigrationRequired)
    ));
    let plan_path = root.join("plan.json");
    fs::write(&plan_path, format!(r#"{{"schema":"smesh-artifact-migration-plan/v1","planId":"migration-1","source":{{"schema":"{schema}","storeId":"{store_id}"}},"sourceSchemaVersion":5,"policy":{{"id":"artifact-migration","revision":1,"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},"actor":"operator","reason":"test migration","batchSize":1}}"#)).unwrap();
    fs::set_permissions(&plan_path, fs::Permissions::from_mode(0o600)).unwrap();
    let plan = ArtifactMigrationPlanFile::open(&plan_path).unwrap();
    let (migration_a, migration_b) = tokio::join!(
        PostgresTaskStore::migrate_inline_artifacts(config.clone(), &plan, "operator-a"),
        PostgresTaskStore::migrate_inline_artifacts(config.clone(), &plan, "operator-b")
    );
    let migration_outcomes = [migration_a, migration_b];
    assert_eq!(
        migration_outcomes
            .iter()
            .filter(|outcome| outcome.is_ok())
            .count(),
        1
    );
    assert_eq!(
        migration_outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Err(PostgresStoreError::ArtifactMigrationBusy)))
            .count(),
        1
    );
    let outcome = migration_outcomes.into_iter().find_map(Result::ok).unwrap();
    assert!(outcome.completed);
    assert_eq!(outcome.migrated_artifacts, 1);
    assert_eq!(outcome.rewritten_rows, 2);
    let rerun = PostgresTaskStore::migrate_inline_artifacts(config.clone(), &plan, "operator-2")
        .await
        .unwrap();
    assert!(rerun.completed);
    assert_eq!(rerun.rewritten_rows, 0);
    let inline_ready = config
        .clone()
        .with_artifact_migration_plan(plan.plan().clone());
    PostgresTaskStore::open(inline_ready.clone())
        .await
        .unwrap()
        .shutdown()
        .await
        .unwrap();
    client
        .execute(
            &format!("UPDATE {schema}.artifact_migration_plans SET batch_size=2 WHERE plan_id='migration-1'"),
            &[],
        )
        .await
        .unwrap();
    assert!(matches!(
        PostgresTaskStore::open(inline_ready.clone()).await,
        Err(PostgresStoreError::ArtifactMigrationRequired)
    ));
    client
        .execute(
            &format!("UPDATE {schema}.artifact_migration_plans SET batch_size=1 WHERE plan_id='migration-1'"),
            &[],
        )
        .await
        .unwrap();
    let file_ready = config
        .clone()
        .with_artifact_migration_plan_file(plan.clone());
    PostgresTaskStore::open(file_ready.clone())
        .await
        .unwrap()
        .shutdown()
        .await
        .unwrap();
    for column in [
        "plan_digest",
        "checkpoint_relation",
        "checkpoint_input_seal",
        "checkpoint_output_seal",
        "completion_seal",
        "full_rescan_digest",
    ] {
        let original: String = client
            .query_one(
                &format!(
                    "SELECT {column} FROM {schema}.artifact_migration_plans WHERE plan_id='migration-1'"
                ),
                &[],
            )
            .await
            .unwrap()
            .get(0);
        client
            .execute(
                &format!(
                    "UPDATE {schema}.artifact_migration_plans SET {column}=$1 WHERE plan_id='migration-1'"
                ),
                &[&format!("sha256:{}", "00".repeat(32))],
            )
            .await
            .unwrap();
        assert!(
            matches!(
                PostgresTaskStore::open(file_ready.clone()).await,
                Err(PostgresStoreError::ArtifactMigrationRequired)
            ),
            "startup accepted corrupted migration field {column}"
        );
        client
            .execute(
                &format!(
                    "UPDATE {schema}.artifact_migration_plans SET {column}=$1 WHERE plan_id='migration-1'"
                ),
                &[&original],
            )
            .await
            .unwrap();
    }
    for column in ["migrated_artifacts", "migrated_rows", "migrated_bytes"] {
        client
            .execute(
                &format!(
                    "UPDATE {schema}.artifact_migration_plans SET {column}={column}+1 WHERE plan_id='migration-1'"
                ),
                &[],
            )
            .await
            .unwrap();
        assert!(
            matches!(
                PostgresTaskStore::open(file_ready.clone()).await,
                Err(PostgresStoreError::ArtifactMigrationRequired)
            ),
            "startup accepted corrupted migration total {column}"
        );
        client
            .execute(
                &format!(
                    "UPDATE {schema}.artifact_migration_plans SET {column}={column}-1 WHERE plan_id='migration-1'"
                ),
                &[],
            )
            .await
            .unwrap();
    }
    client
        .execute(
            &format!("UPDATE {schema}.tasks SET task_json=$1 WHERE task_id='task-1'"),
            &[&inline],
        )
        .await
        .unwrap();
    assert!(matches!(
        PostgresTaskStore::open(file_ready.clone()).await,
        Err(PostgresStoreError::ArtifactMigrationRequired)
    ));
    client
        .execute(
            &format!("UPDATE {schema}.tasks SET task_json=(SELECT event_json FROM {schema}.task_events WHERE task_id='task-1') WHERE task_id='task-1'"),
            &[],
        )
        .await
        .unwrap();
    PostgresTaskStore::open(file_ready.clone())
        .await
        .unwrap()
        .shutdown()
        .await
        .unwrap();
    client
        .execute(
            &format!("UPDATE {schema}.artifact_migration_plans SET source_identity=$1 WHERE plan_id='migration-1'"),
            &[&format!("sha256:{}", "00".repeat(32))],
        )
        .await
        .unwrap();
    assert!(matches!(
        PostgresTaskStore::open(file_ready).await,
        Err(PostgresStoreError::ArtifactMigrationRequired)
    ));
    client
        .execute(
            &format!("UPDATE {schema}.artifact_migration_plans SET source_identity=$1 WHERE plan_id='migration-1'"),
            &[&store_id],
        )
        .await
        .unwrap();
    let rows = client.query(&format!("SELECT task_json FROM {schema}.tasks UNION ALL SELECT event_json FROM {schema}.task_events"), &[]).await.unwrap();
    assert!(rows.iter().all(|row| {
        let json: String = row.get(0);
        !json.contains("héllo")
            && !json.contains("AP8Q")
            && json.contains("smesh-artifact-projection/v1")
    }));
    assert_eq!(
        client
            .query_one(
                &format!("SELECT reference_count FROM {schema}.content_objects"),
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    let store = PostgresTaskStore::open(config.clone()).await.unwrap();
    let claims = store
        .claim_artifact_promotion("backup-test-promoter", 30_000, 10)
        .await
        .unwrap();
    assert_eq!(claims.len(), 1);
    assert!(store.commit_artifact_promotion(&claims[0]).await.unwrap());
    store.shutdown().await.unwrap();

    let before_rotation = client
        .query_one(
            &format!("SELECT o.backend_locator,m.manifest_digest FROM {schema}.content_objects o JOIN {schema}.artifact_manifests m USING(tenant_scope,object_id)"),
            &[],
        )
        .await
        .unwrap();
    let old_locator: String = before_rotation.get(0);
    let logical_manifest_digest: String = before_rotation.get(1);
    fs::write(&keyring, r#"{"activeGeneration":"key-2","generations":{"key-1":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","key-2":"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg"}}"#).unwrap();
    fs::set_permissions(&keyring, fs::Permissions::from_mode(0o600)).unwrap();

    let scope = OwnedTaskScope::new("tenant-a", "account-a", VisibilityScope::Own).unwrap();
    #[cfg(debug_assertions)]
    {
        let corrupt_rotation_path = root.join("corrupt-rotation-plan.json");
        fs::write(&corrupt_rotation_path, format!(r#"{{"schema":"smesh-artifact-key-rotation-plan/v1","rotationId":"rotation-corrupt","source":{{"schema":"{schema}","storeId":"{store_id}"}},"encryptionDomain":"tenant-a/confidential","oldGeneration":"key-1","newGeneration":"key-2","policy":{{"id":"rotation-policy","revision":1,"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},"actor":"operator","reason":"promoted corruption recovery","effectiveAt":1,"batchSize":1,"leaseDurationMillis":1000,"rollbackHorizonMillis":0}}"#)).unwrap();
        fs::set_permissions(&corrupt_rotation_path, fs::Permissions::from_mode(0o600)).unwrap();
        let corrupt_rotation = ArtifactKeyRotationPlanFile::open(&corrupt_rotation_path).unwrap();
        let mut crashed = Command::new(env!("CARGO_BIN_EXE_smesh-a2a-gateway"))
            .arg("artifact-key-rotate")
            .arg(&corrupt_rotation_path)
            .env_clear()
            .env("SMESH_A2A_POSTGRES_MIGRATOR_URL", &admin)
            .env("SMESH_A2A_POSTGRES_RUNTIME_URL", &runtime)
            .env("SMESH_A2A_POSTGRES_SCHEMA", &schema)
            .env("SMESH_A2A_ARTIFACT_ROOT", &cas)
            .env("SMESH_A2A_ARTIFACT_KEYRING_PATH", &keyring)
            .env(
                "SMESH_A2A_ARTIFACT_ROTATION_OWNER",
                "crashed-rotation-owner",
            )
            .env("SMESH_TEST_POSTGRES_INSECURE_LOOPBACK", "1")
            .env(
                "SMESH_TEST_ARTIFACT_CHECKPOINT",
                "reencryption_promoted_before_metadata_swap",
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let ready = if let Some(line) = BufReader::new(crashed.stdout.take().unwrap())
            .lines()
            .next()
        {
            line.unwrap()
        } else {
            let mut stderr = String::new();
            std::io::Read::read_to_string(&mut crashed.stderr.take().unwrap(), &mut stderr)
                .unwrap();
            panic!("rotation child exited before checkpoint: {stderr}");
        };
        assert_eq!(
            ready,
            "SMESH_ARTIFACT_CHECKPOINT READY reencryption_promoted_before_metadata_swap"
        );
        let promoted = client.query_one(&format!("SELECT state,new_locator,new_stage_locator,lease_token,lease_epoch FROM {schema}.artifact_reencryption_jobs WHERE rotation_id='rotation-corrupt'"),&[]).await.unwrap();
        assert_eq!(promoted.get::<_, String>(0), "promoted");
        let corrupt_locator: String = promoted.get(1);
        let corrupt_stage_locator: String = promoted.get(2);
        let stale_token: String = promoted.get(3);
        let stale_epoch: i64 = promoted.get(4);
        let corrupt_path = cas.join(&corrupt_locator);
        assert!(corrupt_path.is_file());
        fs::write(&corrupt_path, [0_u8]).unwrap();
        crashed.kill().unwrap();
        crashed.wait().unwrap();
        tokio::time::sleep(Duration::from_millis(1_100)).await;

        assert!(matches!(
            PostgresTaskStore::rotate_artifact_key(
                config.clone(),
                &corrupt_rotation,
                "recovery-rotation-owner"
            )
            .await,
            Err(PostgresStoreError::ArtifactMigrationInvalidSource)
        ));
        let recovered = client.query_one(&format!("SELECT j.state,j.lease_token,j.lease_epoch,o.backend_locator,o.key_generation,m.manifest_digest,u.final_locator FROM {schema}.artifact_reencryption_jobs j JOIN {schema}.content_objects o USING(tenant_scope,object_id) JOIN {schema}.artifact_manifests m USING(tenant_scope,object_id) JOIN {schema}.upload_intents u USING(tenant_scope,object_id) WHERE j.rotation_id='rotation-corrupt'"),&[]).await.unwrap();
        assert_eq!(recovered.get::<_, String>(0), "failed");
        assert_ne!(recovered.get::<_, String>(1), stale_token);
        assert!(recovered.get::<_, i64>(2) > stale_epoch);
        assert_eq!(recovered.get::<_, String>(3), old_locator);
        assert_eq!(recovered.get::<_, String>(4), "key-1");
        assert_eq!(recovered.get::<_, String>(5), logical_manifest_digest);
        assert_eq!(recovered.get::<_, String>(6), old_locator);
        assert_eq!(client.execute(&format!("UPDATE {schema}.artifact_reencryption_jobs SET state='swapped' WHERE rotation_id='rotation-corrupt' AND lease_token=$1 AND lease_epoch=$2 AND state='promoted'"),&[&stale_token,&stale_epoch]).await.unwrap(),0);
        assert!(!corrupt_path.exists());
        assert!(!cas.join(corrupt_stage_locator).exists());

        let old_store = PostgresTaskStore::open(config.clone()).await.unwrap();
        let lease = old_store
            .begin_artifact_resolution(
                &scope,
                "artifact-inline",
                None,
                &smesh_a2a::content_digest(b"account-a"),
                30_000,
                None,
                AuthorizationAuditInput::new(
                    "post-corrupt-resolve",
                    "tenant-a",
                    "account-a",
                    "rotation-policy",
                    1,
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "artifactResolve",
                    AuthorizationDecisionEffect::Allow,
                    "post-corruption old authority",
                    "artifact",
                    smesh_a2a::content_digest(b"artifact-inline"),
                    Some("task-1".to_owned()),
                    1,
                )
                .unwrap(),
                1,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            old_store.read_artifact_resolution(&lease).await.unwrap(),
            expected_artifact_bytes
        );
        assert!(
            old_store
                .finish_artifact_resolution(&lease, expected_artifact_bytes.len() as u64, true)
                .await
                .unwrap()
        );
        old_store.shutdown().await.unwrap();
    }

    fs::write(&keyring, r#"{"activeGeneration":"key-3","generations":{"key-1":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","key-2":"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg","key-3":"CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk"}}"#).unwrap();
    fs::set_permissions(&keyring, fs::Permissions::from_mode(0o600)).unwrap();
    let rotation_path = root.join("rotation-plan.json");
    fs::write(&rotation_path, format!(r#"{{"schema":"smesh-artifact-key-rotation-plan/v1","rotationId":"rotation-1","source":{{"schema":"{schema}","storeId":"{store_id}"}},"encryptionDomain":"tenant-a/confidential","oldGeneration":"key-1","newGeneration":"key-3","policy":{{"id":"rotation-policy","revision":1,"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},"actor":"operator","reason":"crash resumable rotation","effectiveAt":1,"batchSize":1,"leaseDurationMillis":1000,"rollbackHorizonMillis":0}}"#)).unwrap();
    fs::set_permissions(&rotation_path, fs::Permissions::from_mode(0o600)).unwrap();
    let rotation = ArtifactKeyRotationPlanFile::open(&rotation_path).unwrap();
    #[cfg(debug_assertions)]
    {
        let mut valid_crash = Command::new(env!("CARGO_BIN_EXE_smesh-a2a-gateway"))
            .arg("artifact-key-rotate")
            .arg(&rotation_path)
            .env_clear()
            .env("SMESH_A2A_POSTGRES_MIGRATOR_URL", &admin)
            .env("SMESH_A2A_POSTGRES_RUNTIME_URL", &runtime)
            .env("SMESH_A2A_POSTGRES_SCHEMA", &schema)
            .env("SMESH_A2A_ARTIFACT_ROOT", &cas)
            .env("SMESH_A2A_ARTIFACT_KEYRING_PATH", &keyring)
            .env(
                "SMESH_A2A_ARTIFACT_ROTATION_OWNER",
                "valid-crashed-rotation-owner",
            )
            .env("SMESH_TEST_POSTGRES_INSECURE_LOOPBACK", "1")
            .env(
                "SMESH_TEST_ARTIFACT_CHECKPOINT",
                "reencryption_promoted_before_metadata_swap",
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        assert_eq!(
            BufReader::new(valid_crash.stdout.take().unwrap())
                .lines()
                .next()
                .unwrap()
                .unwrap(),
            "SMESH_ARTIFACT_CHECKPOINT READY reencryption_promoted_before_metadata_swap"
        );
        let valid_promoted = client.query_one(&format!("SELECT j.state,j.new_locator,o.backend_locator,o.key_generation FROM {schema}.artifact_reencryption_jobs j JOIN {schema}.content_objects o USING(tenant_scope,object_id) WHERE j.rotation_id='rotation-1'"),&[]).await.unwrap();
        assert_eq!(valid_promoted.get::<_, String>(0), "promoted");
        assert!(cas.join(valid_promoted.get::<_, String>(1)).is_file());
        assert_eq!(valid_promoted.get::<_, String>(2), old_locator);
        assert_eq!(valid_promoted.get::<_, String>(3), "key-1");
        valid_crash.kill().unwrap();
        valid_crash.wait().unwrap();
        tokio::time::sleep(Duration::from_millis(1_100)).await;
    }
    let rotated =
        PostgresTaskStore::rotate_artifact_key(config.clone(), &rotation, "rotation-owner")
            .await
            .unwrap();
    assert_eq!(rotated.reencrypted, 1);
    assert_eq!(rotated.cleaned, 1);
    assert!(rotated.completed);
    let rotation_row = client.query_one(&format!("SELECT j.state,j.new_locator,j.new_stage_locator,j.new_nonce,j.new_ciphertext_digest,j.new_ciphertext_length,j.new_aad_seal,o.backend_locator,o.key_generation,m.manifest_digest FROM {schema}.artifact_reencryption_jobs j JOIN {schema}.content_objects o USING(tenant_scope,object_id) JOIN {schema}.artifact_manifests m USING(tenant_scope,object_id) WHERE j.rotation_id='rotation-1'"),&[]).await.unwrap();
    assert_eq!(rotation_row.get::<_, String>(0), "completed");
    let new_locator: String = rotation_row.get(1);
    assert_ne!(new_locator, old_locator);
    assert!(rotation_row.get::<_, String>(2).starts_with("stage/"));
    assert_eq!(rotation_row.get::<_, Vec<u8>>(3).len(), 12);
    assert!(rotation_row.get::<_, String>(4).starts_with("sha256:"));
    assert!(rotation_row.get::<_, i64>(5) >= 16);
    assert!(rotation_row.get::<_, String>(6).starts_with("sha256:"));
    assert_eq!(rotation_row.get::<_, String>(7), new_locator);
    assert_eq!(rotation_row.get::<_, String>(8), "key-3");
    assert_eq!(rotation_row.get::<_, String>(9), logical_manifest_digest);
    assert!(!root.join("cas").join(&old_locator).exists());
    assert!(root.join("cas").join(&new_locator).is_file());
    let rotated_store = PostgresTaskStore::open(config.clone()).await.unwrap();
    let rotated_lease = rotated_store
        .begin_artifact_resolution(
            &scope,
            "artifact-inline",
            None,
            &smesh_a2a::content_digest(b"account-a"),
            30_000,
            None,
            AuthorizationAuditInput::new(
                "post-valid-resume",
                "tenant-a",
                "account-a",
                "rotation-policy",
                1,
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "artifactResolve",
                AuthorizationDecisionEffect::Allow,
                "post-valid-resume authority",
                "artifact",
                smesh_a2a::content_digest(b"artifact-inline"),
                Some("task-1".to_owned()),
                2,
            )
            .unwrap(),
            2,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        rotated_store
            .read_artifact_resolution(&rotated_lease)
            .await
            .unwrap(),
        expected_artifact_bytes
    );
    assert!(
        rotated_store
            .finish_artifact_resolution(&rotated_lease, expected_artifact_bytes.len() as u64, true)
            .await
            .unwrap()
    );
    rotated_store.shutdown().await.unwrap();

    let backup_root = root.join("backup");
    fs::create_dir(&backup_root).unwrap();
    fs::set_permissions(&backup_root, fs::Permissions::from_mode(0o700)).unwrap();
    let backup_plan_path = root.join("backup-plan.json");
    let signature_hook = std::env::current_exe().unwrap();
    fs::write(
        &backup_plan_path,
        format!(
            r#"{{"schema":"smesh-artifact-backup-plan/v1","backupId":"backup-1","source":{{"schema":"{schema}","storeId":"{store_id}"}},"artifactPolicy":{{"id":"artifact-migration","revision":1,"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},"actor":"operator","reason":"physical roundtrip evidence","destination":"{}","batchSize":1,"leaseDurationMillis":60000,"signatureHook":{{"command":"{}","args":["--ignored","--exact","detached_signature_signer","--nocapture","--test-threads=1"]}}}}"#,
            backup_root.display(), signature_hook.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&backup_plan_path, fs::Permissions::from_mode(0o600)).unwrap();
    let backup_plan = ArtifactBackupPlanFile::open(&backup_plan_path).unwrap();
    let (backup_a, backup_b) = tokio::join!(
        PostgresTaskStore::backup_artifacts(config.clone(), &backup_plan, "backup-owner-a"),
        PostgresTaskStore::backup_artifacts(config.clone(), &backup_plan, "backup-owner-b")
    );
    let outcomes = [backup_a, backup_b];
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.is_ok()).count(),
        1,
        "backup outcomes: {outcomes:?}"
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Err(PostgresStoreError::ArtifactMigrationBusy)))
            .count(),
        1
    );
    let backup = outcomes.into_iter().find_map(Result::ok).unwrap();
    assert_eq!(backup.objects, 1);
    assert!(backup_root.join("inventory.json").is_file());
    assert!(backup_root.join("inventory.sig").is_file());
    assert!(
        fs::read_dir(backup_root.join("objects"))
            .unwrap()
            .next()
            .is_some()
    );

    let restored_root = root.join("restored-cas");
    fs::create_dir(&restored_root).unwrap();
    fs::set_permissions(&restored_root, fs::Permissions::from_mode(0o700)).unwrap();
    let target_schema = format!("smesh_artifact_restore_{:016x}", rand::random::<u64>());
    let target_config = PostgresStoreConfig::new(&admin, &runtime, &target_schema)
        .unwrap()
        .with_test_only_insecure_loopback(true)
        .with_test_only_parent_managed_cleanup();
    let empty_target = PostgresTaskStore::open(target_config.clone())
        .await
        .unwrap();
    empty_target.shutdown().await.unwrap();
    let restored_config = target_config
        .with_artifact_store(ArtifactStoreConfig::new(&restored_root, &keyring).unwrap());
    let restored_store_id: Vec<u8> = client
        .query_one(
            &format!("SELECT store_id FROM {target_schema}.store_identity"),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let restored_store_id = format!(
        "sha256:{}",
        restored_store_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let restore_path = root.join("restore-plan.json");
    fs::write(&restore_path,format!(r#"{{"schema":"smesh-artifact-restore-plan/v1","restoreId":"restore-1","source":{{"backupRoot":"{}","inventory":"{}","storeId":"{store_id}"}},"target":{{"schema":"{target_schema}","storeId":"{restored_store_id}","root":"{}"}},"artifactPolicyDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","actor":"operator","reason":"physical restore evidence","batchSize":1,"clonePolicy":false,"signatureHook":{{"command":"{}","args":["--ignored","--exact","detached_signature_verifier","--nocapture","--test-threads=1"]}}}}"#,backup_root.display(),backup_root.join("inventory.json").display(),restored_root.display(),signature_hook.display())).unwrap();
    fs::set_permissions(&restore_path, fs::Permissions::from_mode(0o600)).unwrap();
    let restore = ArtifactRestorePlanFile::open(&restore_path).unwrap();

    let write_restore_hook = |verifier: &str| {
        if restored_root.exists() {
            fs::remove_dir_all(&restored_root).unwrap();
        }
        fs::create_dir(&restored_root).unwrap();
        fs::set_permissions(&restored_root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&restore_path,format!(r#"{{"schema":"smesh-artifact-restore-plan/v1","restoreId":"restore-1","source":{{"backupRoot":"{}","inventory":"{}","storeId":"{store_id}"}},"target":{{"schema":"{target_schema}","storeId":"{restored_store_id}","root":"{}"}},"artifactPolicyDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","actor":"operator","reason":"physical restore evidence","batchSize":1,"clonePolicy":false,"signatureHook":{{"command":"{}","args":["--ignored","--exact","{verifier}","--nocapture","--test-threads=1"]}}}}"#,backup_root.display(),backup_root.join("inventory.json").display(),restored_root.display(),signature_hook.display())).unwrap();
        fs::set_permissions(&restore_path, fs::Permissions::from_mode(0o600)).unwrap();
        ArtifactRestorePlanFile::open(&restore_path).unwrap()
    };
    let clean_signature = fs::read(backup_root.join("inventory.sig")).unwrap();
    fs::remove_file(backup_root.join("inventory.sig")).unwrap();
    assert!(
        PostgresTaskStore::restore_artifacts(restored_config.clone(), &restore)
            .await
            .is_err()
    );
    fs::write(backup_root.join("inventory.sig"), &clean_signature).unwrap();
    fs::set_permissions(
        backup_root.join("inventory.sig"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let mutated_signature = String::from_utf8(clean_signature.clone())
        .unwrap()
        .replace("smesh-test-signer-a:", "smesh-test-signer-b:");
    fs::write(backup_root.join("inventory.sig"), mutated_signature).unwrap();
    assert!(
        PostgresTaskStore::restore_artifacts(restored_config.clone(), &restore)
            .await
            .is_err()
    );
    fs::write(backup_root.join("inventory.sig"), &clean_signature).unwrap();
    fs::set_permissions(
        backup_root.join("inventory.sig"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    drop(restore);
    for verifier in [
        "detached_signature_wrong_signer",
        "detached_signature_command_failure",
    ] {
        let rejected = write_restore_hook(verifier);
        assert!(
            PostgresTaskStore::restore_artifacts(restored_config.clone(), &rejected)
                .await
                .is_err()
        );
    }
    assert_eq!(
        client
            .query_one(
                &format!("SELECT count(*) FROM {target_schema}.artifact_restore_jobs"),
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0,
        "signature failures enabled restore metadata"
    );
    let restore = write_restore_hook("detached_signature_verifier");

    let clean_inventory: serde_json::Value =
        serde_json::from_slice(&fs::read(backup_root.join("inventory.json")).unwrap()).unwrap();
    for name in [
        "inventory-digest",
        "inventory-schema",
        "source-store-id",
        "policy-digest",
        "missing-object-list",
        "key-generation",
        "manifest-digest",
        "manifest-canonical-json",
        "invalid-provenance-parent-id",
        "forged-provenance",
        "cross-bound-hold",
        "malformed-tombstone",
        "duplicate-hold-pk",
    ] {
        let mut inventory = clean_inventory.clone();
        match name {
            "inventory-schema" => inventory["schema"] = serde_json::json!("forged/v1"),
            "source-store-id" => {
                inventory["sourceStoreId"] =
                    serde_json::json!(format!("sha256:{}", "11".repeat(32)));
            }
            "policy-digest" => {
                inventory["policyDigest"] =
                    serde_json::json!(format!("sha256:{}", "22".repeat(32)));
            }
            "missing-object-list" => inventory["entries"] = serde_json::json!([]),
            "key-generation" => {
                inventory["entries"][0]["object"]["key_generation"] =
                    serde_json::json!("key-forged");
            }
            "manifest-digest" => {
                inventory["entries"][0]["manifest"]["manifest_digest"] =
                    serde_json::json!(format!("sha256:{}", "33".repeat(32)));
            }
            "manifest-canonical-json" => {
                inventory["entries"][0]["manifest"]["canonical_json"] = serde_json::json!("{}");
            }
            "invalid-provenance-parent-id" => {
                let manifest = &mut inventory["entries"][0]["manifest"];
                let mut canonical: serde_json::Value =
                    serde_json::from_str(manifest["canonical_json"].as_str().unwrap()).unwrap();
                canonical["derivedFrom"] = serde_json::json!([{
                    "artifactId": "parent%2Falias",
                    "relation": "transformation"
                }]);
                let canonical = serde_json::to_string(&canonical).unwrap();
                let mut manifest_bytes = b"smesh-artifact-manifest/v1\0".to_vec();
                manifest_bytes.extend_from_slice(canonical.as_bytes());
                manifest["canonical_json"] = serde_json::json!(canonical);
                manifest["manifest_digest"] =
                    serde_json::json!(smesh_a2a::content_digest(&manifest_bytes));
                inventory["entries"][0]["provenance"] = serde_json::json!([{
                    "tenant_scope": "tenant-a",
                    "child_artifact_id": "artifact-inline",
                    "ordinal": 0,
                    "parent_artifact_id": "parent%2Falias",
                    "relation": "transformation"
                }]);
            }
            "forged-provenance" => {
                inventory["entries"][0]["provenance"] = serde_json::json!([{"tenant_scope":"tenant-a","child_artifact_id":"artifact-inline","ordinal":0,"parent_artifact_id":"artifact-forged","relation":"derived"}]);
            }
            "cross-bound-hold" => {
                inventory["entries"][0]["holds"] = serde_json::json!([{
                    "tenant_scope":"tenant-forged","hold_id":"hold-1","artifact_id":"artifact-inline",
                    "actor_digest":format!("sha256:{}", "44".repeat(32)),
                    "reason_digest":format!("sha256:{}", "55".repeat(32)),
                    "state":"active","created_at":1,"expires_at":null,"released_at":null
                }]);
            }
            "malformed-tombstone" => {
                inventory["entries"][0]["tombstones"] = serde_json::json!([{
                    "tenant_scope":"tenant-a","object_id":inventory["entries"][0]["object"]["object_id"],
                    "tombstone_generation":0,"reason_digest":"not-a-digest",
                    "locator_digest":format!("sha256:{}", "66".repeat(32)),
                    "deletion_receipt_digest":null,"tombstoned_at":1,"deleted_at":null
                }]);
            }
            "duplicate-hold-pk" => {
                let hold = serde_json::json!({
                    "tenant_scope":"tenant-a","hold_id":"hold-duplicate","artifact_id":"artifact-inline",
                    "actor_digest":format!("sha256:{}", "44".repeat(32)),
                    "reason_digest":format!("sha256:{}", "55".repeat(32)),
                    "state":"active","created_at":1,"expires_at":null,"released_at":null
                });
                inventory["entries"][0]["holds"] = serde_json::json!([hold.clone(), hold]);
            }
            "inventory-digest" => {}
            _ => unreachable!(),
        }
        write_inventory_and_digest(&backup_root, &inventory);
        if name == "inventory-digest" {
            fs::write(
                backup_root.join("inventory.digest"),
                format!("sha256:{}", "00".repeat(32)),
            )
            .unwrap();
        }
        let target_files_before = regular_file_count(&restored_root);
        assert!(
            PostgresTaskStore::restore_artifacts(restored_config.clone(), &restore)
                .await
                .is_err(),
            "restore accepted corrupt backup component {name}"
        );
        let unchanged = client.query_one(&format!("SELECT (SELECT count(*) FROM {target_schema}.artifact_restore_jobs),(SELECT count(*) FROM {target_schema}.content_objects),(SELECT count(*) FROM {target_schema}.artifact_manifests),(SELECT count(*) FROM {target_schema}.artifact_retention_holds),(SELECT count(*) FROM {target_schema}.artifact_tombstones)"), &[]).await.unwrap();
        assert_eq!(
            (
                unchanged.get::<_, i64>(0),
                unchanged.get::<_, i64>(1),
                unchanged.get::<_, i64>(2),
                unchanged.get::<_, i64>(3),
                unchanged.get::<_, i64>(4)
            ),
            (0, 0, 0, 0, 0),
            "corrupt restore mutated target metadata for {name}"
        );
        assert_eq!(
            regular_file_count(&restored_root),
            target_files_before,
            "corrupt restore copied target files for {name}"
        );
        client
            .execute(
                &format!(
                    "DELETE FROM {target_schema}.artifact_restore_jobs WHERE state<>'enabled'"
                ),
                &[],
            )
            .await
            .unwrap();
        fs::remove_dir_all(&restored_root).unwrap();
        fs::create_dir(&restored_root).unwrap();
        fs::set_permissions(&restored_root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    write_inventory_and_digest(&backup_root, &clean_inventory);
    let backup_locator = clean_inventory["entries"][0]["object"]["backend_locator"]
        .as_str()
        .unwrap();
    let backup_blob = backup_root.join(backup_locator);
    let clean_blob = fs::read(&backup_blob).unwrap();
    let mut corrupt_blob = clean_blob.clone();
    corrupt_blob[0] ^= 0x80;
    fs::write(&backup_blob, &corrupt_blob).unwrap();
    assert!(
        PostgresTaskStore::restore_artifacts(restored_config.clone(), &restore)
            .await
            .is_err(),
        "restore accepted corrupt ciphertext blob"
    );
    assert_eq!(
        client
            .query_one(
                &format!(
                    "SELECT count(*) FROM {target_schema}.artifact_restore_jobs WHERE state='enabled'"
                ),
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0,
        "corrupt blob enabled restore"
    );
    client
        .execute(
            &format!("DELETE FROM {target_schema}.artifact_restore_jobs WHERE state<>'enabled'"),
            &[],
        )
        .await
        .unwrap();
    fs::write(&backup_blob, clean_blob).unwrap();
    fs::remove_dir_all(&restored_root).unwrap();
    fs::create_dir(&restored_root).unwrap();
    fs::set_permissions(&restored_root, fs::Permissions::from_mode(0o700)).unwrap();
    let (restore_a, restore_b) = tokio::join!(
        PostgresTaskStore::restore_artifacts(restored_config.clone(), &restore),
        PostgresTaskStore::restore_artifacts(restored_config.clone(), &restore)
    );
    let restores = [restore_a, restore_b];
    assert_eq!(
        restores.iter().filter(|result| result.is_ok()).count(),
        1,
        "restore outcomes: {restores:?}"
    );
    assert_eq!(
        restores
            .iter()
            .filter(|result| matches!(result, Err(PostgresStoreError::ArtifactMigrationBusy)))
            .count(),
        1
    );
    let restore_winner = restores.into_iter().find_map(Result::ok).unwrap();
    assert_eq!(restore_winner.objects, 1);
    assert!(restore_winner.enabled);

    assert_eq!(
        client
            .query_one(
                &format!("SELECT o.state,r.state FROM {target_schema}.content_objects o JOIN {target_schema}.artifact_manifests m USING(tenant_scope,object_id) JOIN {target_schema}.artifact_references r USING(tenant_scope,artifact_id)"),
                &[],
            )
            .await
            .unwrap()
            .get::<_, String>(0),
        "available"
    );
    let retained = client
        .query_one(
            &format!("SELECT retained_bytes,{target_schema}.retained_authority_oracle('tenant-a',NULL)+{target_schema}.artifact_retained_oracle('tenant-a',NULL) FROM {target_schema}.retained_authority_usage WHERE tenant_scope='tenant-a' AND scope_kind='tenant'"),
            &[],
        )
        .await
        .unwrap();
    assert_eq!(retained.get::<_, i64>(0), retained.get::<_, i64>(1));
    assert_eq!(
        client
            .query_one(
                &format!("SELECT count(*) FROM {target_schema}.quota_policy_versions"),
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0,
        "clonePolicy=false imported the source quota policy"
    );
    let artifact_invalid: i64 = client
        .query_one(
            &format!("SELECT (SELECT count(*) FROM {target_schema}.content_objects o WHERE o.reference_count<>(SELECT count(*) FROM {target_schema}.artifact_references r JOIN {target_schema}.artifact_manifests m USING(tenant_scope,artifact_id) WHERE m.tenant_scope=o.tenant_scope AND m.object_id=o.object_id AND r.state='active')) +(SELECT count(*) FROM {target_schema}.content_objects WHERE backend_locator!~'^objects/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+$' OR (state='available' AND available_at IS NULL)) +(SELECT count(*) FROM {target_schema}.content_objects o JOIN {target_schema}.artifact_manifests m USING(tenant_scope,object_id) WHERE o.plaintext_length<>m.plaintext_length OR o.classification<>m.classification OR o.encryption_domain<>m.encryption_domain)"),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(artifact_invalid, 0);
    let reopened = PostgresTaskStore::open(restored_config.clone())
        .await
        .unwrap();
    let scope = OwnedTaskScope::new("tenant-a", "account-a", VisibilityScope::Own).unwrap();
    let task = reopened
        .get_authorized(
            &scope,
            "task-1",
            AuthorizationAuditInput::new(
                "restore-task-replay",
                "tenant-a",
                "account-a",
                "restore-test-policy",
                1,
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "taskGet",
                AuthorizationDecisionEffect::Allow,
                "restore replay",
                "task",
                smesh_a2a::content_digest(b"task-1"),
                Some("task-1".to_owned()),
                1,
            )
            .unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(task.id, "task-1");
    assert_eq!(task.artifacts.as_ref().unwrap().len(), 1);
    let lease = reopened
        .begin_artifact_resolution(
            &scope,
            "artifact-inline",
            None,
            &smesh_a2a::content_digest(b"account-a"),
            30_000,
            None,
            AuthorizationAuditInput::new(
                "restore-artifact-resolve",
                "tenant-a",
                "account-a",
                "restore-test-policy",
                1,
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "artifactResolve",
                AuthorizationDecisionEffect::Allow,
                "restore resolver",
                "artifact",
                smesh_a2a::content_digest(b"artifact-inline"),
                Some("task-1".to_owned()),
                1,
            )
            .unwrap(),
            1,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        reopened.read_artifact_resolution(&lease).await.unwrap(),
        expected_artifact_bytes
    );
    assert!(
        reopened
            .finish_artifact_resolution(&lease, expected_artifact_bytes.len() as u64, true)
            .await
            .unwrap()
    );
    reopened.shutdown().await.unwrap();

    // The same sealed inventory exercises the positive clone policy exactly.
    // The false restore above omitted this row; true imports it and preserves
    // the operator audit digests in the restore journal.
    let mut clone_inventory = clean_inventory.clone();
    let cloned_quota = serde_json::json!({
        "tenant_scope":"tenant-a",
        "policy_id":"cloned-quota",
        "policy_revision":1,
        "policy_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "canonical_json":"{\"limits\":{\"retainedAuthorityBytes\":{\"tenant\":67108864,\"account\":67108864,\"principal\":67108864}}}",
        "lifecycle":"active",
        "retired_at":null,
        "created_at":1
    });
    clone_inventory["quotaPolicies"] = serde_json::json!([cloned_quota]);
    clone_inventory["entries"][0]["quotaPolicyKey"] = serde_json::json!(
        serde_json::to_string(&serde_json::json!(["tenant-a", "cloned-quota", 1])).unwrap()
    );
    write_inventory_and_digest(&backup_root, &clone_inventory);
    let clone_root = root.join("clone-cas");
    fs::create_dir(&clone_root).unwrap();
    fs::set_permissions(&clone_root, fs::Permissions::from_mode(0o700)).unwrap();
    let clone_schema = format!("smesh_artifact_clone_{:016x}", rand::random::<u64>());
    let clone_base = PostgresStoreConfig::new(&admin, &runtime, &clone_schema)
        .unwrap()
        .with_test_only_insecure_loopback(true)
        .with_test_only_parent_managed_cleanup();
    PostgresTaskStore::open(clone_base.clone())
        .await
        .unwrap()
        .shutdown()
        .await
        .unwrap();
    let clone_id: Vec<u8> = client
        .query_one(
            &format!("SELECT store_id FROM {clone_schema}.store_identity"),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let clone_id = format!(
        "sha256:{}",
        clone_id
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let clone_plan_path = root.join("clone-restore-plan.json");
    fs::write(&clone_plan_path, format!(r#"{{"schema":"smesh-artifact-restore-plan/v1","restoreId":"restore-clone","source":{{"backupRoot":"{}","inventory":"{}","storeId":"{store_id}"}},"target":{{"schema":"{clone_schema}","storeId":"{clone_id}","root":"{}"}},"artifactPolicyDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","actor":"clone-operator","reason":"clone policy evidence","batchSize":1,"clonePolicy":true,"signatureHook":{{"command":"{}","args":["--ignored","--exact","detached_signature_verifier","--nocapture","--test-threads=1"]}}}}"#,backup_root.display(),backup_root.join("inventory.json").display(),clone_root.display(),signature_hook.display())).unwrap();
    fs::set_permissions(&clone_plan_path, fs::Permissions::from_mode(0o600)).unwrap();
    let clone_plan = ArtifactRestorePlanFile::open(&clone_plan_path).unwrap();
    let clone_config =
        clone_base.with_artifact_store(ArtifactStoreConfig::new(&clone_root, &keyring).unwrap());
    assert!(
        PostgresTaskStore::restore_artifacts(clone_config.clone(), &clone_plan)
            .await
            .unwrap()
            .enabled
    );
    let clone_row = client.query_one(&format!("SELECT p.policy_id,j.actor_digest,j.reason_digest FROM {clone_schema}.quota_policy_versions p JOIN {clone_schema}.artifact_restore_jobs j USING(tenant_scope) WHERE j.state='enabled'"),&[]).await.unwrap();
    assert_eq!(clone_row.get::<_, String>(0), "cloned-quota");
    assert_eq!(
        clone_row.get::<_, String>(1),
        smesh_a2a::content_digest(b"clone-operator")
    );
    assert_eq!(
        clone_row.get::<_, String>(2),
        smesh_a2a::content_digest(b"clone policy evidence")
    );
    client
        .batch_execute(&format!(
            "DROP SCHEMA {clone_schema} CASCADE; DROP ROLE IF EXISTS {clone_schema}_runtime"
        ))
        .await
        .unwrap();
    write_inventory_and_digest(&backup_root, &clean_inventory);

    let reseal_root = root.join("restored-backup");
    fs::create_dir(&reseal_root).unwrap();
    fs::set_permissions(&reseal_root, fs::Permissions::from_mode(0o700)).unwrap();
    let reseal_plan_path = root.join("restored-backup-plan.json");
    fs::write(&reseal_plan_path, format!(
        r#"{{"schema":"smesh-artifact-backup-plan/v1","backupId":"backup-restored","source":{{"schema":"{target_schema}","storeId":"{restored_store_id}"}},"artifactPolicy":{{"id":"artifact-migration","revision":1,"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},"actor":"operator","reason":"restored inventory reseal","destination":"{}","batchSize":1,"leaseDurationMillis":60000,"signatureHook":{{"command":"{}","args":["--ignored","--exact","detached_signature_signer","--nocapture","--test-threads=1"]}}}}"#,
        reseal_root.display(), signature_hook.display())).unwrap();
    fs::set_permissions(&reseal_plan_path, fs::Permissions::from_mode(0o600)).unwrap();
    let reseal_plan = ArtifactBackupPlanFile::open(&reseal_plan_path).unwrap();
    let resealed = PostgresTaskStore::backup_artifacts(
        restored_config.clone(),
        &reseal_plan,
        "restored-backup-owner",
    )
    .await
    .unwrap();
    assert_eq!(resealed.objects, 1);
    let resealed_inventory = fs::read(reseal_root.join("inventory.json")).unwrap();
    let mut resealed_payload = b"smesh-artifact-physical-inventory/v1\0".to_vec();
    resealed_payload.extend_from_slice(&resealed_inventory);
    assert_eq!(
        fs::read_to_string(reseal_root.join("inventory.digest")).unwrap(),
        ContentDigestV1::of(&resealed_payload).to_string()
    );

    client
        .batch_execute(&format!(
            "SET session_replication_role=replica; UPDATE {target_schema}.artifact_manifests SET manifest_digest='sha256:{}' WHERE tenant_scope='tenant-a' AND artifact_id='artifact-inline'; SET session_replication_role=origin",
            "44".repeat(32)
        ))
        .await
        .unwrap();
    assert_eq!(
        test_only_artifact_semantic_stage(&client, &target_schema)
            .await
            .unwrap_err(),
        "artifact-manifest-seal:artifact_manifests:tenant-a/artifact-inline"
    );
    assert!(matches!(
        PostgresTaskStore::open(restored_config.clone()).await,
        Err(PostgresStoreError::InvalidSchema)
    ));

    client
        .batch_execute(&format!(
            "DROP SCHEMA {schema} CASCADE; DROP SCHEMA {target_schema} CASCADE; DROP ROLE IF EXISTS {schema}_runtime; DROP ROLE IF EXISTS {target_schema}_runtime"
        ))
        .await
        .unwrap();
    drop(client);
    driver.abort();
}

async fn test_only_artifact_semantic_stage(
    client: &tokio_postgres::Client,
    schema: &str,
) -> Result<(), String> {
    for row in client
        .query(
            &format!(
                "SELECT tenant_scope,artifact_id,manifest_digest,canonical_json FROM {schema}.artifact_manifests ORDER BY tenant_scope,artifact_id"
            ),
            &[],
        )
        .await
        .unwrap()
    {
        let tenant: String = row.get(0);
        let artifact: String = row.get(1);
        let digest: String = row.get(2);
        let canonical: String = row.get(3);
        let mut sealed = b"smesh-artifact-manifest/v1\0".to_vec();
        sealed.extend_from_slice(canonical.as_bytes());
        if digest != smesh_a2a::content_digest(&sealed) {
            return Err(format!(
                "artifact-manifest-seal:artifact_manifests:{tenant}/{artifact}"
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
#[allow(clippy::too_many_lines, clippy::format_collect)]
async fn empty_backup_restore_is_sealed_retryable_and_requires_a_truly_empty_target() {
    use std::os::unix::fs::PermissionsExt as _;
    use std::str::FromStr as _;

    let Some((admin, runtime, superuser)) = postgres_urls() else {
        return;
    };
    let root = ArtifactTestRoot::new("artifact-empty-roundtrip");
    let keyring = root.join("keys.json");
    fs::write(&keyring, r#"{"activeGeneration":"key-1","generations":{"key-1":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"}}"#).unwrap();
    fs::set_permissions(&keyring, fs::Permissions::from_mode(0o600)).unwrap();
    let source_root = root.join("source-cas");
    let target_root = root.join("target-cas");
    let backup_root = root.join("backup");
    for path in [&source_root, &target_root, &backup_root] {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let source_schema = format!("smesh_empty_source_{:016x}", rand::random::<u64>());
    let target_schema = format!("smesh_empty_target_{:016x}", rand::random::<u64>());
    let source_config = PostgresStoreConfig::new(&admin, &runtime, &source_schema)
        .unwrap()
        .with_test_only_insecure_loopback(true)
        .with_test_only_parent_managed_cleanup()
        .with_artifact_store(ArtifactStoreConfig::new(&source_root, &keyring).unwrap());
    PostgresTaskStore::open(source_config.clone())
        .await
        .unwrap()
        .shutdown()
        .await
        .unwrap();
    let target_base = PostgresStoreConfig::new(&admin, &runtime, &target_schema)
        .unwrap()
        .with_test_only_insecure_loopback(true)
        .with_test_only_parent_managed_cleanup()
        .with_audit_projection(true);
    PostgresTaskStore::open(target_base.clone())
        .await
        .unwrap()
        .shutdown()
        .await
        .unwrap();
    let pg = tokio_postgres::Config::from_str(&superuser).unwrap();
    let (client, connection) = pg.connect(tokio_postgres::NoTls).await.unwrap();
    let driver = tokio::spawn(async move { connection.await.unwrap() });
    let identity = |bytes: Vec<u8>| {
        format!(
            "sha256:{}",
            bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
        )
    };
    let source_id = identity(
        client
            .query_one(
                &format!("SELECT store_id FROM {source_schema}.store_identity"),
                &[],
            )
            .await
            .unwrap()
            .get(0),
    );
    let target_id = identity(
        client
            .query_one(
                &format!("SELECT store_id FROM {target_schema}.store_identity"),
                &[],
            )
            .await
            .unwrap()
            .get(0),
    );
    let policy = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let backup_path = root.join("empty-backup-plan.json");
    fs::write(&backup_path, format!(r#"{{"schema":"smesh-artifact-backup-plan/v1","backupId":"empty-backup","source":{{"schema":"{source_schema}","storeId":"{source_id}"}},"artifactPolicy":{{"id":"artifact-empty","revision":1,"digest":"{policy}"}},"actor":"operator","reason":"empty authority backup","destination":"{}","batchSize":1,"leaseDurationMillis":60000}}"#,backup_root.display())).unwrap();
    fs::set_permissions(&backup_path, fs::Permissions::from_mode(0o600)).unwrap();
    let backup = ArtifactBackupPlanFile::open(&backup_path).unwrap();
    let outcome =
        PostgresTaskStore::backup_artifacts(source_config.clone(), &backup, "empty-owner")
            .await
            .unwrap();
    assert_eq!(outcome.objects, 0);
    let inventory: serde_json::Value =
        serde_json::from_slice(&fs::read(backup_root.join("inventory.json")).unwrap()).unwrap();
    assert_eq!(inventory["entryCount"], 0);
    assert_eq!(inventory["entries"], serde_json::json!([]));
    assert!(backup_root.join("inventory.digest").is_file());
    let restore_path = root.join("empty-restore-plan.json");
    fs::write(&restore_path, format!(r#"{{"schema":"smesh-artifact-restore-plan/v1","restoreId":"empty-restore","source":{{"backupRoot":"{}","inventory":"{}","storeId":"{source_id}"}},"target":{{"schema":"{target_schema}","storeId":"{target_id}","root":"{}"}},"artifactPolicyDigest":"{policy}","actor":"operator","reason":"empty authority restore","batchSize":1,"clonePolicy":false}}"#,backup_root.display(),backup_root.join("inventory.json").display(),target_root.display())).unwrap();
    fs::set_permissions(&restore_path, fs::Permissions::from_mode(0o600)).unwrap();
    let restore = ArtifactRestorePlanFile::open(&restore_path).unwrap();
    let target_config =
        target_base.with_artifact_store(ArtifactStoreConfig::new(&target_root, &keyring).unwrap());
    let orphan_projection_event = smesh_a2a::content_digest(b"bootstrap-only-projection-event");
    let orphan_projection_source = smesh_a2a::content_digest(b"bootstrap-only-projection-source");
    client
        .execute(
            &format!("INSERT INTO {target_schema}.audit_projection_outbox(tenant_scope,event_id,source,source_pk_digest,event_kind,occurred_at,available_at) VALUES('tenant-bootstrap',$1,'task_events',$2,'task_terminal',1,1)"),
            &[&orphan_projection_event, &orphan_projection_source],
        )
        .await
        .unwrap();
    client
        .execute(
            &format!("INSERT INTO {target_schema}.artifact_orphan_audits VALUES($1,0,1)"),
            &[&smesh_a2a::content_digest(b"occupied-target")],
        )
        .await
        .unwrap();
    assert!(matches!(
        PostgresTaskStore::restore_artifacts(target_config.clone(), &restore).await,
        Err(PostgresStoreError::ArtifactRestoreTargetNotEmpty)
    ));
    client
        .execute(
            &format!("DELETE FROM {target_schema}.artifact_orphan_audits"),
            &[],
        )
        .await
        .unwrap();

    // An active projector lease proves a live optional consumer and must fence restore
    // without changing the control row or outbox lease.
    assert_eq!(
        client
            .execute(
                &format!("UPDATE {target_schema}.audit_projection_outbox SET state='leased',attempts=1,lease_owner='live-projector',lease_token='lease-token',lease_epoch=1,lease_expires_at={target_schema}.db_millis()+60000"),
                &[],
            )
            .await
            .unwrap(),
        1
    );
    assert!(client
        .query_one(
            &format!("SELECT EXISTS(SELECT 1 FROM {target_schema}.audit_projection_outbox WHERE state='leased' AND lease_expires_at>{target_schema}.db_millis())"),
            &[],
        )
        .await
        .unwrap()
        .get::<_, bool>(0));
    let active_lease_restore =
        PostgresTaskStore::restore_artifacts(target_config.clone(), &restore).await;
    assert!(
        matches!(
            active_lease_restore,
            Err(PostgresStoreError::ArtifactMigrationBusy)
        ),
        "active lease restore outcome: {active_lease_restore:?}"
    );
    let leased = client
        .query_one(
            &format!("SELECT state,lease_owner,(SELECT enabled FROM {target_schema}.audit_projection_control WHERE singleton=1) FROM {target_schema}.audit_projection_outbox WHERE event_id=$1"),
            &[&orphan_projection_event],
        )
        .await
        .unwrap();
    assert_eq!(leased.get::<_, String>(0), "leased");
    assert_eq!(leased.get::<_, String>(1), "live-projector");
    assert!(leased.get::<_, bool>(2));
    client
        .execute(
            &format!("UPDATE {target_schema}.audit_projection_outbox SET state='pending',attempts=0,lease_owner=NULL,lease_token=NULL,lease_epoch=0,lease_expires_at=NULL"),
            &[],
        )
        .await
        .unwrap();

    // Optional rows are resettable only while no causative authority exists. A
    // preexisting task/event keeps both projection state and enablement exact.
    client
        .batch_execute(&format!("SET session_replication_role=replica;
          INSERT INTO {target_schema}.tasks(tenant_scope,task_id,context_id,state,revision,task_json,owner_account_id) VALUES('tenant-bootstrap','preexisting-task','preexisting-context','\"TASK_STATE_COMPLETED\"',1,'{{}}','preexisting-account');
          INSERT INTO {target_schema}.task_events(tenant_scope,task_id,event_seq,task_revision,event_kind,to_state,event_json,created_at) VALUES('tenant-bootstrap','preexisting-task',1,1,'completed','\"TASK_STATE_COMPLETED\"','{{}}',1);
          SET session_replication_role=origin;"))
        .await
        .unwrap();
    assert!(matches!(
        PostgresTaskStore::restore_artifacts(target_config.clone(), &restore).await,
        Err(PostgresStoreError::ArtifactRestoreTargetNotEmpty)
    ));
    assert_eq!(
        client
            .query_one(
                &format!("SELECT count(*) FROM {target_schema}.audit_projection_outbox"),
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert!(
        client
            .query_one(
                &format!(
                    "SELECT enabled FROM {target_schema}.audit_projection_control WHERE singleton=1"
                ),
                &[]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    client
        .batch_execute(&format!(
            "SET session_replication_role=replica; DELETE FROM {target_schema}.task_events; DELETE FROM {target_schema}.tasks; SET session_replication_role=origin;"
        ))
        .await
        .unwrap();

    let callback_proof_before = client
        .query_one(
            &format!(
                "SELECT proof FROM {target_schema}.callback_worker_session_secret WHERE singleton=1"
            ),
            &[],
        )
        .await
        .unwrap()
        .get::<_, String>(0);

    // A live callback worker capability is non-authoritative bootstrap state, but
    // restore must refuse to reset it while the owning backend is still active.
    let (callback_worker, callback_worker_connection) =
        pg.connect(tokio_postgres::NoTls).await.unwrap();
    let callback_worker_driver = tokio::spawn(callback_worker_connection);
    callback_worker
        .query_one(
            &format!("SELECT {target_schema}.register_callback_worker_session($1)"),
            &[&callback_proof_before],
        )
        .await
        .unwrap();
    let active_callback_restore =
        PostgresTaskStore::restore_artifacts(target_config.clone(), &restore).await;
    assert!(
        matches!(
            active_callback_restore,
            Err(PostgresStoreError::ArtifactMigrationBusy)
        ),
        "active callback worker restore outcome: {active_callback_restore:?}"
    );
    assert_eq!(
        client
            .query_one(
                &format!("SELECT proof,(SELECT count(*) FROM {target_schema}.callback_worker_sessions) FROM {target_schema}.callback_worker_session_secret WHERE singleton=1"),
                &[],
            )
            .await
            .unwrap()
            .get::<_, String>(0),
        callback_proof_before
    );
    drop(callback_worker);
    callback_worker_driver.await.unwrap().unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let active: bool = client
                .query_one(
                    &format!(
                        "SELECT EXISTS(SELECT 1 FROM {target_schema}.callback_worker_sessions s JOIN pg_catalog.pg_stat_get_backend_idset() b ON pg_catalog.pg_stat_get_backend_pid(b)=s.backend_pid)"
                    ),
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            if !active {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("callback worker backend did not leave pg_stat_activity");

    // Callback policy/config authority is not represented in this backup format.
    // These rows are internally coherent, so semantic validation accepts them;
    // the empty-target fence must then reject the occupied authority without mutation.
    let callback_digest = smesh_a2a::content_digest(b"restore-callback-policy");
    let callback_url_digest = smesh_a2a::content_digest(b"https://callback.invalid/restore");
    client
        .batch_execute(&format!(
            "SET session_replication_role=replica;
             INSERT INTO {target_schema}.callback_policy_snapshots VALUES('restore-policy',1,'{callback_digest}',4,100,100,4096,4,60000,1);
             INSERT INTO {target_schema}.callback_enrollments VALUES('restore-policy',1,'tenant-callback','restore-enrollment',1,'https://callback.invalid/restore','{callback_url_digest}','key-1','secret-ref',NULL,NULL,NULL);
             INSERT INTO {target_schema}.tasks(tenant_scope,task_id,context_id,state,revision,task_json,owner_account_id) VALUES('tenant-callback','callback-task','callback-context','\"TASK_STATE_SUBMITTED\"',1,'{{}}','callback-account');
             INSERT INTO {target_schema}.callback_configs VALUES('tenant-callback','callback-task','callback-config','callback-account','account:callback-account','restore-enrollment',1,'https://callback.invalid/restore','{callback_url_digest}','active',NULL,1,1);
             INSERT INTO {target_schema}.callback_audits(tenant_scope,event_kind,source_kind,source_pk_digest,occurred_at) VALUES
               ('tenant-callback','callback_policy_reconciled','callback_enrollments',{target_schema}.callback_audit_digest('callback_policy_reconciled','tenant-callback','','restore-enrollment','',1,0),1),
               ('tenant-callback','callback_config_created','callback_configs',{target_schema}.callback_audit_digest('callback_config_created','tenant-callback','callback-task','callback-config','',1,0),1);
             SET session_replication_role=origin;"
        ))
        .await
        .unwrap();
    let callback_authority_restore =
        PostgresTaskStore::restore_artifacts(target_config.clone(), &restore).await;
    assert!(
        matches!(
            callback_authority_restore,
            Err(PostgresStoreError::ArtifactRestoreTargetNotEmpty)
        ),
        "callback authority restore outcome: {callback_authority_restore:?}"
    );
    let callback_refusal = client
        .query_one(
            &format!("SELECT
                (SELECT count(*) FROM {target_schema}.callback_policy_snapshots),
                (SELECT count(*) FROM {target_schema}.callback_enrollments),
                (SELECT count(*) FROM {target_schema}.callback_configs),
                (SELECT count(*) FROM {target_schema}.callback_worker_sessions),
                (SELECT proof FROM {target_schema}.callback_worker_session_secret WHERE singleton=1),
                (SELECT count(*) FROM {target_schema}.audit_projection_outbox),
                (SELECT enabled FROM {target_schema}.audit_projection_control WHERE singleton=1)"),
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        (
            callback_refusal.get::<_, i64>(0),
            callback_refusal.get::<_, i64>(1),
            callback_refusal.get::<_, i64>(2),
            callback_refusal.get::<_, i64>(3),
            callback_refusal.get::<_, String>(4),
            callback_refusal.get::<_, i64>(5),
            callback_refusal.get::<_, bool>(6),
        ),
        (1, 1, 1, 1, callback_proof_before.clone(), 1, true)
    );
    client
        .batch_execute(&format!(
            "SET session_replication_role=replica;
             DELETE FROM {target_schema}.callback_audits;
             DELETE FROM {target_schema}.callback_configs;
             DELETE FROM {target_schema}.tasks;
             DELETE FROM {target_schema}.callback_enrollments;
             DELETE FROM {target_schema}.callback_policy_snapshots;
             SET session_replication_role=origin;"
        ))
        .await
        .unwrap();

    let restored = PostgresTaskStore::restore_artifacts(target_config.clone(), &restore)
        .await
        .unwrap();
    assert_eq!(restored.objects, 0);
    assert!(restored.enabled);
    let callback_bootstrap_after = client
        .query_one(
            &format!("SELECT proof,(SELECT count(*) FROM {target_schema}.callback_worker_sessions) FROM {target_schema}.callback_worker_session_secret WHERE singleton=1"),
            &[],
        )
        .await
        .unwrap();
    assert_ne!(
        callback_bootstrap_after.get::<_, String>(0),
        callback_proof_before
    );
    assert_eq!(callback_bootstrap_after.get::<_, i64>(1), 0);
    assert_eq!(
        client
            .query_one(
                &format!("SELECT count(*) FROM {target_schema}.audit_projection_outbox"),
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert!(
        client
            .query_one(
                &format!(
                    "SELECT enabled FROM {target_schema}.audit_projection_control WHERE singleton=1"
                ),
                &[]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    PostgresTaskStore::open(target_config.clone())
        .await
        .unwrap()
        .shutdown()
        .await
        .unwrap();
    assert_eq!(client.query_one(&format!("SELECT count(*) FROM {target_schema}.artifact_restore_jobs WHERE state='enabled' AND expected_entries=0 AND imported_entries=0"),&[]).await.unwrap().get::<_,i64>(0),1);
    client.batch_execute(&format!("DROP SCHEMA {source_schema} CASCADE; DROP SCHEMA {target_schema} CASCADE; DROP ROLE IF EXISTS {source_schema}_runtime; DROP ROLE IF EXISTS {target_schema}_runtime")).await.unwrap();
    drop(client);
    driver.abort();
}

#[cfg(unix)]
#[tokio::test]
async fn backup_key_dependency_blocks_reload_and_restart_until_expiry() {
    use std::os::unix::fs::PermissionsExt as _;
    use std::str::FromStr as _;

    let Some((admin, runtime, superuser)) = postgres_urls() else {
        return;
    };
    let root = ArtifactTestRoot::new("artifact-backup-key-dependency");
    let keyring = root.join("keys.json");
    let write_keys = |body: &str| {
        let next = root.join("keys-next.json");
        fs::write(&next, body).unwrap();
        fs::set_permissions(&next, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&next, &keyring).unwrap();
    };
    let both = r#"{"activeGeneration":"key-new","generations":{"key-old":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","key-new":"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg"}}"#;
    let new_only = r#"{"activeGeneration":"key-new","generations":{"key-new":"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg"}}"#;
    write_keys(both);
    let cas = root.join("cas");
    fs::create_dir(&cas).unwrap();
    fs::set_permissions(&cas, fs::Permissions::from_mode(0o700)).unwrap();
    let schema = format!("smesh_backup_key_{:016x}", rand::random::<u64>());
    let config = PostgresStoreConfig::new(&admin, &runtime, &schema)
        .unwrap()
        .with_test_only_insecure_loopback(true)
        .with_test_only_parent_managed_cleanup()
        .with_artifact_store(ArtifactStoreConfig::new(&cas, &keyring).unwrap());
    PostgresTaskStore::open(config.clone())
        .await
        .unwrap()
        .shutdown()
        .await
        .unwrap();
    let pg = tokio_postgres::Config::from_str(&superuser).unwrap();
    let (client, connection) = pg.connect(tokio_postgres::NoTls).await.unwrap();
    let driver = tokio::spawn(async move { connection.await.unwrap() });
    let digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    client.batch_execute(&format!("INSERT INTO {schema}.retained_authority_usage VALUES('tenant-key','tenant','tenant-key',0,1),('tenant-key','account','operator',0,1),('tenant-key','principal','account:operator',0,1); INSERT INTO {schema}.artifact_key_generations VALUES('tenant-key','tenant-key/confidential','key-old','retiring',1,NULL); INSERT INTO {schema}.artifact_backup_jobs(tenant_scope,backup_id,store_id,snapshot_id,policy_id,policy_revision,policy_digest,actor_digest,reason_digest,state,lease_owner,lease_token,lease_epoch,lease_until,candidate_count,inventory_digest,created_at,sealed_at) VALUES('tenant-key','backup-key','{digest}','snapshot','policy',1,'{digest}','{digest}','{digest}','sealed','owner','token',1,9999999999999,0,'{digest}',1,1); INSERT INTO {schema}.artifact_backup_key_dependencies VALUES('tenant-key','backup-key','tenant-key/confidential','key-old',9999999999999,NULL);")).await.unwrap();
    PostgresTaskStore::open(config.clone())
        .await
        .unwrap()
        .shutdown()
        .await
        .unwrap();
    write_keys(new_only);
    assert!(matches!(
        PostgresTaskStore::open(config.clone()).await,
        Err(PostgresStoreError::InvalidSchema)
    ));
    write_keys(both);
    let store = PostgresTaskStore::open(config.clone()).await.unwrap();
    write_keys(new_only);
    assert!(store.reload_artifact_keyring().await.is_err());
    client.execute(&format!("UPDATE {schema}.artifact_backup_key_dependencies SET required_until=1,released_at=2 WHERE backup_id='backup-key'"),&[]).await.unwrap();
    store.reload_artifact_keyring().await.unwrap();
    store.shutdown().await.unwrap();
    PostgresTaskStore::open(config.clone())
        .await
        .unwrap()
        .shutdown()
        .await
        .unwrap();
    assert_eq!(client.query_one(&format!("SELECT count(*) FROM {schema}.artifact_backup_key_dependencies WHERE released_at=2 AND required_until=1"),&[]).await.unwrap().get::<_,i64>(0),1);
    client
        .batch_execute(&format!(
            "DROP SCHEMA {schema} CASCADE; DROP ROLE IF EXISTS {schema}_runtime"
        ))
        .await
        .unwrap();
    drop(client);
    driver.abort();
}
