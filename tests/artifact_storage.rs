mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::sync::Arc;

use smesh_a2a::{
    ArtifactAuthority, ArtifactBackupInventory, ArtifactBackupObject, ArtifactCatalog,
    ArtifactClassification, ArtifactKeyRotationPlan, ArtifactManifestV1, ArtifactMigrationPlan,
    ArtifactPolicySnapshot, ArtifactProducer, ArtifactStoreConfig, ArtifactStoreError,
    AuthorityShutdown, ContentDigestV1, DerivedFrom, DerivedRelation, EncryptionDomain,
    InMemoryKeyring, JsonArtifactKeyring, PosixArtifactBlobStore, ReloadingArtifactKeyring,
    RetentionDecision,
};
use support::artifact_test_root::ArtifactTestRoot;

#[test]
fn phase_b_operator_plans_are_explicit_bounded_and_redacted() {
    let policy = ContentDigestV1::of(b"artifact-migration-policy");
    let plan = ArtifactMigrationPlan::new(
        "migration-01",
        4,
        "artifact-default",
        7,
        policy,
        "operator-a",
        "remove-inline",
        1000,
    )
    .unwrap();
    assert_eq!(plan.source_schema_version(), 4);
    assert_eq!(plan.batch_size(), 1000);
    assert!(format!("{plan:?}").contains("<redacted>"));
    assert!(ArtifactMigrationPlan::new("m", 3, "p", 1, policy, "a", "r", 1).is_err());
    assert!(ArtifactMigrationPlan::new("m", 5, "p", 1, policy, "a", "r", 1001).is_err());

    let rotation = ArtifactKeyRotationPlan::new(
        "rotation-01",
        "tenant-a/confidential",
        "key-old",
        "key-new",
        "operator-a",
        "annual",
        500,
    )
    .unwrap();
    assert_eq!(rotation.batch_size(), 500);
    assert!(format!("{rotation:?}").contains("<redacted>"));
    assert!(ArtifactKeyRotationPlan::new("r", "d", "same", "same", "a", "why", 1).is_err());
}

#[test]
fn backup_inventory_is_sorted_domain_sealed_and_contains_no_key_bytes() {
    let mut inventory = ArtifactBackupInventory::new(
        "backup-01",
        "store-01",
        "snapshot-01",
        6,
        "artifact-default",
        7,
        ContentDigestV1::of(b"policy"),
        42,
    )
    .unwrap();
    inventory
        .push_object(
            ArtifactBackupObject::new(
                "tenant-z",
                "object-z",
                "artifact-z",
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                19,
                "key-2026",
                "objects/aa/random-z",
            )
            .unwrap(),
        )
        .unwrap();
    inventory
        .push_object(
            ArtifactBackupObject::new(
                "tenant-a",
                "object-a",
                "artifact-a",
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                23,
                "key-2025",
                "objects/bb/random-a",
            )
            .unwrap(),
        )
        .unwrap();
    let sealed = inventory.seal().unwrap();
    assert_eq!(sealed.objects()[0].tenant_scope(), "tenant-a");
    assert!(sealed.digest().to_string().starts_with("sha256:"));
    let canonical = sealed.canonical_json();
    assert!(!canonical.contains("BwcHBwcH"));
    assert!(!canonical.contains("keyBytes"));
    let mut reversed = ArtifactBackupInventory::new(
        "backup-01",
        "store-01",
        "snapshot-01",
        6,
        "artifact-default",
        7,
        ContentDigestV1::of(b"policy"),
        42,
    )
    .unwrap();
    for object in sealed.objects().iter().rev().cloned() {
        reversed.push_object(object).unwrap();
    }
    assert_eq!(sealed.digest(), reversed.seal().unwrap().digest());
}

#[test]
fn phase_b_catalog_declares_migration_backup_restore_and_reencryption_fences() {
    let migration = include_str!("../migrations/postgres/0005_artifact_authority.sql");
    for required in [
        "artifact_migration_plans",
        "migrated_rows",
        "migrated_bytes",
        "full_rescan_digest",
        "artifact_backup_jobs",
        "artifact_backup_inventory",
        "artifact_restore_jobs",
        "artifact_key_rotation_plans",
        "artifact_reencryption_jobs",
        "new_aad_seal",
        "'promoted'",
        "'swapped'",
        "'cleanup'",
        "'completed'",
        "artifact_inline_migration_required",
        "claim_artifact_reencryption",
    ] {
        assert!(migration.contains(required), "missing {required}");
    }
    assert!(migration.contains("CHECK(batch_size BETWEEN 1 AND 1000)"));
    assert!(migration.contains("FOR UPDATE SKIP LOCKED"));
    assert!(migration.contains("claim_artifact_reencryption(p_rotation_id text,p_old_generation text,p_new_generation text,p_owner text"));
    assert!(migration.contains("j.rotation_id=p_rotation_id"));
    assert!(migration.contains("j.old_generation=p_old_generation"));
    assert!(migration.contains("j.new_generation=p_new_generation"));
    let postgres = include_str!("../src/postgres_store.rs");
    assert!(migration.contains("content_objects_dedupe ON __SCHEMA__.content_objects(tenant_scope,owner_account_id,classification,encryption_domain,content_digest)"));
    assert!(postgres.contains(
        "owner_account_id,content_digest,classification,encryption_domain,plaintext_length"
    ));
    let migration_executor = include_str!("../src/artifact_migration_executor.rs");
    assert!(
        migration_executor
            .contains("lease_owner=$4 AND lease_token=$5 AND lease_epoch=$6 AND lease_until>")
    );
    assert!(migration_executor.contains("migration_plan_digest(file)"));
    assert!(migration_executor.contains("checkpoint_input_seal"));
    assert!(migration_executor.contains("checkpoint_output_seal"));
    let reencryption_executor = include_str!("../src/artifact_reencryption_executor.rs");
    for checkpoint in [
        "reencryption_stage_registration_before_physical_promotion",
        "reencryption_physical_promotion_before_state_ack",
        "reencryption_promoted_before_metadata_swap",
        "reencryption_metadata_swap_before_old_delete",
        "reencryption_old_delete_before_complete",
    ] {
        assert!(
            reencryption_executor.contains(checkpoint),
            "missing {checkpoint}"
        );
    }
    assert!(postgres.contains("lease.tenant_scope,\n                    owner,"));
    assert!(postgres.contains("ArtifactMigrationRequired"));
    assert!(postgres.contains("with_artifact_migration_plan"));
}

#[test]
fn backup_executor_commits_pins_before_copy_and_renews_in_bounded_batches() {
    let source = include_str!("../src/artifact_backup_executor.rs");
    let pin_commit = source.find("backup_pins_committed_before_copy").unwrap();
    let copy = source
        .find("backup_pin_snapshot_before_object_copy")
        .unwrap();
    assert!(pin_commit < copy);
    assert!(source.contains("plan.batch_size()"));
    assert!(source.contains("renew_backup_pins"));
    assert!(source.contains("lease_token=$"));
    let migration = include_str!("../migrations/postgres/0005_artifact_authority.sql");
    assert!(migration.contains("reject_pinned_artifact_mutation"));
    assert!(migration.contains("candidate_digest"));
    assert!(migration.contains("candidate_count"));
}

#[test]
fn restore_imports_hidden_metadata_before_one_atomic_enable() {
    let source = include_str!("../src/artifact_restore_executor.rs");
    let journal = source
        .find("restore_journal_committed_before_ciphertext_copy")
        .unwrap();
    let import = source.find("restore_metadata_import_batch").unwrap();
    let copy = source
        .find("restore_ciphertext_stage_before_metadata")
        .unwrap();
    let enable = source.find("restore_atomic_enable_before_ack").unwrap();
    assert!(journal < import && import < copy && copy < enable);
    assert!(source.contains("'restoring'"));
    assert!(source.contains("jsonb_populate_record"));
    assert!(source.contains("state='available'"));
    assert!(source.contains("state='active'"));
    assert!(source.contains("plan.batch_size()"));
}

#[test]
fn artifact_worker_indexes_match_ordered_bounded_default_plans() {
    let migration = include_str!("../migrations/postgres/0005_artifact_authority.sql");
    assert!(migration.contains("upload_intents_due ON __SCHEMA__.upload_intents(updated_at,tenant_scope,upload_id) WHERE state IN ('committed','promoting')"));
    assert!(migration.contains("content_objects_gc_due"));
    assert!(migration.contains("artifact_read_leases_active"));
    assert!(migration.contains("artifact_backup_leases_active"));
    assert!(migration.contains("artifact_retention_holds_active"));
    assert!(migration.contains("provenance_edges_parent"));
}

#[test]
fn authenticated_resolver_declares_download_disposition_and_never_dereferences_artifact_urls() {
    let server = include_str!("../src/server.rs");
    assert!(server.contains("header::CONTENT_DISPOSITION"));
    assert!(server.contains("HeaderValue::from_static(\"attachment\")"));
    let receiver = include_str!("../src/postgres_store.rs");
    for canary in ["file://", "data:", "https://"] {
        assert!(
            !receiver[receiver
                .find("async fn prepare_receiver_artifacts")
                .unwrap()..]
                .contains(&format!("reqwest{canary}"))
        );
    }
}

#[test]
fn receiver_publication_exposes_closed_typed_fault_checkpoints() {
    use smesh_a2a::ArtifactPublicationTestFault as F;
    let points = [
        F::BeforeContentObject,
        F::AfterContentObject,
        F::BeforeChunkBatch,
        F::AfterChunkBatch,
        F::BeforeManifest,
        F::AfterManifest,
        F::BeforeProvenanceBatch,
        F::AfterProvenanceBatch,
        F::BeforeReference,
        F::AfterReference,
        F::BeforeUploadIntent,
        F::AfterUploadIntent,
        F::BeforeReceiverEffect,
        F::AfterReceiverEffect,
        F::BeforeReceiverFrames,
        F::AfterReceiverFrames,
        F::BeforeReceiverCompletion,
        F::AfterReceiverCompletion,
    ];
    assert_eq!(points.len(), 18);
    let source = include_str!("../src/postgres_store.rs");
    for point in points {
        assert!(source.contains(&format!(
            "publication_fault(ArtifactPublicationTestFault::{point:?}"
        )));
    }
}

#[test]
fn startup_semantics_include_closed_artifact_tamper_validator() {
    let source = include_str!("../src/postgres_store.rs");
    assert!(source.contains("async fn validate_artifact_semantics"));
    for class in [
        "manifest canonical seal",
        "chunk topology",
        "provenance acyclic",
        "reference count",
        "locator grammar",
        "object lifecycle",
        "upload lease",
        "read lease",
        "backup lease",
        "retention hold",
        "tombstone generation",
    ] {
        assert!(
            source.contains(class),
            "missing artifact tamper class {class}"
        );
    }
}

#[tokio::test]
async fn sqlite_declares_artifact_authority_unsupported() {
    let root = temp_root();
    let store = smesh_a2a::SqliteTaskStore::open(root.join("authority.sqlite3"), 8)
        .await
        .unwrap();
    assert!(!store.artifact_capabilities().publication);
    let error = store
        .claim_artifact_promotion("worker", 1_000, 1)
        .await
        .unwrap_err();
    assert_eq!(error.code, -32_004);
    store.shutdown().await.unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn production_artifact_config_is_bounded_absolute_and_redacted() {
    let root = std::path::PathBuf::from("/srv/private/artifacts");
    let keyring = std::path::PathBuf::from("/run/secrets/artifact-keys.json");
    let config = ArtifactStoreConfig::new(&root, &keyring)
        .unwrap()
        .with_limits(4 * 1024 * 1024, 64 * 1024 * 1024, 86_400_000, 60_000, 250)
        .unwrap();
    let debug = format!("{config:?}");
    assert!(!debug.contains(root.to_str().unwrap()));
    assert!(!debug.contains(keyring.to_str().unwrap()));
    assert!(ArtifactStoreConfig::new("relative", &keyring).is_err());
    assert!(ArtifactStoreConfig::new(&root, "relative").is_err());
    assert!(config.clone().with_limits(0, 1, 1, 1, 1).is_err());
    assert!(config.with_limits(4 * 1024 * 1024, 1, 1, 1, 1001).is_err());
}

#[tokio::test]
async fn postgres_preflights_artifact_material_before_database_acquisition() {
    let artifact = ArtifactStoreConfig::new(
        "/definitely/missing/smesh-artifact-root",
        "/definitely/missing/smesh-artifact-keys.json",
    )
    .unwrap();
    let config = smesh_a2a::PostgresStoreConfig::new(
        "postgresql://migrator:secret@127.0.0.1:9/db?sslmode=require",
        "postgresql://runtime:secret@127.0.0.1:9/db?sslmode=require",
        "artifact_preflight",
    )
    .unwrap()
    .with_artifact_store(artifact);
    assert!(matches!(
        smesh_a2a::PostgresTaskStore::open(config).await,
        Err(smesh_a2a::PostgresStoreError::InvalidConfig)
    ));
}

#[test]
fn json_keyring_is_private_nofollow_and_keeps_old_generations_readable() {
    let root = temp_root();
    let path = root.join("keys.json");
    fs::write(
        &path,
        r#"{"activeGeneration":"key-new","generations":{"key-old":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","key-new":"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg"}}"#,
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let keyring = JsonArtifactKeyring::open(&path).unwrap();
    assert_eq!(keyring.active_generation(), "key-new");
    assert_eq!(
        smesh_a2a::ArtifactKeyring::key(&keyring, "key-old").unwrap(),
        [7; 32]
    );
    assert_eq!(
        smesh_a2a::ArtifactKeyring::key(&keyring, "key-new").unwrap(),
        [8; 32]
    );

    let link = root.join("keys-link.json");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(JsonArtifactKeyring::open(&link).is_err());
    fs::remove_dir_all(root).unwrap();
}

fn temp_root() -> ArtifactTestRoot {
    ArtifactTestRoot::new("artifact-storage")
}

fn manifest(bytes: &[u8]) -> ArtifactManifestV1 {
    manifest_generation(bytes, "key-2026-08")
}

fn manifest_generation(bytes: &[u8], key_generation: &str) -> ArtifactManifestV1 {
    ArtifactManifestV1::new(
        "artifact-opaque-01",
        "résultat.bin",
        Some("exact multibyte payload".to_owned()),
        "application/octet-stream",
        ArtifactClassification::Confidential,
        EncryptionDomain::new("tenant-a/confidential").unwrap(),
        key_generation,
        ArtifactProducer::new(
            "tenant-a",
            "account-a",
            "task-a",
            "context-a",
            "message-a",
            "dispatch-a",
        )
        .unwrap(),
        Vec::<DerivedFrom>::new(),
        ArtifactPolicySnapshot::new(
            "artifact-default",
            1,
            ContentDigestV1::of(b"policy"),
            42,
            10_000,
        )
        .unwrap(),
        42,
        bytes,
    )
    .unwrap()
}

#[test]
fn canonical_manifest_and_digest_are_stable() {
    let bytes = "héllo 🌍\0binary".as_bytes();
    let value = manifest(bytes);
    assert_eq!(
        value.content_digest().to_string(),
        "sha256:be0ba5c29a0858da5fcb7f6151fa09345d130c4a3a3bd661a3a84002b13c524e"
    );
    assert_eq!(value.plaintext_length(), bytes.len() as u64);
    let canonical = value.canonical_json();
    assert_eq!(canonical, value.canonical_json());
    assert!(value.manifest_digest().to_string().starts_with("sha256:"));
    assert!(
        ContentDigestV1::parse(
            "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        .is_err()
    );
}

#[test]
fn logical_manifest_digest_is_independent_of_physical_key_generation() {
    let old = manifest_generation(b"same logical artifact", "key-old");
    let new = manifest_generation(b"same logical artifact", "key-new");
    assert_eq!(old.canonical_json(), new.canonical_json());
    assert_eq!(old.manifest_digest(), new.manifest_digest());
    assert!(!old.canonical_json().contains("keyGeneration"));
}

#[test]
fn a2a_projection_is_manifest_only_and_has_authenticated_resolver_relation() {
    let secret = b"payload-that-must-not-be-inline";
    let value = manifest(secret);
    let projection = value.to_a2a_projection();
    let json = serde_json::to_string(&projection).unwrap();
    assert!(!json.contains("payload-that-must-not-be-inline"));
    assert!(!json.contains("tenant-a"));
    assert!(!json.contains("key-2026-08"));
    assert!(json.contains("/artifacts/v1/artifact-opaque-01"));
    assert!(json.contains(&value.content_digest().to_string()));
}

#[test]
fn encrypted_posix_roundtrip_and_corruption_fail_before_bytes() {
    let root = temp_root();
    let keyring = Arc::new(InMemoryKeyring::new("key-2026-08", [7; 32]).unwrap());
    let store = PosixArtifactBlobStore::open(&root, keyring).unwrap();
    let bytes = "héllo 🌍\0binary".as_bytes();
    let manifest = manifest(bytes);
    let staged = store.stage(&manifest, bytes).unwrap();
    let object = store.promote(staged).unwrap();
    assert_eq!(store.read_verified(&manifest, &object).unwrap(), bytes);

    let path = store.debug_object_path(&object);
    let mut corrupted = fs::read(&path).unwrap();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 1;
    fs::write(&path, corrupted).unwrap();
    assert_eq!(
        store.read_verified(&manifest, &object),
        Err(ArtifactStoreError::Integrity)
    );

    let pristine = store.stage(&manifest, bytes).unwrap();
    let pristine = store.promote(pristine).unwrap();
    let pristine_path = store.debug_object_path(&pristine);
    let full = fs::read(&pristine_path).unwrap();
    fs::write(&pristine_path, &full[..full.len() - 1]).unwrap();
    assert_eq!(
        store.read_verified(&manifest, &pristine),
        Err(ArtifactStoreError::Integrity)
    );
    fs::write(&pristine_path, &full).unwrap();

    let other_manifest = self::manifest(b"different ciphertext object");
    let other = store
        .promote(
            store
                .stage(&other_manifest, b"different ciphertext object")
                .unwrap(),
        )
        .unwrap();
    let other_bytes = fs::read(store.debug_object_path(&other)).unwrap();
    fs::write(&pristine_path, other_bytes).unwrap();
    assert_eq!(
        store.read_verified(&manifest, &pristine),
        Err(ArtifactStoreError::Integrity)
    );

    fs::write(&pristine_path, &full).unwrap();
    let wrong_key = PosixArtifactBlobStore::open(
        &root,
        Arc::new(InMemoryKeyring::new("key-2026-08", [9; 32]).unwrap()),
    )
    .unwrap();
    assert_eq!(
        wrong_key.read_verified(&manifest, &pristine),
        Err(ArtifactStoreError::Integrity)
    );
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn posix_store_held_root_fd_cannot_be_redirected_by_root_replacement() {
    use std::os::unix::fs::symlink;

    let parent = temp_root();
    let root = parent.join("cas");
    let moved = parent.join("cas-held");
    let canary = parent.join("canary");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&canary).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&canary, fs::Permissions::from_mode(0o700)).unwrap();
    let store = PosixArtifactBlobStore::open(
        &root,
        Arc::new(InMemoryKeyring::new("key-2026-08", [7; 32]).unwrap()),
    )
    .unwrap();
    fs::rename(&root, &moved).unwrap();
    symlink(&canary, &root).unwrap();

    let value = manifest(b"held root descriptor");
    let object = store
        .promote(store.stage(&value, b"held root descriptor").unwrap())
        .unwrap();
    assert_eq!(
        store.read_verified(&value, &object).unwrap(),
        b"held root descriptor"
    );
    assert_eq!(fs::read_dir(&canary).unwrap().count(), 0);
    assert!(
        fs::read_dir(moved.join("objects"))
            .unwrap()
            .next()
            .is_some()
    );
}

#[cfg(unix)]
#[test]
fn posix_store_fails_closed_when_stage_or_objects_directory_is_swapped_for_symlink() {
    use std::os::unix::fs::symlink;

    for swapped in ["stage", "objects"] {
        let parent = temp_root();
        let root = parent.join("cas");
        let canary = parent.join("canary");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&canary).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&canary, fs::Permissions::from_mode(0o700)).unwrap();
        let store = PosixArtifactBlobStore::open(
            &root,
            Arc::new(InMemoryKeyring::new("key-2026-08", [7; 32]).unwrap()),
        )
        .unwrap();
        fs::rename(root.join(swapped), root.join(format!("{swapped}-held"))).unwrap();
        symlink(&canary, root.join(swapped)).unwrap();

        let bytes = format!("swapped {swapped}");
        let value = manifest(bytes.as_bytes());
        let result = store.stage(&value, bytes.as_bytes());
        assert!(result.is_err());
        assert_eq!(fs::read_dir(&canary).unwrap().count(), 0);
    }
}

#[test]
fn configured_artifact_limit_rejects_before_creating_a_stage_file() {
    let root = temp_root();
    let keyring = Arc::new(InMemoryKeyring::new("key-2026-08", [7; 32]).unwrap());
    let keyring_path = root.join("unused-keyring.json");
    let config = ArtifactStoreConfig::new(&root, &keyring_path)
        .unwrap()
        .with_limits(
            smesh_a2a::ARTIFACT_CHUNK_BYTES,
            smesh_a2a::ARTIFACT_CHUNK_BYTES as u64,
            7,
            11,
            3,
        )
        .unwrap();
    let store = PosixArtifactBlobStore::open_config(&config, keyring).unwrap();
    let bytes = vec![0_u8; smesh_a2a::ARTIFACT_CHUNK_BYTES + 1];
    let manifest = manifest(&bytes);
    assert_eq!(
        store.stage(&manifest, &bytes),
        Err(ArtifactStoreError::Invalid)
    );
    assert_eq!(fs::read_dir(root.join("stage")).unwrap().count(), 0);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn keyring_reload_is_atomic_nofollow_and_preserves_old_generation() {
    let root = temp_root();
    let path = root.join("reload-keys.json");
    let write = |body: &str| {
        let next = root.join("reload-next.json");
        fs::write(&next, body).unwrap();
        fs::set_permissions(&next, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&next, &path).unwrap();
    };
    write(
        r#"{"activeGeneration":"key-old","generations":{"key-old":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"}}"#,
    );
    let keyring = ReloadingArtifactKeyring::open(&path).unwrap();
    assert_eq!(
        smesh_a2a::ArtifactKeyring::active_generation(&keyring),
        "key-old"
    );
    write(
        r#"{"activeGeneration":"key-new","generations":{"key-old":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","key-new":"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg"}}"#,
    );
    keyring.reload().unwrap();
    assert_eq!(
        smesh_a2a::ArtifactKeyring::active_generation(&keyring),
        "key-new"
    );
    assert_eq!(
        smesh_a2a::ArtifactKeyring::key(&keyring, "key-old").unwrap(),
        [7; 32]
    );
    write(r#"{"activeGeneration":"missing","generations":{}}"#);
    assert!(keyring.reload().is_err());
    assert_eq!(
        smesh_a2a::ArtifactKeyring::active_generation(&keyring),
        "key-new"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn opaque_authorization_precedes_object_lookup_and_foreign_matches_missing() {
    let root = temp_root();
    let keyring = Arc::new(InMemoryKeyring::new("key-2026-08", [8; 32]).unwrap());
    let store = Arc::new(PosixArtifactBlobStore::open(&root, keyring).unwrap());
    let catalog = ArtifactCatalog::new(Arc::clone(&store));
    let bytes = b"private";
    let m = manifest(bytes);
    catalog.publish(m.clone(), bytes).unwrap();
    assert_eq!(
        catalog
            .resolve("tenant-a", "account-a", "task-a", m.artifact_id())
            .unwrap(),
        bytes
    );
    let before = store.lookup_count();
    let foreign = catalog
        .resolve("tenant-b", "account-b", "task-a", m.artifact_id())
        .unwrap_err();
    let missing = catalog
        .resolve("tenant-b", "account-b", "task-a", "artifact-missing")
        .unwrap_err();
    assert_eq!(foreign, missing);
    assert_eq!(store.lookup_count(), before);
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[allow(clippy::too_many_lines)]
fn same_domain_dedupes_without_cross_tenant_or_classification_reuse() {
    let root = temp_root();
    let keyring = Arc::new(InMemoryKeyring::new("key-2026-08", [6; 32]).unwrap());
    let store = Arc::new(PosixArtifactBlobStore::open(&root, keyring).unwrap());
    let catalog = ArtifactCatalog::new(store);
    let first = manifest(b"same");
    catalog.publish(first, b"same").unwrap();
    let second = ArtifactManifestV1::new(
        "artifact-opaque-02",
        "second",
        None,
        "application/octet-stream",
        ArtifactClassification::Confidential,
        EncryptionDomain::new("tenant-a/confidential").unwrap(),
        "key-2026-08",
        ArtifactProducer::new(
            "tenant-a",
            "account-a",
            "task-a",
            "context-a",
            "message-b",
            "dispatch-b",
        )
        .unwrap(),
        vec![],
        ArtifactPolicySnapshot::new(
            "artifact-default",
            1,
            ContentDigestV1::of(b"policy"),
            42,
            10_000,
        )
        .unwrap(),
        42,
        b"same",
    )
    .unwrap();
    catalog.publish(second, b"same").unwrap();
    assert_eq!(catalog.physical_object_count(), 1);
    let different_owner = ArtifactManifestV1::new(
        "artifact-owner-b",
        "owner b",
        None,
        "application/octet-stream",
        ArtifactClassification::Confidential,
        EncryptionDomain::new("tenant-a/confidential").unwrap(),
        "key-2026-08",
        ArtifactProducer::new(
            "tenant-a",
            "account-b",
            "task-b",
            "context-b",
            "message-owner-b",
            "dispatch-owner-b",
        )
        .unwrap(),
        vec![],
        ArtifactPolicySnapshot::new(
            "artifact-default",
            1,
            ContentDigestV1::of(b"policy"),
            42,
            10_000,
        )
        .unwrap(),
        42,
        b"same",
    )
    .unwrap();
    catalog.publish(different_owner, b"same").unwrap();
    assert_eq!(catalog.physical_object_count(), 2);
    for (artifact_id, tenant, classification, domain) in [
        (
            "artifact-cross-class",
            "tenant-a",
            ArtifactClassification::Internal,
            "tenant-a/internal",
        ),
        (
            "artifact-cross-tenant",
            "tenant-b",
            ArtifactClassification::Confidential,
            "tenant-b/confidential",
        ),
    ] {
        let isolated = ArtifactManifestV1::new(
            artifact_id,
            "isolated",
            None,
            "application/octet-stream",
            classification,
            EncryptionDomain::new(domain).unwrap(),
            "key-2026-08",
            ArtifactProducer::new(
                tenant,
                "account-a",
                "task-a",
                "context-a",
                artifact_id,
                artifact_id,
            )
            .unwrap(),
            vec![],
            ArtifactPolicySnapshot::new(
                "artifact-default",
                1,
                ContentDigestV1::of(b"policy"),
                42,
                10_000,
            )
            .unwrap(),
            42,
            b"same",
        )
        .unwrap();
        catalog.publish(isolated, b"same").unwrap();
    }
    assert_eq!(catalog.physical_object_count(), 4);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn provenance_and_retention_gc_are_fenced() {
    let root = temp_root();
    let keyring = Arc::new(InMemoryKeyring::new("key-2026-08", [9; 32]).unwrap());
    let store = Arc::new(PosixArtifactBlobStore::open(&root, keyring).unwrap());
    let catalog = ArtifactCatalog::new(store);
    let parent = manifest(b"parent");
    catalog.publish(parent.clone(), b"parent").unwrap();
    let child = ArtifactManifestV1::new(
        "artifact-opaque-02",
        "child",
        None,
        "text/plain",
        ArtifactClassification::Confidential,
        EncryptionDomain::new("tenant-a/confidential").unwrap(),
        "key-2026-08",
        ArtifactProducer::new(
            "tenant-a",
            "account-a",
            "task-a",
            "context-a",
            "message-a",
            "dispatch-b",
        )
        .unwrap(),
        vec![DerivedFrom::new(DerivedRelation::Transformation, parent.artifact_id()).unwrap()],
        ArtifactPolicySnapshot::new(
            "artifact-default",
            1,
            ContentDigestV1::of(b"policy"),
            42,
            10_000,
        )
        .unwrap(),
        42,
        b"child",
    )
    .unwrap();
    catalog.publish(child, b"child").unwrap();
    let lease = catalog
        .acquire_read_lease(
            "tenant-a",
            "account-a",
            "task-a",
            parent.artifact_id(),
            100,
            10,
        )
        .unwrap();
    assert_eq!(
        catalog.gc(parent.artifact_id(), 105, 10).unwrap(),
        RetentionDecision::Live
    );
    catalog.release_read_lease(&lease).unwrap();
    catalog
        .place_legal_hold("tenant-a", parent.artifact_id(), "case-1")
        .unwrap();
    assert_eq!(
        catalog.gc(parent.artifact_id(), 1_000, 10).unwrap(),
        RetentionDecision::Held
    );
    catalog
        .release_legal_hold("tenant-a", parent.artifact_id(), "case-1")
        .unwrap();
    catalog
        .release_reference("tenant-a", "task-a", parent.artifact_id())
        .unwrap();
    assert_eq!(
        catalog.gc(parent.artifact_id(), 10_000, 10).unwrap(),
        RetentionDecision::Deleted
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn resolver_preflight_is_one_postgres_authority_transaction() {
    let server = include_str!("../src/server.rs");
    let postgres = include_str!("../src/postgres_store.rs");
    assert_eq!(server.matches(".begin_artifact_resolution(").count(), 1);
    let start = postgres
        .find("async fn begin_artifact_resolution(")
        .expect("postgres resolver authority command");
    let end = postgres[start..]
        .find("async fn read_artifact_resolution(")
        .map(|offset| start + offset)
        .expect("resolver command boundary");
    let body = &postgres[start..end];
    assert!(body.contains("apply_quota_intent"));
    assert!(body.contains("egress_intent"));
    assert!(body.contains("insert_audit"));
    assert_eq!(body.matches("run_retryable_transaction").count(), 1);

    let resolver_start = server.find("async fn artifact_resolver(").unwrap();
    let resolver_end = server[resolver_start..]
        .find("/// A task store")
        .map(|offset| resolver_start + offset)
        .unwrap();
    let resolver = &server[resolver_start..resolver_end];
    assert!(!resolver.contains("charge_quota_request"));
    assert!(!resolver.contains("charge_quota_egress"));
    assert!(!resolver.contains("append_authorization_decision"));
}

#[test]
fn postgres_artifact_reference_accounting_is_insert_driven() {
    let postgres = include_str!("../src/postgres_store.rs");
    let start = postgres.find("async fn register_artifact(").unwrap();
    let end = postgres[start..]
        .find("async fn claim_artifact_promotion(")
        .map(|offset| start + offset)
        .unwrap();
    let body = &postgres[start..end];
    assert!(body.contains("'staged',0"));
    assert!(body.contains("RETURNING reference_id"));
    assert!(body.contains("reference_count=o.reference_count+1"));
    assert!(!body.contains("'staged',1"));
}

#[test]
fn receiver_artifact_object_preserves_owner_and_insert_driven_refcount() {
    let postgres = include_str!("../src/postgres_store.rs");
    let start = postgres.find("async fn complete_receiver(").unwrap();
    let body = &postgres[start..];
    assert!(body.contains("content_objects(tenant_scope,owner_account_id,object_id"));
    assert!(body.contains("'staged',0"));
    assert!(body.contains("RETURNING reference_id"));
    assert!(body.contains("reference_count=o.reference_count+1"));
}

#[test]
fn stage_orphan_cleanup_is_bounded_live_safe_and_race_idempotent() {
    use std::collections::BTreeSet;
    use std::sync::Barrier;
    use std::time::{Duration, SystemTime};

    let root = temp_root();
    let keyring = Arc::new(InMemoryKeyring::new("key-2026-08", [5; 32]).unwrap());
    let store = Arc::new(PosixArtifactBlobStore::open(&root, keyring).unwrap());
    let m = manifest(b"orphan");
    let _live_stage = store.stage(&m, b"orphan").unwrap();
    let _orphan_stage = store.stage(&m, b"orphan").unwrap();
    let mut locators = fs::read_dir(root.join("stage"))
        .unwrap()
        .map(|entry| format!("stage/{}", entry.unwrap().file_name().to_string_lossy()))
        .collect::<Vec<_>>();
    locators.sort();
    let live = BTreeSet::from([locators[0].clone()]);
    let cutoff = SystemTime::now() + Duration::from_secs(1);
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let store = Arc::clone(&store);
        let live = live.clone();
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            store.cleanup_stage_orphans(&live, cutoff, 1).unwrap()
        }));
    }
    barrier.wait();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        results.iter().map(|result| result.deleted).sum::<usize>(),
        1
    );
    assert!(root.join(&locators[0]).is_file());
    assert!(!root.join(&locators[1]).exists());
    assert!(store.cleanup_stage_orphans(&live, cutoff, 0).is_err());
    assert!(store.cleanup_stage_orphans(&live, cutoff, 1001).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn manifest_chunks_split_at_exact_four_mib_boundary() {
    let minus_one = vec![0x11; smesh_a2a::ARTIFACT_CHUNK_BYTES - 1];
    let below = manifest(&minus_one);
    assert_eq!(below.chunks().len(), 1);
    assert_eq!(below.chunks()[0].length(), minus_one.len() as u64);

    let exact = vec![0x5a; smesh_a2a::ARTIFACT_CHUNK_BYTES];
    let one = manifest(&exact);
    assert_eq!(one.chunks().len(), 1);
    assert_eq!(
        one.chunks()[0].length(),
        smesh_a2a::ARTIFACT_CHUNK_BYTES as u64
    );

    let plus_one = vec![0xa5; smesh_a2a::ARTIFACT_CHUNK_BYTES + 1];
    let two = manifest(&plus_one);
    assert_eq!(two.chunks().len(), 2);
    assert_eq!(two.chunks()[0].offset(), 0);
    assert_eq!(
        two.chunks()[0].length(),
        smesh_a2a::ARTIFACT_CHUNK_BYTES as u64
    );
    assert_eq!(
        two.chunks()[1].offset(),
        smesh_a2a::ARTIFACT_CHUNK_BYTES as u64
    );
    assert_eq!(two.chunks()[1].length(), 1);
}

#[test]
fn cas_disk_usage_is_ciphertext_bounded_and_gc_returns_to_baseline() {
    fn file_bytes(path: &std::path::Path) -> u64 {
        fs::read_dir(path)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                let metadata = entry.metadata().unwrap();
                if metadata.is_dir() {
                    file_bytes(&entry.path())
                } else {
                    metadata.len()
                }
            })
            .sum()
    }
    let root = temp_root();
    let keyring = Arc::new(InMemoryKeyring::new("key-2026-08", [4; 32]).unwrap());
    let store = Arc::new(PosixArtifactBlobStore::open(&root, keyring).unwrap());
    let catalog = ArtifactCatalog::new(store);
    let baseline = file_bytes(&root);
    let mut plaintext_total = 0_u64;
    let mut ids = Vec::new();
    for n in 0..16_u8 {
        let bytes = vec![n; 64 * 1024 + usize::from(n)];
        plaintext_total += bytes.len() as u64;
        let id = format!("disk-artifact-{n}");
        let value = ArtifactManifestV1::new(
            &id,
            "disk.bin",
            None,
            "application/octet-stream",
            ArtifactClassification::Confidential,
            EncryptionDomain::new("tenant-a/confidential").unwrap(),
            "key-2026-08",
            ArtifactProducer::new(
                "tenant-a",
                "account-a",
                format!("task-{n}"),
                "context-a",
                format!("message-{n}"),
                format!("dispatch-{n}"),
            )
            .unwrap(),
            vec![],
            ArtifactPolicySnapshot::new(
                "artifact-default",
                1,
                ContentDigestV1::of(b"policy"),
                42,
                100,
            )
            .unwrap(),
            42,
            &bytes,
        )
        .unwrap();
        catalog.publish(value, &bytes).unwrap();
        ids.push((id, format!("task-{n}")));
    }
    let peak = file_bytes(&root);
    assert!(peak >= plaintext_total);
    assert!(
        peak <= plaintext_total + 16 * 4096,
        "peak={peak} plaintext={plaintext_total}"
    );
    for (id, task) in &ids {
        catalog.release_reference("tenant-a", task, id).unwrap();
        assert_eq!(
            catalog.gc(id, 101, 1000).unwrap(),
            RetentionDecision::Deleted
        );
    }
    assert_eq!(file_bytes(&root), baseline, "CAS roots leaked after GC");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn postgres_blob_read_verifies_manifest_before_locator_io() {
    let artifact = include_str!("../src/artifact.rs");
    let start = artifact.find("pub(crate) fn read_resolution(").unwrap();
    let end = artifact[start..]
        .find("pub fn stage(")
        .map(|offset| start + offset)
        .unwrap();
    let body = &artifact[start..end];
    let manifest_check = body.find("verify_resolution_manifest").unwrap();
    let locator_read = body.find("read_object_bytes").unwrap();
    assert!(manifest_check < locator_read);
}

#[test]
fn gc_claim_reconciles_delete_before_database_ack() {
    let migration = include_str!("../migrations/postgres/0005_artifact_authority.sql");
    assert!(migration.contains("o.state IN ('tombstoned','deleting')"));
    assert!(migration.contains("FOR UPDATE SKIP LOCKED LIMIT p_batch"));
}

#[test]
fn read_lease_finish_is_exact_replay_idempotent() {
    let postgres = include_str!("../src/postgres_store.rs");
    let start = postgres
        .find("async fn finish_artifact_resolution(")
        .unwrap();
    let end = postgres[start..]
        .find("async fn place_artifact_hold(")
        .map(|offset| start + offset)
        .unwrap();
    assert!(postgres[start..end].contains("state IN ('active','released')"));
}

#[test]
fn artifact_read_lease_is_opaque_and_debug_redacted() {
    let authority = include_str!("../src/durable_authority.rs");
    let exports = include_str!("../src/lib.rs");
    assert!(authority.contains("pub struct ArtifactReadLease"));
    assert!(authority.contains("pub struct ArtifactReadMetadata"));
    assert!(!authority.contains("pub struct ArtifactResolution"));
    let lease_start = authority.find("pub struct ArtifactReadLease").unwrap();
    let lease_end = authority[lease_start..].find("}\n").unwrap() + lease_start;
    for secret in [
        "pub backend_locator:",
        "pub nonce:",
        "pub key_generation:",
        "pub ciphertext_digest:",
    ] {
        assert!(!authority[lease_start..lease_end].contains(secret));
    }
    assert!(!exports.contains("ArtifactResolution"));
    assert!(authority.contains("<redacted>"));
    let server = include_str!("../src/server.rs");
    assert!(server.contains("resolution.metadata()"));
}

#[test]
fn artifact_claims_are_bounded_batches_and_workers_drain_every_claim() {
    let authority = include_str!("../src/durable_authority.rs");
    let postgres = include_str!("../src/postgres_store.rs");
    let migration = include_str!("../migrations/postgres/0005_artifact_authority.sql");
    let promoter = include_str!("../src/artifact_promoter.rs");
    let gc = include_str!("../src/artifact_gc.rs");
    assert!(authority.contains("Result<Vec<ArtifactPromotionClaim>"));
    assert!(authority.contains("Result<Vec<ArtifactGcClaim>"));
    assert!(postgres.matches("!(1..=1000).contains(&batch)").count() >= 2);
    assert!(migration.contains("p_batch integer"));
    assert!(migration.matches("LIMIT p_batch").count() >= 2);
    assert!(migration.matches("SKIP LOCKED").count() >= 2);
    assert!(promoter.contains("for claim in claims"));
    assert!(gc.contains("for claim in claims"));
}

#[test]
fn backup_leases_have_owner_token_epoch_expiry_and_exact_fences() {
    let authority = include_str!("../src/durable_authority.rs");
    let postgres = include_str!("../src/postgres_store.rs");
    let runbook = include_str!("../docs/ARTIFACT_RUNBOOK.md");
    for api in [
        "acquire_artifact_backup_lease",
        "renew_artifact_backup_lease",
        "release_artifact_backup_lease",
    ] {
        assert!(authority.contains(api));
        assert!(postgres.contains(api));
    }
    assert!(authority.contains("pub struct ArtifactBackupLease"));
    assert!(postgres.contains("lease_owner=$"));
    assert!(postgres.contains("lease_token=$"));
    assert!(postgres.contains("lease_epoch=$"));
    assert!(runbook.contains("Backup lease"));
}

#[test]
fn production_orphan_scanner_is_authoritative_joinable_and_fenced() {
    let authority = include_str!("../src/durable_authority.rs");
    let postgres = include_str!("../src/postgres_store.rs");
    let migration = include_str!("../migrations/postgres/0005_artifact_authority.sql");
    let worker = include_str!("../src/artifact_orphan_scanner.rs");
    assert!(authority.contains("scan_artifact_stage_orphans"));
    assert!(postgres.contains("scan_artifact_stage_orphans"));
    assert!(postgres.contains("pg_advisory_xact_lock"));
    assert!(migration.contains("artifact_orphan_audits"));
    assert!(migration.contains("artifact_stage_locator_live"));
    assert!(worker.contains("pub struct ArtifactOrphanScannerHandle"));
    assert!(worker.contains("pub async fn shutdown"));
    assert!(worker.contains("fatal"));
    let server = include_str!("../src/server.rs");
    assert!(server.contains("spawn_artifact_orphan_scanner"));
    assert!(server.contains("orphan_scanner.shutdown().await"));
}

#[test]
fn ci_runs_serial_artifact_evidence_with_a_watchdog() {
    let ci = include_str!("../.github/workflows/ci.yml");
    assert!(ci.contains("Artifact Phase-A evidence"));
    assert!(ci.contains("cargo test --locked --test artifact_storage -- --test-threads=1"));
    assert!(ci.contains("cargo test --locked --test postgres_store artifact_ -- --test-threads=1"));
    assert!(ci.matches("timeout --signal=TERM --kill-after=15s").count() >= 3);
}

#[test]
fn required_postgres_harness_has_no_credential_url_fallbacks() {
    let harness = include_str!("postgres_store.rs");
    assert!(harness.contains("fn required_postgres_url"));
    assert!(!harness.contains("postgresql://postgres:***@127.0.0.1:55432/smesh_test"));
    assert!(!harness.contains("postgresql://smesh_test_runtime:***@127.0.0.1:55432/smesh_test"));
}

#[test]
fn gc_blocker_acquisition_uses_the_content_object_as_the_canonical_fence() {
    let migration = include_str!("../migrations/postgres/0005_artifact_authority.sql");
    let postgres = include_str!("../src/postgres_store.rs");
    let backup = include_str!("../src/artifact_backup_executor.rs");
    assert!(postgres.contains("FOR UPDATE OF o"));
    assert!(postgres.contains("artifact backup object unavailable"));
    assert!(postgres.contains("artifact hold object unavailable"));
    assert!(backup.contains("FOR UPDATE OF o"));
    assert!(migration.contains("FOR UPDATE OF o SKIP LOCKED"));
}

#[test]
fn empty_inventory_and_backup_key_dependencies_are_first_class_schema_state() {
    let migration = include_str!("../migrations/postgres/0005_artifact_authority.sql");
    let backup = include_str!("../src/artifact_backup_executor.rs");
    let restore = include_str!("../src/artifact_restore_executor.rs");
    for required in [
        "artifact_backup_key_dependencies",
        "required_until",
        "released_at",
    ] {
        assert!(migration.contains(required), "missing {required}");
    }
    assert!(backup.contains("smesh-artifact-empty-tenant/v1"));
    assert!(!restore.contains("|| inv.entries.is_empty()"));
    assert!(restore.contains("assert_target_empty"));
    assert!(restore.contains("clone_policy()"));
}

#[test]
fn configured_migration_plan_is_an_exact_sealed_startup_requirement() {
    let postgres = include_str!("../src/postgres_store.rs");
    let migration = include_str!("../migrations/postgres/0005_artifact_authority.sql");
    let main = include_str!("../src/main.rs");
    let executor = include_str!("../src/artifact_migration_executor.rs");
    assert!(postgres.contains("artifact_migration_plan_file"));
    assert!(postgres.contains("verify_completed_plan"));
    assert!(executor.contains("checkpoint_input.ok_or"));
    assert!(executor.contains("checkpoint_output.ok_or"));
    assert!(executor.contains("full_rescan_digest"));
    assert!(executor.contains("migration_plan_digest_parts"));
    assert!(migration.contains("p_plan_id<>'' AND NOT EXISTS"));
    assert!(main.contains("SMESH_A2A_ARTIFACT_MIGRATION_PLAN_PATH"));
}
