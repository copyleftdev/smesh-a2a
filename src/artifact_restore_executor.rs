//! Empty-authority artifact metadata import, ciphertext verification, and atomic enable.
#![allow(clippy::too_many_lines)]
use crate::{
    ArtifactReadLease, ArtifactRestorePlanFile, ContentDigestV1, PosixArtifactBlobStore,
    PostgresStoreError,
};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read as _,
    path::Path,
    process::Stdio,
    sync::Arc,
};
use tokio::io::AsyncWriteExt as _;
use tokio_postgres::{Client, Transaction};

#[derive(Clone, Debug)]
pub struct ArtifactRestoreOutcome {
    pub objects: u64,
    pub enabled: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Inventory {
    schema: String,
    backup_id: String,
    source_store_id: String,
    source_schema: String,
    policy_id: String,
    policy_revision: u64,
    policy_digest: String,
    snapshot_at: i64,
    entry_count: u64,
    entries: Vec<serde_json::Value>,
    tasks: Vec<serde_json::Value>,
    task_events: Vec<serde_json::Value>,
    quota_policies: Vec<serde_json::Value>,
    key_generations: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryRetentionHold {
    tenant_scope: String,
    hold_id: String,
    artifact_id: String,
    actor_digest: String,
    reason_digest: String,
    state: String,
    created_at: i64,
    expires_at: Option<i64>,
    released_at: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryTombstone {
    tenant_scope: String,
    object_id: String,
    tombstone_generation: i64,
    reason_digest: String,
    locator_digest: String,
    deletion_receipt_digest: Option<String>,
    tombstoned_at: i64,
    deleted_at: Option<i64>,
}

pub(crate) async fn execute(
    client: &mut Client,
    schema: &str,
    source: Arc<PosixArtifactBlobStore>,
    target: Arc<PosixArtifactBlobStore>,
    plan: &ArtifactRestorePlanFile,
    audit_projection_enabled: bool,
) -> Result<ArtifactRestoreOutcome, PostgresStoreError> {
    if schema != plan.target_schema() {
        return Err(PostgresStoreError::ArtifactMigrationPlanMismatch);
    }
    if plan.inventory().parent() != Some(plan.source_root())
        || plan.inventory().file_name().and_then(|name| name.to_str()) != Some("inventory.json")
    {
        return Err(PostgresStoreError::ArtifactMigrationPlanMismatch);
    }
    let bytes = read_backup_file(plan.source_root(), "inventory.json", 64 * 1024 * 1024)?;
    if bytes.len() > 64 * 1024 * 1024 {
        return Err(PostgresStoreError::ArtifactMigrationInvalidSource);
    }
    let mut inv: Inventory = serde_json::from_slice(&bytes)
        .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
    validate_inventory_header(&inv, plan)?;
    expand_shared_rows(&mut inv)?;
    validate_inventory_entries(&inv)?;

    let mut payload = b"smesh-artifact-physical-inventory/v1\0".to_vec();
    payload.extend_from_slice(&bytes);
    let digest = ContentDigestV1::of(&payload).to_string();
    let recorded = String::from_utf8(read_backup_file(
        plan.source_root(),
        "inventory.digest",
        1024,
    )?)
    .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
    if recorded != digest {
        return Err(PostgresStoreError::ArtifactMigrationInvalidSource);
    }
    verify_signature(plan, &payload).await?;
    client
        .batch_execute("SELECT set_config('smesh.internal_global','claim-v1',false)")
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?;
    let restore_fence: bool = client
        .query_one(
            "SELECT pg_try_advisory_lock(hashtextextended($1,0))",
            &[&format!(
                "smesh-artifact-restore:{schema}:{}",
                plan.target_store_id()
            )],
        )
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?
        .get(0);
    if !restore_fence {
        return Err(PostgresStoreError::ArtifactMigrationBusy);
    }
    let target_id: Vec<u8> = client
        .query_one(
            &format!("SELECT store_id FROM {schema}.store_identity"),
            &[],
        )
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?
        .get(0);
    if target_id.as_slice() != plan.target_store_id().bytes()
        || target_id.as_slice() == plan.source_store_id().bytes()
    {
        return Err(PostgresStoreError::ArtifactMigrationPlanMismatch);
    }
    assert_target_empty_or_resume(client, schema, plan, &inv, &digest).await?;

    // Authenticate every referenced ciphertext and chunk topology before writing
    // any target journal or authority row. A corrupt backup must leave a truly
    // empty target that can be retried without stale imports.
    for entry in &inv.entries {
        let lease = lease_from_entry(entry)?;
        let plaintext = source
            .read_resolution(&lease)
            .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
        verify_chunks(&plaintext, &entry["chunks"])?;
    }
    let tenants = inventory_tenants(&inv)?;
    let token = crate::content_digest(&rand::random::<[u8; 32]>());
    commit_restore_journal(client, schema, plan, &inv, &digest, &tenants, &token).await?;

    crate::artifact_production_checkpoint("restore_journal_committed_before_ciphertext_copy");
    let shared_tx = client
        .transaction()
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?;
    shared_tx
        .batch_execute("SET LOCAL smesh.internal_global='claim-v1'")
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?;
    import_shared_rows(&shared_tx, schema, &inv, plan.clone_policy()).await?;
    shared_tx
        .commit()
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?;

    let mut copied = BTreeSet::new();
    for batch in inv.entries.chunks(usize::from(plan.batch_size())) {
        let tx = client
            .transaction()
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?;
        tx.batch_execute("SET LOCAL smesh.internal_global='claim-v1'")
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?;
        renew_restore_lease(&tx, schema, plan, &token, tenants.len()).await?;
        for entry in batch {
            import_entry(&tx, schema, entry, plan.clone_policy()).await?;
        }
        tx.commit()
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?;
        crate::artifact_production_checkpoint("restore_metadata_import_batch");
        for entry in batch {
            let lease = lease_from_entry(entry)?;
            let object = s(&entry["object"], "object_id")?;
            if copied.insert((lease.tenant_scope.clone(), object)) {
                source
                    .backup_verified(&lease, target.root_path())
                    .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
                crate::artifact_production_checkpoint("restore_ciphertext_stage_before_metadata");
                target
                    .read_resolution(&lease)
                    .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
            }
        }
    }
    // Provenance is imported after every manifest exists, so cross-batch parent
    // edges retain their exact source identity without weakening foreign keys.
    for batch in inv.entries.chunks(usize::from(plan.batch_size())) {
        let tx = client
            .transaction()
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?;
        tx.batch_execute("SET LOCAL smesh.internal_global='claim-v1'")
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?;
        renew_restore_lease(&tx, schema, plan, &token, tenants.len()).await?;
        for entry in batch {
            import_array(&tx, schema, "provenance_edges", &entry["provenance"], None).await?;
        }
        tx.commit()
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?;
    }
    atomic_enable(
        client,
        schema,
        plan,
        &inv,
        &digest,
        &tenants,
        &token,
        copied.len(),
        audit_projection_enabled,
    )
    .await?;
    crate::artifact_production_checkpoint("restore_atomic_enable_before_ack");
    Ok(ArtifactRestoreOutcome {
        objects: copied.len() as u64,
        enabled: true,
    })
}

fn validate_inventory_header(
    inv: &Inventory,
    plan: &ArtifactRestorePlanFile,
) -> Result<(), PostgresStoreError> {
    if inv.schema != "smesh-artifact-physical-inventory/v1"
        || inv.source_store_id != plan.source_store_id().to_string()
        || inv.policy_digest != plan.policy_digest().to_string()
        || inv.policy_id.is_empty()
        || inv.policy_revision == 0
        || inv.snapshot_at <= 0
        || inv.source_schema.is_empty()
        || inv.entry_count != inv.entries.len() as u64
    {
        return Err(PostgresStoreError::ArtifactMigrationPlanMismatch);
    }
    Ok(())
}

fn expand_shared_rows(inv: &mut Inventory) -> Result<(), PostgresStoreError> {
    fn keyed(
        rows: &[serde_json::Value],
        fields: &[&str],
    ) -> Result<BTreeMap<String, serde_json::Value>, PostgresStoreError> {
        let mut map = BTreeMap::new();
        for row in rows {
            let key = shared_row_key(row, fields)?;
            if map.insert(key, row.clone()).is_some() {
                return Err(PostgresStoreError::ArtifactMigrationInvalidSource);
            }
        }
        Ok(map)
    }
    let tasks = keyed(&inv.tasks, &["tenant_scope", "task_id"])?;
    let events = keyed(&inv.task_events, &["tenant_scope", "task_id", "event_seq"])?;
    let quotas = keyed(
        &inv.quota_policies,
        &["tenant_scope", "policy_id", "policy_revision"],
    )?;
    let generations = keyed(
        &inv.key_generations,
        &["tenant_scope", "encryption_domain", "key_generation"],
    )?;
    let mut used_tasks = BTreeSet::new();
    let mut used_events = BTreeSet::new();
    let mut used_quotas = BTreeSet::new();
    let mut used_generations = BTreeSet::new();
    for entry in &mut inv.entries {
        let task_key = s(entry, "taskKey")?;
        entry["task"] = tasks
            .get(&task_key)
            .cloned()
            .ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?;
        used_tasks.insert(task_key);
        let event_keys = entry
            .get("taskEventKeys")
            .and_then(serde_json::Value::as_array)
            .ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?;
        let mut expanded = Vec::with_capacity(event_keys.len());
        for key in event_keys {
            let key = key
                .as_str()
                .ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?
                .to_owned();
            expanded.push(
                events
                    .get(&key)
                    .cloned()
                    .ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?,
            );
            used_events.insert(key);
        }
        entry["taskEvents"] = serde_json::Value::Array(expanded);
        let generation_key = s(entry, "keyGenerationKey")?;
        entry["keyGenerationMetadata"] = generations
            .get(&generation_key)
            .cloned()
            .ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?;
        used_generations.insert(generation_key);
        if let Some(key) = entry
            .get("quotaPolicyKey")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
        {
            entry["quotaPolicy"] = quotas
                .get(&key)
                .cloned()
                .ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?;
            used_quotas.insert(key);
        } else {
            entry["quotaPolicy"] = serde_json::Value::Null;
        }
    }
    if used_tasks.len() != tasks.len()
        || used_events.len() != events.len()
        || used_quotas.len() != quotas.len()
        || used_generations.len() != generations.len()
    {
        return Err(PostgresStoreError::ArtifactMigrationInvalidSource);
    }
    Ok(())
}
fn shared_row_key(
    value: &serde_json::Value,
    fields: &[&str],
) -> Result<String, PostgresStoreError> {
    let values = fields
        .iter()
        .map(|field| {
            value
                .get(*field)
                .cloned()
                .ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)
        })
        .collect::<Result<Vec<_>, _>>()?;
    serde_json::to_string(&values).map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)
}

fn validate_inventory_entries(inv: &Inventory) -> Result<(), PostgresStoreError> {
    use std::path::Component;

    let invalid = || PostgresStoreError::ArtifactMigrationInvalidSource;
    let canonical_artifacts = inv
        .entries
        .iter()
        .map(|entry| {
            let artifact_id = s(&entry["manifest"], "artifact_id")?;
            crate::artifact::validate_artifact_id(&artifact_id).map_err(|_| invalid())?;
            Ok((s(&entry["manifest"], "tenant_scope")?, artifact_id))
        })
        .collect::<Result<BTreeSet<_>, PostgresStoreError>>()?;
    let canonical_objects = inv
        .entries
        .iter()
        .map(|entry| {
            Ok((
                s(&entry["object"], "tenant_scope")?,
                s(&entry["object"], "object_id")?,
            ))
        })
        .collect::<Result<BTreeSet<_>, PostgresStoreError>>()?;
    if canonical_artifacts.len() != inv.entries.len() {
        return Err(invalid());
    }
    let mut hold_keys = BTreeSet::new();
    let mut tombstone_keys = BTreeSet::new();
    for entry in &inv.entries {
        let task = entry.get("task").ok_or_else(invalid)?;
        let object = entry.get("object").ok_or_else(invalid)?;
        let manifest = entry.get("manifest").ok_or_else(invalid)?;
        let key = entry.get("keyGenerationMetadata").ok_or_else(invalid)?;
        let chunks = entry
            .get("chunks")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(invalid)?;
        let provenance = entry
            .get("provenance")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(invalid)?;
        let references = entry
            .get("references")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(invalid)?;
        let holds = entry
            .get("holds")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(invalid)?;
        let tombstones = entry
            .get("tombstones")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(invalid)?;
        let locator = s(object, "backend_locator")?;
        if !locator.starts_with("objects/")
            || std::path::Path::new(&locator)
                .components()
                .any(|component| {
                    matches!(
                        component,
                        Component::ParentDir
                            | Component::CurDir
                            | Component::RootDir
                            | Component::Prefix(_)
                    )
                })
        {
            return Err(invalid());
        }
        let canonical = manifest
            .get("canonical_json")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(invalid)?;
        let sealed: serde_json::Value = serde_json::from_str(canonical).map_err(|_| invalid())?;
        let producer = sealed.get("producer").ok_or_else(invalid)?;
        let policy = sealed.get("policy").ok_or_else(invalid)?;
        let sealed_chunks = sealed
            .get("chunks")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(invalid)?;
        let sealed_provenance = sealed
            .get("derivedFrom")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(invalid)?;
        for parent in sealed_provenance {
            let parent_id = parent
                .get("artifactId")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(invalid)?;
            crate::artifact::validate_artifact_id(parent_id).map_err(|_| invalid())?;
        }
        let mut manifest_bytes = b"smesh-artifact-manifest/v1\0".to_vec();
        manifest_bytes.extend_from_slice(canonical.as_bytes());
        let active_references = references
            .iter()
            .filter(|reference| reference["state"] == "active")
            .count();
        if manifest["manifest_digest"] != crate::content_digest(&manifest_bytes)
            || sealed["schema"] != "smesh-artifact-manifest/v1"
            || sealed["artifactId"] != manifest["artifact_id"]
            || sealed["mediaType"] != manifest["media_type"]
            || sealed["plaintextLength"] != manifest["plaintext_length"]
            || sealed["classification"] != manifest["classification"]
            || sealed["encryptionDomain"] != manifest["encryption_domain"]
            || sealed["contentDigest"] != object["content_digest"]
            || producer["tenant"] != manifest["tenant_scope"]
            || producer["owner"] != manifest["owner_account_id"]
            || producer["task"] != manifest["task_id"]
            || producer["context"] != manifest["context_id"]
            || producer["message"] != manifest["message_id"]
            || producer["dispatch"] != manifest["dispatch_id"]
            || policy["policyId"] != manifest["policy_id"]
            || policy["revision"] != manifest["policy_revision"]
            || policy["digest"] != manifest["policy_digest"]
            || policy["createdAt"] != manifest["created_at"]
            || policy["retainUntil"] != manifest["retain_until"]
            || manifest["tenant_scope"] != object["tenant_scope"]
            || manifest["object_id"] != object["object_id"]
            || manifest["owner_account_id"] != object["owner_account_id"]
            || manifest["plaintext_length"] != object["plaintext_length"]
            || manifest["classification"] != object["classification"]
            || manifest["encryption_domain"] != object["encryption_domain"]
            || manifest["task_id"] != task["task_id"]
            || manifest["context_id"] != task["context_id"]
            || manifest["tenant_scope"] != task["tenant_scope"]
            || manifest["owner_account_id"] != task["owner_account_id"]
            || object["key_generation"] != key["key_generation"]
            || object["tenant_scope"] != key["tenant_scope"]
            || object["encryption_domain"] != key["encryption_domain"]
            || object["reference_count"].as_u64() != Some(active_references as u64)
            || sealed_chunks.len() != chunks.len()
            || sealed_chunks.iter().zip(chunks).any(|(sealed, stored)| {
                sealed["ordinal"] != stored["ordinal"]
                    || sealed["offset"] != stored["byte_offset"]
                    || sealed["length"] != stored["plaintext_length"]
                    || sealed["digest"] != stored["content_digest"]
                    || stored["tenant_scope"] != manifest["tenant_scope"]
                    || stored["artifact_id"] != manifest["artifact_id"]
            })
            || sealed_provenance.len() != provenance.len()
            || sealed_provenance
                .iter()
                .zip(provenance)
                .any(|(sealed, stored)| {
                    sealed["artifactId"] != stored["parent_artifact_id"]
                        || sealed["relation"] != stored["relation"]
                        || stored["tenant_scope"] != manifest["tenant_scope"]
                        || stored["child_artifact_id"] != manifest["artifact_id"]
                })
            || references.iter().any(|reference| {
                reference["tenant_scope"] != manifest["tenant_scope"]
                    || reference["artifact_id"] != manifest["artifact_id"]
                    || reference["task_id"] != manifest["task_id"]
                    || reference["context_id"] != manifest["context_id"]
                    || reference["owner_account_id"] != manifest["owner_account_id"]
            })
        {
            return Err(invalid());
        }
        let tenant = s(manifest, "tenant_scope")?;
        let artifact_id = s(manifest, "artifact_id")?;
        let object_id = s(object, "object_id")?;
        let object_generation = object["tombstone_generation"]
            .as_i64()
            .ok_or_else(invalid)?;
        for value in holds {
            let hold: InventoryRetentionHold =
                serde_json::from_value(value.clone()).map_err(|_| invalid())?;
            let valid_state = match hold.state.as_str() {
                "active" => hold.released_at.is_none(),
                "released" => hold
                    .released_at
                    .is_some_and(|released| released >= hold.created_at),
                _ => false,
            };
            if hold.tenant_scope != tenant
                || hold.artifact_id != artifact_id
                || !canonical_artifacts
                    .contains(&(hold.tenant_scope.clone(), hold.artifact_id.clone()))
                || hold.hold_id.is_empty()
                || !digest_string(&hold.actor_digest)
                || !digest_string(&hold.reason_digest)
                || hold.created_at <= 0
                || hold
                    .expires_at
                    .is_some_and(|expires| expires < hold.created_at)
                || !valid_state
                || !hold_keys.insert((hold.tenant_scope, hold.hold_id))
            {
                return Err(invalid());
            }
        }
        for value in tombstones {
            let tombstone: InventoryTombstone =
                serde_json::from_value(value.clone()).map_err(|_| invalid())?;
            let deletion_semantics = match (
                tombstone.deletion_receipt_digest.as_deref(),
                tombstone.deleted_at,
            ) {
                (None, None) => true,
                (Some(receipt), Some(deleted)) => {
                    digest_string(receipt) && deleted >= tombstone.tombstoned_at
                }
                _ => false,
            };
            if tombstone.tenant_scope != tenant
                || tombstone.object_id != object_id
                || !canonical_objects.contains(&(tenant.clone(), tombstone.object_id.clone()))
                || tombstone.tombstone_generation <= 0
                || tombstone.tombstone_generation > object_generation
                || !digest_string(&tombstone.reason_digest)
                || !digest_string(&tombstone.locator_digest)
                || tombstone.tombstoned_at <= 0
                || !deletion_semantics
                || !tombstone_keys.insert((
                    tombstone.tenant_scope,
                    tombstone.object_id,
                    tombstone.tombstone_generation,
                ))
            {
                return Err(invalid());
            }
        }
    }
    Ok(())
}

fn digest_string(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn inventory_tenants(inv: &Inventory) -> Result<BTreeSet<String>, PostgresStoreError> {
    let tenants: BTreeSet<String> = inv
        .entries
        .iter()
        .map(|entry| s(&entry["object"], "tenant_scope"))
        .collect::<Result<_, _>>()?;
    Ok(if tenants.is_empty() {
        ["smesh-artifact-empty-tenant/v1".to_owned()]
            .into_iter()
            .collect()
    } else {
        tenants
    })
}

async fn assert_target_empty_or_resume(
    client: &Client,
    schema: &str,
    plan: &ArtifactRestorePlanFile,
    inv: &Inventory,
    digest: &str,
) -> Result<(), PostgresStoreError> {
    client
        .batch_execute("SELECT set_config('smesh.internal_global','audit-projector-v1',false)")
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?;
    let projection_status = client
        .query_one(
            &format!("SELECT EXISTS(SELECT 1 FROM {schema}.audit_projection_outbox WHERE state='leased' AND lease_expires_at>{schema}.db_millis()),(SELECT count(*) FROM {schema}.audit_projection_outbox)"),
            &[],
        )
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?;
    let active_projection_lease: bool = projection_status.get(0);
    let projection_rows: i64 = projection_status.get(1);
    if active_projection_lease {
        return Err(PostgresStoreError::ArtifactMigrationBusy);
    }
    client
        .batch_execute("SELECT set_config('smesh.internal_global','claim-v1',false)")
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?;
    let journals=client.query(&format!("SELECT DISTINCT restore_id,inventory_digest,state FROM {schema}.artifact_restore_jobs"),&[]).await.map_err(|_|PostgresStoreError::InvalidSchema)?;
    if journals.is_empty() {
        return assert_target_empty(client, schema).await;
    }
    if journals.iter().any(|row| {
        row.get::<_, String>(0) != plan.restore_id()
            || row.get::<_, String>(1) != digest
            || row.get::<_, String>(2) != "restoring"
    }) {
        return Err(PostgresStoreError::ArtifactRestoreTargetNotEmpty);
    }
    if projection_rows != 0 {
        return Err(PostgresStoreError::ArtifactRestoreTargetNotEmpty);
    }
    let array_count = |field: &str| {
        inv.entries
            .iter()
            .map(|entry| entry[field].as_array().map_or(0, Vec::len))
            .sum::<usize>()
    };
    let object_count = inv
        .entries
        .iter()
        .filter_map(|e| {
            Some((
                e["object"]["tenant_scope"].as_str()?,
                e["object"]["object_id"].as_str()?,
            ))
        })
        .collect::<BTreeSet<_>>()
        .len();
    let mut allowed = BTreeMap::from([
        ("artifact_restore_jobs", inventory_tenants(inv)?.len()),
        ("tasks", inv.tasks.len()),
        ("task_events", inv.task_events.len()),
        (
            "quota_policy_versions",
            if plan.clone_policy() {
                inv.quota_policies.len()
            } else {
                0
            },
        ),
        ("artifact_key_generations", inv.key_generations.len()),
        ("content_objects", object_count),
        ("artifact_manifests", inv.entries.len()),
        ("artifact_chunks", array_count("chunks")),
        ("provenance_edges", array_count("provenance")),
        ("artifact_references", array_count("references")),
        ("artifact_retention_holds", array_count("holds")),
        ("artifact_tombstones", array_count("tombstones")),
    ]);
    allowed.insert(
        "retained_authority_usage",
        inv.entries
            .len()
            .saturating_mul(3)
            .saturating_add(inventory_tenants(inv)?.len()),
    );
    for table in crate::postgres_store::EXPECTED_TABLES
        .iter()
        .copied()
        .filter(|table| {
            !matches!(
                *table,
                "schema_migrations"
                    | "store_identity"
                    | "store_metadata"
                    | "audit_projection_control"
                    | "audit_projection_outbox"
                    | "audit_projection_session_secret"
                    | "audit_projection_sessions"
            )
        })
    {
        let count: i64 = client
            .query_one(&format!("SELECT count(*) FROM {schema}.{table}"), &[])
            .await
            .map_err(|_| PostgresStoreError::InvalidSchema)?
            .get(0);
        if usize::try_from(count).unwrap_or(usize::MAX) > allowed.get(table).copied().unwrap_or(0) {
            return Err(PostgresStoreError::ArtifactRestoreTargetNotEmpty);
        }
    }
    Ok(())
}

async fn assert_target_empty(client: &Client, schema: &str) -> Result<(), PostgresStoreError> {
    for table in crate::postgres_store::EXPECTED_TABLES
        .iter()
        .copied()
        .filter(|table| {
            !matches!(
                *table,
                "schema_migrations"
                    | "store_identity"
                    | "store_metadata"
                    | "audit_projection_control"
                    | "audit_projection_outbox"
                    | "audit_projection_session_secret"
                    | "audit_projection_sessions"
            )
        })
    {
        let occupied: bool = client
            .query_one(
                &format!("SELECT EXISTS(SELECT 1 FROM {schema}.{table} LIMIT 1)"),
                &[],
            )
            .await
            .map_err(|_| PostgresStoreError::InvalidSchema)?
            .get(0);
        if occupied {
            return Err(PostgresStoreError::ArtifactRestoreTargetNotEmpty);
        }
    }
    Ok(())
}

async fn commit_restore_journal(
    client: &mut Client,
    schema: &str,
    plan: &ArtifactRestorePlanFile,
    inv: &Inventory,
    digest: &str,
    tenants: &BTreeSet<String>,
    token: &str,
) -> Result<(), PostgresStoreError> {
    let tx = client
        .transaction()
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?;
    // Fence claims before resetting optional projection state. Holding the
    // outbox table lock and control-row lock through journal creation makes the
    // reset and the authoritative restore fence one atomic transition.
    tx.batch_execute("SET LOCAL smesh.internal_global='audit-projector-v1'")
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?;
    tx.batch_execute(&format!(
        "LOCK TABLE {schema}.audit_projection_outbox IN ACCESS EXCLUSIVE MODE"
    ))
    .await
    .map_err(|_| PostgresStoreError::Unavailable)?;
    tx.query_one(
        &format!(
            "SELECT enabled FROM {schema}.audit_projection_control WHERE singleton=1 FOR UPDATE"
        ),
        &[],
    )
    .await
    .map_err(|_| PostgresStoreError::InvalidSchema)?;
    let active_projection_lease: bool = tx
        .query_one(
            &format!("SELECT EXISTS(SELECT 1 FROM {schema}.audit_projection_outbox WHERE state='leased' AND lease_expires_at>{schema}.db_millis())"),
            &[],
        )
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?
        .get(0);
    if active_projection_lease {
        return Err(PostgresStoreError::ArtifactMigrationBusy);
    }
    tx.execute(
        &format!("UPDATE {schema}.audit_projection_control SET enabled=false WHERE singleton=1"),
        &[],
    )
    .await
    .map_err(|_| PostgresStoreError::Unavailable)?;
    tx.execute(
        &format!("DELETE FROM {schema}.audit_projection_outbox"),
        &[],
    )
    .await
    .map_err(|_| PostgresStoreError::Unavailable)?;
    tx.batch_execute("SET LOCAL smesh.internal_global='claim-v1'")
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?;
    let now: i64 = tx
        .query_one(&format!("SELECT {schema}.db_millis()"), &[])
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?
        .get(0);
    let until = now.saturating_add(300_000);
    for tenant in tenants {
        let expected = inv
            .entries
            .iter()
            .filter(|entry| entry["object"]["tenant_scope"].as_str() == Some(tenant))
            .count();
        let expected = i64::try_from(expected)
            .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
        let account = if inv.entries.is_empty() {
            "smesh-artifact-empty-tenant/v1".to_owned()
        } else {
            inv.entries
                .iter()
                .find(|entry| entry["object"]["tenant_scope"].as_str() == Some(tenant))
                .ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)
                .and_then(|entry| s(&entry["object"], "owner_account_id"))?
        };
        let principal = format!("account:{account}");
        for (kind, id) in [
            ("tenant", tenant.as_str()),
            ("account", account.as_str()),
            ("principal", principal.as_str()),
        ] {
            tx.execute(&format!("INSERT INTO {schema}.retained_authority_usage(tenant_scope,scope_kind,scope_id,retained_bytes,updated_at) VALUES($1,$2,$3,0,$4) ON CONFLICT DO NOTHING"), &[tenant, &kind, &id, &now])
                .await
                .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
        }
        let changed=tx.execute(&format!("INSERT INTO {schema}.artifact_restore_jobs(tenant_scope,restore_id,source_store_id,restore_store_id,backup_id,inventory_digest,policy_digest,state,actor_digest,reason_digest,lease_owner,lease_token,lease_epoch,lease_until,expected_entries,imported_entries,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,'restoring',$8,$9,$10,$11,1,$12,$13,0,$14) ON CONFLICT(tenant_scope,restore_id) DO UPDATE SET lease_owner=EXCLUDED.lease_owner,lease_token=EXCLUDED.lease_token,lease_epoch={schema}.artifact_restore_jobs.lease_epoch+1,lease_until=EXCLUDED.lease_until,state='restoring' WHERE {schema}.artifact_restore_jobs.state IN ('restoring','failed') AND {schema}.artifact_restore_jobs.inventory_digest=EXCLUDED.inventory_digest AND ({schema}.artifact_restore_jobs.lease_owner=EXCLUDED.lease_owner OR {schema}.artifact_restore_jobs.lease_until<={schema}.db_millis())"),&[tenant,&plan.restore_id(),&plan.source_store_id().to_string(),&plan.target_store_id().to_string(),&inv.backup_id,&digest,&plan.policy_digest().to_string(),&plan.actor_digest().to_string(),&plan.reason_digest().to_string(),&plan.restore_id(),&token,&until,&expected,&now]).await.map_err(|_|PostgresStoreError::ArtifactMigrationBusy)?;
        if changed != 1 {
            return Err(PostgresStoreError::ArtifactMigrationBusy);
        }
    }
    tx.commit()
        .await
        .map_err(|_| PostgresStoreError::Unavailable)
}
async fn renew_restore_lease(
    tx: &Transaction<'_>,
    schema: &str,
    plan: &ArtifactRestorePlanFile,
    token: &str,
    expected: usize,
) -> Result<(), PostgresStoreError> {
    let now: i64 = tx
        .query_one(&format!("SELECT {schema}.db_millis()"), &[])
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?
        .get(0);
    let until = now.saturating_add(300_000);
    let changed=tx.execute(&format!("UPDATE {schema}.artifact_restore_jobs SET lease_until=$1 WHERE restore_id=$2 AND lease_owner=$2 AND lease_token=$3 AND state='restoring' AND lease_until>{schema}.db_millis()"),&[&until,&plan.restore_id(),&token]).await.map_err(|_|PostgresStoreError::Unavailable)?;
    if changed != expected as u64 {
        return Err(PostgresStoreError::ArtifactMigrationBusy);
    }
    Ok(())
}

async fn import_entry(
    tx: &Transaction<'_>,
    schema: &str,
    entry: &serde_json::Value,
    clone_policy: bool,
) -> Result<(), PostgresStoreError> {
    let object = &entry["object"];
    let manifest = &entry["manifest"];
    let _ = clone_policy;
    let tenant = s(object, "tenant_scope")?;
    let account = s(object, "owner_account_id")?;
    for (kind, id) in [
        ("tenant", tenant.as_str()),
        ("account", account.as_str()),
        ("principal", format!("account:{account}").as_str()),
    ] {
        tx.execute(&format!("INSERT INTO {schema}.retained_authority_usage(tenant_scope,scope_kind,scope_id,retained_bytes,updated_at) VALUES($1,$2,$3,0,{schema}.db_millis()) ON CONFLICT DO NOTHING"),&[&tenant,&kind,&id]).await.map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
    }
    let mut hidden_object = object.clone();
    hidden_object["state"] = serde_json::json!("staged");
    hidden_object["available_at"] = serde_json::Value::Null;
    insert_record(tx, schema, "content_objects", &hidden_object, None).await?;
    insert_record(tx, schema, "artifact_manifests", manifest, None).await?;
    import_array(tx, schema, "artifact_chunks", &entry["chunks"], None).await?;
    import_array(
        tx,
        schema,
        "artifact_references",
        &entry["references"],
        Some("restoring"),
    )
    .await?;
    import_array(
        tx,
        schema,
        "artifact_retention_holds",
        &entry["holds"],
        None,
    )
    .await?;
    import_array(
        tx,
        schema,
        "artifact_tombstones",
        &entry["tombstones"],
        None,
    )
    .await
}
async fn import_shared_rows(
    tx: &Transaction<'_>,
    schema: &str,
    inv: &Inventory,
    clone_policy: bool,
) -> Result<(), PostgresStoreError> {
    for row in &inv.tasks {
        insert_record(tx, schema, "tasks", row, None).await?;
    }
    for row in &inv.task_events {
        insert_record(tx, schema, "task_events", row, None).await?;
    }
    for row in &inv.key_generations {
        insert_record(tx, schema, "artifact_key_generations", row, None).await?;
    }
    if clone_policy {
        tx.batch_execute("SET LOCAL smesh.internal_global='reconcile-v1'")
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?;
        for row in &inv.quota_policies {
            insert_record(tx, schema, "quota_policy_versions", row, None).await?;
        }
        tx.batch_execute("SET LOCAL smesh.internal_global='claim-v1'")
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?;
    }
    Ok(())
}
async fn import_array(
    tx: &Transaction<'_>,
    schema: &str,
    table: &str,
    value: &serde_json::Value,
    state: Option<&str>,
) -> Result<(), PostgresStoreError> {
    let rows = value
        .as_array()
        .ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?;
    for row in rows {
        let mut row = row.clone();
        if let Some(state) = state {
            row["state"] = serde_json::json!(state);
        }
        insert_record(tx, schema, table, &row, None).await?;
    }
    Ok(())
}
async fn insert_record(
    tx: &Transaction<'_>,
    schema: &str,
    table: &str,
    value: &serde_json::Value,
    _state: Option<&str>,
) -> Result<(), PostgresStoreError> {
    let json = serde_json::to_string(value)
        .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
    let conflict = match table {
        "tasks" => "(tenant_scope,task_id)",
        "task_events" => "(tenant_scope,task_id,event_seq)",
        "quota_policy_versions" => "(tenant_scope,policy_id,policy_revision)",
        "artifact_key_generations" => "(tenant_scope,encryption_domain,key_generation)",
        "content_objects" => "(tenant_scope,object_id)",
        "artifact_manifests" => "(tenant_scope,artifact_id)",
        "artifact_chunks" => "(tenant_scope,artifact_id,ordinal)",
        "artifact_references" => "(tenant_scope,reference_id)",
        "artifact_retention_holds" => "(tenant_scope,hold_id)",
        "artifact_tombstones" => "(tenant_scope,object_id,tombstone_generation)",
        "provenance_edges" => "(tenant_scope,child_artifact_id,ordinal)",
        _ => return Err(PostgresStoreError::ArtifactMigrationInvalidSource),
    };
    let exact=tx.query_opt(&format!("WITH candidate AS (SELECT (jsonb_populate_record(NULL::{schema}.{table},$1::text::jsonb)).*) INSERT INTO {schema}.{table} AS actual OVERRIDING SYSTEM VALUE SELECT candidate.* FROM candidate ON CONFLICT {conflict} DO UPDATE SET tenant_scope=actual.tenant_scope WHERE to_jsonb(actual)=to_jsonb(EXCLUDED) RETURNING 1"),&[&json]).await.map_err(|_|PostgresStoreError::ArtifactMigrationInvalidSource)?.is_some();
    if !exact {
        return Err(PostgresStoreError::ArtifactMigrationInvalidSource);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn atomic_enable(
    client: &mut Client,
    schema: &str,
    plan: &ArtifactRestorePlanFile,
    inv: &Inventory,
    digest: &str,
    tenants: &BTreeSet<String>,
    token: &str,
    copied: usize,
    audit_projection_enabled: bool,
) -> Result<(), PostgresStoreError> {
    let expected_objects = inv
        .entries
        .iter()
        .map(|entry| {
            (
                entry["object"]["tenant_scope"].as_str().unwrap_or(""),
                entry["object"]["object_id"].as_str().unwrap_or(""),
            )
        })
        .collect::<BTreeSet<_>>()
        .len();
    if copied != expected_objects {
        return Err(PostgresStoreError::ArtifactMigrationInvalidSource);
    }
    let tenant_ids: Vec<String> = inv
        .entries
        .iter()
        .map(|e| s(&e["object"], "tenant_scope"))
        .collect::<Result<_, _>>()?;
    let object_ids: Vec<String> = inv
        .entries
        .iter()
        .map(|e| s(&e["object"], "object_id"))
        .collect::<Result<_, _>>()?;
    let artifact_ids: Vec<String> = inv
        .entries
        .iter()
        .map(|e| s(&e["manifest"], "artifact_id"))
        .collect::<Result<_, _>>()?;
    let tx = client
        .transaction()
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?;
    tx.batch_execute("SET LOCAL smesh.internal_global='claim-v1'")
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?;
    let journal:i64=tx.query_one(&format!("SELECT count(*) FROM {schema}.artifact_restore_jobs WHERE restore_id=$1 AND lease_token=$2 AND state='restoring' AND lease_until>{schema}.db_millis()"),&[&plan.restore_id(),&token]).await.map_err(|_|PostgresStoreError::InvalidSchema)?.get(0);
    if journal != i64::try_from(tenants.len()).unwrap_or(i64::MAX) {
        return Err(PostgresStoreError::ArtifactMigrationBusy);
    }
    let manifests:i64=tx.query_one(&format!("SELECT count(*) FROM {schema}.artifact_manifests m JOIN unnest($1::text[],$2::text[]) x(tenant_scope,artifact_id) USING(tenant_scope,artifact_id)"),&[&tenant_ids,&artifact_ids]).await.map_err(|_|PostgresStoreError::InvalidSchema)?.get(0);
    if manifests != i64::try_from(inv.entries.len()).unwrap_or(i64::MAX) {
        return Err(PostgresStoreError::ArtifactMigrationInvalidSource);
    }
    let totals=tx.query_one(&format!("SELECT (SELECT count(*) FROM {schema}.tasks),(SELECT count(*) FROM {schema}.task_events),(SELECT count(*) FROM {schema}.artifact_key_generations),(SELECT count(*) FROM {schema}.content_objects),(SELECT count(*) FROM {schema}.artifact_manifests),(SELECT count(*) FROM {schema}.artifact_chunks),(SELECT count(*) FROM {schema}.provenance_edges),(SELECT count(*) FROM {schema}.artifact_references),(SELECT count(*) FROM {schema}.artifact_retention_holds),(SELECT count(*) FROM {schema}.artifact_tombstones)"),&[]).await.map_err(|_|PostgresStoreError::InvalidSchema)?;
    let array_count = |field: &str| {
        inv.entries
            .iter()
            .map(|entry| entry[field].as_array().map_or(0, Vec::len))
            .sum::<usize>()
    };
    let expected = [
        inv.tasks.len(),
        inv.task_events.len(),
        inv.key_generations.len(),
        expected_objects,
        inv.entries.len(),
        array_count("chunks"),
        array_count("provenance"),
        array_count("references"),
        array_count("holds"),
        array_count("tombstones"),
    ];
    if expected.iter().enumerate().any(|(index, value)| {
        totals.get::<_, i64>(index) != i64::try_from(*value).unwrap_or(i64::MAX)
    }) {
        return Err(PostgresStoreError::ArtifactRestoreTargetNotEmpty);
    }
    crate::artifact_production_checkpoint("restore_metadata_restoring_before_enable");
    tx.execute(&format!("UPDATE {schema}.content_objects o SET state='available',available_at={schema}.db_millis() FROM unnest($1::text[],$2::text[]) x(tenant_scope,object_id) WHERE o.tenant_scope=x.tenant_scope AND o.object_id=x.object_id AND o.state='staged'"),&[&tenant_ids,&object_ids]).await.map_err(|_|PostgresStoreError::Unavailable)?;
    tx.execute(&format!("UPDATE {schema}.artifact_references r SET state='active' FROM unnest($1::text[],$2::text[]) x(tenant_scope,artifact_id) WHERE r.tenant_scope=x.tenant_scope AND r.artifact_id=x.artifact_id AND r.state='restoring'"),&[&tenant_ids,&artifact_ids]).await.map_err(|_|PostgresStoreError::Unavailable)?;
    let now: i64 = tx
        .query_one(&format!("SELECT {schema}.db_millis()"), &[])
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?
        .get(0);
    let changed=tx.execute(&format!("UPDATE {schema}.artifact_restore_jobs SET state='enabled',imported_entries=expected_entries,completion_seal=$1,verified_at=$2,enabled_at=$2 WHERE restore_id=$3 AND lease_token=$4 AND state='restoring'"),&[&digest,&now,&plan.restore_id(),&token]).await.map_err(|_|PostgresStoreError::Unavailable)?;
    if changed != tenants.len() as u64 {
        return Err(PostgresStoreError::ArtifactMigrationBusy);
    }
    tx.execute(
        &format!("UPDATE {schema}.audit_projection_control SET enabled=$1 WHERE singleton=1"),
        &[&audit_projection_enabled],
    )
    .await
    .map_err(|_| PostgresStoreError::Unavailable)?;
    tx.commit()
        .await
        .map_err(|_| PostgresStoreError::Unavailable)
}

fn verify_chunks(bytes: &[u8], chunks: &serde_json::Value) -> Result<(), PostgresStoreError> {
    let chunks = chunks
        .as_array()
        .ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?;
    for (ordinal, chunk) in chunks.iter().enumerate() {
        let offset = usize::try_from(
            chunk["byte_offset"]
                .as_u64()
                .ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?,
        )
        .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
        let length = usize::try_from(
            chunk["plaintext_length"]
                .as_u64()
                .ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?,
        )
        .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= bytes.len())
            .ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?;
        if chunk["ordinal"].as_u64() != Some(ordinal as u64)
            || crate::content_digest(&bytes[offset..end])
                != chunk["content_digest"].as_str().unwrap_or("")
        {
            return Err(PostgresStoreError::ArtifactMigrationInvalidSource);
        }
    }
    Ok(())
}

fn lease_from_entry(entry: &serde_json::Value) -> Result<ArtifactReadLease, PostgresStoreError> {
    let m = &entry["manifest"];
    let o = &entry["object"];
    let encoded_nonce = s(o, "nonce")?;
    Ok(ArtifactReadLease {
        tenant_scope: s(o, "tenant_scope")?,
        owner_account_id: s(o, "owner_account_id")?,
        task_id: s(m, "task_id")?,
        artifact_id: s(m, "artifact_id")?,
        media_type: s(m, "media_type")?,
        content_digest: s(o, "content_digest")?,
        manifest_digest: s(m, "manifest_digest")?,
        plaintext_length: u64v(o, "plaintext_length")?,
        classification: s(o, "classification")?,
        encryption_domain: s(o, "encryption_domain")?,
        ciphertext_digest: s(o, "ciphertext_digest")?,
        ciphertext_length: u64v(o, "ciphertext_length")?,
        backend_locator: s(o, "backend_locator")?,
        nonce: hex_bytea(&encoded_nonce)?,
        key_generation: s(o, "key_generation")?,
        canonical_manifest_json: s(m, "canonical_json")?,
        lease_id: String::new(),
        lease_token: String::new(),
        lease_epoch: 1,
        lease_until: i64::MAX,
    })
}
fn s(v: &serde_json::Value, k: &str) -> Result<String, PostgresStoreError> {
    v.get(k)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)
}
fn u64v(v: &serde_json::Value, k: &str) -> Result<u64, PostgresStoreError> {
    v.get(k)
        .and_then(serde_json::Value::as_u64)
        .ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)
}
fn hex_bytea(v: &str) -> Result<[u8; 12], PostgresStoreError> {
    let h = v
        .strip_prefix("\\x")
        .ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?;
    if h.len() != 24 {
        return Err(PostgresStoreError::ArtifactMigrationInvalidSource);
    }
    let mut n = [0; 12];
    for (i, b) in n.iter_mut().enumerate() {
        *b = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16)
            .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
    }
    Ok(n)
}
fn read_backup_file(root: &Path, name: &str, max: usize) -> Result<Vec<u8>, PostgresStoreError> {
    let root_fd = rustix::fs::open(
        root,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
    let root_stat = rustix::fs::fstat(&root_fd)
        .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
    if rustix::fs::FileType::from_raw_mode(root_stat.st_mode) != rustix::fs::FileType::Directory
        || rustix::fs::Mode::from_raw_mode(root_stat.st_mode).bits() & 0o077 != 0
        || root_stat.st_uid != rustix::process::getuid().as_raw()
    {
        return Err(PostgresStoreError::ArtifactMigrationInvalidSource);
    }
    let fd = rustix::fs::openat(
        &root_fd,
        name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
    let stat =
        rustix::fs::fstat(&fd).map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile
        || rustix::fs::Mode::from_raw_mode(stat.st_mode).bits() != 0o600
        || stat.st_uid != rustix::process::getuid().as_raw()
        || usize::try_from(stat.st_size)
            .ok()
            .is_none_or(|size| size > max)
    {
        return Err(PostgresStoreError::ArtifactMigrationInvalidSource);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(stat.st_size)
            .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?,
    );
    File::from(fd)
        .take(u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
    if bytes.len() > max {
        return Err(PostgresStoreError::ArtifactMigrationInvalidSource);
    }
    Ok(bytes)
}

async fn verify_signature(
    plan: &ArtifactRestorePlanFile,
    payload: &[u8],
) -> Result<(), PostgresStoreError> {
    let Some(h) = plan.signature_hook() else {
        return Ok(());
    };
    let signature = read_backup_file(plan.source_root(), "inventory.sig", 64 * 1024)?;
    let mut child = tokio::process::Command::new(h.command())
        .args(h.args())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| PostgresStoreError::Unavailable)?;
    let mut stdin = child.stdin.take().ok_or(PostgresStoreError::Unavailable)?;
    let verify = async {
        stdin
            .write_all(payload)
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?;
        stdin
            .write_all(b"\0")
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?;
        stdin
            .write_all(&signature)
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?;
        stdin
            .shutdown()
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?;
        drop(stdin);
        child
            .wait()
            .await
            .map_err(|_| PostgresStoreError::Unavailable)
    };
    let status = tokio::time::timeout(std::time::Duration::from_secs(5), verify)
        .await
        .map_err(|_| PostgresStoreError::Unavailable)??;
    if status.success() {
        Ok(())
    } else {
        Err(PostgresStoreError::ArtifactMigrationInvalidSource)
    }
}
