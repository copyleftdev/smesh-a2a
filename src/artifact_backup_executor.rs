//! Committed-pin, bounded physical artifact backup executor.
#![allow(clippy::too_many_lines)]
use crate::{
    ArtifactBackupPlanFile, ArtifactReadLease, PosixArtifactBlobStore, PostgresStoreError,
};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read as _, Write as _},
    os::fd::OwnedFd,
    path::Path,
    process::Stdio,
    sync::Arc,
};
use tokio_postgres::{Client, IsolationLevel};

#[derive(Clone, Debug)]
pub struct ArtifactBackupOutcome {
    pub objects: u64,
    pub inventory_digest: String,
    pub signature: Option<String>,
}
struct PinnedSnapshot {
    token: String,
    snapshot_at: i64,
    tenants: Vec<String>,
    objects: i64,
    entries: i64,
}

pub(crate) async fn execute(
    client: &mut Client,
    schema: &str,
    blobs: Arc<PosixArtifactBlobStore>,
    plan: &ArtifactBackupPlanFile,
    owner: &str,
) -> Result<ArtifactBackupOutcome, PostgresStoreError> {
    if schema != plan.source_schema() || owner.is_empty() || owner.len() > 256 {
        return Err(PostgresStoreError::ArtifactMigrationPlanMismatch);
    }
    let pinned = acquire_backup_pins(client, schema, plan, owner).await?;
    crate::artifact_production_checkpoint("backup_pins_committed_before_copy");
    let outcome = copy_pinned_snapshot(client, schema, blobs, plan, owner, &pinned).await;
    finish_backup(client, schema, plan, owner, &pinned, outcome.as_ref().ok()).await?;
    outcome
}

async fn acquire_backup_pins(
    client: &mut Client,
    schema: &str,
    plan: &ArtifactBackupPlanFile,
    owner: &str,
) -> Result<PinnedSnapshot, PostgresStoreError> {
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::RepeatableRead)
        .start()
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?;
    tx.batch_execute("SET LOCAL smesh.internal_global='claim-v1'; SET LOCAL lock_timeout='5s'")
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?;
    let identity: Vec<u8> = tx
        .query_one(
            &format!("SELECT store_id FROM {schema}.store_identity WHERE singleton=1 FOR SHARE"),
            &[],
        )
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?
        .get(0);
    if identity.as_slice() != plan.source_store_id().bytes() {
        return Err(PostgresStoreError::ArtifactMigrationPlanMismatch);
    }
    let now: i64 = tx
        .query_one(&format!("SELECT {schema}.db_millis()"), &[])
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?
        .get(0);
    let until = now.saturating_add(plan.lease_duration_millis());
    let token = crate::content_digest(&rand::random::<[u8; 32]>());
    let existing = tx
        .query(
            &format!("SELECT tenant_scope,state FROM {schema}.artifact_backup_jobs WHERE backup_id=$1 ORDER BY tenant_scope FOR UPDATE"),
            &[&plan.backup_id()],
        )
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?;
    let mut tenants: Vec<String> = if existing.is_empty() {
        tx.query(
            &format!("SELECT DISTINCT m.tenant_scope FROM {schema}.artifact_manifests m JOIN {schema}.content_objects o ON o.tenant_scope=m.tenant_scope AND o.object_id=m.object_id WHERE o.state='available' ORDER BY m.tenant_scope"),
            &[],
        )
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?
        .into_iter()
        .map(|row| row.get(0))
        .collect()
    } else {
        if existing.iter().any(|row| row.get::<_, &str>(1) == "sealed") {
            return Err(PostgresStoreError::ArtifactMigrationBusy);
        }
        existing.iter().map(|row| row.get(0)).collect()
    };
    if existing.is_empty() {
        if tenants.is_empty() {
            // Canonical zero-object inventory: the sentinel owns only the
            // operator journal and is never exposed as an application tenant.
            tenants.push("smesh-artifact-empty-tenant/v1".to_owned());
            tx.execute(&format!("INSERT INTO {schema}.retained_authority_usage(tenant_scope,scope_kind,scope_id,retained_bytes,updated_at) VALUES($1,'tenant',$1,0,$2) ON CONFLICT DO NOTHING"),&[&tenants[0],&now]).await.map_err(|_|PostgresStoreError::Unavailable)?;
        }
        for tenant in &tenants {
            tx.execute(
                &format!("INSERT INTO {schema}.artifact_backup_jobs(tenant_scope,backup_id,store_id,snapshot_id,policy_id,policy_revision,policy_digest,actor_digest,reason_digest,state,lease_owner,lease_token,lease_epoch,lease_until,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'inventory',$10,$11,1,$12,$13)"),
                &[tenant,&plan.backup_id(),&plan.source_store_id().to_string(),&format!("snapshot-{now}"),&plan.policy_id(),&i64::try_from(plan.policy_revision()).unwrap_or(i64::MAX),&plan.policy_digest().to_string(),&plan.actor_digest().to_string(),&plan.reason_digest().to_string(),&owner,&token,&until,&now],
            )
            .await
            .map_err(|_| PostgresStoreError::ArtifactMigrationBusy)?;
        }
        // Persist the exact tenant-fair candidate generation in PostgreSQL. The
        // application never materializes the catalog before pins are committed.
        tx.execute(
            &format!(r"WITH raw AS (
 SELECT m.tenant_scope,m.artifact_id,m.object_id,m.manifest_digest,o.content_digest,o.ciphertext_digest,o.ciphertext_length,o.key_generation,o.backend_locator,
        to_jsonb(m) AS manifest,to_jsonb(o) AS object,to_jsonb(task_row) AS task,to_jsonb(key_row) AS key_generation_metadata,
        (SELECT to_jsonb(q) FROM {schema}.quota_policy_versions q WHERE q.tenant_scope=m.tenant_scope AND q.lifecycle='active' LIMIT 1) AS quota_policy,
        (SELECT COALESCE(jsonb_agg(to_jsonb(e) ORDER BY e.event_seq),'[]') FROM {schema}.task_events e WHERE e.tenant_scope=m.tenant_scope AND e.task_id=m.task_id) AS task_events,
        (SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY c.ordinal),'[]') FROM {schema}.artifact_chunks c WHERE c.tenant_scope=m.tenant_scope AND c.artifact_id=m.artifact_id) AS chunks,
        (SELECT COALESCE(jsonb_agg(to_jsonb(p) ORDER BY p.ordinal),'[]') FROM {schema}.provenance_edges p WHERE p.tenant_scope=m.tenant_scope AND p.child_artifact_id=m.artifact_id) AS provenance,
        (SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY r.reference_id),'[]') FROM {schema}.artifact_references r WHERE r.tenant_scope=m.tenant_scope AND r.artifact_id=m.artifact_id) AS refs,
        (SELECT COALESCE(jsonb_agg(to_jsonb(h) ORDER BY h.hold_id),'[]') FROM {schema}.artifact_retention_holds h WHERE h.tenant_scope=m.tenant_scope AND h.artifact_id=m.artifact_id) AS holds,
        (SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.tombstone_generation),'[]') FROM {schema}.artifact_tombstones t WHERE t.tenant_scope=m.tenant_scope AND t.object_id=m.object_id) AS tombstones
 FROM {schema}.artifact_manifests m JOIN {schema}.content_objects o ON o.tenant_scope=m.tenant_scope AND o.object_id=m.object_id
 JOIN {schema}.tasks task_row ON task_row.tenant_scope=m.tenant_scope AND task_row.task_id=m.task_id
 JOIN {schema}.artifact_key_generations key_row ON key_row.tenant_scope=o.tenant_scope AND key_row.encryption_domain=o.encryption_domain AND key_row.key_generation=o.key_generation
 WHERE o.state='available'
), fair AS (SELECT raw.*,row_number() OVER(PARTITION BY tenant_scope ORDER BY object_id,artifact_id) AS tenant_turn FROM raw),
numbered AS (SELECT fair.*,row_number() OVER(ORDER BY tenant_turn,tenant_scope,object_id,artifact_id)-1 AS ordinal FROM fair)
INSERT INTO {schema}.artifact_backup_inventory(tenant_scope,backup_id,ordinal,artifact_id,object_id,manifest_digest,content_digest,ciphertext_digest,ciphertext_length,key_generation,storage_locator,canonical_json)
SELECT tenant_scope,$1,ordinal,artifact_id,object_id,manifest_digest,content_digest,ciphertext_digest,ciphertext_length,key_generation,backend_locator,
 jsonb_build_object('ordinal',ordinal,'task',task,'taskEvents',task_events,'quotaPolicy',quota_policy,'keyGenerationMetadata',key_generation_metadata,'manifest',manifest,'object',object,'chunks',chunks,'provenance',provenance,'references',refs,'holds',holds,'tombstones',tombstones)::text
FROM numbered ORDER BY ordinal"),
            &[&plan.backup_id()],
        )
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?;
    }
    let changed = tx
        .execute(
            &format!("UPDATE {schema}.artifact_backup_jobs SET lease_owner=$1,lease_token=$2,lease_epoch=lease_epoch+1,lease_until=$3,state='inventory' WHERE backup_id=$4 AND (lease_owner=$1 OR lease_until<={schema}.db_millis()) AND state<>'sealed'"),
            &[&owner, &token, &until, &plan.backup_id()],
        )
        .await
        .map_err(|_| PostgresStoreError::ArtifactMigrationBusy)?;
    if changed != tenants.len() as u64 {
        return Err(PostgresStoreError::ArtifactMigrationBusy);
    }
    // Canonical fence: lock objects in deterministic tenant/object order before
    // any pin is inserted. GC uses the same row lock, so exactly one side wins.
    let locked_objects = tx
        .query(
            &format!("SELECT o.tenant_scope,o.object_id FROM {schema}.content_objects o JOIN (SELECT DISTINCT tenant_scope,object_id FROM {schema}.artifact_backup_inventory WHERE backup_id=$1) i USING(tenant_scope,object_id) WHERE o.state='available' AND o.retain_until>=$2::bigint ORDER BY o.tenant_scope,o.object_id FOR UPDATE OF o"),
            &[&plan.backup_id(), &now],
        )
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?;
    let objects = i64::try_from(locked_objects.len())
        .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
    let pin_changed = tx
        .execute(
            &format!("INSERT INTO {schema}.artifact_backup_leases(tenant_scope,lease_id,object_id,lease_owner,lease_epoch,lease_token,state,lease_until,created_at) SELECT DISTINCT i.tenant_scope,'backup-'||$1||'-'||substr(encode(sha256(convert_to(i.tenant_scope,'UTF8')||decode('00','hex')||convert_to(i.object_id,'UTF8')),'hex'),1,32),i.object_id,$2,1,$3,'active',$4::bigint,$5::bigint FROM {schema}.artifact_backup_inventory i JOIN {schema}.content_objects o ON o.tenant_scope=i.tenant_scope AND o.object_id=i.object_id WHERE i.backup_id=$1 AND o.state='available' AND o.retain_until>=$6::bigint ON CONFLICT(tenant_scope,lease_id) DO UPDATE SET lease_owner=EXCLUDED.lease_owner,lease_epoch={schema}.artifact_backup_leases.lease_epoch+1,lease_token=EXCLUDED.lease_token,state='active',lease_until=EXCLUDED.lease_until WHERE {schema}.artifact_backup_leases.lease_owner=$2 OR {schema}.artifact_backup_leases.lease_until<={schema}.db_millis()"),
            &[&plan.backup_id(), &owner, &token, &until, &now, &now],
        )
        .await
        .map_err(|_| PostgresStoreError::ArtifactMigrationBusy)?;
    if pin_changed != u64::try_from(objects).unwrap_or(u64::MAX) {
        return Err(PostgresStoreError::ArtifactMigrationBusy);
    }
    let seal_row = tx
        .query_one(
            &format!("SELECT count(*),COALESCE('sha256:'||encode(sha256(convert_to(string_agg(canonical_json,E'\\n' ORDER BY ordinal),'UTF8')),'hex'),'sha256:'||repeat('0',64)) FROM {schema}.artifact_backup_inventory WHERE backup_id=$1"),
            &[&plan.backup_id()],
        )
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?;
    let entries: i64 = seal_row.get(0);
    let candidate_digest: String = seal_row.get(1);
    tx.execute(
        &format!("UPDATE {schema}.artifact_backup_jobs SET candidate_digest=$1,candidate_count=(SELECT count(*) FROM {schema}.artifact_backup_inventory i WHERE i.tenant_scope=artifact_backup_jobs.tenant_scope AND i.backup_id=$2),snapshot_id=$3 WHERE backup_id=$2 AND lease_token=$4"),
        &[&candidate_digest,&plan.backup_id(),&format!("snapshot-{}",&candidate_digest[7..23]),&token],
    )
    .await
    .map_err(|_| PostgresStoreError::Unavailable)?;
    tx.commit()
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?;
    Ok(PinnedSnapshot {
        token,
        snapshot_at: now,
        tenants,
        objects,
        entries,
    })
}

async fn renew_backup_pins(
    client: &mut Client,
    schema: &str,
    plan: &ArtifactBackupPlanFile,
    owner: &str,
    pinned: &PinnedSnapshot,
) -> Result<(), PostgresStoreError> {
    let tx = client
        .transaction()
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
    let until = now.saturating_add(plan.lease_duration_millis());
    let jobs = tx.execute(&format!("UPDATE {schema}.artifact_backup_jobs SET lease_until=$1 WHERE backup_id=$2 AND lease_owner=$3 AND lease_token=$4 AND state='inventory' AND lease_until>{schema}.db_millis()"),&[&until,&plan.backup_id(),&owner,&pinned.token]).await.map_err(|_|PostgresStoreError::Unavailable)?;
    let pins = tx.execute(&format!("UPDATE {schema}.artifact_backup_leases SET lease_until=$1 WHERE lease_owner=$2 AND lease_token=$3 AND state='active' AND lease_until>{schema}.db_millis()"),&[&until,&owner,&pinned.token]).await.map_err(|_|PostgresStoreError::Unavailable)?;
    if jobs != pinned.tenants.len() as u64
        || pins != u64::try_from(pinned.objects).unwrap_or(u64::MAX)
    {
        return Err(PostgresStoreError::ArtifactMigrationBusy);
    }
    tx.commit()
        .await
        .map_err(|_| PostgresStoreError::Unavailable)
}

async fn copy_pinned_snapshot(
    client: &mut Client,
    schema: &str,
    blobs: Arc<PosixArtifactBlobStore>,
    plan: &ArtifactBackupPlanFile,
    owner: &str,
    pinned: &PinnedSnapshot,
) -> Result<ArtifactBackupOutcome, PostgresStoreError> {
    let mut cursor = -1_i64;
    let mut streamed = InventoryStream::new(
        plan.destination(),
        schema,
        plan,
        pinned.snapshot_at,
        pinned.entries,
    )?;
    let mut entries_seen = 0_i64;
    let mut copied = BTreeSet::new();
    crate::artifact_production_checkpoint("backup_pin_snapshot_before_object_copy");
    loop {
        renew_backup_pins(client, schema, plan, owner, pinned).await?;
        let tx = client
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .start()
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?;
        tx.batch_execute("SET LOCAL smesh.internal_global='claim-v1'")
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?;
        let rows = tx.query(&format!("SELECT i.ordinal,i.canonical_json FROM {schema}.artifact_backup_inventory i JOIN {schema}.artifact_backup_leases b ON b.tenant_scope=i.tenant_scope AND b.object_id=i.object_id JOIN {schema}.content_objects o ON o.tenant_scope=i.tenant_scope AND o.object_id=i.object_id WHERE i.backup_id=$1 AND i.ordinal>$2 AND b.lease_owner=$3 AND b.lease_token=$4 AND b.state='active' AND b.lease_until>{schema}.db_millis() AND o.state='available' ORDER BY i.ordinal LIMIT $5"),&[&plan.backup_id(),&cursor,&owner,&pinned.token,&i64::from(plan.batch_size())]).await.map_err(|_| PostgresStoreError::InvalidSchema)?;
        tx.commit()
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            cursor = row.get(0);
            let canonical: String = row.get(1);
            let entry: serde_json::Value = serde_json::from_str(&canonical)
                .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
            let lease = lease_from_entry(&entry, &pinned.token)?;
            if copied.insert((
                lease.tenant_scope.clone(),
                entry["object"]["object_id"]
                    .as_str()
                    .unwrap_or("")
                    .to_owned(),
            )) {
                let plaintext = blobs
                    .backup_verified(&lease, plan.destination())
                    .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
                verify_chunks(&plaintext, &entry["chunks"])?;
            }
            crate::artifact_production_checkpoint("backup_object_copy_before_inventory_write");
            streamed.push(&entry)?;
            entries_seen = entries_seen.saturating_add(1);
        }
    }
    if entries_seen != pinned.entries
        || i64::try_from(copied.len()).unwrap_or(i64::MAX) != pinned.objects
    {
        return Err(PostgresStoreError::ArtifactMigrationInvalidSource);
    }
    let digest = streamed.finish()?;
    let signature = match plan
        .signature_hook()
        .map(|hook| run_hook_file(hook, plan.destination()))
    {
        Some(value) => Some(value.await?),
        None => None,
    };
    atomic_write(plan.destination(), "inventory.digest", digest.as_bytes())?;
    if let Some(value) = &signature {
        atomic_write(plan.destination(), "inventory.sig", value.as_bytes())?;
    }
    crate::artifact_production_checkpoint("backup_inventory_write_before_seal");
    Ok(ArtifactBackupOutcome {
        objects: copied.len() as u64,
        inventory_digest: digest,
        signature,
    })
}

fn lease_from_entry(
    entry: &serde_json::Value,
    token: &str,
) -> Result<ArtifactReadLease, PostgresStoreError> {
    let m = &entry["manifest"];
    let o = &entry["object"];
    let encoded_nonce = s(o, "nonce")?;
    let nonce = hex_bytea(&encoded_nonce)?;
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
        nonce,
        key_generation: s(o, "key_generation")?,
        canonical_manifest_json: s(m, "canonical_json")?,
        lease_id: String::new(),
        lease_token: token.to_owned(),
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

async fn finish_backup(
    client: &mut Client,
    schema: &str,
    plan: &ArtifactBackupPlanFile,
    owner: &str,
    pinned: &PinnedSnapshot,
    outcome: Option<&ArtifactBackupOutcome>,
) -> Result<(), PostgresStoreError> {
    let tx = client
        .transaction()
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
    if outcome.is_some() {
        let required_until = now.saturating_add(30 * 24 * 60 * 60 * 1000_i64);
        tx.execute(&format!("INSERT INTO {schema}.artifact_backup_key_dependencies(tenant_scope,backup_id,encryption_domain,key_generation,required_until) SELECT DISTINCT i.tenant_scope,i.backup_id,i.canonical_json::jsonb#>>'{{object,encryption_domain}}',i.key_generation,$2::bigint FROM {schema}.artifact_backup_inventory i WHERE i.backup_id=$1 ON CONFLICT DO NOTHING"),&[&plan.backup_id(),&required_until]).await.map_err(|_|PostgresStoreError::Unavailable)?;
    }
    let jobs=if let Some(value)=outcome{tx.execute(&format!("UPDATE {schema}.artifact_backup_jobs SET state='sealed',inventory_digest=$1,signature=$2,sealed_at=$3 WHERE backup_id=$4 AND lease_owner=$5 AND lease_token=$6 AND state='inventory' AND lease_until>{schema}.db_millis()"),&[&value.inventory_digest,&value.signature,&now,&plan.backup_id(),&owner,&pinned.token]).await}else{tx.execute(&format!("UPDATE {schema}.artifact_backup_jobs SET state='failed' WHERE backup_id=$1 AND lease_owner=$2 AND lease_token=$3 AND state='inventory'"),&[&plan.backup_id(),&owner,&pinned.token]).await}.map_err(|_|PostgresStoreError::Unavailable)?;
    if jobs != pinned.tenants.len() as u64 {
        return Err(PostgresStoreError::ArtifactMigrationBusy);
    }
    tx.execute(&format!("UPDATE {schema}.artifact_backup_leases SET state='released' WHERE lease_owner=$1 AND lease_token=$2 AND state='active'"),&[&owner,&pinned.token]).await.map_err(|_|PostgresStoreError::Unavailable)?;
    tx.commit()
        .await
        .map_err(|_| PostgresStoreError::Unavailable)
}

fn verify_chunks(bytes: &[u8], chunks: &serde_json::Value) -> Result<(), PostgresStoreError> {
    let a = chunks
        .as_array()
        .ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?;
    for (i, c) in a.iter().enumerate() {
        let o = usize::try_from(
            c["byte_offset"]
                .as_u64()
                .ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?,
        )
        .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
        let l = usize::try_from(
            c["plaintext_length"]
                .as_u64()
                .ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?,
        )
        .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
        if c["ordinal"].as_u64() != Some(i as u64)
            || o.checked_add(l)
                .as_ref()
                .is_none_or(|end| *end > bytes.len())
            || crate::content_digest(&bytes[o..o + l]) != c["content_digest"].as_str().unwrap_or("")
        {
            return Err(PostgresStoreError::ArtifactMigrationInvalidSource);
        }
    }
    Ok(())
}
struct InventoryStream {
    root_fd: OwnedFd,
    temporary: String,
    file: Option<File>,
    hasher: Sha256,
    first: bool,
    committed: bool,
    tasks: BTreeMap<String, serde_json::Value>,
    task_events: BTreeMap<String, serde_json::Value>,
    quota_policies: BTreeMap<String, serde_json::Value>,
    key_generations: BTreeMap<String, serde_json::Value>,
}
impl InventoryStream {
    fn new(
        root: &Path,
        schema: &str,
        plan: &ArtifactBackupPlanFile,
        snapshot_at: i64,
        entry_count: i64,
    ) -> Result<Self, PostgresStoreError> {
        let root_fd = open_private_root(root)?;
        let temporary = format!(".inventory-{:032x}.tmp", rand::random::<u128>());
        let fd = rustix::fs::openat(
            &root_fd,
            temporary.as_str(),
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(|_| PostgresStoreError::Unavailable)?;
        let mut value = Self {
            root_fd,
            temporary,
            file: Some(File::from(fd)),
            hasher: Sha256::new(),
            first: true,
            committed: false,
            tasks: BTreeMap::new(),
            task_events: BTreeMap::new(),
            quota_policies: BTreeMap::new(),
            key_generations: BTreeMap::new(),
        };
        value
            .hasher
            .update(b"smesh-artifact-physical-inventory/v1\0");
        let q = |text: &str| serde_json::to_string(text).unwrap_or_else(|_| "\"\"".to_owned());
        let header = format!(
            "{{\"schema\":\"smesh-artifact-physical-inventory/v1\",\"backupId\":{},\"sourceStoreId\":{},\"sourceSchema\":{},\"policyId\":{},\"policyRevision\":{},\"policyDigest\":{},\"snapshotAt\":{},\"entryCount\":{},\"entries\":[",
            q(plan.backup_id()),
            q(&plan.source_store_id().to_string()),
            q(schema),
            q(plan.policy_id()),
            plan.policy_revision(),
            q(&plan.policy_digest().to_string()),
            snapshot_at,
            entry_count
        );
        value.write_all(header.as_bytes())?;
        Ok(value)
    }
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), PostgresStoreError> {
        self.file
            .as_mut()
            .ok_or(PostgresStoreError::Unavailable)?
            .write_all(bytes)
            .map_err(|_| PostgresStoreError::Unavailable)?;
        self.hasher.update(bytes);
        Ok(())
    }
    fn push(&mut self, entry: &serde_json::Value) -> Result<(), PostgresStoreError> {
        let mut entry = entry.clone();
        let task = entry
            .get_mut("task")
            .map(std::mem::take)
            .ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?;
        let task_key = row_key(&task, &["tenant_scope", "task_id"])?;
        insert_shared(&mut self.tasks, &task_key, task)?;
        entry["taskKey"] = serde_json::Value::String(task_key);
        let events = entry
            .get_mut("taskEvents")
            .map(std::mem::take)
            .and_then(|v| v.as_array().cloned())
            .ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?;
        let mut event_keys = Vec::with_capacity(events.len());
        for event in events {
            let key = row_key(&event, &["tenant_scope", "task_id", "event_seq"])?;
            insert_shared(&mut self.task_events, &key, event)?;
            event_keys.push(serde_json::Value::String(key));
        }
        entry["taskEventKeys"] = serde_json::Value::Array(event_keys);
        let generation = entry
            .get_mut("keyGenerationMetadata")
            .map(std::mem::take)
            .ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?;
        let generation_key = row_key(
            &generation,
            &["tenant_scope", "encryption_domain", "key_generation"],
        )?;
        insert_shared(&mut self.key_generations, &generation_key, generation)?;
        entry["keyGenerationKey"] = serde_json::Value::String(generation_key);
        let quota = entry
            .get_mut("quotaPolicy")
            .map(std::mem::take)
            .ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?;
        if !quota.is_null() {
            let key = row_key(&quota, &["tenant_scope", "policy_id", "policy_revision"])?;
            insert_shared(&mut self.quota_policies, &key, quota)?;
            entry["quotaPolicyKey"] = serde_json::Value::String(key);
        }
        if !self.first {
            self.write_all(b",")?;
        }
        self.first = false;
        let bytes = serde_json::to_vec(&entry)
            .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
        self.write_all(&bytes)
    }
    fn finish(mut self) -> Result<String, PostgresStoreError> {
        let tasks = serde_json::to_vec(&self.tasks.values().collect::<Vec<_>>())
            .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
        let events = serde_json::to_vec(&self.task_events.values().collect::<Vec<_>>())
            .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
        let quotas = serde_json::to_vec(&self.quota_policies.values().collect::<Vec<_>>())
            .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
        let generations = serde_json::to_vec(&self.key_generations.values().collect::<Vec<_>>())
            .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
        self.write_all(b"],\"tasks\":")?;
        self.write_all(&tasks)?;
        self.write_all(b",\"taskEvents\":")?;
        self.write_all(&events)?;
        self.write_all(b",\"quotaPolicies\":")?;
        self.write_all(&quotas)?;
        self.write_all(b",\"keyGenerations\":")?;
        self.write_all(&generations)?;
        self.write_all(b"}")?;
        self.file
            .as_ref()
            .ok_or(PostgresStoreError::Unavailable)?
            .sync_all()
            .map_err(|_| PostgresStoreError::Unavailable)?;
        self.file.take();
        rustix::fs::renameat(
            &self.root_fd,
            self.temporary.as_str(),
            &self.root_fd,
            "inventory.json",
        )
        .map_err(|_| PostgresStoreError::Unavailable)?;
        rustix::fs::fsync(&self.root_fd).map_err(|_| PostgresStoreError::Unavailable)?;
        self.committed = true;
        let bytes = self.hasher.clone().finalize();
        Ok(format!(
            "sha256:{}",
            bytes.iter().fold(String::new(), |mut encoded, byte| {
                use std::fmt::Write as _;
                let _ = write!(encoded, "{byte:02x}");
                encoded
            })
        ))
    }
}

fn row_key(value: &serde_json::Value, fields: &[&str]) -> Result<String, PostgresStoreError> {
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
fn insert_shared(
    rows: &mut BTreeMap<String, serde_json::Value>,
    key: &str,
    value: serde_json::Value,
) -> Result<(), PostgresStoreError> {
    if let Some(existing) = rows.get(key) {
        if existing != &value {
            return Err(PostgresStoreError::ArtifactMigrationInvalidSource);
        }
    } else {
        rows.insert(key.to_owned(), value);
    }
    Ok(())
}

impl Drop for InventoryStream {
    fn drop(&mut self) {
        if !self.committed {
            let _ = rustix::fs::unlinkat(
                &self.root_fd,
                self.temporary.as_str(),
                rustix::fs::AtFlags::empty(),
            );
        }
    }
}

fn open_private_root(root: &Path) -> Result<OwnedFd, PostgresStoreError> {
    let fd = rustix::fs::open(
        root,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| PostgresStoreError::Unavailable)?;
    let stat = rustix::fs::fstat(&fd).map_err(|_| PostgresStoreError::Unavailable)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory
        || rustix::fs::Mode::from_raw_mode(stat.st_mode).bits() & 0o077 != 0
        || stat.st_uid != rustix::process::getuid().as_raw()
    {
        return Err(PostgresStoreError::ArtifactMigrationInvalidSource);
    }
    Ok(fd)
}

fn atomic_write(root: &Path, name: &str, bytes: &[u8]) -> Result<(), PostgresStoreError> {
    let root_fd = rustix::fs::open(
        root,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| PostgresStoreError::Unavailable)?;
    let stat = rustix::fs::fstat(&root_fd).map_err(|_| PostgresStoreError::Unavailable)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory
        || rustix::fs::Mode::from_raw_mode(stat.st_mode).bits() & 0o077 != 0
        || stat.st_uid != rustix::process::getuid().as_raw()
    {
        return Err(PostgresStoreError::ArtifactMigrationInvalidSource);
    }
    if let Ok(fd) = rustix::fs::openat(
        &root_fd,
        name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        let mut old = Vec::new();
        File::from(fd)
            .read_to_end(&mut old)
            .map_err(|_| PostgresStoreError::Unavailable)?;
        if old == bytes {
            return Ok(());
        }
    }
    let tmp = format!(".{name}-{:032x}.tmp", rand::random::<u128>());
    let fd = rustix::fs::openat(
        &root_fd,
        tmp.as_str(),
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map_err(|_| PostgresStoreError::Unavailable)?;
    let mut f = File::from(fd);
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|_| PostgresStoreError::Unavailable)?;
    rustix::fs::renameat(&root_fd, tmp.as_str(), &root_fd, name)
        .map_err(|_| PostgresStoreError::Unavailable)?;
    rustix::fs::fsync(&root_fd).map_err(|_| PostgresStoreError::Unavailable)
}
async fn run_hook_file(
    h: &crate::SignatureHook,
    root: &Path,
) -> Result<String, PostgresStoreError> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let root_fd = open_private_root(root)?;
    let inventory_fd = rustix::fs::openat(
        &root_fd,
        "inventory.json",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| PostgresStoreError::Unavailable)?;
    let mut inventory = File::from(inventory_fd);
    let mut child = tokio::process::Command::new(h.command())
        .args(h.args())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| PostgresStoreError::Unavailable)?;
    let mut stdin = child.stdin.take().ok_or(PostgresStoreError::Unavailable)?;
    let stdout = child.stdout.take().ok_or(PostgresStoreError::Unavailable)?;
    let operation = async {
        stdin
            .write_all(b"smesh-artifact-physical-inventory/v1\0")
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?;
        let mut chunk = vec![0_u8; 64 * 1024];
        loop {
            let read = inventory
                .read(&mut chunk)
                .map_err(|_| PostgresStoreError::Unavailable)?;
            if read == 0 {
                break;
            }
            stdin
                .write_all(&chunk[..read])
                .await
                .map_err(|_| PostgresStoreError::Unavailable)?;
        }
        stdin
            .shutdown()
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?;
        drop(stdin);
        let mut output = Vec::new();
        stdout
            .take(64 * 1024 + 1)
            .read_to_end(&mut output)
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?;
        let status = child
            .wait()
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?;
        Ok::<_, PostgresStoreError>((status, output))
    };
    let (status, output) = tokio::time::timeout(std::time::Duration::from_secs(5), operation)
        .await
        .map_err(|_| PostgresStoreError::Unavailable)??;
    if !status.success() || output.is_empty() || output.len() > 64 * 1024 {
        return Err(PostgresStoreError::ArtifactMigrationInvalidSource);
    }
    String::from_utf8(output).map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)
}
