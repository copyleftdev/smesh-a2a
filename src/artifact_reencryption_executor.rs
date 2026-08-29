//! Fenced, joinable artifact key rotation and physical re-encryption.
#![allow(clippy::too_many_lines)]
use crate::{
    ArtifactKeyRotationPlanFile, ArtifactKeyring as _, ArtifactReadLease, PosixArtifactBlobStore,
    PostgresStoreError, ReloadingArtifactKeyring,
    artifact::{ReencryptedArtifact, reencryption_aad_seal},
};
use std::sync::Arc;
use tokio_postgres::{Client, Row};

#[derive(Clone, Debug)]
pub struct ArtifactKeyRotationOutcome {
    pub reencrypted: u64,
    pub cleaned: u64,
    pub completed: bool,
}

fn persisted_reencrypted(row: &Row) -> Result<ReencryptedArtifact, PostgresStoreError> {
    let locator: Option<String> = row.get(10);
    let stage_locator: Option<String> = row.get(11);
    let nonce: Option<Vec<u8>> = row.get(12);
    let digest: Option<String> = row.get(13);
    let length: Option<i64> = row.get(14);
    Ok(ReencryptedArtifact {
        locator: locator.ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?,
        stage_locator: stage_locator.ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?,
        nonce: nonce
            .ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?
            .try_into()
            .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?,
        ciphertext_digest: digest.ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?,
        ciphertext_length: u64::try_from(
            length.ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?,
        )
        .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?,
    })
}

async fn fail_job(client: &Client, schema: &str, tenant: &str, job: &str, token: &str, epoch: i64) {
    let _ = client
        .execute(
            &format!("UPDATE {schema}.artifact_reencryption_jobs SET state='failed',updated_at={schema}.db_millis() WHERE tenant_scope=$1 AND job_id=$2 AND lease_token=$3 AND lease_epoch=$4"),
            &[&tenant, &job, &token, &epoch],
        )
        .await;
}

async fn verify_manifest_chunks(
    client: &Client,
    schema: &str,
    lease: &ArtifactReadLease,
    plaintext: &[u8],
) -> Result<(), PostgresStoreError> {
    let canonical: serde_json::Value = serde_json::from_str(&lease.canonical_manifest_json)
        .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
    let canonical_chunks = canonical
        .get("chunks")
        .and_then(serde_json::Value::as_array)
        .ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?;
    let rows = client
        .query(
            &format!("SELECT ordinal,byte_offset,plaintext_length,content_digest FROM {schema}.artifact_chunks WHERE tenant_scope=$1 AND artifact_id=$2 ORDER BY ordinal"),
            &[&lease.tenant_scope, &lease.artifact_id],
        )
        .await
        .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
    if rows.len() != canonical_chunks.len() {
        return Err(PostgresStoreError::ArtifactMigrationInvalidSource);
    }
    let mut expected_offset = 0_usize;
    for (expected_ordinal, (row, canonical_chunk)) in rows.iter().zip(canonical_chunks).enumerate()
    {
        let ordinal: i32 = row.get(0);
        let offset = usize::try_from(row.get::<_, i64>(1))
            .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
        let length = usize::try_from(row.get::<_, i64>(2))
            .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
        let digest: String = row.get(3);
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= plaintext.len())
            .ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?;
        if ordinal != i32::try_from(expected_ordinal).unwrap_or(i32::MAX)
            || offset != expected_offset
            || length == 0
            || crate::content_digest(&plaintext[offset..end]) != digest
            || canonical_chunk
                .get("ordinal")
                .and_then(serde_json::Value::as_i64)
                != Some(i64::from(ordinal))
            || canonical_chunk
                .get("offset")
                .and_then(serde_json::Value::as_i64)
                != Some(i64::try_from(offset).unwrap_or(i64::MAX))
            || canonical_chunk
                .get("length")
                .and_then(serde_json::Value::as_i64)
                != Some(i64::try_from(length).unwrap_or(i64::MAX))
            || canonical_chunk
                .get("digest")
                .and_then(serde_json::Value::as_str)
                != Some(digest.as_str())
        {
            return Err(PostgresStoreError::ArtifactMigrationInvalidSource);
        }
        expected_offset = end;
    }
    if expected_offset != plaintext.len() || (plaintext.is_empty() && !rows.is_empty()) {
        return Err(PostgresStoreError::ArtifactMigrationInvalidSource);
    }
    Ok(())
}

pub(crate) async fn execute(
    client: &mut Client,
    schema: &str,
    blobs: Arc<PosixArtifactBlobStore>,
    keyring: Arc<ReloadingArtifactKeyring>,
    plan: &ArtifactKeyRotationPlanFile,
    owner: &str,
) -> Result<ArtifactKeyRotationOutcome, PostgresStoreError> {
    if schema != plan.source_schema()
        || owner.is_empty()
        || keyring.active_generation() != plan.plan().new_generation()
        || keyring.key(plan.plan().old_generation()).is_err()
        || keyring.key(plan.plan().new_generation()).is_err()
    {
        return Err(PostgresStoreError::ArtifactMigrationPlanMismatch);
    }
    client
        .batch_execute("SELECT set_config('smesh.internal_global','claim-v1',false)")
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?;
    let id: Vec<u8> = client
        .query_one(
            &format!("SELECT store_id FROM {schema}.store_identity"),
            &[],
        )
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?
        .get(0);
    if id.as_slice() != plan.source_store_id().bytes() {
        return Err(PostgresStoreError::ArtifactMigrationPlanMismatch);
    }
    client
        .query_one(
            "SELECT pg_advisory_lock(hashtextextended($1,0))",
            &[&format!(
                "smesh-artifact-rotation:{schema}:{}",
                plan.plan().encryption_domain()
            )],
        )
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?;

    // Keep external blob I/O outside a SQL transaction while still ensuring
    // the session-scoped domain lock is released for every body result.
    let rotation_result: Result<ArtifactKeyRotationOutcome, PostgresStoreError> = async {
    let tenants=client.query(&format!("SELECT DISTINCT tenant_scope FROM {schema}.content_objects WHERE encryption_domain=$1 AND key_generation=$2 AND state<>'deleted' ORDER BY tenant_scope"),&[&plan.plan().encryption_domain(),&plan.plan().old_generation()]).await.map_err(|_|PostgresStoreError::InvalidSchema)?;
    for row in tenants {
        let tenant: String = row.get(0);
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
        if now < plan.effective_at() {
            return Err(PostgresStoreError::ArtifactMigrationBusy);
        }
        tx.execute(&format!("UPDATE {schema}.artifact_key_generations SET state='retiring' WHERE tenant_scope=$1 AND encryption_domain=$2 AND key_generation=$3 AND state='active'"),&[&tenant,&plan.plan().encryption_domain(),&plan.plan().old_generation()]).await.map_err(|_|PostgresStoreError::Unavailable)?;
        tx.execute(&format!("INSERT INTO {schema}.artifact_key_generations(tenant_scope,encryption_domain,key_generation,state,created_at) VALUES($1,$2,$3,'active',$4) ON CONFLICT(tenant_scope,encryption_domain,key_generation) DO UPDATE SET state='active',retired_at=NULL"),&[&tenant,&plan.plan().encryption_domain(),&plan.plan().new_generation(),&now]).await.map_err(|_|PostgresStoreError::Unavailable)?;
        tx.execute(&format!("INSERT INTO {schema}.artifact_key_rotation_plans(tenant_scope,rotation_id,encryption_domain,old_generation,new_generation,actor_digest,reason_digest,batch_size,state,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'active',$9) ON CONFLICT DO NOTHING"),&[&tenant,&plan.plan().plan_id(),&plan.plan().encryption_domain(),&plan.plan().old_generation(),&plan.plan().new_generation(),&plan.plan().actor_digest().to_string(),&plan.plan().reason_digest().to_string(),&i32::from(plan.plan().batch_size()),&now]).await.map_err(|_|PostgresStoreError::ArtifactMigrationBusy)?;
        tx.execute(&format!("INSERT INTO {schema}.artifact_reencryption_jobs(tenant_scope,job_id,rotation_id,object_id,old_generation,new_generation,old_locator,state,lease_epoch,attempts,created_at,updated_at) SELECT o.tenant_scope,'reencrypt-'||encode(sha256(convert_to(o.tenant_scope,'UTF8')||decode('00','hex')||convert_to(o.object_id,'UTF8')||decode('00','hex')||convert_to($2,'UTF8')),'hex'),$2,o.object_id,$3,$4,o.backend_locator,'pending',1,0,$5,$5 FROM {schema}.content_objects o WHERE o.tenant_scope=$1 AND o.encryption_domain=$6 AND o.key_generation=$3 AND o.state<>'deleted' ON CONFLICT DO NOTHING"),&[&tenant,&plan.plan().plan_id(),&plan.plan().old_generation(),&plan.plan().new_generation(),&now,&plan.plan().encryption_domain()]).await.map_err(|_|PostgresStoreError::Unavailable)?;
        tx.execute(&format!("INSERT INTO {schema}.artifact_key_audits(tenant_scope,audit_id,encryption_domain,key_generation,action,actor_digest,created_at) VALUES($1,$2,$3,$4,'rotate',$5,$6) ON CONFLICT DO NOTHING"),&[&tenant,&format!("rotate-{}",plan.plan().plan_id()),&plan.plan().encryption_domain(),&plan.plan().new_generation(),&plan.plan().actor_digest().to_string(),&now]).await.map_err(|_|PostgresStoreError::Unavailable)?;
        tx.commit()
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?;
    }

    let mut done = 0_u64;
    loop {
        let token = crate::content_digest(&rand::random::<[u8; 32]>());
        let claims = client
            .query(
                &format!(
                    "SELECT * FROM {schema}.claim_artifact_reencryption($1,$2,$3,$4,$5,$6,$7)"
                ),
                &[
                    &plan.plan().plan_id(),
                    &plan.plan().old_generation(),
                    &plan.plan().new_generation(),
                    &owner,
                    &token,
                    &plan.lease_duration_millis(),
                    &i32::from(plan.plan().batch_size()),
                ],
            )
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?;
        if claims.is_empty() {
            break;
        }
        for c in claims {
            let tenant: String = c.get(0);
            let job: String = c.get(1);
            let rotation: String = c.get(2);
            let object: String = c.get(3);
            let old_generation: String = c.get(4);
            let new_generation: String = c.get(5);
            let epoch: i64 = c.get(8);
            let mut state: String = c.get(9);
            if rotation != plan.plan().plan_id()
                || old_generation != plan.plan().old_generation()
                || new_generation != plan.plan().new_generation()
            {
                fail_job(client, schema, &tenant, &job, &token, epoch).await;
                return Err(PostgresStoreError::ArtifactMigrationPlanMismatch);
            }
            let row=client.query_one(&format!("SELECT m.owner_account_id,m.task_id,m.artifact_id,m.media_type,m.manifest_digest,m.canonical_json,o.content_digest,o.plaintext_length,o.classification,o.encryption_domain,o.ciphertext_digest,o.ciphertext_length,o.backend_locator,o.nonce,o.key_generation FROM {schema}.content_objects o JOIN LATERAL(SELECT * FROM {schema}.artifact_manifests m WHERE m.tenant_scope=o.tenant_scope AND m.object_id=o.object_id ORDER BY m.artifact_id LIMIT 1)m ON true WHERE o.tenant_scope=$1 AND o.object_id=$2"),&[&tenant,&object]).await.map_err(|_|PostgresStoreError::ArtifactMigrationInvalidSource)?;
            let nonce: Vec<u8> = row.get(13);
            let lease = ArtifactReadLease {
                tenant_scope: tenant.clone(),
                owner_account_id: row.get(0),
                task_id: row.get(1),
                artifact_id: row.get(2),
                media_type: row.get(3),
                content_digest: row.get(6),
                manifest_digest: row.get(4),
                plaintext_length: u64::try_from(row.get::<_, i64>(7))
                    .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?,
                classification: row.get(8),
                encryption_domain: row.get(9),
                ciphertext_digest: row.get(10),
                ciphertext_length: u64::try_from(row.get::<_, i64>(11))
                    .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?,
                backend_locator: row.get(12),
                nonce: nonce
                    .try_into()
                    .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?,
                key_generation: row.get(14),
                canonical_manifest_json: row.get(5),
                lease_id: String::new(),
                lease_token: token.clone(),
                lease_epoch: u64::try_from(epoch).unwrap_or(0),
                lease_until: i64::MAX,
            };
            let expected_aad_seal = reencryption_aad_seal(&lease, plan.plan().new_generation());

            let fresh = if state == "leased" {
                if c.get::<_, Option<String>>(10).is_some()
                    || c.get::<_, Option<String>>(11).is_some()
                {
                    fail_job(client, schema, &tenant, &job, &token, epoch).await;
                    return Err(PostgresStoreError::ArtifactMigrationInvalidSource);
                }
                let fresh = blobs
                    .reencrypt_verified(&lease, plan.plan().new_generation())
                    .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
                crate::artifact_production_checkpoint(
                    "reencryption_new_ciphertext_before_stage_registration",
                );
                let changed=client.execute(&format!("UPDATE {schema}.artifact_reencryption_jobs SET state='staged',new_locator=$1,new_stage_locator=$2,new_nonce=$3,new_ciphertext_digest=$4,new_ciphertext_length=$5,new_aad_seal=$6,updated_at={schema}.db_millis() WHERE tenant_scope=$7 AND job_id=$8 AND rotation_id=$9 AND old_generation=$10 AND new_generation=$11 AND lease_owner=$12 AND lease_token=$13 AND lease_epoch=$14 AND lease_until>{schema}.db_millis() AND state='leased'"), &[&fresh.locator,&fresh.stage_locator,&fresh.nonce.to_vec(),&fresh.ciphertext_digest,&i64::try_from(fresh.ciphertext_length).unwrap_or(i64::MAX),&expected_aad_seal,&tenant,&job,&rotation,&old_generation,&new_generation,&owner,&token,&epoch]).await.map_err(|_|PostgresStoreError::Unavailable)?;
                if changed != 1 {
                    return Err(PostgresStoreError::ArtifactMigrationBusy);
                }
                state = "staged".into();
                fresh
            } else {
                let persisted = persisted_reencrypted(&c)?;
                if c.get::<_, Option<String>>(15).as_deref() != Some(expected_aad_seal.as_str()) {
                    fail_job(client, schema, &tenant, &job, &token, epoch).await;
                    return Err(PostgresStoreError::ArtifactMigrationInvalidSource);
                }
                persisted
            };

            if state == "staged" {
                crate::artifact_production_checkpoint(
                    "reencryption_stage_registration_before_physical_promotion",
                );
                if blobs.promote_reencrypted(&fresh).is_err() {
                    // The registered final is not authoritative until the
                    // metadata swap. Remove a mismatching promotion; any
                    // remaining registered stage is then reclaimable because
                    // the failed job is not considered live by the scanner.
                    let _ = blobs.delete_locator(&fresh.locator);
                    fail_job(client, schema, &tenant, &job, &token, epoch).await;
                    return Err(PostgresStoreError::ArtifactMigrationInvalidSource);
                }
                crate::artifact_production_checkpoint(
                    "reencryption_physical_promotion_before_state_ack",
                );
                let changed=client.execute(&format!("UPDATE {schema}.artifact_reencryption_jobs SET state='promoted',updated_at={schema}.db_millis() WHERE tenant_scope=$1 AND job_id=$2 AND rotation_id=$3 AND lease_owner=$4 AND lease_token=$5 AND lease_epoch=$6 AND lease_until>{schema}.db_millis() AND state='staged' AND new_locator=$7 AND new_stage_locator=$8 AND new_ciphertext_digest=$9 AND new_ciphertext_length=$10 AND new_aad_seal=$11"), &[&tenant,&job,&rotation,&owner,&token,&epoch,&fresh.locator,&fresh.stage_locator,&fresh.ciphertext_digest,&i64::try_from(fresh.ciphertext_length).unwrap_or(i64::MAX),&expected_aad_seal]).await.map_err(|_|PostgresStoreError::Unavailable)?;
                if changed != 1 {
                    return Err(PostgresStoreError::ArtifactMigrationBusy);
                }
                state = "promoted".into();
            }

            if state == "promoted" {
                let Ok(verified) =
                    blobs.verify_reencrypted(&lease, plan.plan().new_generation(), &fresh)
                else {
                    let _ = blobs.delete_locator(&fresh.locator);
                    fail_job(client, schema, &tenant, &job, &token, epoch).await;
                    return Err(PostgresStoreError::ArtifactMigrationInvalidSource);
                };
                if verify_manifest_chunks(client, schema, &lease, &verified)
                    .await
                    .is_err()
                {
                    let _ = blobs.delete_locator(&fresh.locator);
                    fail_job(client, schema, &tenant, &job, &token, epoch).await;
                    return Err(PostgresStoreError::ArtifactMigrationInvalidSource);
                }
                crate::artifact_production_checkpoint("reencryption_promoted_before_metadata_swap");
                let tx = client
                    .transaction()
                    .await
                    .map_err(|_| PostgresStoreError::Unavailable)?;
                tx.batch_execute("SET LOCAL smesh.internal_global='claim-v1'")
                    .await
                    .map_err(|_| PostgresStoreError::Unavailable)?;
                let rollback: i64 = tx
                    .query_one(
                        &format!("SELECT {schema}.db_millis()+$1"),
                        &[&plan.rollback_horizon_millis()],
                    )
                    .await
                    .map_err(|_| PostgresStoreError::Unavailable)?
                    .get(0);
                let changed=tx.execute(&format!("UPDATE {schema}.content_objects o SET key_generation=j.new_generation,backend_locator=j.new_locator,nonce=j.new_nonce,ciphertext_digest=j.new_ciphertext_digest,ciphertext_length=j.new_ciphertext_length FROM {schema}.artifact_reencryption_jobs j WHERE j.tenant_scope=o.tenant_scope AND j.object_id=o.object_id AND j.tenant_scope=$1 AND j.job_id=$2 AND j.rotation_id=$3 AND j.lease_owner=$4 AND j.lease_token=$5 AND j.lease_epoch=$6 AND j.lease_until>{schema}.db_millis() AND j.state='promoted' AND j.new_aad_seal=$7 AND o.key_generation=j.old_generation AND o.backend_locator=j.old_locator"),&[&tenant,&job,&rotation,&owner,&token,&epoch,&expected_aad_seal]).await.map_err(|_|PostgresStoreError::Unavailable)?;
                if changed != 1 {
                    return Err(PostgresStoreError::ArtifactMigrationBusy);
                }
                tx.execute(&format!("UPDATE {schema}.upload_intents SET final_locator=$1,ciphertext_digest=$2,ciphertext_length=$3,updated_at={schema}.db_millis() WHERE tenant_scope=$4 AND object_id=$5"),&[&fresh.locator,&fresh.ciphertext_digest,&i64::try_from(fresh.ciphertext_length).unwrap_or(i64::MAX),&tenant,&object]).await.map_err(|_|PostgresStoreError::Unavailable)?;
                if tx.execute(&format!("UPDATE {schema}.artifact_reencryption_jobs SET state='swapped',rollback_until=$1,updated_at={schema}.db_millis() WHERE tenant_scope=$2 AND job_id=$3 AND state='promoted' AND lease_token=$4 AND lease_epoch=$5"),&[&rollback,&tenant,&job,&token,&epoch]).await.map_err(|_|PostgresStoreError::Unavailable)? != 1 { return Err(PostgresStoreError::ArtifactMigrationBusy); }
                tx.commit()
                    .await
                    .map_err(|_| PostgresStoreError::Unavailable)?;
                crate::artifact_production_checkpoint(
                    "reencryption_metadata_swap_before_old_delete",
                );
                done = done.saturating_add(1);
            }
        }
    }

    let mut cleaned = 0_u64;
    loop {
        let tx = client
            .transaction()
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?;
        tx.batch_execute("SET LOCAL smesh.internal_global='claim-v1'")
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?;
        let due=tx.query(&format!("SELECT j.tenant_scope,j.job_id,j.object_id,j.old_locator,j.state FROM {schema}.artifact_reencryption_jobs j JOIN {schema}.content_objects o USING(tenant_scope,object_id) WHERE j.rotation_id=$1 AND j.state IN ('swapped','cleanup') AND j.rollback_until<={schema}.db_millis() AND o.key_generation=j.new_generation AND o.backend_locator=j.new_locator AND NOT EXISTS(SELECT 1 FROM {schema}.artifact_backup_leases b WHERE b.tenant_scope=j.tenant_scope AND b.object_id=j.object_id AND b.state='active' AND b.lease_until>{schema}.db_millis()) AND NOT EXISTS(SELECT 1 FROM {schema}.artifact_read_leases r JOIN {schema}.artifact_manifests m USING(tenant_scope,artifact_id) WHERE m.tenant_scope=j.tenant_scope AND m.object_id=j.object_id AND r.state='active' AND r.lease_until>{schema}.db_millis()) ORDER BY j.tenant_scope,j.job_id FOR UPDATE OF j,o SKIP LOCKED LIMIT $2"),&[&plan.plan().plan_id(),&i64::from(plan.plan().batch_size())]).await.map_err(|_|PostgresStoreError::Unavailable)?;
        if due.is_empty() {
            tx.rollback()
                .await
                .map_err(|_| PostgresStoreError::Unavailable)?;
            break;
        }
        for row in due {
            let tenant: String = row.get(0);
            let job: String = row.get(1);
            let old: String = row.get(3);
            let state: String = row.get(4);
            if state == "swapped" {
                blobs
                    .delete_locator(&old)
                    .map_err(|_| PostgresStoreError::Unavailable)?;
                crate::artifact_production_checkpoint("reencryption_old_delete_before_complete");
                if tx.execute(&format!("UPDATE {schema}.artifact_reencryption_jobs SET state='cleanup',updated_at={schema}.db_millis() WHERE tenant_scope=$1 AND job_id=$2 AND state='swapped'"),&[&tenant,&job]).await.map_err(|_|PostgresStoreError::Unavailable)? != 1 { return Err(PostgresStoreError::ArtifactMigrationBusy); }
            }
            cleaned=cleaned.saturating_add(tx.execute(&format!("UPDATE {schema}.artifact_reencryption_jobs SET state='completed',lease_owner=NULL,lease_token=NULL,lease_until=NULL,updated_at={schema}.db_millis() WHERE tenant_scope=$1 AND job_id=$2 AND state='cleanup'"),&[&tenant,&job]).await.map_err(|_|PostgresStoreError::Unavailable)?);
        }
        tx.commit()
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?;
    }
    let remaining:i64=client.query_one(&format!("SELECT count(*) FROM {schema}.artifact_reencryption_jobs WHERE rotation_id=$1 AND state<>'completed'"),&[&plan.plan().plan_id()]).await.map_err(|_|PostgresStoreError::Unavailable)?.get(0);
    if remaining == 0 {
        client.execute(&format!("UPDATE {schema}.artifact_backup_key_dependencies SET released_at={schema}.db_millis() WHERE released_at IS NULL AND required_until<={schema}.db_millis()"),&[]).await.map_err(|_|PostgresStoreError::Unavailable)?;
        client.execute(&format!("UPDATE {schema}.artifact_key_rotation_plans SET state='completed',completed_at={schema}.db_millis() WHERE rotation_id=$1 AND state<>'completed'"),&[&plan.plan().plan_id()]).await.map_err(|_|PostgresStoreError::Unavailable)?;
        client.execute(&format!("UPDATE {schema}.artifact_key_generations k SET state='retired',retired_at={schema}.db_millis() WHERE k.encryption_domain=$1 AND k.key_generation=$2 AND k.state='retiring' AND NOT EXISTS(SELECT 1 FROM {schema}.artifact_backup_key_dependencies d JOIN {schema}.artifact_backup_jobs b USING(tenant_scope,backup_id) WHERE d.tenant_scope=k.tenant_scope AND d.encryption_domain=k.encryption_domain AND d.key_generation=k.key_generation AND d.released_at IS NULL AND d.required_until>{schema}.db_millis() AND b.state='sealed')"),&[&plan.plan().encryption_domain(),&plan.plan().old_generation()]).await.map_err(|_|PostgresStoreError::Unavailable)?;
    }
    Ok(ArtifactKeyRotationOutcome {
        reencrypted: done,
        cleaned,
        completed: remaining == 0,
    })
    }
    .await;
    let unlock_result = client
        .query_one(
            "SELECT pg_advisory_unlock(hashtextextended($1,0))",
            &[&format!(
                "smesh-artifact-rotation:{schema}:{}",
                plan.plan().encryption_domain()
            )],
        )
        .await;
    match (rotation_result, unlock_result) {
        (Err(error), _) => Err(error),
        (Ok(outcome), Ok(_)) => Ok(outcome),
        (Ok(_), Err(_)) => Err(PostgresStoreError::Unavailable),
    }
}
