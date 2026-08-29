//! Fenced, restartable populated inline-artifact migration executor.
#![allow(clippy::too_many_lines)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde_json::Value;
use tokio_postgres::{Client, GenericClient, Transaction};

use crate::{
    ArtifactChunkRegistration, ArtifactClassification, ArtifactManifestV1,
    ArtifactMigrationOutcome, ArtifactMigrationPlanFile, ArtifactPolicySnapshot, ArtifactProducer,
    ArtifactProvenanceRegistration, ArtifactStageRegistration, EncryptionDomain, InlineArtifact,
    PosixArtifactBlobStore, PostgresStoreError, extract_inline_artifacts,
};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SourceKey {
    relation: String,
    key1: String,
    key2: String,
    key3: String,
}

#[derive(Clone)]
struct SourceRow {
    key: SourceKey,
    tenant: String,
    task: String,
    owner: String,
    context: String,
    message: String,
    dispatch: String,
    revision: i64,
    json: String,
    value: Value,
}

#[derive(Clone)]
struct ArtifactGroup {
    tenant: String,
    task: String,
    owner: String,
    context: String,
    message: String,
    dispatch: String,
    revision: i64,
    artifact: InlineArtifact,
    rows: BTreeSet<SourceKey>,
}

struct Prepared {
    group_key: (String, String, String),
    registration: ArtifactStageRegistration,
    projection: Value,
}

pub(crate) async fn execute(
    client: &mut Client,
    schema: &str,
    blobs: Arc<PosixArtifactBlobStore>,
    plan_file: &ArtifactMigrationPlanFile,
    lease_owner: &str,
    cursor_key: &[u8; 32],
) -> Result<ArtifactMigrationOutcome, PostgresStoreError> {
    if schema != plan_file.source_schema() || lease_owner.is_empty() || lease_owner.len() > 256 {
        return Err(PostgresStoreError::ArtifactMigrationPlanMismatch);
    }
    client
        .batch_execute("SELECT set_config('smesh.internal_global','claim-v1',false)")
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?;
    let identity = client
        .query_one(
            &format!("SELECT store_id FROM {schema}.store_identity WHERE singleton=1"),
            &[],
        )
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?
        .get::<_, Vec<u8>>(0);
    if identity.as_slice() != plan_file.source_store_id().bytes() {
        return Err(PostgresStoreError::ArtifactMigrationPlanMismatch);
    }

    let existing = client
        .query_opt(
            &format!("SELECT tenant_scope,state,migrated_artifacts,completion_seal,source_identity,plan_digest,policy_id,policy_revision,policy_digest FROM {schema}.artifact_migration_plans WHERE plan_id=$1"),
            &[&plan_file.plan().plan_id()],
        )
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?;
    if let Some(row) = existing.as_ref() {
        let state: String = row.get(1);
        if state == "completed" {
            verify_completed_plan(
                client,
                schema,
                &plan_file.source_store_id().to_string(),
                plan_file.plan(),
            )
            .await
            .map_err(|_| PostgresStoreError::ArtifactMigrationPlanMismatch)?;
            return Ok(ArtifactMigrationOutcome {
                migrated_artifacts: u64::try_from(row.get::<_, i64>(2)).unwrap_or(0),
                rewritten_rows: 0,
                completed: true,
                completion_seal: row.get(3),
            });
        }
    } else if has_active_work(client, schema).await? {
        return Err(PostgresStoreError::ArtifactMigrationBusy);
    }

    let mut total_artifacts = 0_u64;
    let mut total_rows = 0_u64;
    let mut completion_fence: Option<(String, i64)> = None;
    loop {
        let rows = scan_rows(client, schema).await?;
        let groups = group_artifacts(&rows)?;
        if groups.is_empty() {
            let (lease_token, lease_epoch) = if let Some(fence) = completion_fence.as_ref() {
                fence.clone()
            } else {
                let tenant = existing.as_ref().map_or_else(
                    || "smesh-artifact-empty-tenant/v1".to_owned(),
                    |row| row.get::<_, String>(0),
                );
                acquire_lease(client, schema, plan_file, lease_owner, &tenant).await?
            };
            let completion_seal = complete_plan(
                client,
                schema,
                plan_file,
                lease_owner,
                &lease_token,
                lease_epoch,
            )
            .await?;
            return Ok(ArtifactMigrationOutcome {
                migrated_artifacts: total_artifacts,
                rewritten_rows: total_rows,
                completed: true,
                completion_seal: Some(completion_seal),
            });
        }
        let journal_tenant = existing.as_ref().map_or_else(
            || groups.values().next().expect("nonempty").tenant.clone(),
            |row| row.get::<_, String>(0),
        );
        let (lease_token, lease_epoch) =
            acquire_lease(client, schema, plan_file, lease_owner, &journal_tenant).await?;
        completion_fence = Some((lease_token.clone(), lease_epoch));
        let selected = groups
            .into_iter()
            .take(usize::from(plan_file.plan().batch_size()))
            .collect::<BTreeMap<_, _>>();
        let now = db_millis(client, schema).await?;
        let mut prepared = Vec::with_capacity(selected.len());
        for (key, group) in &selected {
            prepared.push(prepare_artifact(
                &blobs,
                plan_file,
                now,
                key.clone(),
                group,
            )?);
        }
        crate::artifact_production_checkpoint("migration_stage_before_batch_transaction");
        let (rewritten, input_seal, output_seal) = commit_batch(
            client,
            schema,
            plan_file,
            lease_owner,
            &lease_token,
            lease_epoch,
            &rows,
            &selected,
            &prepared,
            cursor_key,
        )
        .await?;
        let _ = (input_seal, output_seal);
        total_artifacts = total_artifacts.saturating_add(prepared.len() as u64);
        total_rows = total_rows.saturating_add(rewritten);
    }
}

async fn has_active_work(client: &Client, schema: &str) -> Result<bool, PostgresStoreError> {
    let sql = format!(
        "SELECT EXISTS(SELECT 1 FROM {schema}.tasks WHERE state NOT IN ('\"TASK_STATE_COMPLETED\"','\"TASK_STATE_FAILED\"','\"TASK_STATE_CANCELED\"','\"TASK_STATE_REJECTED\"'))
         OR EXISTS(SELECT 1 FROM {schema}.outbox WHERE state IN ('pending','leased'))
         OR EXISTS(SELECT 1 FROM {schema}.receiver_inbox WHERE state='processing')
         OR EXISTS(SELECT 1 FROM {schema}.stream_transcripts WHERE state='open')
         OR EXISTS(SELECT 1 FROM {schema}.cancellation_intents WHERE state='requested')"
    );
    client
        .query_one(&sql, &[])
        .await
        .map(|row| row.get(0))
        .map_err(|_| PostgresStoreError::InvalidSchema)
}

async fn db_millis(client: &Client, schema: &str) -> Result<i64, PostgresStoreError> {
    client
        .query_one(&format!("SELECT {schema}.db_millis()"), &[])
        .await
        .map(|row| row.get(0))
        .map_err(|_| PostgresStoreError::Unavailable)
}

async fn acquire_lease(
    client: &mut Client,
    schema: &str,
    file: &ArtifactMigrationPlanFile,
    owner: &str,
    tenant: &str,
) -> Result<(String, i64), PostgresStoreError> {
    let plan = file.plan();
    let token = crate::content_digest(&rand::random::<[u8; 32]>());
    let source_identity = file.source_store_id().to_string();
    let plan_digest = migration_plan_digest(file);
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
    let until = now.saturating_add(60_000);
    let insert = format!(
        "INSERT INTO {schema}.artifact_migration_plans(tenant_scope,plan_id,source_schema_version,source_identity,plan_digest,policy_id,policy_revision,policy_digest,actor_digest,reason_digest,batch_size,state,lease_epoch,migrated_artifacts,created_at)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'pending',0,0,$12) ON CONFLICT DO NOTHING"
    );
    tx.execute(
        &insert,
        &[
            &tenant,
            &plan.plan_id(),
            &i64::try_from(plan.source_schema_version()).unwrap_or(i64::MAX),
            &source_identity,
            &plan_digest,
            &plan.policy_id(),
            &i64::try_from(plan.policy_revision()).unwrap_or(i64::MAX),
            &plan.policy_digest().to_string(),
            &plan.actor_digest().to_string(),
            &plan.reason_digest().to_string(),
            &i32::from(plan.batch_size()),
            &now,
        ],
    )
    .await
    .map_err(|_| PostgresStoreError::ArtifactMigrationBusy)?;
    let claim = format!(
        "UPDATE {schema}.artifact_migration_plans SET state='processing',lease_owner=$1,lease_token=$2,lease_epoch=lease_epoch+1,lease_until=$3
         WHERE plan_id=$4 AND source_identity=$5 AND plan_digest=$6 AND state<>'completed'
           AND (state='pending' OR lease_until<={schema}.db_millis() OR lease_owner=$1)
         RETURNING lease_epoch"
    );
    let row = tx
        .query_opt(
            &claim,
            &[
                &owner,
                &token,
                &until,
                &plan.plan_id(),
                &source_identity,
                &plan_digest,
            ],
        )
        .await
        .map_err(|_| PostgresStoreError::ArtifactMigrationBusy)?
        .ok_or(PostgresStoreError::ArtifactMigrationBusy)?;
    let epoch: i64 = row.get(0);
    tx.commit()
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?;
    Ok((token, epoch))
}

fn migration_plan_digest(file: &ArtifactMigrationPlanFile) -> String {
    migration_plan_digest_parts(
        file.source_schema(),
        &file.source_store_id().to_string(),
        file.plan(),
    )
}

fn migration_plan_digest_parts(
    source_schema: &str,
    source_identity: &str,
    plan: &crate::ArtifactMigrationPlan,
) -> String {
    crate::content_digest(
        format!(
            "smesh-artifact-migration-plan/v1\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            source_schema,
            source_identity,
            plan.plan_id(),
            plan.source_schema_version(),
            plan.policy_id(),
            plan.policy_revision(),
            plan.policy_digest(),
            plan.actor_digest(),
            plan.reason_digest(),
            plan.batch_size(),
        )
        .as_bytes(),
    )
}

async fn scan_rows(client: &Client, schema: &str) -> Result<Vec<SourceRow>, PostgresStoreError> {
    let sql = format!(
        "SELECT relation,key1,key2,key3,tenant_scope,task_id,owner_account_id,context_id,message_id,dispatch_id,revision,json_value FROM (
         SELECT 'tasks.task_json' relation,t.task_id key1,'' key2,'' key3,t.tenant_scope,t.task_id,t.owner_account_id,t.context_id,'' message_id,'' dispatch_id,t.revision,t.task_json json_value FROM {schema}.tasks t
         UNION ALL SELECT 'task_events.event_json',e.task_id,e.event_seq::text,'',e.tenant_scope,e.task_id,t.owner_account_id,t.context_id,'','',e.task_revision,e.event_json FROM {schema}.task_events e JOIN {schema}.tasks t USING(tenant_scope,task_id)
         UNION ALL SELECT 'idempotency_records.admission_result_json',i.message_id,'','',i.tenant_scope,i.task_id,t.owner_account_id,t.context_id,i.message_id,COALESCE(o.dispatch_id,''),t.revision,i.admission_result_json FROM {schema}.idempotency_records i JOIN {schema}.tasks t USING(tenant_scope,task_id) LEFT JOIN {schema}.outbox o ON o.tenant_scope=i.tenant_scope AND o.message_id=i.message_id
         UNION ALL SELECT 'idempotency_records.final_result_json',i.message_id,'','',i.tenant_scope,i.task_id,t.owner_account_id,t.context_id,i.message_id,COALESCE(o.dispatch_id,''),t.revision,i.final_result_json FROM {schema}.idempotency_records i JOIN {schema}.tasks t USING(tenant_scope,task_id) LEFT JOIN {schema}.outbox o ON o.tenant_scope=i.tenant_scope AND o.message_id=i.message_id WHERE i.final_result_json IS NOT NULL
         UNION ALL SELECT 'idempotency_records.causative_request_json',i.message_id,'','',i.tenant_scope,i.task_id,t.owner_account_id,t.context_id,i.message_id,COALESCE(o.dispatch_id,''),t.revision,i.causative_request_json FROM {schema}.idempotency_records i JOIN {schema}.tasks t USING(tenant_scope,task_id) LEFT JOIN {schema}.outbox o ON o.tenant_scope=i.tenant_scope AND o.message_id=i.message_id WHERE i.causative_request_json IS NOT NULL
         UNION ALL SELECT 'outbox.payload_json',o.outbox_id::text,'','',o.tenant_scope,o.task_id,t.owner_account_id,t.context_id,o.message_id,o.dispatch_id,t.revision,o.payload_json FROM {schema}.outbox o JOIN {schema}.tasks t USING(tenant_scope,task_id)
         UNION ALL SELECT 'receiver_inbox.payload_json',r.dispatch_id,'','',r.tenant_scope,r.task_id,t.owner_account_id,t.context_id,o.message_id,r.dispatch_id,t.revision,r.payload_json FROM {schema}.receiver_inbox r JOIN {schema}.tasks t USING(tenant_scope,task_id) JOIN {schema}.outbox o ON o.tenant_scope=r.tenant_scope AND o.dispatch_id=r.dispatch_id
         UNION ALL SELECT 'receiver_inbox.termination_json',r.dispatch_id,'','',r.tenant_scope,r.task_id,t.owner_account_id,t.context_id,o.message_id,r.dispatch_id,t.revision,r.termination_json FROM {schema}.receiver_inbox r JOIN {schema}.tasks t USING(tenant_scope,task_id) JOIN {schema}.outbox o ON o.tenant_scope=r.tenant_scope AND o.dispatch_id=r.dispatch_id WHERE r.termination_json IS NOT NULL
         UNION ALL SELECT 'receiver_frames.frame_json',f.dispatch_id,f.frame_seq::text,'',f.tenant_scope,r.task_id,t.owner_account_id,t.context_id,o.message_id,f.dispatch_id,t.revision,f.frame_json FROM {schema}.receiver_frames f JOIN {schema}.receiver_inbox r USING(tenant_scope,dispatch_id) JOIN {schema}.tasks t USING(tenant_scope,task_id) JOIN {schema}.outbox o ON o.tenant_scope=f.tenant_scope AND o.dispatch_id=f.dispatch_id
         UNION ALL SELECT 'stream_frames.frame_json',f.message_id,f.frame_seq::text,'',f.tenant_scope,s.task_id,t.owner_account_id,t.context_id,f.message_id,s.dispatch_id,t.revision,f.frame_json FROM {schema}.stream_frames f JOIN {schema}.stream_transcripts s USING(tenant_scope,message_id) JOIN {schema}.tasks t USING(tenant_scope,task_id)
         UNION ALL SELECT 'list_snapshot_entries.task_json',encode(e.snapshot_id,'hex'),e.ordinal::text,'',e.tenant_scope,e.task_id,t.owner_account_id,t.context_id,'','',e.task_revision,e.task_json FROM {schema}.list_snapshot_entries e JOIN {schema}.tasks t USING(tenant_scope,task_id)
        ) sources ORDER BY tenant_scope,task_id,relation,key1,key2,key3"
    );
    client
        .query(&sql, &[])
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?
        .into_iter()
        .map(|row| {
            let json: String = row.get(11);
            let value = serde_json::from_str(&json)
                .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
            Ok(SourceRow {
                key: SourceKey {
                    relation: row.get(0),
                    key1: row.get(1),
                    key2: row.get(2),
                    key3: row.get(3),
                },
                tenant: row.get(4),
                task: row.get(5),
                owner: row.get(6),
                context: row.get(7),
                message: row.get(8),
                dispatch: row.get(9),
                revision: row.get(10),
                json,
                value,
            })
        })
        .collect()
}

fn group_artifacts(
    rows: &[SourceRow],
) -> Result<BTreeMap<(String, String, String), ArtifactGroup>, PostgresStoreError> {
    let mut groups = BTreeMap::new();
    for row in rows {
        for artifact in extract_inline_artifacts(&row.value)
            .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?
        {
            let key = (
                row.tenant.clone(),
                row.task.clone(),
                artifact.artifact_id.clone(),
            );
            if let Some(existing) = groups.get_mut(&key) {
                let existing: &mut ArtifactGroup = existing;
                if existing.artifact != artifact
                    || existing.owner != row.owner
                    || existing.context != row.context
                {
                    return Err(PostgresStoreError::ArtifactMigrationInvalidSource);
                }
                existing.rows.insert(row.key.clone());
            } else {
                groups.insert(
                    key,
                    ArtifactGroup {
                        tenant: row.tenant.clone(),
                        task: row.task.clone(),
                        owner: row.owner.clone(),
                        context: row.context.clone(),
                        message: nonempty_identity(&row.message, "message", &row.task),
                        dispatch: nonempty_identity(&row.dispatch, "dispatch", &row.task),
                        revision: row.revision,
                        artifact,
                        rows: BTreeSet::from([row.key.clone()]),
                    },
                );
            }
        }
    }
    Ok(groups)
}

fn nonempty_identity(value: &str, prefix: &str, task: &str) -> String {
    if value.is_empty() {
        let digest = crate::content_digest(format!("{prefix}\0{task}").as_bytes());
        format!("migration-{prefix}-{}", &digest[7..39])
    } else {
        value.to_owned()
    }
}

fn prepare_artifact(
    blobs: &PosixArtifactBlobStore,
    file: &ArtifactMigrationPlanFile,
    now: i64,
    group_key: (String, String, String),
    group: &ArtifactGroup,
) -> Result<Prepared, PostgresStoreError> {
    let bytes = group
        .artifact
        .canonical_bytes()
        .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
    let plan = file.plan();
    let key_generation = blobs.active_key_generation();
    let domain = EncryptionDomain::new(format!("{}/confidential", group.tenant))
        .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
    let producer = ArtifactProducer::new(
        &group.tenant,
        &group.owner,
        &group.task,
        &group.context,
        &group.message,
        &group.dispatch,
    )
    .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
    let retain_until = now.saturating_add(30 * 24 * 60 * 60 * 1_000);
    let policy = ArtifactPolicySnapshot::new(
        plan.policy_id(),
        plan.policy_revision(),
        plan.policy_digest(),
        now,
        retain_until,
    )
    .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
    let manifest = ArtifactManifestV1::new(
        &group.artifact.artifact_id,
        group
            .artifact
            .name
            .clone()
            .unwrap_or_else(|| group.artifact.artifact_id.clone()),
        group.artifact.description.clone(),
        group.artifact.media_type(),
        ArtifactClassification::Confidential,
        domain,
        key_generation.clone(),
        producer,
        vec![],
        policy,
        now,
        &bytes,
    )
    .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
    let semantic = crate::content_digest(
        format!(
            "{}\0{}\0{}",
            group.tenant, group.task, group.artifact.artifact_id
        )
        .as_bytes(),
    );
    let object_id = crate::content_digest(
        format!(
            "{}\0{}\0{}\0{}\0{}",
            group.tenant,
            group.owner,
            key_generation,
            manifest.content_digest(),
            group.artifact.artifact_id
        )
        .as_bytes(),
    );
    let registration = ArtifactStageRegistration {
        tenant_scope: group.tenant.clone(),
        account_id: group.owner.clone(),
        owner_account_id: group.owner.clone(),
        task_id: group.task.clone(),
        context_id: group.context.clone(),
        message_id: group.message.clone(),
        dispatch_id: group.dispatch.clone(),
        upload_id: format!("migration-upload-{}", &semantic[7..39]),
        artifact_id: group.artifact.artifact_id.clone(),
        object_id,
        content_digest: manifest.content_digest().to_string(),
        manifest_digest: manifest.manifest_digest().to_string(),
        ciphertext_digest: String::new(),
        plaintext_length: manifest.plaintext_length(),
        ciphertext_length: 0,
        classification: "confidential".to_owned(),
        encryption_domain: format!("{}/confidential", group.tenant),
        key_generation,
        canonical_manifest_json: manifest.canonical_json().to_owned(),
        chunks: manifest
            .chunks()
            .iter()
            .map(|chunk| ArtifactChunkRegistration {
                ordinal: chunk.ordinal(),
                byte_offset: chunk.offset(),
                plaintext_length: chunk.length(),
                content_digest: chunk.digest().to_string(),
            })
            .collect(),
        provenance: Vec::<ArtifactProvenanceRegistration>::new(),
        media_type: manifest.media_type().to_owned(),
        reference_id: format!("migration-reference-{}", &semantic[39..71]),
        task_revision: u64::try_from(group.revision)
            .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?,
        policy_id: plan.policy_id().to_owned(),
        policy_revision: plan.policy_revision(),
        policy_digest: plan.policy_digest().to_string(),
        created_at: now,
        stage_locator: String::new(),
        final_locator: String::new(),
        nonce: [0; 12],
        retain_until,
        quota_binding_digest: None,
        receiver_lease_epoch: 1,
        receiver_lease_token: format!("migration-fence-{}", &semantic[7..39]),
    };
    let registration = blobs
        .stage_registration(registration, &bytes)
        .map_err(|_| PostgresStoreError::Unavailable)?;
    Ok(Prepared {
        group_key,
        projection: serde_json::to_value(manifest.to_a2a_projection())
            .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?,
        registration,
    })
}

#[allow(clippy::too_many_arguments)]
async fn commit_batch(
    client: &mut Client,
    schema: &str,
    file: &ArtifactMigrationPlanFile,
    owner: &str,
    token: &str,
    epoch: i64,
    rows: &[SourceRow],
    groups: &BTreeMap<(String, String, String), ArtifactGroup>,
    prepared: &[Prepared],
    cursor_key: &[u8; 32],
) -> Result<(u64, String, String), PostgresStoreError> {
    let tx = client
        .transaction()
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?;
    tx.batch_execute("SET LOCAL smesh.internal_global='claim-v1'")
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?;
    let fence = format!(
        "SELECT checkpoint_input_seal,checkpoint_output_seal FROM {schema}.artifact_migration_plans WHERE plan_id=$1 AND state='processing' AND lease_owner=$2 AND lease_token=$3 AND lease_epoch=$4 AND lease_until>{schema}.db_millis() FOR UPDATE"
    );
    let fence_row = tx
        .query_opt(&fence, &[&file.plan().plan_id(), &owner, &token, &epoch])
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?
        .ok_or(PostgresStoreError::ArtifactMigrationBusy)?;
    let prior_input: Option<String> = fence_row.get(0);
    let prior_output: Option<String> = fence_row.get(1);
    for item in prepared {
        register(&tx, schema, &item.registration).await?;
    }
    let projections = prepared
        .iter()
        .map(|item| (item.group_key.clone(), item.projection.clone()))
        .collect::<BTreeMap<_, _>>();
    let affected = groups
        .values()
        .flat_map(|group| group.rows.iter().cloned())
        .collect::<BTreeSet<_>>();
    let mut rewritten = 0_u64;
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();
    for key in affected {
        let row = rows
            .iter()
            .find(|row| row.key == key)
            .ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?;
        let mut value = row.value.clone();
        let mut changed = 0;
        for (group_key, projection) in &projections {
            if group_key.0 == row.tenant && group_key.1 == row.task {
                let artifact = &groups[group_key].artifact;
                if extract_inline_artifacts(&value)
                    .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?
                    .iter()
                    .any(|candidate| candidate.artifact_id == artifact.artifact_id)
                {
                    changed += artifact
                        .rewrite_all(&mut value, projection)
                        .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
                }
            }
        }
        if changed == 0 {
            continue;
        }
        let output = serde_json::to_string(&value)
            .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
        update_source(&tx, schema, row, &output).await?;
        inputs.extend_from_slice(crate::content_digest(row.json.as_bytes()).as_bytes());
        inputs.push(0);
        outputs.extend_from_slice(crate::content_digest(output.as_bytes()).as_bytes());
        outputs.push(0);
        rewritten += 1;
    }
    recompute_aggregate_seals(&tx, schema, cursor_key).await?;
    let batch_input_seal = crate::content_digest(&inputs);
    let batch_output_seal = crate::content_digest(&outputs);
    let last = prepared
        .last()
        .ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?;
    let group = &groups[&last.group_key];
    let last_row = group.rows.iter().next_back().expect("group has row");
    let checkpoint_key = format!(
        "{}\0{}\0{}\0{}\0{}",
        last_row.relation, last_row.key1, last_row.key2, last_row.key3, last.group_key.2
    );
    let input_seal = crate::content_digest(
        format!(
            "smesh-artifact-migration-checkpoint-input/v1\0{}\0{}\0{}",
            prior_input.as_deref().unwrap_or(""),
            checkpoint_key,
            batch_input_seal
        )
        .as_bytes(),
    );
    let output_seal = crate::content_digest(
        format!(
            "smesh-artifact-migration-checkpoint-output/v1\0{}\0{}\0{}",
            prior_output.as_deref().unwrap_or(""),
            checkpoint_key,
            batch_output_seal
        )
        .as_bytes(),
    );
    let migrated_bytes = prepared
        .iter()
        .try_fold(0_i64, |total, item| {
            total.checked_add(i64::try_from(item.registration.plaintext_length).ok()?)
        })
        .ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?;
    let update = format!(
        "UPDATE {schema}.artifact_migration_plans SET checkpoint_relation=$1,checkpoint_row_id=$2,checkpoint_json_path=$3,checkpoint_artifact=$4,checkpoint_input_seal=$5,checkpoint_output_seal=$6,migrated_artifacts=migrated_artifacts+$7,migrated_rows=migrated_rows+$8,migrated_bytes=migrated_bytes+$9,lease_until={schema}.db_millis()+60000 WHERE plan_id=$10 AND state='processing' AND lease_owner=$11 AND lease_token=$12 AND lease_epoch=$13 AND lease_until>{schema}.db_millis()"
    );
    if tx
        .execute(
            &update,
            &[
                &last_row.relation,
                &format!("{}:{}:{}", last_row.key1, last_row.key2, last_row.key3),
                &"$",
                &last.group_key.2,
                &input_seal,
                &output_seal,
                &i64::try_from(prepared.len()).unwrap_or(i64::MAX),
                &i64::try_from(rewritten).unwrap_or(i64::MAX),
                &migrated_bytes,
                &file.plan().plan_id(),
                &owner,
                &token,
                &epoch,
            ],
        )
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?
        != 1
    {
        return Err(PostgresStoreError::ArtifactMigrationPlanMismatch);
    }
    tx.commit()
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?;
    crate::artifact_production_checkpoint("migration_batch_commit_before_checkpoint_ack");
    Ok((rewritten, input_seal, output_seal))
}

async fn register(
    tx: &Transaction<'_>,
    schema: &str,
    r: &ArtifactStageRegistration,
) -> Result<(), PostgresStoreError> {
    let now: i64 = tx
        .query_one(&format!("SELECT {schema}.db_millis()"), &[])
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?
        .get(0);
    tx.execute(&format!("INSERT INTO {schema}.artifact_key_generations(tenant_scope,encryption_domain,key_generation,state,created_at) VALUES($1,$2,$3,'active',$4) ON CONFLICT DO NOTHING"), &[&r.tenant_scope,&r.encryption_domain,&r.key_generation,&now]).await.map_err(|_|PostgresStoreError::Unavailable)?;
    let nonce = r.nonce.to_vec();
    tx.execute(&format!("INSERT INTO {schema}.content_objects(tenant_scope,owner_account_id,object_id,content_digest,classification,encryption_domain,key_generation,plaintext_length,ciphertext_length,ciphertext_digest,backend_locator,nonce,state,reference_count,retain_until,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'staged',0,$13,$14) ON CONFLICT DO NOTHING"), &[&r.tenant_scope,&r.owner_account_id,&r.object_id,&r.content_digest,&r.classification,&r.encryption_domain,&r.key_generation,&i64::try_from(r.plaintext_length).unwrap_or(i64::MAX),&i64::try_from(r.ciphertext_length).unwrap_or(i64::MAX),&r.ciphertext_digest,&r.final_locator,&nonce,&r.retain_until,&r.created_at]).await.map_err(|_|PostgresStoreError::Unavailable)?;
    tx.execute(&format!("INSERT INTO {schema}.artifact_manifests(tenant_scope,artifact_id,manifest_digest,object_id,schema_version,canonical_json,owner_account_id,task_id,context_id,message_id,dispatch_id,media_type,plaintext_length,classification,encryption_domain,policy_id,policy_revision,policy_digest,created_at,retain_until) VALUES($1,$2,$3,$4,1,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) ON CONFLICT DO NOTHING"), &[&r.tenant_scope,&r.artifact_id,&r.manifest_digest,&r.object_id,&r.canonical_manifest_json,&r.owner_account_id,&r.task_id,&r.context_id,&r.message_id,&r.dispatch_id,&r.media_type,&i64::try_from(r.plaintext_length).unwrap_or(i64::MAX),&r.classification,&r.encryption_domain,&r.policy_id,&i64::try_from(r.policy_revision).unwrap_or(i64::MAX),&r.policy_digest,&r.created_at,&r.retain_until]).await.map_err(|_|PostgresStoreError::Unavailable)?;
    for chunk in &r.chunks {
        tx.execute(&format!("INSERT INTO {schema}.artifact_chunks(tenant_scope,artifact_id,ordinal,byte_offset,plaintext_length,content_digest) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING"), &[&r.tenant_scope,&r.artifact_id,&i32::try_from(chunk.ordinal).unwrap_or(i32::MAX),&i64::try_from(chunk.byte_offset).unwrap_or(i64::MAX),&i64::try_from(chunk.plaintext_length).unwrap_or(i64::MAX),&chunk.content_digest]).await.map_err(|_|PostgresStoreError::Unavailable)?;
    }
    let inserted = tx.query_opt(&format!("INSERT INTO {schema}.artifact_references(tenant_scope,reference_id,artifact_id,task_id,context_id,owner_account_id,task_revision,state,retain_until,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,'active',$8,$9) ON CONFLICT DO NOTHING RETURNING reference_id"), &[&r.tenant_scope,&r.reference_id,&r.artifact_id,&r.task_id,&r.context_id,&r.owner_account_id,&i64::try_from(r.task_revision).unwrap_or(i64::MAX),&r.retain_until,&r.created_at]).await.map_err(|_|PostgresStoreError::Unavailable)?.is_some();
    if inserted {
        tx.execute(&format!("UPDATE {schema}.content_objects SET reference_count=reference_count+1 WHERE tenant_scope=$1 AND object_id=$2"), &[&r.tenant_scope,&r.object_id]).await.map_err(|_|PostgresStoreError::Unavailable)?;
    }
    tx.execute(&format!("INSERT INTO {schema}.upload_intents(tenant_scope,upload_id,artifact_id,object_id,state,stage_locator,final_locator,ciphertext_digest,ciphertext_length,lease_epoch,created_at,updated_at) VALUES($1,$2,$3,$4,'committed',$5,$6,$7,$8,1,$9,$9) ON CONFLICT DO NOTHING"), &[&r.tenant_scope,&r.upload_id,&r.artifact_id,&r.object_id,&r.stage_locator,&r.final_locator,&r.ciphertext_digest,&i64::try_from(r.ciphertext_length).unwrap_or(i64::MAX),&now]).await.map_err(|_|PostgresStoreError::Unavailable)?;
    let object=tx.query_one(&format!("SELECT content_digest,ciphertext_digest,backend_locator,plaintext_length,ciphertext_length FROM {schema}.content_objects WHERE tenant_scope=$1 AND object_id=$2"),&[&r.tenant_scope,&r.object_id]).await.map_err(|_|PostgresStoreError::Unavailable)?;
    let manifest=tx.query_one(&format!("SELECT manifest_digest,object_id,canonical_json FROM {schema}.artifact_manifests WHERE tenant_scope=$1 AND artifact_id=$2"),&[&r.tenant_scope,&r.artifact_id]).await.map_err(|_|PostgresStoreError::Unavailable)?;
    let upload=tx.query_one(&format!("SELECT artifact_id,object_id,stage_locator,final_locator,ciphertext_digest,ciphertext_length FROM {schema}.upload_intents WHERE tenant_scope=$1 AND upload_id=$2"),&[&r.tenant_scope,&r.upload_id]).await.map_err(|_|PostgresStoreError::Unavailable)?;
    if object.get::<_, String>(0) != r.content_digest
        || object.get::<_, String>(1) != r.ciphertext_digest
        || object.get::<_, String>(2) != r.final_locator
        || object.get::<_, i64>(3) != i64::try_from(r.plaintext_length).unwrap_or(i64::MAX)
        || object.get::<_, i64>(4) != i64::try_from(r.ciphertext_length).unwrap_or(i64::MAX)
        || manifest.get::<_, String>(0) != r.manifest_digest
        || manifest.get::<_, String>(1) != r.object_id
        || manifest.get::<_, String>(2) != r.canonical_manifest_json
        || upload.get::<_, String>(0) != r.artifact_id
        || upload.get::<_, String>(1) != r.object_id
        || upload.get::<_, String>(2) != r.stage_locator
        || upload.get::<_, String>(3) != r.final_locator
        || upload.get::<_, String>(4) != r.ciphertext_digest
        || upload.get::<_, i64>(5) != i64::try_from(r.ciphertext_length).unwrap_or(i64::MAX)
    {
        return Err(PostgresStoreError::ArtifactMigrationInvalidSource);
    }
    Ok(())
}

async fn update_source(
    tx: &Transaction<'_>,
    schema: &str,
    row: &SourceRow,
    output: &str,
) -> Result<(), PostgresStoreError> {
    tx.query_one(
        "SELECT set_config('smesh.tenant_scope',$1,true)",
        &[&row.tenant],
    )
    .await
    .map_err(|_| PostgresStoreError::Unavailable)?;
    let digest = crate::content_digest(output.as_bytes());
    let (sql, params): (String, Vec<&(dyn tokio_postgres::types::ToSql + Sync)>) = match row
        .key
        .relation
        .as_str()
    {
        "tasks.task_json" => (
            format!(
                "UPDATE {schema}.tasks SET task_json=$1 WHERE tenant_scope=$2 AND task_id=$3 AND task_json=$4"
            ),
            vec![&output, &row.tenant, &row.key.key1, &row.json],
        ),
        "task_events.event_json" => (
            format!(
                "UPDATE {schema}.task_events SET event_json=$1 WHERE tenant_scope=$2 AND task_id=$3 AND event_seq=$4::text::bigint AND event_json=$5"
            ),
            vec![
                &output,
                &row.tenant,
                &row.key.key1,
                &row.key.key2,
                &row.json,
            ],
        ),
        "idempotency_records.admission_result_json" => (
            format!(
                "UPDATE {schema}.idempotency_records SET admission_result_json=$1 WHERE tenant_scope=$2 AND message_id=$3 AND admission_result_json=$4"
            ),
            vec![&output, &row.tenant, &row.key.key1, &row.json],
        ),
        "idempotency_records.final_result_json" => (
            format!(
                "UPDATE {schema}.idempotency_records SET final_result_json=$1 WHERE tenant_scope=$2 AND message_id=$3 AND final_result_json=$4"
            ),
            vec![&output, &row.tenant, &row.key.key1, &row.json],
        ),
        "idempotency_records.causative_request_json" => (
            format!(
                "UPDATE {schema}.idempotency_records SET causative_request_json=$1,digest_version=3 WHERE tenant_scope=$2 AND message_id=$3 AND causative_request_json=$4"
            ),
            vec![&output, &row.tenant, &row.key.key1, &row.json],
        ),
        "outbox.payload_json" => (
            format!(
                "UPDATE {schema}.outbox SET payload_json=$1,payload_digest=$2 WHERE tenant_scope=$3 AND outbox_id=$4::text::bigint AND payload_json=$5"
            ),
            vec![&output, &digest, &row.tenant, &row.key.key1, &row.json],
        ),
        "receiver_inbox.payload_json" => (
            format!(
                "UPDATE {schema}.receiver_inbox SET payload_json=$1,payload_digest=$2 WHERE tenant_scope=$3 AND dispatch_id=$4 AND payload_json=$5"
            ),
            vec![&output, &digest, &row.tenant, &row.key.key1, &row.json],
        ),
        "receiver_inbox.termination_json" => (
            format!(
                "UPDATE {schema}.receiver_inbox SET termination_json=$1 WHERE tenant_scope=$2 AND dispatch_id=$3 AND termination_json=$4"
            ),
            vec![&output, &row.tenant, &row.key.key1, &row.json],
        ),
        "receiver_frames.frame_json" => (
            format!(
                "UPDATE {schema}.receiver_frames SET frame_json=$1,frame_digest=$2 WHERE tenant_scope=$3 AND dispatch_id=$4 AND frame_seq=$5::text::bigint AND frame_json=$6"
            ),
            vec![
                &output,
                &digest,
                &row.tenant,
                &row.key.key1,
                &row.key.key2,
                &row.json,
            ],
        ),
        "stream_frames.frame_json" => (
            format!(
                "UPDATE {schema}.stream_frames SET frame_json=$1,frame_digest=$2 WHERE tenant_scope=$3 AND message_id=$4 AND frame_seq=$5::text::bigint AND frame_json=$6"
            ),
            vec![
                &output,
                &digest,
                &row.tenant,
                &row.key.key1,
                &row.key.key2,
                &row.json,
            ],
        ),
        "list_snapshot_entries.task_json" => (
            format!(
                "UPDATE {schema}.list_snapshot_entries SET task_json=$1,task_digest=$2 WHERE tenant_scope=$3 AND snapshot_id=decode($4,'hex') AND ordinal=$5::text::bigint AND task_json=$6"
            ),
            vec![
                &output,
                &digest,
                &row.tenant,
                &row.key.key1,
                &row.key.key2,
                &row.json,
            ],
        ),
        _ => return Err(PostgresStoreError::ArtifactMigrationInvalidSource),
    };
    if tx
        .execute(&sql, &params)
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?
        != 1
    {
        return Err(PostgresStoreError::ArtifactMigrationInvalidSource);
    }
    Ok(())
}

async fn recompute_aggregate_seals(
    tx: &Transaction<'_>,
    schema: &str,
    cursor_key: &[u8; 32],
) -> Result<(), PostgresStoreError> {
    for row in tx.query(&format!("SELECT tenant_scope,dispatch_id FROM {schema}.receiver_inbox WHERE state='completed'"),&[]).await.map_err(|_|PostgresStoreError::Unavailable)? {
        let tenant:String=row.get(0); let dispatch:String=row.get(1);
        let frames=tx.query(&format!("SELECT frame_json FROM {schema}.receiver_frames WHERE tenant_scope=$1 AND dispatch_id=$2 ORDER BY frame_seq"),&[&tenant,&dispatch]).await.map_err(|_|PostgresStoreError::Unavailable)?;
        let encoded=frames.iter().map(|frame| frame.get::<_,String>(0)).collect::<Vec<_>>();
        let values=encoded.iter().map(|json|serde_json::from_str::<Value>(json).map_err(|_|PostgresStoreError::ArtifactMigrationInvalidSource)).collect::<Result<Vec<_>,_>>()?;
        let bytes=serde_json::to_vec(&values).map_err(|_|PostgresStoreError::ArtifactMigrationInvalidSource)?;
        let measured:i64=encoded.iter().map(|json|i64::try_from(json.len()).unwrap_or(i64::MAX)).sum();
        tx.execute(&format!("UPDATE {schema}.receiver_inbox SET transcript_digest=$1,measured_output_bytes=$2 WHERE tenant_scope=$3 AND dispatch_id=$4"),&[&crate::content_digest(&bytes),&measured,&tenant,&dispatch]).await.map_err(|_|PostgresStoreError::Unavailable)?;
    }
    for row in tx.query(&format!("SELECT tenant_scope,message_id FROM {schema}.stream_transcripts WHERE state='terminal'"),&[]).await.map_err(|_|PostgresStoreError::Unavailable)? {
        let tenant:String=row.get(0); let message:String=row.get(1);
        let frames=tx.query(&format!("SELECT frame_json FROM {schema}.stream_frames WHERE tenant_scope=$1 AND message_id=$2 ORDER BY frame_seq"),&[&tenant,&message]).await.map_err(|_|PostgresStoreError::Unavailable)?;
        let values=frames.iter().map(|frame|serde_json::from_str::<Value>(frame.get::<_,&str>(0)).map_err(|_|PostgresStoreError::ArtifactMigrationInvalidSource)).collect::<Result<Vec<_>,_>>()?;
        let bytes=serde_json::to_vec(&values).map_err(|_|PostgresStoreError::ArtifactMigrationInvalidSource)?;
        tx.execute(&format!("UPDATE {schema}.stream_transcripts SET transcript_digest=$1 WHERE tenant_scope=$2 AND message_id=$3"),&[&crate::content_digest(&bytes),&tenant,&message]).await.map_err(|_|PostgresStoreError::Unavailable)?;
    }
    for row in tx.query(&format!("SELECT tenant_scope,snapshot_id,scope_digest,query_digest,total_size,page_size,issued_at,expires_at,projection_version FROM {schema}.list_snapshots"),&[]).await.map_err(|_|PostgresStoreError::Unavailable)? {
        let tenant:String=row.get(0); let snapshot:Vec<u8>=row.get(1); let scope:String=row.get(2); let query:String=row.get(3);
        let total:i64=row.get(4); let page:i64=row.get(5); let issued:i64=row.get(6); let expires:i64=row.get(7); let projection:i64=row.get(8);
        let entries=tx.query(&format!("SELECT ordinal,task_id,task_revision,task_digest,task_json FROM {schema}.list_snapshot_entries WHERE tenant_scope=$1 AND snapshot_id=$2 ORDER BY ordinal"),&[&tenant,&snapshot]).await.map_err(|_|PostgresStoreError::Unavailable)?;
        let mut frozen=0_i64; let mut seals=Vec::with_capacity(entries.len());
        for entry in entries { let json:String=entry.get(4); frozen=frozen.checked_add(i64::try_from(json.len()).map_err(|_|PostgresStoreError::ArtifactMigrationInvalidSource)?).ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?; seals.push((entry.get(0),entry.get(1),entry.get(2),entry.get(3))); }
        let metadata=crate::postgres_store::snapshot_metadata_digest(cursor_key,&snapshot,&scope,&query,total,page,issued,expires,projection,frozen,&seals).to_vec();
        tx.execute(&format!("UPDATE {schema}.list_snapshots SET frozen_bytes=$1,metadata_digest=$2 WHERE tenant_scope=$3 AND snapshot_id=$4"),&[&frozen,&metadata,&tenant,&snapshot]).await.map_err(|_|PostgresStoreError::Unavailable)?;
    }
    Ok(())
}

async fn durable_json_rescan<C: GenericClient + Sync>(
    client: &C,
    schema: &str,
) -> Result<(String, i64, i64), PostgresStoreError> {
    let sql = format!(
        "SELECT relation,key1,key2,key3,json_value FROM (
         SELECT 'tasks.task_json' relation,tenant_scope key1,task_id key2,'' key3,task_json json_value FROM {schema}.tasks
         UNION ALL SELECT 'task_events.event_json',tenant_scope,task_id,event_seq::text,event_json FROM {schema}.task_events
         UNION ALL SELECT 'idempotency_records.admission_result_json',tenant_scope,message_id,'',admission_result_json FROM {schema}.idempotency_records
         UNION ALL SELECT 'idempotency_records.final_result_json',tenant_scope,message_id,'',final_result_json FROM {schema}.idempotency_records WHERE final_result_json IS NOT NULL
         UNION ALL SELECT 'idempotency_records.causative_request_json',tenant_scope,message_id,'',causative_request_json FROM {schema}.idempotency_records WHERE causative_request_json IS NOT NULL
         UNION ALL SELECT 'outbox.payload_json',tenant_scope,outbox_id::text,'',payload_json FROM {schema}.outbox
         UNION ALL SELECT 'receiver_inbox.payload_json',tenant_scope,dispatch_id,'',payload_json FROM {schema}.receiver_inbox
         UNION ALL SELECT 'receiver_inbox.termination_json',tenant_scope,dispatch_id,'',termination_json FROM {schema}.receiver_inbox WHERE termination_json IS NOT NULL
         UNION ALL SELECT 'receiver_frames.frame_json',tenant_scope,dispatch_id,frame_seq::text,frame_json FROM {schema}.receiver_frames
         UNION ALL SELECT 'stream_frames.frame_json',tenant_scope,message_id,frame_seq::text,frame_json FROM {schema}.stream_frames
         UNION ALL SELECT 'list_snapshot_entries.task_json',tenant_scope,encode(snapshot_id,'hex'),ordinal::text,task_json FROM {schema}.list_snapshot_entries
        ) durable_json ORDER BY relation,key1,key2,key3"
    );
    let rows = client
        .query(&sql, &[])
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?;
    let mut canonical = b"smesh-artifact-migration-full-rescan/v1\0".to_vec();
    let mut total_bytes = 0_i64;
    for row in &rows {
        let relation: String = row.get(0);
        let key1: String = row.get(1);
        let key2: String = row.get(2);
        let key3: String = row.get(3);
        let json: String = row.get(4);
        let value: Value = serde_json::from_str(&json)
            .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?;
        if !extract_inline_artifacts(&value)
            .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?
            .is_empty()
        {
            return Err(PostgresStoreError::ArtifactMigrationInvalidSource);
        }
        total_bytes = total_bytes
            .checked_add(
                i64::try_from(json.len())
                    .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?,
            )
            .ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?;
        for field in [&relation, &key1, &key2, &key3] {
            canonical.extend_from_slice(field.as_bytes());
            canonical.push(0);
        }
        canonical.extend_from_slice(crate::content_digest(json.as_bytes()).as_bytes());
        canonical.push(0);
    }
    Ok((
        crate::content_digest(&canonical),
        i64::try_from(rows.len())
            .map_err(|_| PostgresStoreError::ArtifactMigrationInvalidSource)?,
        total_bytes,
    ))
}

fn completion_seal_from_row(
    schema: &str,
    row: &tokio_postgres::Row,
    rescan_digest: &str,
) -> Result<String, PostgresStoreError> {
    let checkpoint_relation: Option<String> = row.get(9);
    let checkpoint_row_id: Option<String> = row.get(10);
    let checkpoint_json_path: Option<String> = row.get(11);
    let checkpoint_artifact: Option<String> = row.get(12);
    let checkpoint_input: Option<String> = row.get(13);
    let checkpoint_output: Option<String> = row.get(14);
    let checkpoint_key = format!(
        "{}\0{}\0{}\0{}",
        checkpoint_relation.as_deref().unwrap_or(""),
        checkpoint_row_id.as_deref().unwrap_or(""),
        checkpoint_json_path.as_deref().unwrap_or(""),
        checkpoint_artifact.as_deref().unwrap_or("")
    );
    Ok(crate::content_digest(
        format!(
            "smesh-artifact-migration-completion/v2\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            row.get::<_, String>(0),
            row.get::<_, String>(1),
            row.get::<_, String>(2),
            schema,
            row.get::<_, i64>(3),
            row.get::<_, String>(4),
            row.get::<_, i64>(5),
            row.get::<_, String>(6),
            checkpoint_key,
            checkpoint_input.ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?,
            checkpoint_output.ok_or(PostgresStoreError::ArtifactMigrationInvalidSource)?,
            row.get::<_, i64>(15),
            row.get::<_, i64>(16),
            row.get::<_, i64>(17),
            rescan_digest,
        )
        .as_bytes(),
    ))
}

async fn completion_row<C: GenericClient + Sync>(
    client: &C,
    schema: &str,
    plan_id: &str,
    for_update: bool,
) -> Result<tokio_postgres::Row, PostgresStoreError> {
    client
        .query_one(
            &format!(
                "SELECT plan_id,plan_digest,source_identity,source_schema_version,policy_id,policy_revision,policy_digest,actor_digest,reason_digest,checkpoint_relation,checkpoint_row_id,checkpoint_json_path,checkpoint_artifact,checkpoint_input_seal,checkpoint_output_seal,migrated_artifacts,migrated_rows,migrated_bytes,completion_seal,full_rescan_digest,state,lease_owner,lease_token,lease_epoch,lease_until,batch_size FROM {schema}.artifact_migration_plans WHERE plan_id=$1{}",
                if for_update { " FOR UPDATE" } else { "" }
            ),
            &[&plan_id],
        )
        .await
        .map_err(|_| PostgresStoreError::ArtifactMigrationRequired)
}

fn row_matches_plan(
    row: &tokio_postgres::Row,
    schema: &str,
    source_identity: &str,
    plan: &crate::ArtifactMigrationPlan,
) -> bool {
    row.get::<_, String>(0) == plan.plan_id()
        && row.get::<_, String>(1) == migration_plan_digest_parts(schema, source_identity, plan)
        && row.get::<_, String>(2) == source_identity
        && row.get::<_, i64>(3) == i64::try_from(plan.source_schema_version()).unwrap_or(i64::MAX)
        && row.get::<_, String>(4) == plan.policy_id()
        && row.get::<_, i64>(5) == i64::try_from(plan.policy_revision()).unwrap_or(i64::MAX)
        && row.get::<_, String>(6) == plan.policy_digest().to_string()
        && row.get::<_, String>(7) == plan.actor_digest().to_string()
        && row.get::<_, String>(8) == plan.reason_digest().to_string()
        && row.get::<_, i32>(25) == i32::from(plan.batch_size())
}

pub(crate) async fn verify_completed_plan(
    client: &Client,
    schema: &str,
    source_identity: &str,
    plan: &crate::ArtifactMigrationPlan,
) -> Result<(), PostgresStoreError> {
    let row = completion_row(client, schema, plan.plan_id(), false).await?;
    if row.get::<_, String>(20) != "completed"
        || !row_matches_plan(&row, schema, source_identity, plan)
    {
        return Err(PostgresStoreError::ArtifactMigrationRequired);
    }
    let persisted_rescan: String = row
        .get::<_, Option<String>>(19)
        .ok_or(PostgresStoreError::ArtifactMigrationRequired)?;
    let expected = completion_seal_from_row(schema, &row, &persisted_rescan)
        .map_err(|_| PostgresStoreError::ArtifactMigrationRequired)?;
    if row.get::<_, Option<String>>(18).as_deref() != Some(expected.as_str()) {
        return Err(PostgresStoreError::ArtifactMigrationRequired);
    }
    // The authenticated completion seal binds the completion-time full rescan.
    // Startup additionally performs a fresh zero-inline scan; normal post-
    // migration manifest-only durable writes need not reproduce old row bytes.
    durable_json_rescan(client, schema)
        .await
        .map_err(|_| PostgresStoreError::ArtifactMigrationRequired)?;
    Ok(())
}

async fn complete_plan(
    client: &mut Client,
    schema: &str,
    file: &ArtifactMigrationPlanFile,
    owner: &str,
    token: &str,
    epoch: i64,
) -> Result<String, PostgresStoreError> {
    let tx = client
        .transaction()
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?;
    tx.batch_execute("SET LOCAL smesh.internal_global='claim-v1'")
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?;
    let row = completion_row(&tx, schema, file.plan().plan_id(), true).await?;
    let lease_until: Option<i64> = row.get(24);
    let now: i64 = tx
        .query_one(&format!("SELECT {schema}.db_millis()"), &[])
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?
        .get(0);
    if row.get::<_, String>(20) != "processing"
        || row.get::<_, Option<String>>(21).as_deref() != Some(owner)
        || row.get::<_, Option<String>>(22).as_deref() != Some(token)
        || row.get::<_, i64>(23) != epoch
        || lease_until.is_none_or(|until| until <= now)
        || !row_matches_plan(
            &row,
            schema,
            &file.source_store_id().to_string(),
            file.plan(),
        )
    {
        return Err(PostgresStoreError::ArtifactMigrationBusy);
    }
    let empty_input = crate::content_digest(b"smesh-artifact-migration-empty-input/v1");
    let empty_output = crate::content_digest(b"smesh-artifact-migration-empty-output/v1");
    tx.execute(
        &format!("UPDATE {schema}.artifact_migration_plans SET checkpoint_relation=COALESCE(checkpoint_relation,'$end'),checkpoint_row_id=COALESCE(checkpoint_row_id,''),checkpoint_json_path=COALESCE(checkpoint_json_path,'$'),checkpoint_artifact=COALESCE(checkpoint_artifact,''),checkpoint_input_seal=COALESCE(checkpoint_input_seal,$1),checkpoint_output_seal=COALESCE(checkpoint_output_seal,$2) WHERE plan_id=$3 AND state='processing' AND lease_owner=$4 AND lease_token=$5 AND lease_epoch=$6 AND lease_until>{schema}.db_millis()"),
        &[&empty_input, &empty_output, &file.plan().plan_id(), &owner, &token, &epoch],
    )
    .await
    .map_err(|_| PostgresStoreError::Unavailable)?;
    let (rescan, _, _) = durable_json_rescan(&tx, schema).await?;
    let sealed_row = completion_row(&tx, schema, file.plan().plan_id(), false).await?;
    let seal = completion_seal_from_row(schema, &sealed_row, &rescan)?;
    let changed = tx.execute(&format!("UPDATE {schema}.artifact_migration_plans SET state='completed',full_rescan_digest=$1,completion_seal=$2,completed_at={schema}.db_millis(),lease_owner=NULL,lease_token=NULL,lease_until=NULL WHERE plan_id=$3 AND state='processing' AND lease_owner=$4 AND lease_token=$5 AND lease_epoch=$6 AND lease_until>{schema}.db_millis()"),&[&rescan,&seal,&file.plan().plan_id(),&owner,&token,&epoch]).await.map_err(|_|PostgresStoreError::Unavailable)?;
    if changed != 1 {
        return Err(PostgresStoreError::ArtifactMigrationBusy);
    }
    tx.commit()
        .await
        .map_err(|_| PostgresStoreError::Unavailable)?;
    Ok(seal)
}
