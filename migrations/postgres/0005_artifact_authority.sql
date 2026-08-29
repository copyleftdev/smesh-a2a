-- Artifact authority revision 5. PostgreSQL is the sole visibility, reference,
-- retention, lease, refcount, and work authority; blob locators are private.
-- Digest version 3 explicitly marks causative JSON manifest projection while
-- preserving the original semantic request digest used for exact replay.
ALTER TABLE __SCHEMA__.quota_intents
 DROP CONSTRAINT quota_intents_tenant_scope_operation_semantic_id_key;
ALTER TABLE __SCHEMA__.quota_intents
 ADD CONSTRAINT quota_intents_replay_identity_key
 UNIQUE(tenant_scope,account_id,principal_scope,operation,semantic_id);
ALTER TABLE __SCHEMA__.idempotency_records DROP CONSTRAINT idempotency_records_digest_version_check;
ALTER TABLE __SCHEMA__.idempotency_records ADD CONSTRAINT idempotency_records_digest_version_check CHECK(digest_version IN (1,2,3));
ALTER TABLE __SCHEMA__.tasks ADD CONSTRAINT tasks_artifact_owner_binding
 UNIQUE(tenant_scope,task_id,context_id,owner_account_id);
CREATE TABLE __SCHEMA__.artifact_key_generations(
 tenant_scope text NOT NULL, encryption_domain text NOT NULL, key_generation text NOT NULL,
 state text NOT NULL CHECK(state IN ('active','retiring','retired')), created_at bigint NOT NULL,
 retired_at bigint, PRIMARY KEY(tenant_scope,encryption_domain,key_generation)
);
CREATE TABLE __SCHEMA__.content_objects(
 tenant_scope text NOT NULL, owner_account_id text NOT NULL, object_id text NOT NULL, content_digest text NOT NULL CHECK(content_digest ~ '^sha256:[0-9a-f]{64}$'),
 classification text NOT NULL CHECK(classification IN ('public','internal','confidential','secret')),
 encryption_domain text NOT NULL, key_generation text NOT NULL, plaintext_length bigint NOT NULL CHECK(plaintext_length>=0),
 ciphertext_length bigint NOT NULL CHECK(ciphertext_length>=16), ciphertext_digest text NOT NULL CHECK(ciphertext_digest ~ '^sha256:[0-9a-f]{64}$'),
 backend_locator text NOT NULL, nonce bytea NOT NULL CHECK(octet_length(nonce)=12), state text NOT NULL CHECK(state IN ('staged','available','tombstoned','deleting','deleted','quarantined')),
 reference_count bigint NOT NULL DEFAULT 0 CHECK(reference_count>=0), retain_until bigint NOT NULL, tombstone_generation bigint NOT NULL DEFAULT 0 CHECK(tombstone_generation>=0),
 created_at bigint NOT NULL, available_at bigint, PRIMARY KEY(tenant_scope,object_id),
 UNIQUE(tenant_scope,content_digest,classification,encryption_domain,key_generation,object_id),
 FOREIGN KEY(tenant_scope,encryption_domain,key_generation) REFERENCES __SCHEMA__.artifact_key_generations(tenant_scope,encryption_domain,key_generation) ON DELETE RESTRICT
);
CREATE INDEX content_objects_dedupe ON __SCHEMA__.content_objects(tenant_scope,owner_account_id,classification,encryption_domain,content_digest) WHERE state='available';
CREATE INDEX content_objects_gc_due ON __SCHEMA__.content_objects(state,retain_until,tenant_scope,object_id) WHERE state IN ('available','tombstoned','deleting');

CREATE TABLE __SCHEMA__.artifact_manifests(
 tenant_scope text NOT NULL, artifact_id text NOT NULL, manifest_digest text NOT NULL CHECK(manifest_digest ~ '^sha256:[0-9a-f]{64}$'),
 object_id text NOT NULL, schema_version bigint NOT NULL CHECK(schema_version=1), canonical_json text NOT NULL CHECK(__SCHEMA__.json_text_valid(canonical_json)),
 owner_account_id text NOT NULL, task_id text NOT NULL, context_id text NOT NULL, message_id text NOT NULL, dispatch_id text NOT NULL,
 media_type text NOT NULL, plaintext_length bigint NOT NULL CHECK(plaintext_length>=0), classification text NOT NULL,
 encryption_domain text NOT NULL, policy_id text NOT NULL, policy_revision bigint NOT NULL CHECK(policy_revision>0), policy_digest text NOT NULL,
 created_at bigint NOT NULL, retain_until bigint NOT NULL CHECK(retain_until>=created_at), PRIMARY KEY(tenant_scope,artifact_id),
 UNIQUE(tenant_scope,manifest_digest),
 UNIQUE(tenant_scope,artifact_id,task_id,context_id,owner_account_id),
 FOREIGN KEY(tenant_scope,object_id) REFERENCES __SCHEMA__.content_objects(tenant_scope,object_id) ON DELETE RESTRICT,
 FOREIGN KEY(tenant_scope,task_id,context_id,owner_account_id) REFERENCES __SCHEMA__.tasks(tenant_scope,task_id,context_id,owner_account_id) ON DELETE RESTRICT
);
CREATE INDEX artifact_manifests_resolve ON __SCHEMA__.artifact_manifests(tenant_scope,task_id,artifact_id,owner_account_id);
CREATE INDEX artifact_manifests_object ON __SCHEMA__.artifact_manifests(tenant_scope,object_id,artifact_id);

CREATE TABLE __SCHEMA__.artifact_chunks(
 tenant_scope text NOT NULL, artifact_id text NOT NULL, ordinal integer NOT NULL CHECK(ordinal>=0), byte_offset bigint NOT NULL CHECK(byte_offset>=0),
 plaintext_length bigint NOT NULL CHECK(plaintext_length>=0), content_digest text NOT NULL CHECK(content_digest ~ '^sha256:[0-9a-f]{64}$'),
 PRIMARY KEY(tenant_scope,artifact_id,ordinal), FOREIGN KEY(tenant_scope,artifact_id) REFERENCES __SCHEMA__.artifact_manifests(tenant_scope,artifact_id) ON DELETE RESTRICT
);
CREATE TABLE __SCHEMA__.artifact_references(
 tenant_scope text NOT NULL, reference_id text NOT NULL, artifact_id text NOT NULL, task_id text NOT NULL, context_id text NOT NULL,
 owner_account_id text NOT NULL, task_revision bigint NOT NULL CHECK(task_revision>0), state text NOT NULL CHECK(state IN ('restoring','active','released','tombstoned')),
 retain_until bigint NOT NULL, created_at bigint NOT NULL, released_at bigint, PRIMARY KEY(tenant_scope,reference_id), UNIQUE(tenant_scope,task_id,artifact_id),
 FOREIGN KEY(tenant_scope,artifact_id,task_id,context_id,owner_account_id)
  REFERENCES __SCHEMA__.artifact_manifests(tenant_scope,artifact_id,task_id,context_id,owner_account_id) ON DELETE RESTRICT,
 FOREIGN KEY(tenant_scope,task_id,context_id,owner_account_id) REFERENCES __SCHEMA__.tasks(tenant_scope,task_id,context_id,owner_account_id) ON DELETE RESTRICT
);
CREATE INDEX artifact_references_resolve ON __SCHEMA__.artifact_references(tenant_scope,task_id,artifact_id,owner_account_id) WHERE state='active';
CREATE INDEX artifact_references_gc ON __SCHEMA__.artifact_references(tenant_scope,state,retain_until,reference_id);

CREATE TABLE __SCHEMA__.provenance_edges(
 tenant_scope text NOT NULL, child_artifact_id text NOT NULL, ordinal integer NOT NULL CHECK(ordinal BETWEEN 0 AND 31),
 parent_artifact_id text NOT NULL, relation text NOT NULL CHECK(relation IN ('transformation','summary','extraction','redaction')),
 PRIMARY KEY(tenant_scope,child_artifact_id,ordinal), UNIQUE(tenant_scope,child_artifact_id,parent_artifact_id),
 CHECK(child_artifact_id<>parent_artifact_id),
 FOREIGN KEY(tenant_scope,child_artifact_id) REFERENCES __SCHEMA__.artifact_manifests(tenant_scope,artifact_id) ON DELETE RESTRICT,
 FOREIGN KEY(tenant_scope,parent_artifact_id) REFERENCES __SCHEMA__.artifact_manifests(tenant_scope,artifact_id) ON DELETE RESTRICT
);
CREATE INDEX provenance_edges_parent ON __SCHEMA__.provenance_edges(tenant_scope,parent_artifact_id,child_artifact_id);

CREATE TABLE __SCHEMA__.upload_intents(
 tenant_scope text NOT NULL, upload_id text NOT NULL, artifact_id text NOT NULL, object_id text NOT NULL, state text NOT NULL CHECK(state IN ('staged','committed','promoting','available','failed','orphaned')),
 stage_locator text NOT NULL, final_locator text NOT NULL, ciphertext_digest text NOT NULL CHECK(ciphertext_digest ~ '^sha256:[0-9a-f]{64}$'), ciphertext_length bigint NOT NULL CHECK(ciphertext_length>=16), last_error_digest text,
 lease_epoch bigint NOT NULL CHECK(lease_epoch>0), lease_token text, lease_until bigint, attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 1000), created_at bigint NOT NULL, updated_at bigint NOT NULL,
 PRIMARY KEY(tenant_scope,upload_id), UNIQUE(tenant_scope,artifact_id), FOREIGN KEY(tenant_scope,object_id) REFERENCES __SCHEMA__.content_objects(tenant_scope,object_id) ON DELETE RESTRICT
);
CREATE INDEX upload_intents_due ON __SCHEMA__.upload_intents(updated_at,tenant_scope,upload_id) WHERE state IN ('committed','promoting');
CREATE FUNCTION __SCHEMA__.claim_artifact_upload(p_owner text,p_token text,p_duration bigint,p_batch integer)
RETURNS TABLE(tenant_scope text,upload_id text,artifact_id text,object_id text,stage_locator text,final_locator text,ciphertext_digest text,ciphertext_length bigint,lease_token text,lease_epoch bigint,lease_until bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $fn$
DECLARE n bigint;
BEGIN
 PERFORM set_config('smesh.internal_global','claim-v1',true);
 IF p_owner IS NULL OR p_owner='' OR p_token IS NULL OR p_token='' OR p_duration<10 OR p_duration>300000 OR p_batch<1 OR p_batch>1000 THEN RAISE EXCEPTION 'invalid artifact lease'; END IF;
 n := __SCHEMA__.db_millis();
 -- Each call terminalizes at most p_batch rows and separately claims at most p_batch rows:
 -- no more than 2*p_batch upload-intent rows are mutated, and concurrent callers lock disjoint rows.
 RETURN QUERY
 WITH terminal_ranked AS MATERIALIZED (
   SELECT u.tenant_scope,u.upload_id,row_number() OVER(PARTITION BY u.tenant_scope ORDER BY u.updated_at,u.upload_id) AS terminal_turn
   FROM __SCHEMA__.upload_intents u
   WHERE u.attempts>=1000 AND (
    (u.state='committed' AND u.lease_token IS NULL AND u.lease_until IS NULL)
    OR (u.state='promoting' AND u.lease_token IS NOT NULL AND u.lease_until IS NOT NULL AND u.lease_until<=n)
   )
 ), terminal_due AS MATERIALIZED (
   SELECT u.tenant_scope,u.upload_id FROM __SCHEMA__.upload_intents u JOIN terminal_ranked r USING(tenant_scope,upload_id)
   ORDER BY r.terminal_turn,u.updated_at,u.tenant_scope,u.upload_id FOR UPDATE OF u SKIP LOCKED LIMIT p_batch
 ), terminalized AS (
   UPDATE __SCHEMA__.upload_intents u SET state='failed',lease_token=NULL,lease_until=NULL,
    last_error_digest='sha256:'||encode(sha256(convert_to('artifact upload attempts exhausted','UTF8')),'hex'),updated_at=n
   FROM terminal_due d WHERE u.tenant_scope=d.tenant_scope AND u.upload_id=d.upload_id RETURNING u.tenant_scope
 ), ranked AS MATERIALIZED (
   SELECT u.tenant_scope,u.upload_id,row_number() OVER(PARTITION BY u.tenant_scope ORDER BY u.updated_at,u.upload_id) AS tenant_turn
   FROM __SCHEMA__.upload_intents u WHERE u.state IN ('committed','promoting') AND u.attempts<1000 AND (u.state='committed' OR u.lease_until<=n)
 ), due AS (
   SELECT u.tenant_scope,u.upload_id FROM __SCHEMA__.upload_intents u JOIN ranked r USING(tenant_scope,upload_id)
   ORDER BY r.tenant_turn,u.updated_at,u.tenant_scope,u.upload_id FOR UPDATE OF u SKIP LOCKED LIMIT p_batch
 ),
  changed AS (UPDATE __SCHEMA__.upload_intents u SET state='promoting',lease_epoch=u.lease_epoch+1,lease_token=p_token,lease_until=n+p_duration,attempts=u.attempts+1,updated_at=n FROM due d WHERE u.tenant_scope=d.tenant_scope AND u.upload_id=d.upload_id RETURNING u.*)
 SELECT c.tenant_scope,c.upload_id,c.artifact_id,c.object_id,c.stage_locator,c.final_locator,c.ciphertext_digest,c.ciphertext_length,c.lease_token,c.lease_epoch,c.lease_until FROM changed c
 WHERE (SELECT count(*) FROM terminalized)>=0;
END $fn$;
REVOKE ALL ON FUNCTION __SCHEMA__.claim_artifact_upload(text,text,bigint,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION __SCHEMA__.claim_artifact_upload(text,text,bigint,integer) TO __ROLE__;

CREATE TABLE __SCHEMA__.artifact_read_leases(
 tenant_scope text NOT NULL, lease_id text NOT NULL, artifact_id text NOT NULL, lease_epoch bigint NOT NULL CHECK(lease_epoch>0), lease_token text NOT NULL,
 owner_digest text NOT NULL, state text NOT NULL CHECK(state IN ('active','released','expired')), lease_until bigint NOT NULL, created_at bigint NOT NULL,
 PRIMARY KEY(tenant_scope,lease_id), FOREIGN KEY(tenant_scope,artifact_id) REFERENCES __SCHEMA__.artifact_manifests(tenant_scope,artifact_id) ON DELETE RESTRICT
);
CREATE INDEX artifact_read_leases_active ON __SCHEMA__.artifact_read_leases(tenant_scope,artifact_id,state,lease_until);

CREATE TABLE __SCHEMA__.artifact_backup_leases(
 tenant_scope text NOT NULL, lease_id text NOT NULL, object_id text NOT NULL, lease_owner text NOT NULL,
 lease_epoch bigint NOT NULL CHECK(lease_epoch>0), lease_token text NOT NULL,
 state text NOT NULL CHECK(state IN ('active','released','expired')),
 lease_until bigint NOT NULL, created_at bigint NOT NULL,
 PRIMARY KEY(tenant_scope,lease_id),
 FOREIGN KEY(tenant_scope,object_id) REFERENCES __SCHEMA__.content_objects(tenant_scope,object_id) ON DELETE RESTRICT
);
CREATE INDEX artifact_backup_leases_active ON __SCHEMA__.artifact_backup_leases(tenant_scope,object_id,state,lease_until);

CREATE TABLE __SCHEMA__.artifact_orphan_audits(
 locator_digest text PRIMARY KEY CHECK(locator_digest ~ '^sha256:[0-9a-f]{64}$'),
 refunded_bytes bigint NOT NULL CHECK(refunded_bytes>=0), deleted_at bigint NOT NULL
);
GRANT SELECT,INSERT ON __SCHEMA__.artifact_orphan_audits TO __ROLE__;
-- Filesystem unlink is outside PostgreSQL atomicity. Persist a fenced owner
-- before unlink so restart can complete exactly one refund and audit.
CREATE TABLE __SCHEMA__.artifact_orphan_candidates(
 stage_locator text PRIMARY KEY CHECK(stage_locator ~ '^stage/[A-Za-z0-9_-]{32}[.]tmp$'),
 locator_digest text NOT NULL UNIQUE CHECK(locator_digest ~ '^sha256:[0-9a-f]{64}$'),
 ciphertext_length bigint NOT NULL CHECK(ciphertext_length>=0),
 state text NOT NULL CHECK(state IN ('claimed','finalized')),
 claim_token text NOT NULL CHECK(claim_token ~ '^sha256:[0-9a-f]{64}$'),
 claim_generation bigint NOT NULL CHECK(claim_generation>0), claim_until bigint NOT NULL,
 claimed_at bigint NOT NULL, finalized_at bigint
);
CREATE INDEX artifact_orphan_candidates_due ON __SCHEMA__.artifact_orphan_candidates(state,claim_until,stage_locator);
GRANT SELECT,INSERT,UPDATE ON __SCHEMA__.artifact_orphan_candidates TO __ROLE__;
CREATE FUNCTION __SCHEMA__.artifact_stage_locator_live(p_locator text) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $fn$
BEGIN
 PERFORM set_config('smesh.internal_global','claim-v1',true);
 RETURN EXISTS(SELECT 1 FROM __SCHEMA__.upload_intents WHERE stage_locator=p_locator AND state IN ('committed','promoting','available'));
END $fn$;
REVOKE ALL ON FUNCTION __SCHEMA__.artifact_stage_locator_live(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION __SCHEMA__.artifact_stage_locator_live(text) TO __ROLE__;

CREATE TABLE __SCHEMA__.artifact_retention_holds(
 tenant_scope text NOT NULL, hold_id text NOT NULL, artifact_id text NOT NULL, actor_digest text NOT NULL, reason_digest text NOT NULL,
 state text NOT NULL CHECK(state IN ('active','released')), created_at bigint NOT NULL, expires_at bigint, released_at bigint,
 PRIMARY KEY(tenant_scope,hold_id), FOREIGN KEY(tenant_scope,artifact_id) REFERENCES __SCHEMA__.artifact_manifests(tenant_scope,artifact_id) ON DELETE RESTRICT
);
CREATE INDEX artifact_retention_holds_active ON __SCHEMA__.artifact_retention_holds(tenant_scope,artifact_id,state,expires_at);

CREATE TABLE __SCHEMA__.artifact_gc_jobs(
 tenant_scope text NOT NULL, job_id text NOT NULL, object_id text NOT NULL, tombstone_generation bigint NOT NULL CHECK(tombstone_generation>0),
 state text NOT NULL CHECK(state IN ('pending','leased','complete','dead')), lease_epoch bigint NOT NULL CHECK(lease_epoch>0), lease_owner text, lease_token text,
 available_at bigint NOT NULL, lease_until bigint, attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 1000), last_error_digest text,
 PRIMARY KEY(tenant_scope,job_id), FOREIGN KEY(tenant_scope,object_id) REFERENCES __SCHEMA__.content_objects(tenant_scope,object_id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX artifact_gc_jobs_one_active ON __SCHEMA__.artifact_gc_jobs(tenant_scope,object_id,tombstone_generation) WHERE state IN ('pending','leased');
CREATE INDEX artifact_gc_jobs_due ON __SCHEMA__.artifact_gc_jobs(state,available_at,lease_until,tenant_scope,job_id);

CREATE FUNCTION __SCHEMA__.claim_artifact_gc(p_owner text,p_token text,p_duration bigint,p_batch integer)
RETURNS TABLE(tenant_scope text,job_id text,object_id text,backend_locator text,tombstone_generation bigint,lease_token text,lease_epoch bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $fn$
DECLARE n bigint;
BEGIN
 PERFORM set_config('smesh.internal_global','claim-v1',true);
 IF p_owner IS NULL OR p_owner='' OR p_token IS NULL OR p_token='' OR p_duration<10 OR p_duration>300000 OR p_batch<1 OR p_batch>1000 THEN RAISE EXCEPTION 'invalid artifact gc lease'; END IF;
 n := __SCHEMA__.db_millis();
 -- A call terminalizes <=p_batch jobs, tombstones <=p_batch objects (and creates the
 -- corresponding <=p_batch jobs), then claims <=p_batch jobs. Thus job-state mutations
 -- are <=2*p_batch and all authority-row mutations are explicitly bounded by 4*p_batch.
 WITH terminal_ranked AS MATERIALIZED (
   SELECT j.tenant_scope,j.job_id,row_number() OVER(PARTITION BY j.tenant_scope ORDER BY j.available_at,j.job_id) AS terminal_turn
   FROM __SCHEMA__.artifact_gc_jobs j JOIN __SCHEMA__.content_objects o USING(tenant_scope,object_id)
   WHERE (j.attempts>=1000 OR o.state='quarantined') AND (
    (j.state='pending' AND j.lease_owner IS NULL AND j.lease_token IS NULL AND j.lease_until IS NULL)
    OR (j.state='leased' AND j.lease_owner IS NOT NULL AND j.lease_token IS NOT NULL
        AND j.lease_until IS NOT NULL AND j.lease_until<=n)
   )
 ), terminal_due AS MATERIALIZED (
   SELECT j.tenant_scope,j.job_id FROM __SCHEMA__.artifact_gc_jobs j JOIN terminal_ranked r USING(tenant_scope,job_id)
   ORDER BY r.terminal_turn,j.available_at,j.tenant_scope,j.job_id FOR UPDATE OF j SKIP LOCKED LIMIT p_batch
 ), terminalized AS (
   UPDATE __SCHEMA__.artifact_gc_jobs j SET state='dead',lease_owner=NULL,lease_token=NULL,lease_until=NULL,
    last_error_digest='sha256:'||encode(sha256(convert_to(CASE WHEN o.state='quarantined' THEN 'artifact gc object quarantined' ELSE 'artifact gc attempts exhausted' END,'UTF8')),'hex')
   FROM terminal_due d, __SCHEMA__.content_objects o WHERE j.tenant_scope=d.tenant_scope AND j.job_id=d.job_id
    AND o.tenant_scope=j.tenant_scope AND o.object_id=j.object_id RETURNING j.tenant_scope
 ), candidate_ranked AS MATERIALIZED (
   SELECT o.tenant_scope,o.object_id,o.retain_until,row_number() OVER(PARTITION BY o.tenant_scope ORDER BY o.retain_until,o.object_id) AS tenant_turn
   FROM __SCHEMA__.content_objects o
   WHERE o.state='available' AND o.reference_count=0 AND o.retain_until<=n
   AND NOT EXISTS(SELECT 1 FROM __SCHEMA__.artifact_references r WHERE r.tenant_scope=o.tenant_scope AND r.artifact_id IN (SELECT m.artifact_id FROM __SCHEMA__.artifact_manifests m WHERE m.tenant_scope=o.tenant_scope AND m.object_id=o.object_id) AND r.state='active')
   AND NOT EXISTS(SELECT 1 FROM __SCHEMA__.artifact_retention_holds h JOIN __SCHEMA__.artifact_manifests m USING(tenant_scope,artifact_id) WHERE m.tenant_scope=o.tenant_scope AND m.object_id=o.object_id AND h.state='active' AND (h.expires_at IS NULL OR h.expires_at>n))
   AND NOT EXISTS(SELECT 1 FROM __SCHEMA__.artifact_read_leases l JOIN __SCHEMA__.artifact_manifests m USING(tenant_scope,artifact_id) WHERE m.tenant_scope=o.tenant_scope AND m.object_id=o.object_id AND l.state='active' AND l.lease_until>n)
   AND NOT EXISTS(SELECT 1 FROM __SCHEMA__.artifact_backup_leases b WHERE b.tenant_scope=o.tenant_scope AND b.object_id=o.object_id AND b.state='active' AND b.lease_until>n)
 ), candidates AS (
   SELECT o.tenant_scope,o.object_id FROM __SCHEMA__.content_objects o JOIN candidate_ranked r USING(tenant_scope,object_id)
   ORDER BY r.tenant_turn,o.retain_until,o.tenant_scope,o.object_id FOR UPDATE OF o SKIP LOCKED LIMIT p_batch
 ), tombstoned AS (
   UPDATE __SCHEMA__.content_objects o SET state='tombstoned',tombstone_generation=o.tombstone_generation+1
   FROM candidates c WHERE o.tenant_scope=c.tenant_scope AND o.object_id=c.object_id AND o.state='available'
   RETURNING o.tenant_scope,o.object_id,o.tombstone_generation
 )
 INSERT INTO __SCHEMA__.artifact_gc_jobs(tenant_scope,job_id,object_id,tombstone_generation,state,lease_epoch,available_at,attempts)
 SELECT t.tenant_scope,'gc-'||encode(sha256(convert_to(t.tenant_scope||E'\\000'||t.object_id||E'\\000'||t.tombstone_generation::text,'UTF8')),'hex'),t.object_id,t.tombstone_generation,'pending',1,n,0 FROM tombstoned t WHERE (SELECT count(*) FROM terminalized)>=0 ON CONFLICT DO NOTHING;
 RETURN QUERY WITH ranked AS MATERIALIZED (
   SELECT j.tenant_scope,j.job_id,j.available_at,row_number() OVER(PARTITION BY j.tenant_scope ORDER BY j.available_at,j.job_id) AS tenant_turn
   FROM __SCHEMA__.artifact_gc_jobs j JOIN __SCHEMA__.content_objects o USING(tenant_scope,object_id)
  WHERE j.state IN ('pending','leased') AND j.attempts<1000 AND o.state IN ('tombstoned','deleting') AND o.tombstone_generation=j.tombstone_generation AND j.available_at<=n AND (j.state='pending' OR j.lease_until<=n)
 ), due AS (
   SELECT j.tenant_scope,j.job_id FROM __SCHEMA__.artifact_gc_jobs j JOIN ranked r USING(tenant_scope,job_id)
   ORDER BY r.tenant_turn,j.available_at,j.tenant_scope,j.job_id FOR UPDATE OF j SKIP LOCKED LIMIT p_batch
 ), changed AS (
   UPDATE __SCHEMA__.artifact_gc_jobs j SET state='leased',lease_owner=p_owner,lease_token=p_token,lease_until=n+p_duration,lease_epoch=j.lease_epoch+1,attempts=j.attempts+1
   FROM due d WHERE j.tenant_scope=d.tenant_scope AND j.job_id=d.job_id RETURNING j.*
 ), objects AS (
   UPDATE __SCHEMA__.content_objects o SET state='deleting' FROM changed c WHERE o.tenant_scope=c.tenant_scope AND o.object_id=c.object_id AND o.tombstone_generation=c.tombstone_generation AND o.state IN ('tombstoned','deleting') RETURNING o.tenant_scope,o.object_id,o.backend_locator,o.tombstone_generation
 ) SELECT c.tenant_scope,c.job_id,c.object_id,o.backend_locator,c.tombstone_generation,c.lease_token,c.lease_epoch FROM changed c JOIN objects o USING(tenant_scope,object_id,tombstone_generation);
END $fn$;
REVOKE ALL ON FUNCTION __SCHEMA__.claim_artifact_gc(text,text,bigint,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION __SCHEMA__.claim_artifact_gc(text,text,bigint,integer) TO __ROLE__;

CREATE TABLE __SCHEMA__.artifact_tombstones(
 tenant_scope text NOT NULL, object_id text NOT NULL, tombstone_generation bigint NOT NULL, reason_digest text NOT NULL,
 locator_digest text NOT NULL, deletion_receipt_digest text, tombstoned_at bigint NOT NULL, deleted_at bigint,
 PRIMARY KEY(tenant_scope,object_id,tombstone_generation)
);

-- Phase-B operator journals. Revision 5 only creates transactional metadata;
-- migration, backup copy, restore verification and re-encryption blob I/O are
-- explicitly performed by bounded fenced operator jobs after this transaction.
CREATE TABLE __SCHEMA__.artifact_migration_plans(
 tenant_scope text NOT NULL, plan_id text NOT NULL, source_schema_version bigint NOT NULL CHECK(source_schema_version IN (4,5)),
 source_identity text NOT NULL CHECK(source_identity ~ '^sha256:[0-9a-f]{64}$'), plan_digest text NOT NULL CHECK(plan_digest ~ '^sha256:[0-9a-f]{64}$'),
 policy_id text NOT NULL, policy_revision bigint NOT NULL CHECK(policy_revision>0), policy_digest text NOT NULL CHECK(policy_digest ~ '^sha256:[0-9a-f]{64}$'),
 actor_digest text NOT NULL CHECK(actor_digest ~ '^sha256:[0-9a-f]{64}$'), reason_digest text NOT NULL CHECK(reason_digest ~ '^sha256:[0-9a-f]{64}$'),
 batch_size integer NOT NULL CHECK(batch_size BETWEEN 1 AND 1000), state text NOT NULL CHECK(state IN ('pending','leased','processing','completed','failed')),
 checkpoint_relation text, checkpoint_row_id text, checkpoint_json_path text, checkpoint_artifact text,
 checkpoint_input_seal text CHECK(checkpoint_input_seal IS NULL OR checkpoint_input_seal ~ '^sha256:[0-9a-f]{64}$'),
 checkpoint_output_seal text CHECK(checkpoint_output_seal IS NULL OR checkpoint_output_seal ~ '^sha256:[0-9a-f]{64}$'),
 completion_seal text CHECK(completion_seal IS NULL OR completion_seal ~ '^sha256:[0-9a-f]{64}$'),
 lease_owner text, lease_token text, lease_epoch bigint NOT NULL DEFAULT 0 CHECK(lease_epoch>=0), lease_until bigint,
 migrated_artifacts bigint NOT NULL DEFAULT 0 CHECK(migrated_artifacts>=0),
 migrated_rows bigint NOT NULL DEFAULT 0 CHECK(migrated_rows>=0),
 migrated_bytes bigint NOT NULL DEFAULT 0 CHECK(migrated_bytes>=0),
 full_rescan_digest text CHECK(full_rescan_digest IS NULL OR full_rescan_digest ~ '^sha256:[0-9a-f]{64}$'),
 created_at bigint NOT NULL, completed_at bigint,
 PRIMARY KEY(tenant_scope,plan_id),
 CHECK((state IN ('leased','processing'))=(lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_until IS NOT NULL)),
 CHECK((state='completed')=(completed_at IS NOT NULL AND completion_seal IS NOT NULL))
);
CREATE UNIQUE INDEX artifact_migration_one_active ON __SCHEMA__.artifact_migration_plans((1)) WHERE state IN ('leased','processing');
CREATE INDEX artifact_migration_checkpoint ON __SCHEMA__.artifact_migration_plans(state,checkpoint_relation,checkpoint_row_id,checkpoint_json_path,checkpoint_artifact);

CREATE TABLE __SCHEMA__.artifact_backup_jobs(
 tenant_scope text NOT NULL, backup_id text NOT NULL, store_id text NOT NULL, snapshot_id text NOT NULL,
 policy_id text NOT NULL, policy_revision bigint NOT NULL CHECK(policy_revision>0), policy_digest text NOT NULL CHECK(policy_digest ~ '^sha256:[0-9a-f]{64}$'),
 actor_digest text NOT NULL, reason_digest text NOT NULL, state text NOT NULL CHECK(state IN ('leased','inventory','sealed','failed')),
 lease_owner text NOT NULL, lease_token text NOT NULL, lease_epoch bigint NOT NULL CHECK(lease_epoch>0), lease_until bigint NOT NULL,
 candidate_digest text CHECK(candidate_digest IS NULL OR candidate_digest ~ '^sha256:[0-9a-f]{64}$'),
 candidate_count bigint NOT NULL DEFAULT 0 CHECK(candidate_count>=0),
 inventory_digest text, signature text, created_at bigint NOT NULL, sealed_at bigint, PRIMARY KEY(tenant_scope,backup_id)
);
CREATE UNIQUE INDEX artifact_backup_jobs_active ON __SCHEMA__.artifact_backup_jobs(tenant_scope) WHERE state IN ('leased','inventory');
CREATE TABLE __SCHEMA__.artifact_backup_inventory(
 tenant_scope text NOT NULL, backup_id text NOT NULL, ordinal bigint NOT NULL CHECK(ordinal>=0),
 artifact_id text NOT NULL, object_id text NOT NULL, manifest_digest text NOT NULL, content_digest text NOT NULL,
 ciphertext_digest text NOT NULL, ciphertext_length bigint NOT NULL CHECK(ciphertext_length>=16), key_generation text NOT NULL,
 storage_locator text NOT NULL, canonical_json text NOT NULL CHECK(__SCHEMA__.json_text_valid(canonical_json)),
 PRIMARY KEY(tenant_scope,backup_id,ordinal), UNIQUE(tenant_scope,backup_id,object_id,artifact_id),
 FOREIGN KEY(tenant_scope,backup_id) REFERENCES __SCHEMA__.artifact_backup_jobs(tenant_scope,backup_id) ON DELETE RESTRICT
);
CREATE TABLE __SCHEMA__.artifact_backup_key_dependencies(
 tenant_scope text NOT NULL, backup_id text NOT NULL, encryption_domain text NOT NULL,
 key_generation text NOT NULL, required_until bigint NOT NULL, released_at bigint,
 PRIMARY KEY(tenant_scope,backup_id,encryption_domain,key_generation),
 FOREIGN KEY(tenant_scope,backup_id) REFERENCES __SCHEMA__.artifact_backup_jobs(tenant_scope,backup_id) ON DELETE RESTRICT
);

-- Committed DB-time pins freeze the exact physical and logical snapshot while
-- filesystem copy is in progress. GC observes the same rows before copy starts.
CREATE FUNCTION __SCHEMA__.reject_pinned_artifact_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE wanted_tenant text:=CASE WHEN TG_OP='DELETE' THEN OLD.tenant_scope ELSE NEW.tenant_scope END;
        wanted_object text:=CASE WHEN TG_OP='DELETE' THEN OLD.object_id ELSE NEW.object_id END;
BEGIN
 IF EXISTS(SELECT 1 FROM __SCHEMA__.artifact_backup_leases b
           WHERE b.tenant_scope=wanted_tenant AND b.object_id=wanted_object
             AND b.state='active' AND b.lease_until>__SCHEMA__.db_millis()) THEN
   IF TG_OP='DELETE' OR to_jsonb(OLD)<>to_jsonb(NEW) THEN
     RAISE EXCEPTION 'artifact object is pinned by committed backup';
   END IF;
 END IF;
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END $fn$;
CREATE TRIGGER content_objects_backup_pin_barrier BEFORE UPDATE OR DELETE ON __SCHEMA__.content_objects
 FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_pinned_artifact_mutation();

CREATE FUNCTION __SCHEMA__.reject_pinned_manifest_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE wanted_tenant text:=CASE WHEN TG_OP='DELETE' THEN OLD.tenant_scope ELSE NEW.tenant_scope END;
        wanted_object text:=CASE WHEN TG_OP='DELETE' THEN OLD.object_id ELSE NEW.object_id END;
BEGIN
 IF EXISTS(SELECT 1 FROM __SCHEMA__.artifact_backup_leases b
           WHERE b.tenant_scope=wanted_tenant AND b.object_id=wanted_object
             AND b.state='active' AND b.lease_until>__SCHEMA__.db_millis()) THEN
   RAISE EXCEPTION 'artifact manifest is pinned by committed backup';
 END IF;
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END $fn$;
CREATE TRIGGER artifact_manifests_backup_pin_barrier BEFORE UPDATE OR DELETE ON __SCHEMA__.artifact_manifests
 FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_pinned_manifest_mutation();

CREATE TABLE __SCHEMA__.artifact_restore_jobs(
 tenant_scope text NOT NULL, restore_id text NOT NULL, source_store_id text NOT NULL, restore_store_id text NOT NULL,
 backup_id text NOT NULL, inventory_digest text NOT NULL, policy_digest text NOT NULL,
 state text NOT NULL CHECK(state IN ('restoring','verified','enabled','failed')), actor_digest text NOT NULL, reason_digest text NOT NULL,
 lease_owner text NOT NULL, lease_token text NOT NULL, lease_epoch bigint NOT NULL CHECK(lease_epoch>0), lease_until bigint NOT NULL,
 expected_entries bigint NOT NULL CHECK(expected_entries>=0), imported_entries bigint NOT NULL DEFAULT 0 CHECK(imported_entries>=0),
 completion_seal text CHECK(completion_seal IS NULL OR completion_seal ~ '^sha256:[0-9a-f]{64}$'),
 created_at bigint NOT NULL, verified_at bigint, enabled_at bigint, PRIMARY KEY(tenant_scope,restore_id),
 CHECK(source_store_id<>restore_store_id), CHECK((state='enabled')=(enabled_at IS NOT NULL))
);
CREATE UNIQUE INDEX artifact_restore_one_enabled_identity ON __SCHEMA__.artifact_restore_jobs(restore_store_id) WHERE state='enabled';
CREATE FUNCTION __SCHEMA__.artifact_restore_incomplete() RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $fn$
BEGIN
 PERFORM set_config('smesh.internal_global','claim-v1',true);
 RETURN EXISTS(SELECT 1 FROM __SCHEMA__.artifact_restore_jobs WHERE state IN ('restoring','verified'));
END $fn$;
REVOKE ALL ON FUNCTION __SCHEMA__.artifact_restore_incomplete() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION __SCHEMA__.artifact_restore_incomplete() TO __ROLE__;

CREATE TABLE __SCHEMA__.artifact_key_rotation_plans(
 tenant_scope text NOT NULL, rotation_id text NOT NULL, encryption_domain text NOT NULL,
 old_generation text NOT NULL, new_generation text NOT NULL, actor_digest text NOT NULL, reason_digest text NOT NULL,
 batch_size integer NOT NULL CHECK(batch_size BETWEEN 1 AND 1000), state text NOT NULL CHECK(state IN ('pending','active','draining','completed','failed')),
 created_at bigint NOT NULL, completed_at bigint, PRIMARY KEY(tenant_scope,rotation_id),
 UNIQUE(tenant_scope,encryption_domain,new_generation), CHECK(old_generation<>new_generation)
);
CREATE TABLE __SCHEMA__.artifact_reencryption_jobs(
 tenant_scope text NOT NULL, job_id text NOT NULL, rotation_id text NOT NULL, object_id text NOT NULL,
 old_generation text NOT NULL, new_generation text NOT NULL, old_locator text NOT NULL, new_locator text, new_stage_locator text,
 new_nonce bytea, new_ciphertext_digest text, new_ciphertext_length bigint, last_error_digest text,
 new_aad_seal text CHECK(new_aad_seal IS NULL OR new_aad_seal ~ '^sha256:[0-9a-f]{64}$'),
 state text NOT NULL CHECK(state IN ('pending','leased','staged','promoted','swapped','cleanup','completed','failed')),
 lease_owner text, lease_token text, lease_epoch bigint NOT NULL DEFAULT 1 CHECK(lease_epoch>0), lease_until bigint,
 rollback_until bigint, attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 1000), created_at bigint NOT NULL, updated_at bigint NOT NULL,
 PRIMARY KEY(tenant_scope,job_id), UNIQUE(tenant_scope,rotation_id,object_id),
 FOREIGN KEY(tenant_scope,rotation_id) REFERENCES __SCHEMA__.artifact_key_rotation_plans(tenant_scope,rotation_id) ON DELETE RESTRICT,
 FOREIGN KEY(tenant_scope,object_id) REFERENCES __SCHEMA__.content_objects(tenant_scope,object_id) ON DELETE RESTRICT
);
CREATE INDEX artifact_reencryption_due ON __SCHEMA__.artifact_reencryption_jobs(state,updated_at,tenant_scope,job_id) WHERE state IN ('pending','leased','staged','promoted','swapped','cleanup');
CREATE FUNCTION __SCHEMA__.claim_artifact_reencryption(p_rotation_id text,p_old_generation text,p_new_generation text,p_owner text,p_token text,p_duration bigint,p_batch integer)
RETURNS TABLE(tenant_scope text,job_id text,rotation_id text,object_id text,old_generation text,new_generation text,old_locator text,lease_token text,lease_epoch bigint,job_state text,new_locator text,new_stage_locator text,new_nonce bytea,new_ciphertext_digest text,new_ciphertext_length bigint,new_aad_seal text,rollback_until bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $fn$
DECLARE n bigint;
BEGIN
 PERFORM set_config('smesh.internal_global','claim-v1',true);
 IF p_rotation_id IS NULL OR p_rotation_id='' OR p_old_generation IS NULL OR p_old_generation='' OR p_new_generation IS NULL OR p_new_generation='' OR p_old_generation=p_new_generation OR p_owner IS NULL OR p_owner='' OR p_token IS NULL OR p_token='' OR p_duration<10 OR p_duration>300000 OR p_batch<1 OR p_batch>1000 THEN RAISE EXCEPTION 'invalid artifact reencryption lease'; END IF;
 n:=__SCHEMA__.db_millis();
 -- Each call terminalizes at most p_batch rows and separately claims at most p_batch rows:
 -- no more than 2*p_batch reencryption-job rows are mutated, with tenant-fair disjoint locks.
 RETURN QUERY WITH terminal_ranked AS MATERIALIZED (
  SELECT j.tenant_scope,j.job_id,row_number() OVER(PARTITION BY j.tenant_scope ORDER BY j.updated_at,j.job_id) AS terminal_turn
  FROM __SCHEMA__.artifact_reencryption_jobs j
  WHERE j.rotation_id=p_rotation_id AND j.old_generation=p_old_generation AND j.new_generation=p_new_generation
   AND j.attempts>=1000 AND (
    (j.state='pending' AND j.lease_owner IS NULL AND j.lease_token IS NULL AND j.lease_until IS NULL)
    OR (j.state='leased' AND j.lease_owner IS NOT NULL AND j.lease_token IS NOT NULL
        AND j.lease_until IS NOT NULL AND j.lease_until<=n)
    OR (j.state IN ('staged','promoted','swapped','cleanup')
        AND (j.lease_until IS NULL OR j.lease_until<=n)
        AND ((j.lease_owner IS NULL AND j.lease_token IS NULL AND j.lease_until IS NULL)
             OR (j.lease_owner IS NOT NULL AND j.lease_token IS NOT NULL AND j.lease_until IS NOT NULL)))
   )
 ), terminal_due AS MATERIALIZED (
  SELECT j.tenant_scope,j.job_id FROM __SCHEMA__.artifact_reencryption_jobs j JOIN terminal_ranked r USING(tenant_scope,job_id)
  ORDER BY r.terminal_turn,j.updated_at,j.tenant_scope,j.job_id FOR UPDATE OF j SKIP LOCKED LIMIT p_batch
 ), terminalized AS (
  UPDATE __SCHEMA__.artifact_reencryption_jobs j SET state='failed',lease_owner=NULL,lease_token=NULL,lease_until=NULL,
   last_error_digest='sha256:'||encode(sha256(convert_to('artifact reencryption attempts exhausted','UTF8')),'hex'),updated_at=n
  FROM terminal_due d WHERE j.tenant_scope=d.tenant_scope AND j.job_id=d.job_id RETURNING j.tenant_scope
 ), ranked AS MATERIALIZED (
  SELECT j.tenant_scope,j.job_id,row_number() OVER(PARTITION BY j.tenant_scope ORDER BY j.updated_at,j.job_id) AS tenant_turn FROM __SCHEMA__.artifact_reencryption_jobs j
  JOIN __SCHEMA__.artifact_key_rotation_plans p ON p.tenant_scope=j.tenant_scope AND p.rotation_id=j.rotation_id
  WHERE j.rotation_id=p_rotation_id AND j.old_generation=p_old_generation AND j.new_generation=p_new_generation
   AND p.old_generation=p_old_generation AND p.new_generation=p_new_generation AND p.state='active'
   AND j.state IN ('pending','leased','staged','promoted','swapped','cleanup') AND j.attempts<1000
   AND (j.state='pending' OR j.lease_until IS NULL OR j.lease_until<=n)
 ), due AS (
  SELECT j.tenant_scope,j.job_id FROM __SCHEMA__.artifact_reencryption_jobs j JOIN ranked r USING(tenant_scope,job_id)
  ORDER BY r.tenant_turn,j.updated_at,j.tenant_scope,j.job_id FOR UPDATE OF j SKIP LOCKED LIMIT p_batch
 ), changed AS (
  UPDATE __SCHEMA__.artifact_reencryption_jobs j SET state=CASE WHEN j.state IN ('pending','leased') THEN 'leased' ELSE j.state END,lease_owner=p_owner,lease_token=p_token,
   lease_epoch=j.lease_epoch+1,lease_until=n+p_duration,attempts=j.attempts+1,updated_at=n
  FROM due d WHERE j.tenant_scope=d.tenant_scope AND j.job_id=d.job_id RETURNING j.*
 ) SELECT c.tenant_scope,c.job_id,c.rotation_id,c.object_id,c.old_generation,c.new_generation,c.old_locator,c.lease_token,c.lease_epoch,c.state,c.new_locator,c.new_stage_locator,c.new_nonce,c.new_ciphertext_digest,c.new_ciphertext_length,c.new_aad_seal,c.rollback_until FROM changed c
 WHERE (SELECT count(*) FROM terminalized)>=0;
END $fn$;
REVOKE ALL ON FUNCTION __SCHEMA__.claim_artifact_reencryption(text,text,text,text,text,bigint,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION __SCHEMA__.claim_artifact_reencryption(text,text,text,text,text,bigint,integer) TO __ROLE__;

-- Re-encryption stages are registered durable state too. Failed jobs are
-- intentionally excluded so the bounded orphan scanner can reclaim them.
CREATE OR REPLACE FUNCTION __SCHEMA__.artifact_stage_locator_live(p_locator text) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $fn$
BEGIN
 PERFORM set_config('smesh.internal_global','claim-v1',true);
 RETURN EXISTS(SELECT 1 FROM __SCHEMA__.upload_intents WHERE stage_locator=p_locator AND state IN ('committed','promoting','available'))
     OR EXISTS(SELECT 1 FROM __SCHEMA__.artifact_reencryption_jobs WHERE new_stage_locator=p_locator AND state IN ('staged','promoted','swapped','cleanup','completed'));
END $fn$;
REVOKE ALL ON FUNCTION __SCHEMA__.artifact_stage_locator_live(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION __SCHEMA__.artifact_stage_locator_live(text) TO __ROLE__;

CREATE FUNCTION __SCHEMA__.artifact_json_has_inline(p_json text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $fn$
 SELECT jsonb_path_exists(p_json::jsonb,
  '$.** ? (exists(@.artifactId) && exists(@.parts[*] ? (exists(@.text) || exists(@.raw) || exists(@.data))) && !exists(@.metadata.smeshArtifact.schema))')
$fn$;
REVOKE ALL ON FUNCTION __SCHEMA__.artifact_json_has_inline(text) FROM PUBLIC;

CREATE FUNCTION __SCHEMA__.artifact_inline_migration_required(p_plan_id text) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $fn$
DECLARE found_inline boolean;
BEGIN
 PERFORM set_config('smesh.internal_global','claim-v1',true);
 SELECT EXISTS(
  SELECT 1 FROM __SCHEMA__.tasks WHERE __SCHEMA__.artifact_json_has_inline(task_json)
  UNION ALL SELECT 1 FROM __SCHEMA__.task_events WHERE __SCHEMA__.artifact_json_has_inline(event_json)
  UNION ALL SELECT 1 FROM __SCHEMA__.idempotency_records WHERE __SCHEMA__.artifact_json_has_inline(admission_result_json) OR __SCHEMA__.artifact_json_has_inline(final_result_json) OR __SCHEMA__.artifact_json_has_inline(causative_request_json)
  UNION ALL SELECT 1 FROM __SCHEMA__.outbox WHERE __SCHEMA__.artifact_json_has_inline(payload_json)
  UNION ALL SELECT 1 FROM __SCHEMA__.receiver_inbox WHERE __SCHEMA__.artifact_json_has_inline(payload_json) OR __SCHEMA__.artifact_json_has_inline(termination_json)
  UNION ALL SELECT 1 FROM __SCHEMA__.receiver_frames WHERE __SCHEMA__.artifact_json_has_inline(frame_json)
  UNION ALL SELECT 1 FROM __SCHEMA__.stream_frames WHERE __SCHEMA__.artifact_json_has_inline(frame_json)
  UNION ALL SELECT 1 FROM __SCHEMA__.list_snapshot_entries WHERE __SCHEMA__.artifact_json_has_inline(task_json)
 ) INTO found_inline;
 RETURN CASE WHEN p_plan_id<>'' THEN
   p_plan_id<>'' AND NOT EXISTS(
    SELECT 1 FROM __SCHEMA__.artifact_migration_plans
    WHERE plan_id=p_plan_id AND state='completed'
      AND checkpoint_input_seal IS NOT NULL
      AND checkpoint_output_seal IS NOT NULL
      AND completion_seal IS NOT NULL)
  ELSE found_inline OR EXISTS(
    SELECT 1 FROM __SCHEMA__.artifact_migration_plans WHERE state<>'completed')
 END;
END $fn$;
REVOKE ALL ON FUNCTION __SCHEMA__.artifact_inline_migration_required(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION __SCHEMA__.artifact_inline_migration_required(text) TO __ROLE__;

-- The offline executor must see and rewrite every durable causal copy while
-- normal runtime sessions remain tenant-scoped. The setting is transaction
-- local and accepted only for the generated non-login migrator authority.
DO $do$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY['tasks','task_events','idempotency_records','outbox','receiver_inbox','receiver_frames','stream_transcripts','stream_frames','list_snapshots','list_snapshot_entries'] LOOP
 EXECUTE format('CREATE POLICY artifact_inline_migrator ON __SCHEMA__.%I TO %I USING (current_setting(''smesh.internal_global'',true)=''claim-v1'') WITH CHECK (current_setting(''smesh.internal_global'',true)=''claim-v1'')',t,'__MIGRATOR__');
END LOOP; END $do$;

CREATE TABLE __SCHEMA__.artifact_key_audits(
 tenant_scope text NOT NULL, audit_id text NOT NULL, encryption_domain text NOT NULL, key_generation text NOT NULL,
 action text NOT NULL CHECK(action IN ('activate','rotate','verify','retire')), actor_digest text NOT NULL, created_at bigint NOT NULL,
 PRIMARY KEY(tenant_scope,audit_id)
);
CREATE TABLE __SCHEMA__.artifact_corruption_audits(
 tenant_scope text NOT NULL, audit_id text NOT NULL, object_id text NOT NULL,
 artifact_id text NOT NULL, detection_digest text NOT NULL CHECK(detection_digest ~ '^sha256:[0-9a-f]{64}$'),
 detected_at bigint NOT NULL, PRIMARY KEY(tenant_scope,audit_id),
 UNIQUE(tenant_scope,object_id,detection_digest),
 FOREIGN KEY(tenant_scope,object_id) REFERENCES __SCHEMA__.content_objects(tenant_scope,object_id) ON DELETE RESTRICT
);
CREATE TRIGGER artifact_key_audits_no_update BEFORE UPDATE OR DELETE ON __SCHEMA__.artifact_key_audits FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_audit_mutation();
CREATE TRIGGER artifact_corruption_audits_no_update BEFORE UPDATE OR DELETE ON __SCHEMA__.artifact_corruption_audits FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_audit_mutation();
CREATE TRIGGER artifact_tombstones_no_update BEFORE UPDATE OR DELETE ON __SCHEMA__.artifact_tombstones FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_audit_mutation();
CREATE TRIGGER artifact_manifests_identity_immutable BEFORE UPDATE ON __SCHEMA__.artifact_manifests FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_identity_change('tenant_scope','artifact_id','manifest_digest','object_id','schema_version','canonical_json','owner_account_id','task_id','context_id','message_id','dispatch_id','media_type','plaintext_length','classification','encryption_domain','policy_id','policy_revision','policy_digest','created_at','retain_until');
CREATE TRIGGER content_objects_identity_immutable BEFORE UPDATE ON __SCHEMA__.content_objects FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_identity_change('tenant_scope','owner_account_id','object_id','content_digest','classification','encryption_domain','plaintext_length','created_at');

DO $do$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY['artifact_backup_inventory','artifact_backup_key_dependencies','artifact_backup_jobs','artifact_backup_leases','artifact_corruption_audits','artifact_key_audits','artifact_key_generations','artifact_key_rotation_plans','artifact_migration_plans','artifact_reencryption_jobs','artifact_restore_jobs','artifact_chunks','artifact_gc_jobs','artifact_manifests','artifact_read_leases','artifact_references','artifact_retention_holds','artifact_tombstones','content_objects','provenance_edges','upload_intents'] LOOP
 EXECUTE format('ALTER TABLE __SCHEMA__.%I ENABLE ROW LEVEL SECURITY',t); EXECUTE format('ALTER TABLE __SCHEMA__.%I FORCE ROW LEVEL SECURITY',t);
 EXECUTE format('CREATE POLICY tenant_isolation ON __SCHEMA__.%I TO __ROLE__ USING (tenant_scope=NULLIF(current_setting(''smesh.tenant_scope'',true),'''')) WITH CHECK (tenant_scope=NULLIF(current_setting(''smesh.tenant_scope'',true),''''))',t);
 EXECUTE format('CREATE POLICY artifact_authority_migrator ON __SCHEMA__.%I TO %I USING (current_setting(''smesh.internal_global'',true)=''claim-v1'') WITH CHECK (current_setting(''smesh.internal_global'',true)=''claim-v1'')',t,'__MIGRATOR__');
 EXECUTE format('GRANT SELECT,INSERT,UPDATE,DELETE ON __SCHEMA__.%I TO __ROLE__',t);
END LOOP; END $do$;

-- Revision-4 retained accounting remains the hot-path authority. Every artifact
-- metadata row participates transactionally, so quota overflow rolls the entire
-- publication, lease, hold, promotion, or deletion transaction back.
DO $do$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY['artifact_backup_inventory','artifact_backup_key_dependencies','artifact_backup_jobs','artifact_backup_leases','artifact_corruption_audits','artifact_key_audits','artifact_key_generations','artifact_key_rotation_plans','artifact_migration_plans','artifact_reencryption_jobs','artifact_restore_jobs','artifact_chunks','artifact_gc_jobs','artifact_manifests','artifact_read_leases','artifact_references','artifact_retention_holds','artifact_tombstones','content_objects','provenance_edges','upload_intents'] LOOP
 EXECUTE format('CREATE TRIGGER retained_authority_accounting AFTER INSERT OR UPDATE OR DELETE ON __SCHEMA__.%I FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.account_retained_authority_row()',t);
END LOOP; END $do$;

CREATE FUNCTION __SCHEMA__.account_artifact_payload_bytes() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE old_bytes bigint:=0; new_bytes bigint:=0; delta bigint; tenant text; account text; principal text;
        tenant_limit bigint; account_limit bigint; principal_limit bigint; current_bytes bigint; n bigint;
BEGIN
 IF TG_OP<>'INSERT' AND OLD.state<>'deleted' THEN old_bytes:=OLD.ciphertext_length; END IF;
 IF TG_OP<>'DELETE' AND NEW.state<>'deleted' THEN new_bytes:=NEW.ciphertext_length; END IF;
 delta:=new_bytes-old_bytes;
 IF delta=0 THEN RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END; END IF;
 tenant:=CASE WHEN TG_OP='DELETE' THEN OLD.tenant_scope ELSE NEW.tenant_scope END;
 account:=CASE WHEN TG_OP='DELETE' THEN OLD.owner_account_id ELSE NEW.owner_account_id END;
 principal:='account:'||account; n:=__SCHEMA__.db_millis();
 UPDATE __SCHEMA__.retained_authority_usage SET retained_bytes=retained_bytes+delta,updated_at=n WHERE tenant_scope=tenant AND scope_kind='tenant' AND scope_id=tenant AND retained_bytes+delta>=0 RETURNING retained_bytes INTO current_bytes;
 IF NOT FOUND THEN RAISE EXCEPTION 'artifact retained tenant counter corrupt'; END IF;
 SELECT (canonical_json::jsonb#>>'{limits,retainedAuthorityBytes,tenant}')::bigint,(canonical_json::jsonb#>>'{limits,retainedAuthorityBytes,account}')::bigint,(canonical_json::jsonb#>>'{limits,retainedAuthorityBytes,principal}')::bigint INTO tenant_limit,account_limit,principal_limit FROM __SCHEMA__.quota_policy_versions WHERE tenant_scope=tenant AND lifecycle='active';
 IF current_bytes>COALESCE(tenant_limit,67108864) THEN RAISE EXCEPTION 'retained authority tenant quota exceeded' USING ERRCODE='53000'; END IF;
 UPDATE __SCHEMA__.retained_authority_usage SET retained_bytes=retained_bytes+delta,updated_at=n WHERE tenant_scope=tenant AND scope_kind='account' AND scope_id=account AND retained_bytes+delta>=0 RETURNING retained_bytes INTO current_bytes;
 IF NOT FOUND THEN RAISE EXCEPTION 'artifact retained account counter corrupt'; END IF;
 IF current_bytes>COALESCE(account_limit,67108864) THEN RAISE EXCEPTION 'retained authority account quota exceeded' USING ERRCODE='53000'; END IF;
 UPDATE __SCHEMA__.retained_authority_usage SET retained_bytes=retained_bytes+delta,updated_at=n WHERE tenant_scope=tenant AND scope_kind='principal' AND scope_id=principal AND retained_bytes+delta>=0 RETURNING retained_bytes INTO current_bytes;
 IF NOT FOUND THEN RAISE EXCEPTION 'artifact retained principal counter corrupt'; END IF;
 IF current_bytes>COALESCE(principal_limit,67108864) THEN RAISE EXCEPTION 'retained authority principal quota exceeded' USING ERRCODE='53000'; END IF;
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END $fn$;
CREATE TRIGGER z_retained_artifact_payload_accounting AFTER INSERT OR UPDATE OR DELETE ON __SCHEMA__.content_objects FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.account_artifact_payload_bytes();

CREATE FUNCTION __SCHEMA__.artifact_retained_oracle(wanted_tenant text,wanted_principal text) RETURNS bigint
LANGUAGE plpgsql STABLE SET search_path=pg_catalog AS $fn$
DECLARE t text; total numeric:=0; part numeric;
BEGIN
 FOREACH t IN ARRAY ARRAY['artifact_backup_inventory','artifact_backup_key_dependencies','artifact_backup_jobs','artifact_backup_leases','artifact_corruption_audits','artifact_key_audits','artifact_key_generations','artifact_key_rotation_plans','artifact_migration_plans','artifact_reencryption_jobs','artifact_restore_jobs','artifact_chunks','artifact_gc_jobs','artifact_manifests','artifact_read_leases','artifact_references','artifact_retention_holds','artifact_tombstones','content_objects','provenance_edges','upload_intents'] LOOP
  EXECUTE format('SELECT COALESCE(sum(__SCHEMA__.row_retained_bytes(r)),0) FROM __SCHEMA__.%I r WHERE tenant_scope=$1 AND ($2 IS NULL OR __SCHEMA__.retained_principal(to_jsonb(r))=$2)',t) INTO part USING wanted_tenant,wanted_principal;
  total:=total+part;
  IF total>9223372036854775807 THEN RAISE EXCEPTION 'artifact retained oracle overflow'; END IF;
 END LOOP;
 SELECT COALESCE(sum(ciphertext_length),0) INTO part FROM __SCHEMA__.content_objects
  WHERE tenant_scope=wanted_tenant AND state<>'deleted'
    AND (wanted_principal IS NULL OR 'account:'||owner_account_id=wanted_principal);
 total:=total+part;
 RETURN total::bigint;
END $fn$;
REVOKE ALL ON FUNCTION __SCHEMA__.artifact_retained_oracle(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION __SCHEMA__.artifact_retained_oracle(text,text) TO __ROLE__;

CREATE FUNCTION __SCHEMA__.artifact_retained_account_oracle(wanted_tenant text,wanted_account text) RETURNS bigint
LANGUAGE plpgsql STABLE SET search_path=pg_catalog AS $fn$
DECLARE t text; total numeric:=0; part numeric;
BEGIN
 FOREACH t IN ARRAY ARRAY['artifact_backup_inventory','artifact_backup_key_dependencies','artifact_backup_jobs','artifact_backup_leases','artifact_corruption_audits','artifact_key_audits','artifact_key_generations','artifact_key_rotation_plans','artifact_migration_plans','artifact_reencryption_jobs','artifact_restore_jobs','artifact_chunks','artifact_gc_jobs','artifact_manifests','artifact_read_leases','artifact_references','artifact_retention_holds','artifact_tombstones','content_objects','provenance_edges','upload_intents'] LOOP
  EXECUTE format('SELECT COALESCE(sum(__SCHEMA__.row_retained_bytes(r)),0) FROM __SCHEMA__.%I r WHERE tenant_scope=$1 AND __SCHEMA__.retained_account(to_jsonb(r))=$2',t) INTO part USING wanted_tenant,wanted_account;
  total:=total+part;
  IF total>9223372036854775807 THEN RAISE EXCEPTION 'artifact retained account oracle overflow'; END IF;
 END LOOP;
 SELECT COALESCE(sum(ciphertext_length),0) INTO part FROM __SCHEMA__.content_objects
  WHERE tenant_scope=wanted_tenant AND owner_account_id=wanted_account AND state<>'deleted';
 total:=total+part;
 RETURN total::bigint;
END $fn$;
REVOKE ALL ON FUNCTION __SCHEMA__.artifact_retained_account_oracle(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION __SCHEMA__.artifact_retained_account_oracle(text,text) TO __ROLE__;
