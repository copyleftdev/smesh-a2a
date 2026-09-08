-- Include durable human-ratification packets and receipts in the bounded retained-authority domain.
ALTER TABLE __SCHEMA__.schema_migrations DROP CONSTRAINT schema_migrations_logical_schema_version_check;
ALTER TABLE __SCHEMA__.schema_migrations ADD CONSTRAINT schema_migrations_logical_schema_version_check CHECK((revision=11 AND logical_schema_version=11) OR (revision=10 AND logical_schema_version=10) OR (revision=9 AND logical_schema_version=9) OR (revision=8 AND logical_schema_version=8) OR (revision=7 AND logical_schema_version=7) OR (revision NOT IN (7,8,9,10,11) AND logical_schema_version=6));
ALTER TABLE __SCHEMA__.store_metadata DROP CONSTRAINT store_metadata_schema_version_check;
ALTER TABLE __SCHEMA__.store_metadata ADD CONSTRAINT store_metadata_schema_version_check CHECK(schema_version IN (6,7,8,9,10,11));

-- The migrator intentionally has no BYPASSRLS. Fence every table consulted by
-- retained_account/retained_principal and make the backfill fully visible only
-- inside this migration transaction.
LOCK TABLE __SCHEMA__.tasks,__SCHEMA__.outbox,__SCHEMA__.quota_policy_versions,__SCHEMA__.ratification_packets,__SCHEMA__.ratification_events,__SCHEMA__.retained_authority_usage IN ACCESS EXCLUSIVE MODE;
ALTER TABLE __SCHEMA__.outbox ADD COLUMN ratification_required boolean NOT NULL DEFAULT false;
ALTER TABLE __SCHEMA__.store_identity ADD COLUMN ratification_initialized boolean NOT NULL DEFAULT false;
ALTER TABLE __SCHEMA__.store_identity ADD COLUMN ratification_migration_pending boolean NOT NULL DEFAULT false;
DROP TRIGGER store_identity_immutable ON __SCHEMA__.store_identity;
DROP TRIGGER outbox_identity_immutable ON __SCHEMA__.outbox;
CREATE TRIGGER outbox_identity_immutable BEFORE UPDATE ON __SCHEMA__.outbox
 FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_identity_change('tenant_scope','outbox_id','dispatch_id','task_id','message_id','ratification_required');
CREATE TABLE __SCHEMA__.ratification_ledger_anchor(
 singleton smallint PRIMARY KEY CHECK(singleton=1),
 version smallint NOT NULL CHECK(version=1),
 initialized boolean NOT NULL DEFAULT false,
 key_generation text,
 packet_count bigint NOT NULL DEFAULT 0 CHECK(packet_count>=0),
 event_count bigint NOT NULL DEFAULT 0 CHECK(event_count>=0),
 retained_bytes bigint NOT NULL DEFAULT 0 CHECK(retained_bytes>=0),
 generation_high_water_hash text NOT NULL DEFAULT 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
 state_hash text NOT NULL DEFAULT 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
 state_seal text
);
INSERT INTO __SCHEMA__.ratification_ledger_anchor(singleton,version) VALUES(1,1);
-- A keyed revision-10 authority must be allowed exactly one authenticated v11
-- anchor initialization even though its key check predates this migration.
-- Persist that provenance during the migration; startup must not infer it from
-- an absent/reset anchor or deleted key-check row.
UPDATE __SCHEMA__.store_identity
SET ratification_migration_pending=EXISTS(
 SELECT 1 FROM __SCHEMA__.ratification_key_check
 WHERE singleton=1 AND version=1
   AND key_generation ~ '^sha256:[0-9a-f]{64}$'
   AND check_seal ~ '^[A-Za-z0-9_-]{43}$'
);
CREATE FUNCTION __SCHEMA__.guard_store_identity_ratification_provenance() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'durable audit rows are immutable'; END IF;
 IF NEW.singleton<>OLD.singleton OR NEW.store_id<>OLD.store_id OR NEW.created_at<>OLD.created_at
    OR OLD.ratification_initialized OR NOT NEW.ratification_initialized
    OR NEW.ratification_migration_pending THEN
  RAISE EXCEPTION 'store identity is immutable';
 END IF;
 RETURN NEW;
END $fn$;
CREATE TRIGGER store_identity_immutable BEFORE UPDATE OR DELETE ON __SCHEMA__.store_identity
 FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.guard_store_identity_ratification_provenance();
REVOKE ALL ON FUNCTION __SCHEMA__.guard_store_identity_ratification_provenance() FROM PUBLIC,__ROLE__;
CREATE TABLE __SCHEMA__.ratification_tenant_anchors(
 tenant_scope text PRIMARY KEY CHECK(octet_length(tenant_scope) BETWEEN 1 AND 64),
 packet_count bigint NOT NULL CHECK(packet_count>=0),
 event_count bigint NOT NULL CHECK(event_count>=0),
 key_generation text,
 state_seal text
);
REVOKE ALL ON __SCHEMA__.ratification_tenant_anchors FROM PUBLIC,__ROLE__;
GRANT SELECT ON __SCHEMA__.ratification_tenant_anchors TO __ROLE__;
CREATE TABLE __SCHEMA__.ratification_chain_anchors(
 tenant_scope text NOT NULL CHECK(octet_length(tenant_scope) BETWEEN 1 AND 64),
 task_id text NOT NULL CHECK(octet_length(task_id) BETWEEN 1 AND 256),
 packet_count bigint NOT NULL CHECK(packet_count>=0),
 event_count bigint NOT NULL CHECK(event_count>=0),
 key_generation text,
 state_seal text,
 PRIMARY KEY(tenant_scope,task_id)
);
REVOKE ALL ON __SCHEMA__.ratification_chain_anchors FROM PUBLIC,__ROLE__;
GRANT SELECT ON __SCHEMA__.ratification_chain_anchors TO __ROLE__;
CREATE FUNCTION __SCHEMA__.guard_ratification_ledger_anchor() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
 IF NEW.singleton<>OLD.singleton OR NEW.version<>OLD.version OR (OLD.initialized AND (NOT NEW.initialized OR NEW.key_generation<>OLD.key_generation)) THEN
  RAISE EXCEPTION 'ratification ledger anchor identity is immutable';
 END IF;
 RETURN NEW;
END $fn$;
CREATE TRIGGER ratification_ledger_anchor_identity BEFORE UPDATE ON __SCHEMA__.ratification_ledger_anchor
 FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.guard_ratification_ledger_anchor();
CREATE TRIGGER ratification_ledger_anchor_no_delete BEFORE DELETE ON __SCHEMA__.ratification_ledger_anchor
 FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_ratification_packet_delete();
REVOKE ALL ON __SCHEMA__.ratification_ledger_anchor FROM PUBLIC,__ROLE__;
REVOKE ALL ON FUNCTION __SCHEMA__.guard_ratification_ledger_anchor() FROM PUBLIC,__ROLE__;
ALTER TABLE __SCHEMA__.tasks DISABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.outbox DISABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.quota_policy_versions DISABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.ratification_packets DISABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.ratification_events DISABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.retained_authority_usage DISABLE ROW LEVEL SECURITY;

-- Adding the server-owned ratification fence changes the retained byte size of
-- every pre-v11 outbox row without firing its accounting trigger. Reconcile
-- that structural delta before authenticating the revision-10 materialization.
INSERT INTO __SCHEMA__.retained_authority_usage(tenant_scope,scope_kind,scope_id,retained_bytes,updated_at)
 SELECT tenant_scope,'tenant',tenant_scope,
        sum(__SCHEMA__.row_retained_bytes(o)-octet_length((to_jsonb(o)-'ratification_required')::text)::bigint),
        __SCHEMA__.db_millis()
 FROM __SCHEMA__.outbox o GROUP BY tenant_scope
 ON CONFLICT(tenant_scope,scope_kind,scope_id) DO UPDATE
 SET retained_bytes=__SCHEMA__.retained_authority_usage.retained_bytes+EXCLUDED.retained_bytes,
     updated_at=EXCLUDED.updated_at;
INSERT INTO __SCHEMA__.retained_authority_usage(tenant_scope,scope_kind,scope_id,retained_bytes,updated_at)
 SELECT tenant_scope,'account',__SCHEMA__.retained_account(to_jsonb(o)),
        sum(__SCHEMA__.row_retained_bytes(o)-octet_length((to_jsonb(o)-'ratification_required')::text)::bigint),
        __SCHEMA__.db_millis()
 FROM __SCHEMA__.outbox o
 WHERE __SCHEMA__.retained_account(to_jsonb(o)) IS NOT NULL
 GROUP BY tenant_scope,__SCHEMA__.retained_account(to_jsonb(o))
 ON CONFLICT(tenant_scope,scope_kind,scope_id) DO UPDATE
 SET retained_bytes=__SCHEMA__.retained_authority_usage.retained_bytes+EXCLUDED.retained_bytes,
     updated_at=EXCLUDED.updated_at;
INSERT INTO __SCHEMA__.retained_authority_usage(tenant_scope,scope_kind,scope_id,retained_bytes,updated_at)
 SELECT tenant_scope,'principal',__SCHEMA__.retained_principal(to_jsonb(o)),
        sum(__SCHEMA__.row_retained_bytes(o)-octet_length((to_jsonb(o)-'ratification_required')::text)::bigint),
        __SCHEMA__.db_millis()
 FROM __SCHEMA__.outbox o
 WHERE __SCHEMA__.retained_principal(to_jsonb(o)) IS NOT NULL
 GROUP BY tenant_scope,__SCHEMA__.retained_principal(to_jsonb(o))
 ON CONFLICT(tenant_scope,scope_kind,scope_id) DO UPDATE
 SET retained_bytes=__SCHEMA__.retained_authority_usage.retained_bytes+EXCLUDED.retained_bytes,
     updated_at=EXCLUDED.updated_at;
-- Replace revision 10's broad mutable-column guard with the exact packet state machine.
CREATE OR REPLACE FUNCTION __SCHEMA__.guard_ratification_packet_identity() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
 IF (to_jsonb(NEW)-'state'-'revision'-'reviewer_account_id'-'head_receipt_hash'-'approved_task_json'-'approved_result_json'-'approved_transcript_json'-'updated_at')
    <> (to_jsonb(OLD)-'state'-'revision'-'reviewer_account_id'-'head_receipt_hash'-'approved_task_json'-'approved_result_json'-'approved_transcript_json'-'updated_at')
    OR NEW.updated_at<OLD.updated_at THEN
  RAISE EXCEPTION 'ratification packet identity is immutable';
 END IF;
 IF OLD.state=NEW.state AND OLD.revision=NEW.revision
    AND NEW.reviewer_account_id IS NOT DISTINCT FROM OLD.reviewer_account_id
    AND NEW.head_receipt_hash IS NOT DISTINCT FROM OLD.head_receipt_hash
    AND OLD.approved_task_json IS NULL AND OLD.approved_result_json IS NULL AND OLD.approved_transcript_json IS NULL
    AND NEW.approved_task_json IS NOT NULL AND NEW.approved_result_json IS NOT NULL AND NEW.approved_transcript_json IS NOT NULL
 THEN RETURN NEW; END IF;
 IF OLD.state='awaiting_review' AND OLD.revision=0 AND NEW.state='reviewed' AND NEW.revision=1
    AND NEW.approved_task_json IS NOT DISTINCT FROM OLD.approved_task_json
    AND NEW.approved_result_json IS NOT DISTINCT FROM OLD.approved_result_json
    AND NEW.approved_transcript_json IS NOT DISTINCT FROM OLD.approved_transcript_json
    AND OLD.reviewer_account_id IS NULL AND OLD.head_receipt_hash IS NULL
    AND NEW.reviewer_account_id IS NOT NULL AND NEW.head_receipt_hash IS NOT NULL
    AND EXISTS(SELECT 1 FROM __SCHEMA__.ratification_events e WHERE e.tenant_scope=NEW.tenant_scope AND e.task_id=NEW.task_id AND e.generation=NEW.generation AND e.revision=1 AND e.action='review' AND e.account_id=NEW.reviewer_account_id AND e.receipt_hash=NEW.head_receipt_hash)
 THEN RETURN NEW; END IF;
 IF OLD.state='reviewed' AND OLD.revision=1 AND NEW.state IN('approved','rejected','amended') AND NEW.revision=2
    AND NEW.approved_task_json IS NOT DISTINCT FROM OLD.approved_task_json
    AND NEW.approved_result_json IS NOT DISTINCT FROM OLD.approved_result_json
    AND NEW.approved_transcript_json IS NOT DISTINCT FROM OLD.approved_transcript_json
    AND NEW.reviewer_account_id=OLD.reviewer_account_id AND NEW.head_receipt_hash IS NOT NULL
    AND EXISTS(SELECT 1 FROM __SCHEMA__.ratification_events e WHERE e.tenant_scope=NEW.tenant_scope AND e.task_id=NEW.task_id AND e.generation=NEW.generation AND e.revision=2 AND e.action=CASE NEW.state WHEN 'approved' THEN 'approve' WHEN 'rejected' THEN 'reject' ELSE 'amend' END AND e.account_id=NEW.reviewer_account_id AND e.previous_receipt_hash=OLD.head_receipt_hash AND e.receipt_hash=NEW.head_receipt_hash)
 THEN RETURN NEW; END IF;
 IF OLD.state IN('awaiting_review','reviewed') AND NEW.state IN('canceled','superseded')
    AND NEW.revision=OLD.revision AND NEW.reviewer_account_id IS NOT DISTINCT FROM OLD.reviewer_account_id
    AND NEW.head_receipt_hash IS NOT DISTINCT FROM OLD.head_receipt_hash
    AND NEW.approved_task_json IS NOT DISTINCT FROM OLD.approved_task_json
    AND NEW.approved_result_json IS NOT DISTINCT FROM OLD.approved_result_json
    AND NEW.approved_transcript_json IS NOT DISTINCT FROM OLD.approved_transcript_json
 THEN RETURN NEW; END IF;
 RAISE EXCEPTION 'ratification packet state transition is invalid';
END $fn$;

-- The artifact and callback oracles normally run through tenant-scoped runtime
-- sessions. Give this transaction the same complete view while the revision-10
-- materialization is authenticated. CREATE POLICY also takes a table lock that
-- keeps the multi-domain snapshot coherent until these temporary policies are
-- removed below.
DO $do$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY[
  'artifact_backup_inventory','artifact_backup_key_dependencies','artifact_backup_jobs','artifact_backup_leases','artifact_corruption_audits','artifact_key_audits','artifact_key_generations','artifact_key_rotation_plans','artifact_migration_plans','artifact_reencryption_jobs','artifact_restore_jobs','artifact_chunks','artifact_gc_jobs','artifact_manifests','artifact_read_leases','artifact_references','artifact_retention_holds','artifact_tombstones','content_objects','provenance_edges','upload_intents',
  'callback_configs','callback_events','callback_deliveries','callback_attempts','callback_tenant_scheduler'
 ] LOOP
  EXECUTE format('CREATE POLICY migration_0011_oracle ON __SCHEMA__.%I FOR SELECT TO __MIGRATOR__ USING(current_setting(''smesh.internal_global'',true)=''diag-v1'')',t);
 END LOOP;
END $do$;

-- Packets retain the task owner's authenticated principal. Immutable receipt
-- rows retain the authenticated human principal sealed into receipt_json.
CREATE OR REPLACE FUNCTION __SCHEMA__.retained_principal(value jsonb) RETURNS text
LANGUAGE plpgsql STABLE SET search_path=pg_catalog AS $$
DECLARE principal text; packet_principal text; binding text; account text; task text; config text; event text;
BEGIN
 IF value ? 'packet_json' AND value ? 'packet_seal' AND value ? 'approved_task_json' THEN
  packet_principal := (value->>'packet_json')::jsonb->>'principalScope';
  SELECT t.principal_scope INTO principal FROM __SCHEMA__.tasks t
   WHERE t.tenant_scope=value->>'tenant_scope' AND t.task_id=value->>'task_id';
  IF principal IS NULL OR packet_principal IS NULL OR principal<>packet_principal THEN
   RAISE EXCEPTION 'ratification packet principal attribution is invalid' USING ERRCODE='XX001';
  END IF;
  RETURN principal;
 END IF;
 IF value ? 'receipt_json' AND value ? 'receipt_seal' AND value ? 'action' THEN
  principal := (value->>'receipt_json')::jsonb->>'principalScope';
  IF principal IS NULL OR principal='' THEN
   RAISE EXCEPTION 'ratification receipt principal attribution is invalid' USING ERRCODE='XX001';
  END IF;
  RETURN principal;
 END IF;
 principal := value->>'principal_scope';
 IF principal IS NOT NULL THEN RETURN principal; END IF;
 binding := value->>'binding_digest';
 IF binding IS NOT NULL THEN
  SELECT i.principal_scope INTO principal FROM __SCHEMA__.quota_intents i
   WHERE i.tenant_scope=value->>'tenant_scope' AND i.binding_digest=binding;
  IF principal IS NOT NULL THEN RETURN principal; END IF;
 END IF;
 config := value->>'config_id';
 IF config IS NOT NULL THEN
  task := value->>'task_id'; event := value->>'event_id';
  IF task IS NOT NULL THEN
   SELECT c.principal_scope INTO principal FROM __SCHEMA__.callback_configs c
    WHERE c.tenant_scope=value->>'tenant_scope' AND c.task_id=task AND c.config_id=config;
  ELSIF event IS NOT NULL THEN
   SELECT c.principal_scope INTO principal FROM __SCHEMA__.callback_deliveries d
    JOIN __SCHEMA__.callback_configs c USING(tenant_scope,task_id,config_id)
    WHERE d.tenant_scope=value->>'tenant_scope' AND d.event_id=event AND d.config_id=config;
  END IF;
  IF principal IS NOT NULL THEN RETURN principal; END IF;
 END IF;
 account := COALESCE(value->>'owner_account_id',value->>'actor_account_id',value->>'account_id');
 IF account IS NOT NULL THEN RETURN 'account:'||account; END IF;
 task := value->>'task_id';
 IF task IS NOT NULL THEN
  SELECT 'account:'||t.owner_account_id INTO principal FROM __SCHEMA__.tasks t
   WHERE t.tenant_scope=value->>'tenant_scope' AND t.task_id=task;
 END IF;
 RETURN principal;
END $$;

DO $do$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['ratification_packets','ratification_events'] LOOP
  EXECUTE format('INSERT INTO __SCHEMA__.retained_authority_usage(tenant_scope,scope_kind,scope_id,retained_bytes,updated_at) SELECT tenant_scope,''tenant'',tenant_scope,sum(__SCHEMA__.row_retained_bytes(r)),__SCHEMA__.db_millis() FROM __SCHEMA__.%I r GROUP BY tenant_scope ON CONFLICT(tenant_scope,scope_kind,scope_id) DO UPDATE SET retained_bytes=__SCHEMA__.retained_authority_usage.retained_bytes+EXCLUDED.retained_bytes,updated_at=EXCLUDED.updated_at',t);
  EXECUTE format('INSERT INTO __SCHEMA__.retained_authority_usage(tenant_scope,scope_kind,scope_id,retained_bytes,updated_at) SELECT tenant_scope,''account'',__SCHEMA__.retained_account(to_jsonb(r)),sum(__SCHEMA__.row_retained_bytes(r)),__SCHEMA__.db_millis() FROM __SCHEMA__.%I r WHERE __SCHEMA__.retained_account(to_jsonb(r)) IS NOT NULL GROUP BY tenant_scope,__SCHEMA__.retained_account(to_jsonb(r)) ON CONFLICT(tenant_scope,scope_kind,scope_id) DO UPDATE SET retained_bytes=__SCHEMA__.retained_authority_usage.retained_bytes+EXCLUDED.retained_bytes,updated_at=EXCLUDED.updated_at',t);
  EXECUTE format('INSERT INTO __SCHEMA__.retained_authority_usage(tenant_scope,scope_kind,scope_id,retained_bytes,updated_at) SELECT tenant_scope,''principal'',__SCHEMA__.retained_principal(to_jsonb(r)),sum(__SCHEMA__.row_retained_bytes(r)),__SCHEMA__.db_millis() FROM __SCHEMA__.%I r WHERE __SCHEMA__.retained_principal(to_jsonb(r)) IS NOT NULL GROUP BY tenant_scope,__SCHEMA__.retained_principal(to_jsonb(r)) ON CONFLICT(tenant_scope,scope_kind,scope_id) DO UPDATE SET retained_bytes=__SCHEMA__.retained_authority_usage.retained_bytes+EXCLUDED.retained_bytes,updated_at=EXCLUDED.updated_at',t);
  EXECUTE format('CREATE TRIGGER retained_authority_accounting AFTER INSERT OR UPDATE OR DELETE ON __SCHEMA__.%I FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.account_retained_authority_row()',t);
 END LOOP;
END $do$;

CREATE OR REPLACE FUNCTION __SCHEMA__.retained_authority_oracle(wanted_tenant text,wanted_principal text) RETURNS bigint
LANGUAGE plpgsql STABLE SET search_path=pg_catalog AS $$
DECLARE t text; total numeric:=0; part numeric;
BEGIN
 FOREACH t IN ARRAY ARRAY[
  'tasks','task_events','idempotency_records','outbox','outbox_attempts','outbox_tenant_scheduler','receiver_inbox','receiver_frames',
  'loopback_effects','stream_transcripts','stream_frames','cancellation_intents','authorization_decisions',
  'list_snapshots','list_snapshot_entries','list_page_tokens','quota_reservations','quota_policy_versions','quota_policy_reconciliation_audits',
  'quota_intents','quota_buckets','quota_receipts','quota_request_receipts','quota_execution_reservations','quota_allocations','quota_leases',
  'quota_denial_audits','quota_override_audits'
 ] LOOP
  EXECUTE format('SELECT COALESCE(sum(__SCHEMA__.row_retained_bytes(r)),0) FROM __SCHEMA__.%I r WHERE tenant_scope=$1 AND ($2 IS NULL OR __SCHEMA__.retained_principal(to_jsonb(r))=$2)',t)
   INTO part USING wanted_tenant,wanted_principal;
  total:=total+part;
  IF total>9223372036854775807 THEN RAISE EXCEPTION 'retained authority oracle overflow'; END IF;
 END LOOP;
 SELECT COALESCE(sum(__SCHEMA__.row_retained_bytes(p)),0) INTO part
  FROM __SCHEMA__.ratification_packets p JOIN __SCHEMA__.tasks x USING(tenant_scope,task_id)
  WHERE p.tenant_scope=wanted_tenant AND (wanted_principal IS NULL OR x.principal_scope=wanted_principal);
 total:=total+part;
 SELECT COALESCE(sum(__SCHEMA__.row_retained_bytes(e)),0) INTO part
  FROM __SCHEMA__.ratification_events e
  WHERE e.tenant_scope=wanted_tenant
    AND (wanted_principal IS NULL OR (e.receipt_json::jsonb->>'principalScope')=wanted_principal);
 total:=total+part;
 IF total>9223372036854775807 THEN RAISE EXCEPTION 'retained authority oracle overflow'; END IF;
 RETURN total::bigint;
END $$;

CREATE OR REPLACE FUNCTION __SCHEMA__.retained_authority_account_oracle(wanted_tenant text,wanted_account text) RETURNS bigint
LANGUAGE plpgsql STABLE SET search_path=pg_catalog AS $$
DECLARE t text; total numeric:=0; part numeric;
BEGIN
 FOREACH t IN ARRAY ARRAY[
  'tasks','task_events','idempotency_records','outbox','outbox_attempts','outbox_tenant_scheduler','receiver_inbox','receiver_frames',
  'loopback_effects','stream_transcripts','stream_frames','cancellation_intents','authorization_decisions',
  'list_snapshots','list_snapshot_entries','list_page_tokens','quota_reservations','quota_policy_versions','quota_policy_reconciliation_audits',
  'quota_intents','quota_buckets','quota_receipts','quota_request_receipts','quota_execution_reservations','quota_allocations','quota_leases',
  'quota_denial_audits','quota_override_audits'
 ] LOOP
  EXECUTE format('SELECT COALESCE(sum(__SCHEMA__.row_retained_bytes(r)),0) FROM __SCHEMA__.%I r WHERE tenant_scope=$1 AND __SCHEMA__.retained_account(to_jsonb(r))=$2',t)
   INTO part USING wanted_tenant,wanted_account;
  total:=total+part;
  IF total>9223372036854775807 THEN RAISE EXCEPTION 'retained authority account oracle overflow'; END IF;
 END LOOP;
 SELECT COALESCE(sum(__SCHEMA__.row_retained_bytes(p)),0) INTO part
  FROM __SCHEMA__.ratification_packets p JOIN __SCHEMA__.tasks x USING(tenant_scope,task_id)
  WHERE p.tenant_scope=wanted_tenant AND x.owner_account_id=wanted_account;
 total:=total+part;
 SELECT COALESCE(sum(__SCHEMA__.row_retained_bytes(e)),0) INTO part
  FROM __SCHEMA__.ratification_events e
  WHERE e.tenant_scope=wanted_tenant AND e.account_id=wanted_account;
 total:=total+part;
 IF total>9223372036854775807 THEN RAISE EXCEPTION 'retained authority account oracle overflow'; END IF;
 RETURN total::bigint;
END $$;

CREATE FUNCTION __SCHEMA__.artifact_retained_scopes_bounded(wanted_tenant text,wanted_kind text) RETURNS SETOF text
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE t text; expression text;
BEGIN
 IF wanted_kind NOT IN ('account','principal') THEN RAISE EXCEPTION 'invalid retained scope kind'; END IF;
 IF wanted_tenant IS DISTINCT FROM current_setting('smesh.tenant_scope',true) THEN
  RAISE EXCEPTION 'insufficient privilege' USING ERRCODE='42501';
 END IF;
 PERFORM set_config('smesh.internal_global','diag-v1',true);
 expression:=CASE wanted_kind WHEN 'account' THEN 'retained_account' ELSE 'retained_principal' END;
 FOREACH t IN ARRAY ARRAY[
  'artifact_backup_inventory','artifact_backup_key_dependencies','artifact_backup_jobs','artifact_backup_leases','artifact_corruption_audits','artifact_key_audits','artifact_key_generations','artifact_key_rotation_plans','artifact_migration_plans','artifact_reencryption_jobs','artifact_restore_jobs','artifact_chunks','artifact_gc_jobs','artifact_manifests','artifact_read_leases','artifact_references','artifact_retention_holds','artifact_tombstones','content_objects','provenance_edges','upload_intents'
 ] LOOP
  RETURN QUERY EXECUTE format('SELECT DISTINCT __SCHEMA__.%I(to_jsonb(r)) FROM __SCHEMA__.%I r WHERE tenant_scope=$1 AND __SCHEMA__.%I(to_jsonb(r)) IS NOT NULL',expression,t,expression) USING wanted_tenant;
 END LOOP;
END $$;
REVOKE ALL ON FUNCTION __SCHEMA__.artifact_retained_scopes_bounded(text,text) FROM PUBLIC,__ROLE__;
GRANT EXECUTE ON FUNCTION __SCHEMA__.artifact_retained_scopes_bounded(text,text) TO __ROLE__;

CREATE OR REPLACE FUNCTION __SCHEMA__.authority_tenants_bounded() RETURNS SETOF text
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM set_config('smesh.internal_global','diag-v1',true);
 RETURN QUERY SELECT tenant_scope FROM (
  SELECT tenant_scope FROM __SCHEMA__.tasks
  UNION SELECT tenant_scope FROM __SCHEMA__.task_events
  UNION SELECT tenant_scope FROM __SCHEMA__.idempotency_records
  UNION SELECT tenant_scope FROM __SCHEMA__.outbox
  UNION SELECT tenant_scope FROM __SCHEMA__.outbox_attempts
  UNION SELECT tenant_scope FROM __SCHEMA__.receiver_inbox
  UNION SELECT tenant_scope FROM __SCHEMA__.receiver_frames
  UNION SELECT tenant_scope FROM __SCHEMA__.loopback_effects
  UNION SELECT tenant_scope FROM __SCHEMA__.stream_transcripts
  UNION SELECT tenant_scope FROM __SCHEMA__.stream_frames
  UNION SELECT tenant_scope FROM __SCHEMA__.cancellation_intents
  UNION SELECT tenant_scope FROM __SCHEMA__.authorization_decisions
  UNION SELECT tenant_scope FROM __SCHEMA__.list_snapshots
  UNION SELECT tenant_scope FROM __SCHEMA__.list_snapshot_entries
  UNION SELECT tenant_scope FROM __SCHEMA__.list_page_tokens
  UNION SELECT tenant_scope FROM __SCHEMA__.quota_reservations
  UNION SELECT tenant_scope FROM __SCHEMA__.quota_policy_versions
  UNION SELECT tenant_scope FROM __SCHEMA__.quota_policy_reconciliation_audits
  UNION SELECT tenant_scope FROM __SCHEMA__.quota_intents
  UNION SELECT tenant_scope FROM __SCHEMA__.quota_buckets
  UNION SELECT tenant_scope FROM __SCHEMA__.quota_receipts
  UNION SELECT tenant_scope FROM __SCHEMA__.quota_request_receipts
  UNION SELECT tenant_scope FROM __SCHEMA__.quota_execution_reservations
  UNION SELECT tenant_scope FROM __SCHEMA__.quota_allocations
  UNION SELECT tenant_scope FROM __SCHEMA__.quota_leases
  UNION SELECT tenant_scope FROM __SCHEMA__.quota_denial_audits
  UNION SELECT tenant_scope FROM __SCHEMA__.quota_override_audits
  UNION SELECT tenant_scope FROM __SCHEMA__.ratification_packets
  UNION SELECT tenant_scope FROM __SCHEMA__.ratification_events
  UNION SELECT tenant_scope FROM __SCHEMA__.artifact_backup_inventory
  UNION SELECT tenant_scope FROM __SCHEMA__.artifact_backup_key_dependencies
  UNION SELECT tenant_scope FROM __SCHEMA__.artifact_backup_jobs
  UNION SELECT tenant_scope FROM __SCHEMA__.artifact_backup_leases
  UNION SELECT tenant_scope FROM __SCHEMA__.artifact_corruption_audits
  UNION SELECT tenant_scope FROM __SCHEMA__.artifact_key_audits
  UNION SELECT tenant_scope FROM __SCHEMA__.artifact_key_generations
  UNION SELECT tenant_scope FROM __SCHEMA__.artifact_key_rotation_plans
  UNION SELECT tenant_scope FROM __SCHEMA__.artifact_migration_plans
  UNION SELECT tenant_scope FROM __SCHEMA__.artifact_reencryption_jobs
  UNION SELECT tenant_scope FROM __SCHEMA__.artifact_restore_jobs
  UNION SELECT tenant_scope FROM __SCHEMA__.artifact_chunks
  UNION SELECT tenant_scope FROM __SCHEMA__.artifact_gc_jobs
  UNION SELECT tenant_scope FROM __SCHEMA__.artifact_manifests
  UNION SELECT tenant_scope FROM __SCHEMA__.artifact_read_leases
  UNION SELECT tenant_scope FROM __SCHEMA__.artifact_references
  UNION SELECT tenant_scope FROM __SCHEMA__.artifact_retention_holds
  UNION SELECT tenant_scope FROM __SCHEMA__.artifact_tombstones
  UNION SELECT tenant_scope FROM __SCHEMA__.content_objects
  UNION SELECT tenant_scope FROM __SCHEMA__.provenance_edges
  UNION SELECT tenant_scope FROM __SCHEMA__.upload_intents
  UNION SELECT tenant_scope FROM __SCHEMA__.callback_configs
  UNION SELECT tenant_scope FROM __SCHEMA__.callback_events
  UNION SELECT tenant_scope FROM __SCHEMA__.callback_deliveries
  UNION SELECT tenant_scope FROM __SCHEMA__.callback_attempts
  UNION SELECT tenant_scope FROM __SCHEMA__.callback_tenant_scheduler
  UNION SELECT tenant_scope FROM __SCHEMA__.retained_authority_usage
  UNION SELECT tenant_scope FROM __SCHEMA__.outbox_tenant_scheduler
 ) scopes ORDER BY tenant_scope;
END $$;
REVOKE ALL ON FUNCTION __SCHEMA__.authority_tenants_bounded() FROM PUBLIC,__ROLE__;

-- Keyring reload is global operator work, but the runtime role must not regain
-- the tenant-enumeration authority revoked above. Return only the bounded set
-- of opaque generations that are still required by live objects or sealed
-- backup dependencies.
CREATE FUNCTION __SCHEMA__.artifact_required_key_generations_bounded() RETURNS SETOF text
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $fn$
DECLARE requirement_count bigint;
BEGIN
 PERFORM set_config('smesh.internal_global','claim-v1',true);
 SELECT count(*)::bigint INTO requirement_count FROM (
  SELECT key_generation FROM (
   SELECT key_generation FROM __SCHEMA__.content_objects WHERE state<>'deleted'
   UNION
   SELECT d.key_generation FROM __SCHEMA__.artifact_backup_key_dependencies d
    JOIN __SCHEMA__.artifact_backup_jobs b USING(tenant_scope,backup_id)
    WHERE b.state='sealed' AND d.released_at IS NULL AND d.required_until>__SCHEMA__.db_millis()
  ) required LIMIT 100001
 ) bounded_probe;
 IF requirement_count>100000 THEN RAISE EXCEPTION 'artifact key requirement cap exceeded'; END IF;
 RETURN QUERY
  SELECT key_generation FROM (
   SELECT key_generation FROM __SCHEMA__.content_objects WHERE state<>'deleted'
   UNION
   SELECT d.key_generation FROM __SCHEMA__.artifact_backup_key_dependencies d
    JOIN __SCHEMA__.artifact_backup_jobs b USING(tenant_scope,backup_id)
    WHERE b.state='sealed' AND d.released_at IS NULL AND d.required_until>__SCHEMA__.db_millis()
  ) required ORDER BY key_generation;
END $fn$;
REVOKE ALL ON FUNCTION __SCHEMA__.artifact_required_key_generations_bounded() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION __SCHEMA__.artifact_required_key_generations_bounded() TO __ROLE__;

CREATE OR REPLACE FUNCTION __SCHEMA__.authority_retained_scopes_bounded(wanted_tenant text,wanted_kind text) RETURNS SETOF text
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE t text; expression text;
BEGIN
 IF wanted_kind NOT IN ('account','principal') THEN RAISE EXCEPTION 'invalid retained scope kind'; END IF;
 PERFORM set_config('smesh.internal_global','diag-v1',true);
 expression:=CASE wanted_kind WHEN 'account' THEN 'retained_account' ELSE 'retained_principal' END;
 FOREACH t IN ARRAY ARRAY[
  'tasks','task_events','idempotency_records','outbox','outbox_attempts','outbox_tenant_scheduler','receiver_inbox','receiver_frames',
  'loopback_effects','stream_transcripts','stream_frames','cancellation_intents','authorization_decisions',
  'list_snapshots','list_snapshot_entries','list_page_tokens','quota_reservations','quota_policy_versions','quota_policy_reconciliation_audits',
  'quota_intents','quota_buckets','quota_receipts','quota_request_receipts','quota_execution_reservations','quota_allocations','quota_leases',
  'quota_denial_audits','quota_override_audits'
 ] LOOP
  RETURN QUERY EXECUTE format('SELECT DISTINCT __SCHEMA__.%I(to_jsonb(r)) FROM __SCHEMA__.%I r WHERE tenant_scope=$1 AND __SCHEMA__.%I(to_jsonb(r)) IS NOT NULL',expression,t,expression)
   USING wanted_tenant;
 END LOOP;
 IF wanted_kind='account' THEN
  RETURN QUERY SELECT DISTINCT x.owner_account_id FROM __SCHEMA__.ratification_packets p JOIN __SCHEMA__.tasks x USING(tenant_scope,task_id) WHERE p.tenant_scope=wanted_tenant;
  RETURN QUERY SELECT DISTINCT e.account_id FROM __SCHEMA__.ratification_events e WHERE e.tenant_scope=wanted_tenant;
 ELSE
  RETURN QUERY SELECT DISTINCT x.principal_scope FROM __SCHEMA__.ratification_packets p JOIN __SCHEMA__.tasks x USING(tenant_scope,task_id) WHERE p.tenant_scope=wanted_tenant;
  RETURN QUERY SELECT DISTINCT e.receipt_json::jsonb->>'principalScope' FROM __SCHEMA__.ratification_events e WHERE e.tenant_scope=wanted_tenant;
 END IF;
END $$;

-- Commit gate: every materialized scope must equal an independent table-specific
-- oracle before revision 11 can be recorded or store_metadata advanced.
DO $do$ DECLARE r record; expected bigint; tenant text; scope text; BEGIN
 PERFORM set_config('smesh.internal_global','diag-v1',true);
 FOR r IN SELECT * FROM __SCHEMA__.retained_authority_usage LOOP
  expected:=CASE r.scope_kind
   WHEN 'tenant' THEN __SCHEMA__.retained_authority_oracle(r.tenant_scope,NULL)+__SCHEMA__.artifact_retained_oracle(r.tenant_scope,NULL)+__SCHEMA__.callback_retained_oracle(r.tenant_scope,NULL)
   WHEN 'account' THEN __SCHEMA__.retained_authority_account_oracle(r.tenant_scope,r.scope_id)+__SCHEMA__.artifact_retained_account_oracle(r.tenant_scope,r.scope_id)+__SCHEMA__.callback_retained_account_oracle(r.tenant_scope,r.scope_id)
   ELSE __SCHEMA__.retained_authority_oracle(r.tenant_scope,r.scope_id)+__SCHEMA__.artifact_retained_oracle(r.tenant_scope,r.scope_id)+__SCHEMA__.callback_retained_oracle(r.tenant_scope,r.scope_id) END;
  IF r.retained_bytes<>expected THEN
   RAISE EXCEPTION 'retained authority materialization mismatch' USING ERRCODE='XX001';
  END IF;
 END LOOP;
 FOR tenant IN SELECT * FROM __SCHEMA__.authority_tenants_bounded() LOOP
  PERFORM set_config('smesh.tenant_scope',tenant,true);
  expected:=__SCHEMA__.retained_authority_oracle(tenant,NULL)+__SCHEMA__.artifact_retained_oracle(tenant,NULL)+__SCHEMA__.callback_retained_oracle(tenant,NULL);
  IF NOT EXISTS(SELECT 1 FROM __SCHEMA__.retained_authority_usage u WHERE u.tenant_scope=tenant AND u.scope_kind='tenant' AND u.scope_id=tenant AND u.retained_bytes=expected) THEN
   RAISE EXCEPTION 'retained authority materialization mismatch' USING ERRCODE='XX001';
  END IF;
  FOR scope IN SELECT scope_id FROM (SELECT x AS scope_id FROM __SCHEMA__.authority_retained_scopes_bounded(tenant,'account') x UNION SELECT x FROM __SCHEMA__.artifact_retained_scopes_bounded(tenant,'account') x UNION SELECT x FROM __SCHEMA__.callback_retained_scopes_bounded(tenant,'account') x UNION SELECT scope_id FROM __SCHEMA__.retained_authority_usage WHERE tenant_scope=tenant AND scope_kind='account') scopes LOOP
   expected:=__SCHEMA__.retained_authority_account_oracle(tenant,scope)+__SCHEMA__.artifact_retained_account_oracle(tenant,scope)+__SCHEMA__.callback_retained_account_oracle(tenant,scope);
   IF NOT EXISTS(SELECT 1 FROM __SCHEMA__.retained_authority_usage u WHERE u.tenant_scope=tenant AND u.scope_kind='account' AND u.scope_id=scope AND u.retained_bytes=expected) THEN
    RAISE EXCEPTION 'retained authority materialization mismatch' USING ERRCODE='XX001';
   END IF;
  END LOOP;
  FOR scope IN SELECT scope_id FROM (SELECT x AS scope_id FROM __SCHEMA__.authority_retained_scopes_bounded(tenant,'principal') x UNION SELECT x FROM __SCHEMA__.artifact_retained_scopes_bounded(tenant,'principal') x UNION SELECT x FROM __SCHEMA__.callback_retained_scopes_bounded(tenant,'principal') x UNION SELECT scope_id FROM __SCHEMA__.retained_authority_usage WHERE tenant_scope=tenant AND scope_kind='principal') scopes LOOP
   expected:=__SCHEMA__.retained_authority_oracle(tenant,scope)+__SCHEMA__.artifact_retained_oracle(tenant,scope)+__SCHEMA__.callback_retained_oracle(tenant,scope);
   IF NOT EXISTS(SELECT 1 FROM __SCHEMA__.retained_authority_usage u WHERE u.tenant_scope=tenant AND u.scope_kind='principal' AND u.scope_id=scope AND u.retained_bytes=expected) THEN
    RAISE EXCEPTION 'retained authority materialization mismatch' USING ERRCODE='XX001';
   END IF;
  END LOOP;
 END LOOP;
END $do$;

DO $do$ DECLARE r record; configured_limit bigint; BEGIN
 FOR r IN SELECT * FROM __SCHEMA__.retained_authority_usage LOOP
  SELECT CASE r.scope_kind
    WHEN 'tenant' THEN (canonical_json::jsonb#>>'{limits,retainedAuthorityBytes,tenant}')::bigint
    WHEN 'account' THEN (canonical_json::jsonb#>>'{limits,retainedAuthorityBytes,account}')::bigint
    ELSE (canonical_json::jsonb#>>'{limits,retainedAuthorityBytes,principal}')::bigint END
   INTO configured_limit FROM __SCHEMA__.quota_policy_versions
   WHERE tenant_scope=r.tenant_scope AND lifecycle='active';
  configured_limit:=COALESCE(configured_limit,67108864);
  IF r.retained_bytes>configured_limit THEN
   IF r.scope_kind='tenant' THEN RAISE EXCEPTION 'retained authority tenant quota exceeded' USING ERRCODE='53000';
   ELSIF r.scope_kind='account' THEN RAISE EXCEPTION 'retained authority account quota exceeded' USING ERRCODE='53000';
   ELSE RAISE EXCEPTION 'retained authority principal quota exceeded' USING ERRCODE='53000'; END IF;
  END IF;
 END LOOP;
END $do$;

DO $do$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY[
  'artifact_backup_inventory','artifact_backup_key_dependencies','artifact_backup_jobs','artifact_backup_leases','artifact_corruption_audits','artifact_key_audits','artifact_key_generations','artifact_key_rotation_plans','artifact_migration_plans','artifact_reencryption_jobs','artifact_restore_jobs','artifact_chunks','artifact_gc_jobs','artifact_manifests','artifact_read_leases','artifact_references','artifact_retention_holds','artifact_tombstones','content_objects','provenance_edges','upload_intents',
  'callback_configs','callback_events','callback_deliveries','callback_attempts','callback_tenant_scheduler'
 ] LOOP
  EXECUTE format('DROP POLICY migration_0011_oracle ON __SCHEMA__.%I',t);
 END LOOP;
END $do$;

-- Permanent diagnostic visibility is SELECT-only and restricted to the non-login
-- migrator that owns the bounded SECURITY DEFINER discovery/oracle functions.
-- Runtime roles can execute those bounded functions but cannot select these rows.
DO $do$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY[
  'artifact_backup_inventory','artifact_backup_key_dependencies','artifact_backup_jobs','artifact_backup_leases','artifact_corruption_audits','artifact_key_audits','artifact_key_generations','artifact_key_rotation_plans','artifact_migration_plans','artifact_reencryption_jobs','artifact_restore_jobs','artifact_chunks','artifact_gc_jobs','artifact_manifests','artifact_read_leases','artifact_references','artifact_retention_holds','artifact_tombstones','content_objects','provenance_edges','upload_intents',
  'callback_configs','callback_events','callback_deliveries','callback_attempts','callback_tenant_scheduler'
 ] LOOP
  EXECUTE format('CREATE POLICY retained_diagnostics ON __SCHEMA__.%I FOR SELECT TO __MIGRATOR__ USING(current_setting(''smesh.internal_global'',true)=''diag-v1'')',t);
 END LOOP;
END $do$;

CREATE POLICY internal_quota_diagnostics ON __SCHEMA__.ratification_packets FOR SELECT
 USING(current_user='__MIGRATOR__' AND current_setting('smesh.internal_global',true) IN ('diag-v1','ratification-anchor-v1'));
CREATE POLICY internal_quota_diagnostics ON __SCHEMA__.ratification_events FOR SELECT
 USING(current_user='__MIGRATOR__' AND current_setting('smesh.internal_global',true) IN ('diag-v1','ratification-anchor-v1'));

-- A commutative 256-bit accumulator lets ordinary writes update the anchor in
-- constant work. The keyed seal is still produced by the application; this
-- helper and the trigger entry point are intentionally not callable by runtime.
CREATE FUNCTION __SCHEMA__.ratification_xor_hash(existing_hash text,component_hash text) RETURNS text
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $fn$
DECLARE result text := ''; i integer; a bigint; b bigint;
BEGIN
 IF existing_hash !~ '^sha256:[0-9a-f]{64}$' OR component_hash !~ '^sha256:[0-9a-f]{64}$' THEN
  RAISE EXCEPTION 'invalid ratification accumulator';
 END IF;
 FOR i IN 0..3 LOOP
  a := ('x'||substr(existing_hash,8+i*16,16))::bit(64)::bigint;
  b := ('x'||substr(component_hash,8+i*16,16))::bit(64)::bigint;
  result := result||lpad(to_hex(a # b),16,'0');
 END LOOP;
 RETURN 'sha256:'||result;
END $fn$;
REVOKE ALL ON FUNCTION __SCHEMA__.ratification_xor_hash(text,text) FROM PUBLIC,__ROLE__;

CREATE FUNCTION __SCHEMA__.track_ratification_anchor() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE new_hash text; old_hash text := 'sha256:0000000000000000000000000000000000000000000000000000000000000000';
DECLARE high_hash text := 'sha256:0000000000000000000000000000000000000000000000000000000000000000';
DECLARE packet_delta bigint := 0; event_delta bigint := 0; byte_delta bigint;
BEGIN
 PERFORM set_config('smesh.internal_global','ratification-anchor-v1',true);
 new_hash := 'sha256:'||encode(sha256(convert_to(to_jsonb(NEW)::text,'UTF8')),'hex');
 byte_delta := __SCHEMA__.row_retained_bytes(NEW);
 IF TG_OP='UPDATE' THEN
  old_hash := 'sha256:'||encode(sha256(convert_to(to_jsonb(OLD)::text,'UTF8')),'hex');
  byte_delta := byte_delta-__SCHEMA__.row_retained_bytes(OLD);
 ELSIF TG_TABLE_NAME='ratification_packets' THEN
  packet_delta := 1;
  high_hash := 'sha256:'||encode(sha256(convert_to(jsonb_build_array(NEW.tenant_scope,NEW.task_id,NEW.generation)::text,'UTF8')),'hex');
 ELSE
  event_delta := 1;
 END IF;
 UPDATE __SCHEMA__.ratification_ledger_anchor
 SET packet_count=packet_count+packet_delta,
     event_count=event_count+event_delta,
     retained_bytes=retained_bytes+byte_delta,
     generation_high_water_hash=__SCHEMA__.ratification_xor_hash(generation_high_water_hash,high_hash),
     state_hash=__SCHEMA__.ratification_xor_hash(__SCHEMA__.ratification_xor_hash(state_hash,old_hash),new_hash),
     state_seal=NULL
 WHERE singleton=1 AND version=1;
 IF NOT FOUND THEN RAISE EXCEPTION 'ratification ledger anchor unavailable'; END IF;
 INSERT INTO __SCHEMA__.ratification_tenant_anchors(tenant_scope,packet_count,event_count)
 VALUES(NEW.tenant_scope,packet_delta,event_delta)
 ON CONFLICT(tenant_scope) DO UPDATE
 SET packet_count=__SCHEMA__.ratification_tenant_anchors.packet_count+EXCLUDED.packet_count,
     event_count=__SCHEMA__.ratification_tenant_anchors.event_count+EXCLUDED.event_count,
     state_seal=NULL;
 INSERT INTO __SCHEMA__.ratification_chain_anchors(tenant_scope,task_id,packet_count,event_count)
 VALUES(NEW.tenant_scope,NEW.task_id,packet_delta,event_delta)
 ON CONFLICT(tenant_scope,task_id) DO UPDATE
 SET packet_count=__SCHEMA__.ratification_chain_anchors.packet_count+EXCLUDED.packet_count,
     event_count=__SCHEMA__.ratification_chain_anchors.event_count+EXCLUDED.event_count,
     state_seal=NULL;
 RETURN NEW;
END $fn$;
REVOKE ALL ON FUNCTION __SCHEMA__.track_ratification_anchor() FROM PUBLIC,__ROLE__;

-- Runtime sealing exposes only a fixed-size one-way digest of the canonical
-- anchor state. Counts, hashes, tenant membership, and key material never cross
-- this least-privilege function boundary.
CREATE FUNCTION __SCHEMA__.ratification_anchor_signing_digest(key_generation_arg text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE a record;
BEGIN
 SELECT * INTO STRICT a FROM __SCHEMA__.ratification_ledger_anchor WHERE singleton=1 AND version=1;
 IF NOT a.initialized OR a.key_generation<>key_generation_arg THEN RAISE EXCEPTION 'ratification ledger anchor identity mismatch'; END IF;
 RETURN 'sha256:'||encode(sha256(convert_to(key_generation_arg||':'||a.packet_count||':'||a.event_count||':'||a.retained_bytes||':'||a.generation_high_water_hash||':'||a.state_hash,'UTF8')),'hex');
END $fn$;
REVOKE ALL ON FUNCTION __SCHEMA__.ratification_anchor_signing_digest(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION __SCHEMA__.ratification_anchor_signing_digest(text) TO __ROLE__;

-- Runtime validation receives only fixed-size authenticated anchor material.
-- The tenant seal binds its counters independently of unrelated tenants.
CREATE FUNCTION __SCHEMA__.ratification_anchor_authentication_state(key_generation_arg text,task_id_arg text)
RETURNS TABLE(signing_digest text,global_seal text,tenant_packet_count bigint,tenant_event_count bigint,tenant_key_generation text,tenant_seal text,chain_packet_count bigint,chain_event_count bigint,chain_key_generation text,chain_seal text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE a record; t record; c record;
BEGIN
 SELECT * INTO STRICT a FROM __SCHEMA__.ratification_ledger_anchor WHERE singleton=1 AND version=1;
 IF NOT a.initialized OR a.key_generation<>key_generation_arg THEN RAISE EXCEPTION 'ratification ledger anchor identity mismatch'; END IF;
 SELECT * INTO t FROM __SCHEMA__.ratification_tenant_anchors
  WHERE tenant_scope=current_setting('smesh.tenant_scope',true);
 SELECT * INTO c FROM __SCHEMA__.ratification_chain_anchors
  WHERE tenant_scope=current_setting('smesh.tenant_scope',true) AND task_id=task_id_arg;
 RETURN QUERY SELECT
  'sha256:'||encode(sha256(convert_to(key_generation_arg||':'||a.packet_count||':'||a.event_count||':'||a.retained_bytes||':'||a.generation_high_water_hash||':'||a.state_hash,'UTF8')),'hex'),
  a.state_seal,t.packet_count,t.event_count,t.key_generation,t.state_seal,
  c.packet_count,c.event_count,c.key_generation,c.state_seal;
END $fn$;
REVOKE ALL ON FUNCTION __SCHEMA__.ratification_anchor_authentication_state(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION __SCHEMA__.ratification_anchor_authentication_state(text,text) TO __ROLE__;

CREATE FUNCTION __SCHEMA__.seal_ratification_anchor(expected_digest text,key_generation_arg text,state_seal_arg text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE a record; actual_digest text;
BEGIN
 IF expected_digest!~'^sha256:[0-9a-f]{64}$' OR state_seal_arg!~'^[A-Za-z0-9_-]{43}$' THEN RAISE EXCEPTION 'invalid ratification seal input'; END IF;
 SELECT * INTO STRICT a FROM __SCHEMA__.ratification_ledger_anchor WHERE singleton=1 AND version=1 FOR UPDATE;
 actual_digest := 'sha256:'||encode(sha256(convert_to(key_generation_arg||':'||a.packet_count||':'||a.event_count||':'||a.retained_bytes||':'||a.generation_high_water_hash||':'||a.state_hash,'UTF8')),'hex');
 IF NOT a.initialized OR a.key_generation<>key_generation_arg OR a.state_seal IS NOT NULL OR actual_digest<>expected_digest THEN
  RAISE EXCEPTION 'ratification ledger anchor seal race';
 END IF;
 UPDATE __SCHEMA__.ratification_ledger_anchor
 SET state_seal=state_seal_arg
 WHERE singleton=1 AND version=1 AND initialized AND key_generation=key_generation_arg AND state_seal IS NULL;
 IF NOT FOUND THEN RAISE EXCEPTION 'ratification ledger anchor seal race'; END IF;
END $fn$;
REVOKE ALL ON FUNCTION __SCHEMA__.seal_ratification_anchor(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION __SCHEMA__.seal_ratification_anchor(text,text,text) TO __ROLE__;

CREATE FUNCTION __SCHEMA__.seal_ratification_tenant_anchor(expected_packets bigint,expected_events bigint,key_generation_arg text,state_seal_arg text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
 IF expected_packets<0 OR expected_events<0 OR state_seal_arg!~'^[A-Za-z0-9_-]{43}$' THEN RAISE EXCEPTION 'invalid ratification tenant seal input'; END IF;
 UPDATE __SCHEMA__.ratification_tenant_anchors
 SET key_generation=key_generation_arg,state_seal=state_seal_arg
 WHERE tenant_scope=current_setting('smesh.tenant_scope',true)
   AND packet_count=expected_packets AND event_count=expected_events AND state_seal IS NULL;
 IF NOT FOUND THEN RAISE EXCEPTION 'ratification tenant anchor seal race'; END IF;
END $fn$;
REVOKE ALL ON FUNCTION __SCHEMA__.seal_ratification_tenant_anchor(bigint,bigint,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION __SCHEMA__.seal_ratification_tenant_anchor(bigint,bigint,text,text) TO __ROLE__;

CREATE FUNCTION __SCHEMA__.seal_ratification_chain_anchor(task_id_arg text,expected_packets bigint,expected_events bigint,key_generation_arg text,state_seal_arg text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
 IF expected_packets<=0 OR expected_events<0 OR state_seal_arg!~'^[A-Za-z0-9_-]{43}$' THEN RAISE EXCEPTION 'invalid ratification chain seal input'; END IF;
 UPDATE __SCHEMA__.ratification_chain_anchors
 SET key_generation=key_generation_arg,state_seal=state_seal_arg
 WHERE tenant_scope=current_setting('smesh.tenant_scope',true) AND task_id=task_id_arg
   AND packet_count=expected_packets AND event_count=expected_events AND state_seal IS NULL;
 IF NOT FOUND THEN RAISE EXCEPTION 'ratification chain anchor seal race'; END IF;
END $fn$;
REVOKE ALL ON FUNCTION __SCHEMA__.seal_ratification_chain_anchor(text,bigint,bigint,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION __SCHEMA__.seal_ratification_chain_anchor(text,bigint,bigint,text,text) TO __ROLE__;

-- Startup qualification is migrator-only, capped, and returns fixed-size
-- metadata. It never transfers packet/event JSON to the application.
CREATE FUNCTION __SCHEMA__.ratification_anchor_qualify_bounded()
RETURNS TABLE(packet_count bigint,event_count bigint,retained_bytes bigint,generation_hash text,state_hash text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE p_count bigint; e_count bigint; bytes bigint; generation_state text; ledger_state text;
DECLARE probe_count bigint; anchor_initialized boolean; invalid_tenants bigint; invalid_chains bigint; anchored_packets bigint; anchored_events bigint;
BEGIN
 PERFORM set_config('smesh.internal_global','ratification-anchor-v1',true);
 SELECT count(*)::bigint INTO probe_count FROM (
  SELECT 1 FROM __SCHEMA__.ratification_packets
  UNION ALL
  SELECT 1 FROM __SCHEMA__.ratification_events
  LIMIT 100001
 ) bounded_probe;
 IF probe_count>100000 THEN RAISE EXCEPTION 'ratification startup qualification cap exceeded'; END IF;
 SELECT count(*)::bigint INTO p_count FROM __SCHEMA__.ratification_packets;
 SELECT count(*)::bigint INTO e_count FROM __SCHEMA__.ratification_events;
 SELECT initialized INTO STRICT anchor_initialized FROM __SCHEMA__.ratification_ledger_anchor WHERE singleton=1 AND version=1;
 IF anchor_initialized THEN
  WITH qualified AS (
   SELECT tenants.tenant_scope,COALESCE(p.packet_count,0)::bigint packet_count,COALESCE(e.event_count,0)::bigint event_count
   FROM (SELECT tenant_scope FROM __SCHEMA__.ratification_packets UNION SELECT tenant_scope FROM __SCHEMA__.ratification_events) tenants
   LEFT JOIN (SELECT tenant_scope,count(*)::bigint packet_count FROM __SCHEMA__.ratification_packets GROUP BY tenant_scope) p USING(tenant_scope)
   LEFT JOIN (SELECT tenant_scope,count(*)::bigint event_count FROM __SCHEMA__.ratification_events GROUP BY tenant_scope) e USING(tenant_scope)
  ), membership AS (
   SELECT a.tenant_scope anchor_tenant,q.tenant_scope qualified_tenant,a.packet_count anchor_packets,a.event_count anchor_events,q.packet_count qualified_packets,q.event_count qualified_events
   FROM __SCHEMA__.ratification_tenant_anchors a FULL OUTER JOIN qualified q USING(tenant_scope)
  )
  SELECT count(*) FILTER (WHERE anchor_tenant IS NULL OR qualified_tenant IS NULL OR anchor_packets<>qualified_packets OR anchor_events<>qualified_events)::bigint,
         COALESCE(sum(anchor_packets),0)::bigint,COALESCE(sum(anchor_events),0)::bigint
  INTO invalid_tenants,anchored_packets,anchored_events
  FROM membership;
  IF invalid_tenants<>0 OR anchored_packets<>p_count OR anchored_events<>e_count THEN
   RAISE EXCEPTION 'ratification tenant anchor qualification failed';
  END IF;
  WITH qualified AS (
   SELECT p.tenant_scope,p.task_id,count(*)::bigint packet_count,COALESCE(e.event_count,0)::bigint event_count
   FROM __SCHEMA__.ratification_packets p
   LEFT JOIN (SELECT tenant_scope,task_id,count(*)::bigint event_count FROM __SCHEMA__.ratification_events GROUP BY tenant_scope,task_id) e USING(tenant_scope,task_id)
   GROUP BY p.tenant_scope,p.task_id,e.event_count
  ), membership AS (
   SELECT a.tenant_scope anchor_tenant,q.tenant_scope qualified_tenant,a.task_id anchor_task,q.task_id qualified_task,
          a.packet_count anchor_packets,a.event_count anchor_events,q.packet_count qualified_packets,q.event_count qualified_events
   FROM __SCHEMA__.ratification_chain_anchors a FULL OUTER JOIN qualified q USING(tenant_scope,task_id)
  )
  SELECT count(*) FILTER (WHERE anchor_tenant IS NULL OR qualified_tenant IS NULL OR anchor_task IS NULL OR qualified_task IS NULL OR anchor_packets<>qualified_packets OR anchor_events<>qualified_events)::bigint
  INTO invalid_chains FROM membership;
  IF invalid_chains<>0 THEN RAISE EXCEPTION 'ratification chain anchor qualification failed'; END IF;
 END IF;
 SELECT COALESCE(sum(value),0)::bigint INTO bytes FROM (
  SELECT __SCHEMA__.row_retained_bytes(p) value FROM __SCHEMA__.ratification_packets p
  UNION ALL SELECT __SCHEMA__.row_retained_bytes(e) FROM __SCHEMA__.ratification_events e
 ) retained;
 SELECT 'sha256:'||lpad(to_hex(COALESCE(bit_xor(('x'||substr(hash,1,16))::bit(64)::bigint),0)),16,'0')
                  ||lpad(to_hex(COALESCE(bit_xor(('x'||substr(hash,17,16))::bit(64)::bigint),0)),16,'0')
                  ||lpad(to_hex(COALESCE(bit_xor(('x'||substr(hash,33,16))::bit(64)::bigint),0)),16,'0')
                  ||lpad(to_hex(COALESCE(bit_xor(('x'||substr(hash,49,16))::bit(64)::bigint),0)),16,'0')
 INTO generation_state FROM (
  SELECT encode(sha256(convert_to(jsonb_build_array(tenant_scope,task_id,generation)::text,'UTF8')),'hex') hash
  FROM __SCHEMA__.ratification_packets
 ) components;
 SELECT 'sha256:'||lpad(to_hex(COALESCE(bit_xor(('x'||substr(hash,1,16))::bit(64)::bigint),0)),16,'0')
                  ||lpad(to_hex(COALESCE(bit_xor(('x'||substr(hash,17,16))::bit(64)::bigint),0)),16,'0')
                  ||lpad(to_hex(COALESCE(bit_xor(('x'||substr(hash,33,16))::bit(64)::bigint),0)),16,'0')
                  ||lpad(to_hex(COALESCE(bit_xor(('x'||substr(hash,49,16))::bit(64)::bigint),0)),16,'0')
 INTO ledger_state FROM (
  SELECT encode(sha256(convert_to(to_jsonb(p)::text,'UTF8')),'hex') hash FROM __SCHEMA__.ratification_packets p
  UNION ALL SELECT encode(sha256(convert_to(to_jsonb(e)::text,'UTF8')),'hex') FROM __SCHEMA__.ratification_events e
 ) components;
 RETURN QUERY SELECT p_count,e_count,bytes,generation_state,ledger_state;
END $fn$;
REVOKE ALL ON FUNCTION __SCHEMA__.ratification_anchor_qualify_bounded() FROM PUBLIC,__ROLE__;

UPDATE __SCHEMA__.ratification_ledger_anchor a
SET packet_count=q.packet_count,event_count=q.event_count,retained_bytes=q.retained_bytes,
    generation_high_water_hash=q.generation_hash,state_hash=q.state_hash
FROM __SCHEMA__.ratification_anchor_qualify_bounded() q
WHERE a.singleton=1 AND a.version=1;
INSERT INTO __SCHEMA__.ratification_tenant_anchors(tenant_scope,packet_count,event_count)
SELECT tenants.tenant_scope,COALESCE(p.packet_count,0),COALESCE(e.event_count,0)
FROM (
 SELECT tenant_scope FROM __SCHEMA__.ratification_packets
 UNION SELECT tenant_scope FROM __SCHEMA__.ratification_events
) tenants
LEFT JOIN (SELECT tenant_scope,count(*)::bigint packet_count FROM __SCHEMA__.ratification_packets GROUP BY tenant_scope) p USING(tenant_scope)
LEFT JOIN (SELECT tenant_scope,count(*)::bigint event_count FROM __SCHEMA__.ratification_events GROUP BY tenant_scope) e USING(tenant_scope);
INSERT INTO __SCHEMA__.ratification_chain_anchors(tenant_scope,task_id,packet_count,event_count)
SELECT p.tenant_scope,p.task_id,count(*)::bigint,COALESCE(e.event_count,0)::bigint
FROM __SCHEMA__.ratification_packets p
LEFT JOIN (SELECT tenant_scope,task_id,count(*)::bigint event_count FROM __SCHEMA__.ratification_events GROUP BY tenant_scope,task_id) e USING(tenant_scope,task_id)
GROUP BY p.tenant_scope,p.task_id,e.event_count;
CREATE TRIGGER ratification_packet_anchor AFTER INSERT OR UPDATE ON __SCHEMA__.ratification_packets
 FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.track_ratification_anchor();
CREATE TRIGGER ratification_event_anchor AFTER INSERT ON __SCHEMA__.ratification_events
 FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.track_ratification_anchor();
ALTER TABLE __SCHEMA__.ratification_tenant_anchors ENABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.ratification_tenant_anchors FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.ratification_chain_anchors ENABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.ratification_chain_anchors FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON __SCHEMA__.ratification_tenant_anchors
 USING(tenant_scope=current_setting('smesh.tenant_scope',true))
 WITH CHECK(tenant_scope=current_setting('smesh.tenant_scope',true));
CREATE POLICY tenant_isolation ON __SCHEMA__.ratification_chain_anchors
 USING(tenant_scope=current_setting('smesh.tenant_scope',true))
 WITH CHECK(tenant_scope=current_setting('smesh.tenant_scope',true));
CREATE POLICY internal_quota_diagnostics ON __SCHEMA__.ratification_tenant_anchors FOR SELECT
 USING(current_user='__MIGRATOR__' AND current_setting('smesh.internal_global',true) IN ('diag-v1','ratification-anchor-v1'));
CREATE POLICY internal_ratification_anchor_write ON __SCHEMA__.ratification_tenant_anchors FOR ALL
 USING(current_user='__MIGRATOR__' AND current_setting('smesh.internal_global',true)='ratification-anchor-v1')
 WITH CHECK(current_user='__MIGRATOR__' AND current_setting('smesh.internal_global',true)='ratification-anchor-v1');
CREATE POLICY internal_ratification_chain_anchor ON __SCHEMA__.ratification_chain_anchors FOR ALL
 USING(current_user='__MIGRATOR__' AND current_setting('smesh.internal_global',true)='ratification-anchor-v1')
 WITH CHECK(current_user='__MIGRATOR__' AND current_setting('smesh.internal_global',true)='ratification-anchor-v1');

ALTER TABLE __SCHEMA__.tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.tasks FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.outbox FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.quota_policy_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.quota_policy_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.ratification_packets ENABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.ratification_packets FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.ratification_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.ratification_events FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.retained_authority_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.retained_authority_usage FORCE ROW LEVEL SECURITY;
