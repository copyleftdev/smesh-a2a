-- Include durable human-ratification packets and receipts in the bounded retained-authority domain.
ALTER TABLE __SCHEMA__.schema_migrations DROP CONSTRAINT schema_migrations_logical_schema_version_check;
ALTER TABLE __SCHEMA__.schema_migrations ADD CONSTRAINT schema_migrations_logical_schema_version_check CHECK((revision=11 AND logical_schema_version=11) OR (revision=10 AND logical_schema_version=10) OR (revision=9 AND logical_schema_version=9) OR (revision=8 AND logical_schema_version=8) OR (revision=7 AND logical_schema_version=7) OR (revision NOT IN (7,8,9,10,11) AND logical_schema_version=6));
ALTER TABLE __SCHEMA__.store_metadata DROP CONSTRAINT store_metadata_schema_version_check;
ALTER TABLE __SCHEMA__.store_metadata ADD CONSTRAINT store_metadata_schema_version_check CHECK(schema_version IN (6,7,8,9,10,11));

-- The migrator intentionally has no BYPASSRLS. Fence every table consulted by
-- retained_account/retained_principal and make the backfill fully visible only
-- inside this migration transaction.
LOCK TABLE __SCHEMA__.tasks,__SCHEMA__.quota_policy_versions,__SCHEMA__.ratification_packets,__SCHEMA__.ratification_events,__SCHEMA__.retained_authority_usage IN ACCESS EXCLUSIVE MODE;
ALTER TABLE __SCHEMA__.tasks DISABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.quota_policy_versions DISABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.ratification_packets DISABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.ratification_events DISABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.retained_authority_usage DISABLE ROW LEVEL SECURITY;

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
DECLARE principal text; packet_principal text; binding text; account text; task text;
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
 PERFORM set_config('smesh.internal_global','diag-v1',true);
 expression:=CASE wanted_kind WHEN 'account' THEN 'retained_account' ELSE 'retained_principal' END;
 FOREACH t IN ARRAY ARRAY[
  'artifact_backup_inventory','artifact_backup_key_dependencies','artifact_backup_jobs','artifact_backup_leases','artifact_corruption_audits','artifact_key_audits','artifact_key_generations','artifact_key_rotation_plans','artifact_migration_plans','artifact_reencryption_jobs','artifact_restore_jobs','artifact_chunks','artifact_gc_jobs','artifact_manifests','artifact_read_leases','artifact_references','artifact_retention_holds','artifact_tombstones','content_objects','provenance_edges','upload_intents'
 ] LOOP
  RETURN QUERY EXECUTE format('SELECT DISTINCT __SCHEMA__.%I(to_jsonb(r)) FROM __SCHEMA__.%I r WHERE tenant_scope=$1 AND __SCHEMA__.%I(to_jsonb(r)) IS NOT NULL',expression,t,expression) USING wanted_tenant;
 END LOOP;
END $$;
REVOKE ALL ON FUNCTION __SCHEMA__.artifact_retained_scopes_bounded(text,text) FROM PUBLIC;
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
 USING(current_user='__MIGRATOR__' AND current_setting('smesh.internal_global',true)='diag-v1');
CREATE POLICY internal_quota_diagnostics ON __SCHEMA__.ratification_events FOR SELECT
 USING(current_user='__MIGRATOR__' AND current_setting('smesh.internal_global',true)='diag-v1');

ALTER TABLE __SCHEMA__.tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.tasks FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.quota_policy_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.quota_policy_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.ratification_packets ENABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.ratification_packets FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.ratification_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.ratification_events FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.retained_authority_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.retained_authority_usage FORCE ROW LEVEL SECURITY;
