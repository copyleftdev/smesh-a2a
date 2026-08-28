CREATE SCHEMA IF NOT EXISTS __SCHEMA__;
REVOKE ALL ON SCHEMA __SCHEMA__ FROM PUBLIC;
DO $do$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='__ROLE__') THEN
   CREATE ROLE __ROLE__ NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
 END IF;
END $do$;

CREATE FUNCTION __SCHEMA__.json_text_valid(value text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog AS $$
BEGIN PERFORM value::jsonb; RETURN true; EXCEPTION WHEN others THEN RETURN false; END $$;
CREATE FUNCTION __SCHEMA__.db_millis() RETURNS bigint
LANGUAGE sql VOLATILE SET search_path = pg_catalog AS $$
 SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint $$;
CREATE FUNCTION __SCHEMA__.reject_identity_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE field text;
BEGIN
 FOREACH field IN ARRAY TG_ARGV LOOP
   IF to_jsonb(NEW)->field IS DISTINCT FROM to_jsonb(OLD)->field THEN
     RAISE EXCEPTION 'authority identity is immutable' USING ERRCODE='23000';
   END IF;
 END LOOP;
 RETURN NEW;
END $$;
CREATE FUNCTION __SCHEMA__.reject_audit_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN RAISE EXCEPTION 'authorization decisions are append-only' USING ERRCODE='23000'; END $$;

CREATE TABLE __SCHEMA__.schema_migrations(
 revision bigint PRIMARY KEY CHECK(revision > 0), logical_schema_version bigint NOT NULL CHECK(logical_schema_version=6),
 name text NOT NULL UNIQUE, checksum text NOT NULL CHECK(octet_length(checksum)=71), applied_at bigint NOT NULL);
CREATE TABLE __SCHEMA__.store_metadata(
 singleton smallint PRIMARY KEY CHECK(singleton=1), schema_version bigint NOT NULL CHECK(schema_version=6),
 migration_hash text NOT NULL CHECK(octet_length(migration_hash)=71), catalog_hash text NOT NULL CHECK(octet_length(catalog_hash)=71), cursor_key bytea NOT NULL CHECK(octet_length(cursor_key)=32),
 receipt_key bytea NOT NULL CHECK(octet_length(receipt_key)=32));
CREATE TABLE __SCHEMA__.store_identity(
 singleton smallint PRIMARY KEY CHECK(singleton=1), store_id bytea NOT NULL UNIQUE CHECK(octet_length(store_id)=32),
 created_at bigint NOT NULL);
CREATE TABLE __SCHEMA__.tasks(
 created_order bigint GENERATED ALWAYS AS IDENTITY UNIQUE, tenant_scope text NOT NULL CHECK(octet_length(tenant_scope) BETWEEN 1 AND 64),
 task_id text NOT NULL CHECK(octet_length(task_id) BETWEEN 1 AND 4096), context_id text NOT NULL CHECK(octet_length(context_id) BETWEEN 1 AND 4096),
 state text NOT NULL CHECK(octet_length(state) BETWEEN 1 AND 256), status_timestamp text,
 revision bigint NOT NULL CHECK(revision > 0), task_json text NOT NULL CHECK(octet_length(task_json)<=1048576 AND __SCHEMA__.json_text_valid(task_json)),
 owner_account_id text NOT NULL CHECK(octet_length(owner_account_id) BETWEEN 1 AND 64), PRIMARY KEY(tenant_scope,task_id));
CREATE TABLE __SCHEMA__.task_events(
 event_order bigint GENERATED ALWAYS AS IDENTITY UNIQUE, tenant_scope text NOT NULL, task_id text NOT NULL,
 event_seq bigint NOT NULL CHECK(event_seq>0), task_revision bigint NOT NULL CHECK(task_revision>0), event_kind text NOT NULL CHECK(octet_length(event_kind) BETWEEN 1 AND 4096),
 from_state text, to_state text NOT NULL, event_json text NOT NULL CHECK(octet_length(event_json)<=1048576 AND __SCHEMA__.json_text_valid(event_json)), created_at bigint NOT NULL,
 PRIMARY KEY(tenant_scope,task_id,event_seq), FOREIGN KEY(tenant_scope,task_id) REFERENCES __SCHEMA__.tasks(tenant_scope,task_id) ON DELETE RESTRICT);
CREATE TABLE __SCHEMA__.idempotency_records(
 tenant_scope text NOT NULL, message_id text NOT NULL CHECK(octet_length(message_id) BETWEEN 1 AND 4096), request_digest text NOT NULL,
 task_id text NOT NULL, state text NOT NULL CHECK(state IN ('in_progress','completed')), admission_result_json text NOT NULL CHECK(octet_length(admission_result_json)<=1048576 AND __SCHEMA__.json_text_valid(admission_result_json)),
 final_result_json text CHECK(final_result_json IS NULL OR (octet_length(final_result_json)<=1048576 AND __SCHEMA__.json_text_valid(final_result_json))),
 created_at bigint NOT NULL, updated_at bigint NOT NULL, digest_version bigint NOT NULL CHECK(digest_version IN (1,2)), actor_account_id text,
 causative_request_json text CHECK(causative_request_json IS NULL OR __SCHEMA__.json_text_valid(causative_request_json)), invocation_kind text CHECK(invocation_kind IN ('unary','streaming')),
 PRIMARY KEY(tenant_scope,message_id), FOREIGN KEY(tenant_scope,task_id) REFERENCES __SCHEMA__.tasks(tenant_scope,task_id) ON DELETE RESTRICT,
 CHECK((state='completed')=(final_result_json IS NOT NULL)));
CREATE TABLE __SCHEMA__.outbox(
 outbox_id bigint GENERATED ALWAYS AS IDENTITY, dispatch_id text NOT NULL, tenant_scope text NOT NULL, task_id text NOT NULL, message_id text NOT NULL,
 causative_revision bigint NOT NULL CHECK(causative_revision>0), payload_json text NOT NULL CHECK(octet_length(payload_json)<=1048576 AND __SCHEMA__.json_text_valid(payload_json)), payload_digest text NOT NULL,
 state text NOT NULL CHECK(state IN ('pending','leased','delivered','dead','superseded')), attempt_count bigint NOT NULL DEFAULT 0 CHECK(attempt_count>=0),
 max_attempts bigint NOT NULL CHECK(max_attempts BETWEEN 1 AND 1000), available_at bigint NOT NULL, lease_owner text, lease_token text, lease_until bigint,
 last_error text CHECK(last_error IS NULL OR octet_length(last_error)<=4096), created_at bigint NOT NULL, updated_at bigint NOT NULL,
 dispatch_identity_version bigint NOT NULL CHECK(dispatch_identity_version IN (1,2)), PRIMARY KEY(tenant_scope,outbox_id),
 UNIQUE(tenant_scope,dispatch_id), UNIQUE(tenant_scope,dispatch_id,task_id), UNIQUE(tenant_scope,message_id),
 FOREIGN KEY(tenant_scope,task_id) REFERENCES __SCHEMA__.tasks(tenant_scope,task_id) ON DELETE RESTRICT,
 CHECK((state='leased')=(lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_until IS NOT NULL)));
CREATE TABLE __SCHEMA__.outbox_attempts(
 tenant_scope text NOT NULL, outbox_id bigint NOT NULL, attempt_no bigint NOT NULL CHECK(attempt_no>0), lease_token text NOT NULL,
 started_at bigint NOT NULL, finished_at bigint, outcome text, error text CHECK(error IS NULL OR octet_length(error)<=4096), next_attempt_at bigint,
 PRIMARY KEY(tenant_scope,outbox_id,attempt_no), FOREIGN KEY(tenant_scope,outbox_id) REFERENCES __SCHEMA__.outbox(tenant_scope,outbox_id) ON DELETE RESTRICT);
CREATE TABLE __SCHEMA__.receiver_inbox(
 tenant_scope text NOT NULL, dispatch_id text NOT NULL, payload_digest text NOT NULL, payload_json text NOT NULL CHECK(__SCHEMA__.json_text_valid(payload_json)),
 task_id text NOT NULL, context_id text NOT NULL, state text NOT NULL CHECK(state IN ('processing','completed')), lease_epoch bigint NOT NULL CHECK(lease_epoch>0),
 lease_owner text, lease_token text, lease_until bigint, completion_kind text CHECK(completion_kind IS NULL OR completion_kind IN ('success','input_required','auth_required','canceled')),
 termination_json text CHECK(termination_json IS NULL OR __SCHEMA__.json_text_valid(termination_json)), frame_count bigint, transcript_digest text,
 accepted_at bigint NOT NULL, completed_at bigint, updated_at bigint NOT NULL, PRIMARY KEY(tenant_scope,dispatch_id),
 FOREIGN KEY(tenant_scope,dispatch_id,task_id) REFERENCES __SCHEMA__.outbox(tenant_scope,dispatch_id,task_id) ON DELETE RESTRICT,
 CHECK((state='processing' AND lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_until IS NOT NULL AND completed_at IS NULL) OR
       (state='completed' AND lease_owner IS NULL AND lease_token IS NULL AND lease_until IS NULL AND completed_at IS NOT NULL)));
CREATE TABLE __SCHEMA__.receiver_frames(
 tenant_scope text NOT NULL, dispatch_id text NOT NULL, frame_seq bigint NOT NULL CHECK(frame_seq BETWEEN 1 AND 1024), frame_version bigint NOT NULL CHECK(frame_version=1),
 frame_kind text NOT NULL CHECK(frame_kind IN ('mesh_event','dispatch_error')), frame_json text NOT NULL CHECK(__SCHEMA__.json_text_valid(frame_json)), frame_digest text NOT NULL, created_at bigint NOT NULL,
 PRIMARY KEY(tenant_scope,dispatch_id,frame_seq), FOREIGN KEY(tenant_scope,dispatch_id) REFERENCES __SCHEMA__.receiver_inbox(tenant_scope,dispatch_id) ON DELETE RESTRICT);
CREATE TABLE __SCHEMA__.loopback_effects(
 tenant_scope text NOT NULL, dispatch_id text NOT NULL, effect_kind text NOT NULL CHECK(effect_kind='accepted'), committed_at bigint NOT NULL,
 PRIMARY KEY(tenant_scope,dispatch_id), FOREIGN KEY(tenant_scope,dispatch_id) REFERENCES __SCHEMA__.receiver_inbox(tenant_scope,dispatch_id) ON DELETE RESTRICT);
CREATE TABLE __SCHEMA__.stream_transcripts(
 tenant_scope text NOT NULL, message_id text NOT NULL, dispatch_id text NOT NULL, task_id text NOT NULL, transcript_version bigint NOT NULL CHECK(transcript_version=1),
 state text NOT NULL CHECK(state IN ('open','terminal','interrupted')), frame_count bigint NOT NULL CHECK(frame_count BETWEEN 0 AND 1024), transcript_digest text,
 terminal_seq bigint, interruption_error text, created_at bigint NOT NULL, updated_at bigint NOT NULL, PRIMARY KEY(tenant_scope,message_id),
 UNIQUE(tenant_scope,dispatch_id), FOREIGN KEY(tenant_scope,message_id) REFERENCES __SCHEMA__.idempotency_records(tenant_scope,message_id) ON DELETE RESTRICT,
 FOREIGN KEY(tenant_scope,dispatch_id,task_id) REFERENCES __SCHEMA__.outbox(tenant_scope,dispatch_id,task_id) ON DELETE RESTRICT);
CREATE TABLE __SCHEMA__.stream_frames(
 tenant_scope text NOT NULL, message_id text NOT NULL, frame_seq bigint NOT NULL CHECK(frame_seq BETWEEN 1 AND 1024), frame_version bigint NOT NULL CHECK(frame_version=1),
 frame_kind text NOT NULL CHECK(frame_kind IN ('task','message','status_update','artifact_update')), frame_json text NOT NULL CHECK(__SCHEMA__.json_text_valid(frame_json)),
 frame_digest text NOT NULL, created_at bigint NOT NULL, PRIMARY KEY(tenant_scope,message_id,frame_seq),
 FOREIGN KEY(tenant_scope,message_id) REFERENCES __SCHEMA__.stream_transcripts(tenant_scope,message_id) ON DELETE RESTRICT);
CREATE TABLE __SCHEMA__.cancellation_intents(
 tenant_scope text NOT NULL, dispatch_id text NOT NULL, task_id text NOT NULL, state text NOT NULL CHECK(state IN ('requested','receiver_canceled')),
 requested_at bigint NOT NULL, completed_at bigint, PRIMARY KEY(tenant_scope,dispatch_id),
 FOREIGN KEY(tenant_scope,dispatch_id,task_id) REFERENCES __SCHEMA__.outbox(tenant_scope,dispatch_id,task_id) ON DELETE RESTRICT);
CREATE TABLE __SCHEMA__.authorization_decisions(
 decision_order bigint GENERATED ALWAYS AS IDENTITY UNIQUE, decision_id text NOT NULL CHECK(octet_length(decision_id) BETWEEN 1 AND 256),
 tenant_scope text NOT NULL CHECK(octet_length(tenant_scope) BETWEEN 1 AND 64), actor_account_id text NOT NULL CHECK(octet_length(actor_account_id) BETWEEN 1 AND 64),
 policy_id text NOT NULL CHECK(octet_length(policy_id) BETWEEN 1 AND 64), policy_revision bigint NOT NULL CHECK(policy_revision>0), policy_digest text NOT NULL CHECK(octet_length(policy_digest) BETWEEN 1 AND 256),
 operation text NOT NULL CHECK(octet_length(operation) BETWEEN 1 AND 256), effect text NOT NULL CHECK(effect IN ('allow','deny')), reason text NOT NULL CHECK(octet_length(reason) BETWEEN 1 AND 256),
 resource_kind text NOT NULL CHECK(octet_length(resource_kind) BETWEEN 1 AND 256), resource_digest text NOT NULL CHECK(octet_length(resource_digest) BETWEEN 1 AND 256), task_id text, decided_at bigint NOT NULL,
 PRIMARY KEY(tenant_scope,decision_id), FOREIGN KEY(tenant_scope,task_id) REFERENCES __SCHEMA__.tasks(tenant_scope,task_id) ON DELETE RESTRICT);
CREATE TABLE __SCHEMA__.list_snapshots(
 tenant_scope text NOT NULL, snapshot_id bytea NOT NULL CHECK(octet_length(snapshot_id)=32), owner_account_id text NOT NULL, scope_digest text NOT NULL,
 query_digest text NOT NULL, total_size bigint NOT NULL CHECK(total_size>=0), page_size bigint NOT NULL CHECK(page_size BETWEEN 1 AND 100), issued_at bigint NOT NULL,
 expires_at bigint NOT NULL CHECK(expires_at>issued_at), projection_version bigint NOT NULL CHECK(projection_version=1), frozen_bytes bigint NOT NULL CHECK(frozen_bytes>=0),
 metadata_digest bytea NOT NULL CHECK(octet_length(metadata_digest)=32), PRIMARY KEY(tenant_scope,snapshot_id));
CREATE TABLE __SCHEMA__.list_snapshot_entries(
 tenant_scope text NOT NULL, snapshot_id bytea NOT NULL, ordinal bigint NOT NULL CHECK(ordinal>=0), task_id text NOT NULL, task_revision bigint NOT NULL CHECK(task_revision>0),
 task_digest text NOT NULL CHECK(octet_length(task_digest)=71), task_json text NOT NULL CHECK(__SCHEMA__.json_text_valid(task_json)), PRIMARY KEY(tenant_scope,snapshot_id,ordinal),
 UNIQUE(tenant_scope,snapshot_id,task_id), FOREIGN KEY(tenant_scope,snapshot_id) REFERENCES __SCHEMA__.list_snapshots(tenant_scope,snapshot_id) ON DELETE CASCADE);
CREATE TABLE __SCHEMA__.list_page_tokens(
 tenant_scope text NOT NULL, token_hash bytea NOT NULL CHECK(octet_length(token_hash)=32), snapshot_id bytea NOT NULL, next_position bigint NOT NULL CHECK(next_position>0),
 scope_digest text NOT NULL, query_digest text NOT NULL, token_version bigint NOT NULL CHECK(token_version=1), key_generation bigint NOT NULL CHECK(key_generation=1),
 issued_at bigint NOT NULL, expires_at bigint NOT NULL CHECK(expires_at>issued_at), PRIMARY KEY(tenant_scope,token_hash), UNIQUE(tenant_scope,snapshot_id,next_position),
 FOREIGN KEY(tenant_scope,snapshot_id) REFERENCES __SCHEMA__.list_snapshots(tenant_scope,snapshot_id) ON DELETE CASCADE);

CREATE INDEX tasks_context_state_time ON __SCHEMA__.tasks(tenant_scope,context_id,state,status_timestamp DESC NULLS LAST,task_id);
CREATE INDEX tasks_tenant_time_v6 ON __SCHEMA__.tasks(tenant_scope,status_timestamp DESC NULLS LAST,task_id);
CREATE INDEX tasks_tenant_state_time_v6 ON __SCHEMA__.tasks(tenant_scope,state,status_timestamp DESC NULLS LAST,task_id);
CREATE INDEX tasks_tenant_context_time_v6 ON __SCHEMA__.tasks(tenant_scope,context_id,status_timestamp DESC NULLS LAST,task_id);
CREATE INDEX tasks_tenant_owner_time_v6 ON __SCHEMA__.tasks(tenant_scope,owner_account_id,status_timestamp DESC NULLS LAST,task_id);
CREATE INDEX tasks_tenant_owner_state_time_v6 ON __SCHEMA__.tasks(tenant_scope,owner_account_id,state,status_timestamp DESC NULLS LAST,task_id);
CREATE INDEX tasks_tenant_owner_context_time_v6 ON __SCHEMA__.tasks(tenant_scope,owner_account_id,context_id,status_timestamp DESC NULLS LAST,task_id);
CREATE INDEX tasks_tenant_owner_context_state_time_v6 ON __SCHEMA__.tasks(tenant_scope,owner_account_id,context_id,state,status_timestamp DESC NULLS LAST,task_id);
CREATE INDEX task_events_task_revision ON __SCHEMA__.task_events(tenant_scope,task_id,task_revision);
CREATE INDEX idempotency_records_task ON __SCHEMA__.idempotency_records(tenant_scope,task_id);
CREATE INDEX outbox_due ON __SCHEMA__.outbox(state,available_at,lease_until,outbox_id);
CREATE INDEX outbox_task_state ON __SCHEMA__.outbox(tenant_scope,task_id,state);
CREATE INDEX receiver_inbox_reclaim ON __SCHEMA__.receiver_inbox(state,lease_until,accepted_at,dispatch_id);
CREATE INDEX stream_transcripts_task ON __SCHEMA__.stream_transcripts(tenant_scope,task_id,state);
CREATE INDEX cancellation_intents_task ON __SCHEMA__.cancellation_intents(tenant_scope,task_id,state);
CREATE INDEX cancellation_intents_dispatch_requested ON __SCHEMA__.cancellation_intents(dispatch_id) WHERE state='requested';
CREATE INDEX authorization_decisions_tenant_time ON __SCHEMA__.authorization_decisions(tenant_scope,decided_at,decision_order);
CREATE INDEX authorization_decisions_actor_time ON __SCHEMA__.authorization_decisions(tenant_scope,actor_account_id,decided_at);
CREATE INDEX authorization_decisions_resource_time ON __SCHEMA__.authorization_decisions(tenant_scope,resource_digest,decided_at);
CREATE INDEX list_snapshots_expiry ON __SCHEMA__.list_snapshots(tenant_scope,expires_at,snapshot_id);
CREATE INDEX list_page_tokens_snapshot ON __SCHEMA__.list_page_tokens(tenant_scope,snapshot_id,next_position);

CREATE TRIGGER tasks_identity_immutable BEFORE UPDATE ON __SCHEMA__.tasks FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_identity_change('tenant_scope','task_id','owner_account_id','created_order');
CREATE TRIGGER task_events_identity_immutable BEFORE UPDATE ON __SCHEMA__.task_events FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_identity_change('tenant_scope','task_id','event_seq','event_order');
CREATE TRIGGER idempotency_identity_immutable BEFORE UPDATE ON __SCHEMA__.idempotency_records FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_identity_change('tenant_scope','message_id','task_id');
CREATE TRIGGER outbox_identity_immutable BEFORE UPDATE ON __SCHEMA__.outbox FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_identity_change('tenant_scope','outbox_id','dispatch_id','task_id','message_id');
CREATE TRIGGER outbox_attempts_identity_immutable BEFORE UPDATE ON __SCHEMA__.outbox_attempts FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_identity_change('tenant_scope','outbox_id','attempt_no');
CREATE TRIGGER receiver_inbox_identity_immutable BEFORE UPDATE ON __SCHEMA__.receiver_inbox FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_identity_change('tenant_scope','dispatch_id','task_id','context_id');
CREATE TRIGGER receiver_frames_identity_immutable BEFORE UPDATE ON __SCHEMA__.receiver_frames FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_identity_change('tenant_scope','dispatch_id','frame_seq');
CREATE TRIGGER loopback_effects_identity_immutable BEFORE UPDATE ON __SCHEMA__.loopback_effects FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_identity_change('tenant_scope','dispatch_id','effect_kind');
CREATE TRIGGER stream_transcripts_identity_immutable BEFORE UPDATE ON __SCHEMA__.stream_transcripts FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_identity_change('tenant_scope','message_id','dispatch_id','task_id');
CREATE TRIGGER stream_frames_identity_immutable BEFORE UPDATE ON __SCHEMA__.stream_frames FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_identity_change('tenant_scope','message_id','frame_seq');
CREATE TRIGGER cancellation_identity_immutable BEFORE UPDATE ON __SCHEMA__.cancellation_intents FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_identity_change('tenant_scope','dispatch_id','task_id');
CREATE TRIGGER authorization_decisions_no_update BEFORE UPDATE ON __SCHEMA__.authorization_decisions FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_audit_mutation();
CREATE TRIGGER authorization_decisions_no_delete BEFORE DELETE ON __SCHEMA__.authorization_decisions FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_audit_mutation();
CREATE TRIGGER store_metadata_immutable BEFORE UPDATE OR DELETE ON __SCHEMA__.store_metadata FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_audit_mutation();
CREATE TRIGGER store_identity_immutable BEFORE UPDATE OR DELETE ON __SCHEMA__.store_identity FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_audit_mutation();
CREATE TRIGGER schema_migrations_immutable BEFORE UPDATE OR DELETE ON __SCHEMA__.schema_migrations FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_audit_mutation();

ALTER TABLE __SCHEMA__.tasks ENABLE ROW LEVEL SECURITY; ALTER TABLE __SCHEMA__.tasks FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.task_events ENABLE ROW LEVEL SECURITY; ALTER TABLE __SCHEMA__.task_events FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.idempotency_records ENABLE ROW LEVEL SECURITY; ALTER TABLE __SCHEMA__.idempotency_records FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.outbox ENABLE ROW LEVEL SECURITY; ALTER TABLE __SCHEMA__.outbox FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.outbox_attempts ENABLE ROW LEVEL SECURITY; ALTER TABLE __SCHEMA__.outbox_attempts FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.receiver_inbox ENABLE ROW LEVEL SECURITY; ALTER TABLE __SCHEMA__.receiver_inbox FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.receiver_frames ENABLE ROW LEVEL SECURITY; ALTER TABLE __SCHEMA__.receiver_frames FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.loopback_effects ENABLE ROW LEVEL SECURITY; ALTER TABLE __SCHEMA__.loopback_effects FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.stream_transcripts ENABLE ROW LEVEL SECURITY; ALTER TABLE __SCHEMA__.stream_transcripts FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.stream_frames ENABLE ROW LEVEL SECURITY; ALTER TABLE __SCHEMA__.stream_frames FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.cancellation_intents ENABLE ROW LEVEL SECURITY; ALTER TABLE __SCHEMA__.cancellation_intents FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.authorization_decisions ENABLE ROW LEVEL SECURITY; ALTER TABLE __SCHEMA__.authorization_decisions FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.list_snapshots ENABLE ROW LEVEL SECURITY; ALTER TABLE __SCHEMA__.list_snapshots FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.list_snapshot_entries ENABLE ROW LEVEL SECURITY; ALTER TABLE __SCHEMA__.list_snapshot_entries FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.list_page_tokens ENABLE ROW LEVEL SECURITY; ALTER TABLE __SCHEMA__.list_page_tokens FORCE ROW LEVEL SECURITY;

DO $do$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY['tasks','task_events','idempotency_records','outbox','outbox_attempts','receiver_inbox','receiver_frames','loopback_effects','stream_transcripts','stream_frames','cancellation_intents','authorization_decisions','list_snapshots','list_snapshot_entries','list_page_tokens'] LOOP
 EXECUTE format('CREATE POLICY tenant_isolation ON __SCHEMA__.%I USING (tenant_scope = current_setting(''smesh.tenant_scope'', true)) WITH CHECK (tenant_scope = current_setting(''smesh.tenant_scope'', true))',t);
END LOOP; END $do$;

-- Global workers never receive table-wide RLS authority. These fixed-search-path,
-- SECURITY DEFINER procedures expose only one bounded claim row or one boolean.
CREATE POLICY internal_claim_outbox ON __SCHEMA__.outbox FOR ALL
 USING (current_user = '__MIGRATOR__' AND current_setting('smesh.internal_global',true)='claim-v1')
 WITH CHECK (current_user = '__MIGRATOR__' AND current_setting('smesh.internal_global',true)='claim-v1');
CREATE POLICY internal_claim_attempts ON __SCHEMA__.outbox_attempts FOR ALL
 USING (current_user = '__MIGRATOR__' AND current_setting('smesh.internal_global',true)='claim-v1')
 WITH CHECK (current_user = '__MIGRATOR__' AND current_setting('smesh.internal_global',true)='claim-v1');
CREATE POLICY internal_cancel_lookup ON __SCHEMA__.cancellation_intents FOR SELECT
 USING (current_user = '__MIGRATOR__' AND current_setting('smesh.internal_global',true)='cancel-v1');
CREATE POLICY internal_cancel_outbox ON __SCHEMA__.outbox FOR SELECT
 USING (current_user = '__MIGRATOR__' AND current_setting('smesh.internal_global',true)='cancel-v1');
DO $do$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY['authorization_decisions','tasks','task_events','idempotency_records','outbox','loopback_effects'] LOOP
 EXECUTE format('CREATE POLICY internal_diagnostics ON __SCHEMA__.%I FOR SELECT USING (current_user = ''__MIGRATOR__'' AND current_setting(''smesh.internal_global'',true)=''diag-v1'')',t);
END LOOP; END $do$;

CREATE FUNCTION __SCHEMA__.claim_outbox_bounded(now_ms bigint, owner_id text, token_id text, until_ms bigint)
RETURNS TABLE(tenant_scope text,outbox_id bigint,dispatch_id text,task_id text,attempt_no bigint,max_attempts bigint,payload_json text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM set_config('smesh.internal_global','claim-v1',true);
 WITH expired AS (
   UPDATE __SCHEMA__.outbox o SET state='dead',last_error=COALESCE(o.last_error,'final outbox lease expired'),
     lease_owner=NULL,lease_token=NULL,lease_until=NULL,updated_at=now_ms
   WHERE o.state='leased' AND o.lease_until<=now_ms AND o.attempt_count>=o.max_attempts
   RETURNING o.tenant_scope,o.outbox_id,o.attempt_count
 )
 UPDATE __SCHEMA__.outbox_attempts a SET finished_at=now_ms,outcome='permanent',
   error=COALESCE(a.error,'final outbox lease expired')
 FROM expired e WHERE a.tenant_scope=e.tenant_scope AND a.outbox_id=e.outbox_id
   AND a.attempt_no=e.attempt_count AND a.finished_at IS NULL;
 RETURN QUERY
 WITH candidate AS (
   SELECT o.tenant_scope,o.outbox_id FROM __SCHEMA__.outbox o
   WHERE ((o.state='pending' AND o.available_at<=now_ms) OR (o.state='leased' AND o.lease_until<=now_ms))
     AND o.attempt_count<o.max_attempts
   ORDER BY o.available_at,o.outbox_id FOR UPDATE SKIP LOCKED LIMIT 1
 ), claimed AS (
   UPDATE __SCHEMA__.outbox o SET state='leased',attempt_count=o.attempt_count+1,
     lease_owner=owner_id,lease_token=token_id,lease_until=until_ms,updated_at=now_ms
   FROM candidate c WHERE o.tenant_scope=c.tenant_scope AND o.outbox_id=c.outbox_id
   RETURNING o.tenant_scope,o.outbox_id,o.dispatch_id,o.task_id,o.attempt_count,o.max_attempts,o.payload_json
 )
 INSERT INTO __SCHEMA__.outbox_attempts(tenant_scope,outbox_id,attempt_no,lease_token,started_at)
 SELECT c.tenant_scope,c.outbox_id,c.attempt_count,token_id,now_ms FROM claimed c
 RETURNING outbox_attempts.tenant_scope,outbox_attempts.outbox_id,
   (SELECT c.dispatch_id FROM claimed c),(SELECT c.task_id FROM claimed c),
   outbox_attempts.attempt_no,(SELECT c.max_attempts FROM claimed c),(SELECT c.payload_json FROM claimed c);
END $$;

CREATE FUNCTION __SCHEMA__.cancellation_requested_bounded(wanted_dispatch text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM set_config('smesh.internal_global','cancel-v1',true);
 RETURN EXISTS(
   SELECT 1 FROM __SCHEMA__.cancellation_intents c
   JOIN __SCHEMA__.outbox o ON o.tenant_scope=c.tenant_scope AND o.dispatch_id=c.dispatch_id
   WHERE c.dispatch_id=wanted_dispatch AND c.state='requested'
 );
END $$;

CREATE FUNCTION __SCHEMA__.authority_diagnostics_bounded()
RETURNS TABLE(authorization_count bigint,tasks bigint,events bigint,idempotency bigint,outbox bigint,effects bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM set_config('smesh.internal_global','diag-v1',true);
 RETURN QUERY SELECT
   (SELECT count(*) FROM __SCHEMA__.authorization_decisions),
   (SELECT count(*) FROM __SCHEMA__.tasks),
   (SELECT count(*) FROM __SCHEMA__.task_events),
   (SELECT count(*) FROM __SCHEMA__.idempotency_records),
   (SELECT count(*) FROM __SCHEMA__.outbox),
   (SELECT count(*) FROM __SCHEMA__.loopback_effects);
END $$;

CREATE FUNCTION __SCHEMA__.authority_tenants_bounded()
RETURNS SETOF text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM set_config('smesh.internal_global','diag-v1',true);
 RETURN QUERY SELECT DISTINCT tenant_scope FROM __SCHEMA__.tasks ORDER BY tenant_scope;
END $$;

GRANT USAGE ON SCHEMA __SCHEMA__ TO __ROLE__;
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA __SCHEMA__ TO __ROLE__;
GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA __SCHEMA__ TO __ROLE__;
GRANT EXECUTE ON FUNCTION __SCHEMA__.json_text_valid(text), __SCHEMA__.db_millis() TO __ROLE__;
REVOKE ALL ON FUNCTION __SCHEMA__.claim_outbox_bounded(bigint,text,text,bigint), __SCHEMA__.cancellation_requested_bounded(text), __SCHEMA__.authority_diagnostics_bounded(), __SCHEMA__.authority_tenants_bounded() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION __SCHEMA__.claim_outbox_bounded(bigint,text,text,bigint), __SCHEMA__.cancellation_requested_bounded(text), __SCHEMA__.authority_diagnostics_bounded(), __SCHEMA__.authority_tenants_bounded() TO __ROLE__;
REVOKE UPDATE,DELETE ON __SCHEMA__.authorization_decisions FROM __ROLE__;
REVOKE INSERT,UPDATE,DELETE ON __SCHEMA__.schema_migrations, __SCHEMA__.store_metadata, __SCHEMA__.store_identity FROM __ROLE__;
