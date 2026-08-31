-- PostgreSQL callback authority. Revision 7 is append-only; revisions 1-6 remain immutable.
ALTER TABLE __SCHEMA__.schema_migrations DROP CONSTRAINT schema_migrations_logical_schema_version_check;
ALTER TABLE __SCHEMA__.schema_migrations ADD CONSTRAINT schema_migrations_logical_schema_version_check CHECK((revision=7 AND logical_schema_version=7) OR (revision<>7 AND logical_schema_version=6));
ALTER TABLE __SCHEMA__.store_metadata DROP CONSTRAINT store_metadata_schema_version_check;
ALTER TABLE __SCHEMA__.store_metadata ADD CONSTRAINT store_metadata_schema_version_check CHECK(schema_version IN (6,7));
CREATE TABLE __SCHEMA__.callback_policy_snapshots(
 policy_id text NOT NULL CHECK(octet_length(policy_id) BETWEEN 1 AND 128),
 policy_revision bigint NOT NULL CHECK(policy_revision>0),
 policy_digest text NOT NULL CHECK(policy_digest ~ '^sha256:[0-9a-f]{64}$'),
 max_configs_per_task integer NOT NULL CHECK(max_configs_per_task BETWEEN 1 AND 32),
 max_configs_per_tenant bigint NOT NULL CHECK(max_configs_per_tenant BETWEEN 1 AND 1000000),
 max_pending bigint NOT NULL CHECK(max_pending BETWEEN 1 AND 1000000),
 max_payload_bytes integer NOT NULL CHECK(max_payload_bytes BETWEEN 1 AND 262144),
 max_attempts integer NOT NULL CHECK(max_attempts BETWEEN 1 AND 32),
 max_delivery_age_ms bigint NOT NULL CHECK(max_delivery_age_ms BETWEEN 1 AND 604800000),
 created_at bigint NOT NULL CHECK(created_at>0), PRIMARY KEY(policy_id,policy_revision)
);
CREATE TABLE __SCHEMA__.callback_enrollments(
 policy_id text NOT NULL, policy_revision bigint NOT NULL,
 tenant_scope text NOT NULL CHECK(octet_length(tenant_scope) BETWEEN 1 AND 128),
 enrollment_id text NOT NULL CHECK(octet_length(enrollment_id) BETWEEN 1 AND 128),
 enrollment_generation bigint NOT NULL CHECK(enrollment_generation>0),
 canonical_url text NOT NULL CHECK(octet_length(canonical_url) BETWEEN 1 AND 2048),
 url_digest text NOT NULL CHECK(url_digest ~ '^sha256:[0-9a-f]{64}$'),
 key_generation text NOT NULL CHECK(octet_length(key_generation) BETWEEN 1 AND 128),
 secret_reference text NOT NULL CHECK(octet_length(secret_reference) BETWEEN 1 AND 4096),
 ca_reference text, mtls_cert_reference text, mtls_key_reference text,
 PRIMARY KEY(tenant_scope,enrollment_id,enrollment_generation),
 FOREIGN KEY(policy_id,policy_revision) REFERENCES __SCHEMA__.callback_policy_snapshots(policy_id,policy_revision) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX callback_enrollments_url ON __SCHEMA__.callback_enrollments(tenant_scope,canonical_url,enrollment_generation);
CREATE TABLE __SCHEMA__.callback_configs(
 tenant_scope text NOT NULL, task_id text NOT NULL, config_id text NOT NULL CHECK(octet_length(config_id) BETWEEN 1 AND 128),
 owner_account_id text NOT NULL CHECK(octet_length(owner_account_id) BETWEEN 1 AND 128),
 principal_scope text NOT NULL CHECK(octet_length(principal_scope) BETWEEN 1 AND 256),
 enrollment_id text NOT NULL, enrollment_generation bigint NOT NULL,
 canonical_url text NOT NULL CHECK(octet_length(canonical_url) BETWEEN 1 AND 2048),
 url_digest text NOT NULL CHECK(url_digest ~ '^sha256:[0-9a-f]{64}$'),
 state text NOT NULL CHECK(state IN ('active','draining','revoked','terminal_closed')),
 causative_message_id text, created_at bigint NOT NULL CHECK(created_at>0), updated_at bigint NOT NULL CHECK(updated_at>=created_at),
 PRIMARY KEY(tenant_scope,task_id,config_id),
 FOREIGN KEY(tenant_scope,task_id) REFERENCES __SCHEMA__.tasks(tenant_scope,task_id) ON DELETE RESTRICT,
 FOREIGN KEY(tenant_scope,enrollment_id,enrollment_generation) REFERENCES __SCHEMA__.callback_enrollments(tenant_scope,enrollment_id,enrollment_generation) ON DELETE RESTRICT
);
CREATE INDEX callback_configs_task_state ON __SCHEMA__.callback_configs(tenant_scope,task_id,state,created_at,config_id);
CREATE INDEX callback_configs_task_list ON __SCHEMA__.callback_configs(tenant_scope,task_id,created_at,config_id) WHERE state<>'revoked';
CREATE TABLE __SCHEMA__.callback_events(
 tenant_scope text NOT NULL,event_id text NOT NULL CHECK(octet_length(event_id) BETWEEN 1 AND 128),task_id text NOT NULL,
 causative_revision bigint NOT NULL CHECK(causative_revision>0),payload bytea NOT NULL CHECK(octet_length(payload) BETWEEN 1 AND 262144),
 payload_digest text NOT NULL CHECK(payload_digest ~ '^sha256:[0-9a-f]{64}$'),public_egress_bytes bigint NOT NULL CHECK(public_egress_bytes>=octet_length(payload)),
 created_at bigint NOT NULL CHECK(created_at>0),expires_at bigint NOT NULL CHECK(expires_at>=created_at),PRIMARY KEY(tenant_scope,event_id),
 FOREIGN KEY(tenant_scope,task_id) REFERENCES __SCHEMA__.tasks(tenant_scope,task_id) ON DELETE RESTRICT
);
CREATE TABLE __SCHEMA__.callback_deliveries(
 tenant_scope text NOT NULL,event_id text NOT NULL,task_id text NOT NULL,config_id text NOT NULL,
 state text NOT NULL CHECK(state IN ('pending','leased','delivered','retry','dead','canceled')),available_at bigint NOT NULL,
 attempt_count integer NOT NULL DEFAULT 0 CHECK(attempt_count BETWEEN 0 AND 32),lease_owner text,lease_token text,
 lease_epoch bigint NOT NULL DEFAULT 0 CHECK(lease_epoch>=0),lease_until bigint,last_error_digest text,
 created_at bigint NOT NULL CHECK(created_at>0),updated_at bigint NOT NULL CHECK(updated_at>=created_at),
 PRIMARY KEY(tenant_scope,event_id,config_id),
 FOREIGN KEY(tenant_scope,event_id) REFERENCES __SCHEMA__.callback_events(tenant_scope,event_id) ON DELETE RESTRICT,
 FOREIGN KEY(tenant_scope,task_id,config_id) REFERENCES __SCHEMA__.callback_configs(tenant_scope,task_id,config_id) ON DELETE RESTRICT,
 CHECK((state='leased')=(lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_until IS NOT NULL)),
 CHECK(last_error_digest IS NULL OR last_error_digest ~ '^sha256:[0-9a-f]{64}$')
);
CREATE INDEX callback_deliveries_due ON __SCHEMA__.callback_deliveries(state,available_at,lease_until,tenant_scope,event_id,config_id);
CREATE INDEX callback_deliveries_tenant_due ON __SCHEMA__.callback_deliveries(tenant_scope,state,available_at,event_id,config_id);
CREATE INDEX callback_deliveries_claim ON __SCHEMA__.callback_deliveries(tenant_scope,available_at,event_id,config_id) WHERE state IN ('pending','retry');
CREATE SEQUENCE __SCHEMA__.callback_tenant_served_sequence;
CREATE TABLE __SCHEMA__.callback_tenant_scheduler(
 tenant_scope text PRIMARY KEY CHECK(octet_length(tenant_scope) BETWEEN 1 AND 128),
 last_served_sequence bigint NOT NULL
);
CREATE INDEX callback_tenant_scheduler_turn ON __SCHEMA__.callback_tenant_scheduler(last_served_sequence,tenant_scope);
CREATE TABLE __SCHEMA__.callback_attempts(
 tenant_scope text NOT NULL,event_id text NOT NULL,config_id text NOT NULL,attempt_no integer NOT NULL CHECK(attempt_no BETWEEN 1 AND 32),
 lease_epoch bigint NOT NULL CHECK(lease_epoch>0),started_at bigint NOT NULL,finished_at bigint NOT NULL,outcome text NOT NULL,
 category text,evidence_digest text CHECK(evidence_digest IS NULL OR evidence_digest ~ '^sha256:[0-9a-f]{64}$'),
 PRIMARY KEY(tenant_scope,event_id,config_id,attempt_no),
 FOREIGN KEY(tenant_scope,event_id,config_id) REFERENCES __SCHEMA__.callback_deliveries(tenant_scope,event_id,config_id) ON DELETE RESTRICT
);
CREATE TABLE __SCHEMA__.callback_audits(
 tenant_scope text NOT NULL,audit_order bigint GENERATED ALWAYS AS IDENTITY,event_kind text NOT NULL,
 source_kind text NOT NULL CHECK(source_kind IN ('callback_enrollments','callback_configs','callback_events','callback_deliveries')),
 source_pk_digest text NOT NULL CHECK(source_pk_digest ~ '^sha256:[0-9a-f]{64}$'),occurred_at bigint NOT NULL,
 PRIMARY KEY(tenant_scope,audit_order), UNIQUE(tenant_scope,event_kind,source_pk_digest)
);
CREATE INDEX callback_audits_tenant_time ON __SCHEMA__.callback_audits(tenant_scope,occurred_at,audit_order);

-- Revision-7's private audit ledger is populated in the same transaction as
-- each causative authority mutation. The closed, length-framed preimage binds
-- the exact audit kind and source-row identity without retaining plaintext URLs,
-- payloads, secret references, principals, or errors.
CREATE FUNCTION __SCHEMA__.callback_audit_digest(kind text,tenant text,task text,config text,event text,revision bigint,attempt bigint) RETURNS text LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $fn$
 SELECT 'sha256:'||encode(sha256(convert_to('smesh-callback-audit/v1'||octet_length(kind)::text||':'||kind||octet_length(tenant)::text||':'||tenant||octet_length(task)::text||':'||task||octet_length(config)::text||':'||config||octet_length(event)::text||':'||event||octet_length(revision::text)::text||':'||revision::text||octet_length(attempt::text)::text||':'||attempt::text,'UTF8')),'hex')
$fn$;
REVOKE ALL ON FUNCTION __SCHEMA__.callback_audit_digest(text,text,text,text,text,bigint,bigint) FROM PUBLIC;
CREATE FUNCTION __SCHEMA__.record_callback_audit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE row_data jsonb:=to_jsonb(NEW); tenant text:=row_data->>'tenant_scope'; task text:=''; config text:=''; event text:=''; revision bigint:=0; attempt bigint:=0; source text; occurred bigint; prior_internal text:=current_setting('smesh.internal_global',true);
BEGIN
 occurred:=CASE WHEN TG_ARGV[1]='' THEN __SCHEMA__.db_millis() ELSE COALESCE((row_data->>TG_ARGV[1])::bigint,__SCHEMA__.db_millis()) END;
 CASE TG_ARGV[0]
  WHEN 'callback_policy_reconciled' THEN source:='callback_enrollments'; config:=row_data->>'enrollment_id'; revision:=(row_data->>'enrollment_generation')::bigint;
  WHEN 'callback_config_created' THEN source:='callback_configs'; task:=row_data->>'task_id'; config:=row_data->>'config_id'; revision:=(row_data->>'enrollment_generation')::bigint;
  WHEN 'callback_config_deleted' THEN source:='callback_configs'; task:=row_data->>'task_id'; config:=row_data->>'config_id'; revision:=(row_data->>'enrollment_generation')::bigint;
  WHEN 'callback_event_enqueued' THEN source:='callback_events'; task:=row_data->>'task_id'; event:=row_data->>'event_id'; revision:=(row_data->>'causative_revision')::bigint;
  WHEN 'callback_delivery_attempted' THEN source:='callback_deliveries'; task:=row_data->>'task_id'; config:=row_data->>'config_id'; event:=row_data->>'event_id'; attempt:=(row_data->>'attempt_count')::bigint;
  WHEN 'callback_delivered' THEN source:='callback_deliveries'; task:=row_data->>'task_id'; config:=row_data->>'config_id'; event:=row_data->>'event_id'; attempt:=(row_data->>'attempt_count')::bigint;
  WHEN 'callback_retry_scheduled' THEN source:='callback_deliveries'; task:=row_data->>'task_id'; config:=row_data->>'config_id'; event:=row_data->>'event_id'; attempt:=(row_data->>'attempt_count')::bigint;
  WHEN 'callback_dead' THEN source:='callback_deliveries'; task:=row_data->>'task_id'; config:=row_data->>'config_id'; event:=row_data->>'event_id'; attempt:=(row_data->>'attempt_count')::bigint;
  ELSE RAISE EXCEPTION 'invalid callback audit kind';
 END CASE;
 PERFORM set_config('smesh.internal_global','callback-worker-v1',true);
 INSERT INTO __SCHEMA__.callback_audits(tenant_scope,event_kind,source_kind,source_pk_digest,occurred_at)
 VALUES(tenant,TG_ARGV[0],source,__SCHEMA__.callback_audit_digest(TG_ARGV[0],tenant,task,config,event,revision,attempt),occurred);
 PERFORM set_config('smesh.internal_global',COALESCE(prior_internal,''),true);
 RETURN NEW;
END $fn$;
REVOKE ALL ON FUNCTION __SCHEMA__.record_callback_audit() FROM PUBLIC;
CREATE TRIGGER callback_audit_config AFTER INSERT ON __SCHEMA__.callback_configs FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.record_callback_audit('callback_config_created','created_at');
CREATE TRIGGER callback_audit_policy AFTER INSERT ON __SCHEMA__.callback_enrollments FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.record_callback_audit('callback_policy_reconciled','');
CREATE TRIGGER callback_audit_config_delete AFTER UPDATE ON __SCHEMA__.callback_configs FOR EACH ROW WHEN (OLD.state IS DISTINCT FROM NEW.state AND OLD.state IN ('active','terminal_closed') AND NEW.state IN ('draining','revoked')) EXECUTE FUNCTION __SCHEMA__.record_callback_audit('callback_config_deleted','updated_at');
CREATE TRIGGER callback_audit_event AFTER INSERT ON __SCHEMA__.callback_events FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.record_callback_audit('callback_event_enqueued','created_at');
CREATE TRIGGER callback_audit_attempt AFTER UPDATE ON __SCHEMA__.callback_deliveries FOR EACH ROW WHEN (OLD.state IS DISTINCT FROM NEW.state AND NEW.state='leased') EXECUTE FUNCTION __SCHEMA__.record_callback_audit('callback_delivery_attempted','updated_at');
CREATE TRIGGER callback_audit_delivered AFTER UPDATE ON __SCHEMA__.callback_deliveries FOR EACH ROW WHEN (OLD.state IS DISTINCT FROM NEW.state AND NEW.state='delivered') EXECUTE FUNCTION __SCHEMA__.record_callback_audit('callback_delivered','updated_at');
CREATE TRIGGER callback_audit_retry AFTER UPDATE ON __SCHEMA__.callback_deliveries FOR EACH ROW WHEN (OLD.state IS DISTINCT FROM NEW.state AND NEW.state='retry') EXECUTE FUNCTION __SCHEMA__.record_callback_audit('callback_retry_scheduled','updated_at');
CREATE TRIGGER callback_audit_dead AFTER UPDATE ON __SCHEMA__.callback_deliveries FOR EACH ROW WHEN (OLD.state IS DISTINCT FROM NEW.state AND NEW.state='dead') EXECUTE FUNCTION __SCHEMA__.record_callback_audit('callback_dead','updated_at');

-- Revision 6 remains byte-immutable. Extend its closed projection vocabulary
-- here, then project callback facts only from the transactions that commit the
-- callback authority rows. Event identities are digest-only and never include
-- URLs, payloads, secret references, principals, or error text.
ALTER TABLE __SCHEMA__.audit_projection_outbox DROP CONSTRAINT audit_projection_outbox_source_check;
ALTER TABLE __SCHEMA__.audit_projection_outbox ADD CONSTRAINT audit_projection_outbox_source_check CHECK(source IN ('authorization_decisions','task_events','cancellation_intents','quota_denial_audits','quota_override_audits','quota_policy_reconciliation_audits','artifact_corruption_audits','artifact_key_audits','artifact_migration_plans','artifact_backup_jobs','artifact_restore_jobs','artifact_key_rotation_plans','callback_policy_snapshots','callback_configs','callback_events','callback_deliveries','callback_attempts'));
ALTER TABLE __SCHEMA__.audit_projection_outbox DROP CONSTRAINT audit_projection_outbox_event_kind_check;
ALTER TABLE __SCHEMA__.audit_projection_outbox ADD CONSTRAINT audit_projection_outbox_event_kind_check CHECK(event_kind IN ('authorization_decided','task_terminal','task_canceled','quota_denied','quota_overridden','quota_reconciled','artifact_corruption_detected','artifact_key_changed','artifact_operator_completed','callback_policy_reconciled','callback_config_created','callback_config_deleted','callback_event_enqueued','callback_delivery_attempted','callback_delivered','callback_retry_scheduled','callback_dead'));

CREATE FUNCTION __SCHEMA__.callback_reject_immutable() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN RAISE EXCEPTION 'immutable callback row'; END $$;
CREATE TRIGGER callback_audits_no_update BEFORE UPDATE OR DELETE ON __SCHEMA__.callback_audits FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.callback_reject_immutable();
CREATE TRIGGER callback_policy_no_update BEFORE UPDATE OR DELETE ON __SCHEMA__.callback_policy_snapshots FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.callback_reject_immutable();
CREATE TRIGGER callback_enrollments_no_update BEFORE UPDATE OR DELETE ON __SCHEMA__.callback_enrollments FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.callback_reject_immutable();
CREATE TRIGGER callback_events_no_update BEFORE UPDATE OR DELETE ON __SCHEMA__.callback_events FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.callback_reject_immutable();
CREATE TRIGGER callback_attempts_no_update BEFORE UPDATE OR DELETE ON __SCHEMA__.callback_attempts FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.callback_reject_immutable();
CREATE TRIGGER callback_configs_identity_immutable BEFORE UPDATE ON __SCHEMA__.callback_configs FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_identity_change('tenant_scope','task_id','config_id','enrollment_id','enrollment_generation','canonical_url','url_digest','causative_message_id','created_at');

CREATE FUNCTION __SCHEMA__.enqueue_callback_audit_projection() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE row_data jsonb:=to_jsonb(NEW); tenant text; primary_value text; revision text; occurred bigint; material text; prior_internal text:=current_setting('smesh.internal_global',true);
BEGIN
 IF NOT (SELECT enabled FROM __SCHEMA__.audit_projection_control WHERE singleton=1) OR NOT __SCHEMA__.audit_projection_session_valid() THEN RETURN NEW; END IF;
 tenant:=row_data->>'tenant_scope'; primary_value:=COALESCE(row_data->>TG_ARGV[2],'')||CASE WHEN COALESCE(TG_ARGV[5],'')='' THEN '' ELSE chr(31)||COALESCE(row_data->>TG_ARGV[5],'') END; revision:=COALESCE(row_data->>TG_ARGV[4],'0');
 occurred:=CASE WHEN TG_ARGV[3]='' THEN __SCHEMA__.db_millis() ELSE COALESCE((row_data->>TG_ARGV[3])::bigint,__SCHEMA__.db_millis()) END;
 material:='smesh-callback-audit-projection/v1'||chr(31)||TG_ARGV[0]||chr(31)||TG_ARGV[1]||chr(31)||tenant||chr(31)||primary_value||chr(31)||revision;
 PERFORM set_config('smesh.internal_global','audit-projector-v1',true);
 INSERT INTO __SCHEMA__.audit_projection_outbox(tenant_scope,event_id,source,source_pk_digest,event_kind,occurred_at,available_at)
 VALUES(tenant,'sha256:'||encode(sha256(convert_to(material,'UTF8')),'hex'),TG_ARGV[0],'sha256:'||encode(sha256(convert_to('pk'||chr(31)||material,'UTF8')),'hex'),TG_ARGV[1],occurred,occurred) ON CONFLICT(event_id) DO NOTHING;
 PERFORM set_config('smesh.internal_global',COALESCE(prior_internal,''),true);
 RETURN NEW;
END $fn$;
REVOKE ALL ON FUNCTION __SCHEMA__.enqueue_callback_audit_projection() FROM PUBLIC;
CREATE TRIGGER audit_projection_callback_policy AFTER INSERT ON __SCHEMA__.callback_enrollments FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.enqueue_callback_audit_projection('callback_policy_snapshots','callback_policy_reconciled','enrollment_id','','policy_revision');
-- Policy rows are installed before starts-at-enable projection is switched on.
-- The first committed config therefore also projects the exact enrolled policy
-- generation, without scanning or backfilling unrelated historical rows.
CREATE TRIGGER audit_projection_callback_policy_config AFTER INSERT ON __SCHEMA__.callback_configs FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.enqueue_callback_audit_projection('callback_policy_snapshots','callback_policy_reconciled','enrollment_id','created_at','enrollment_generation');
CREATE TRIGGER audit_projection_callback_config_create AFTER INSERT ON __SCHEMA__.callback_configs FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.enqueue_callback_audit_projection('callback_configs','callback_config_created','config_id','created_at','enrollment_generation','task_id');
CREATE TRIGGER audit_projection_callback_config_delete AFTER UPDATE ON __SCHEMA__.callback_configs FOR EACH ROW WHEN (OLD.state IS DISTINCT FROM NEW.state AND NEW.state IN ('draining','revoked')) EXECUTE FUNCTION __SCHEMA__.enqueue_callback_audit_projection('callback_configs','callback_config_deleted','config_id','updated_at','enrollment_generation','task_id');
CREATE TRIGGER audit_projection_callback_event AFTER INSERT ON __SCHEMA__.callback_events FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.enqueue_callback_audit_projection('callback_events','callback_event_enqueued','event_id','created_at','causative_revision');
CREATE TRIGGER audit_projection_callback_attempt AFTER UPDATE ON __SCHEMA__.callback_deliveries FOR EACH ROW WHEN (OLD.state IS DISTINCT FROM NEW.state AND NEW.state='leased') EXECUTE FUNCTION __SCHEMA__.enqueue_callback_audit_projection('callback_deliveries','callback_delivery_attempted','event_id','updated_at','attempt_count','config_id');
CREATE TRIGGER audit_projection_callback_delivered AFTER UPDATE ON __SCHEMA__.callback_deliveries FOR EACH ROW WHEN (OLD.state IS DISTINCT FROM NEW.state AND NEW.state='delivered') EXECUTE FUNCTION __SCHEMA__.enqueue_callback_audit_projection('callback_deliveries','callback_delivered','event_id','updated_at','attempt_count','config_id');
CREATE TRIGGER audit_projection_callback_retry AFTER UPDATE ON __SCHEMA__.callback_deliveries FOR EACH ROW WHEN (OLD.state IS DISTINCT FROM NEW.state AND NEW.state='retry') EXECUTE FUNCTION __SCHEMA__.enqueue_callback_audit_projection('callback_deliveries','callback_retry_scheduled','event_id','updated_at','attempt_count','config_id');
CREATE TRIGGER audit_projection_callback_dead AFTER UPDATE ON __SCHEMA__.callback_deliveries FOR EACH ROW WHEN (OLD.state IS DISTINCT FROM NEW.state AND NEW.state='dead') EXECUTE FUNCTION __SCHEMA__.enqueue_callback_audit_projection('callback_deliveries','callback_dead','event_id','updated_at','attempt_count','config_id');

DO $$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY['callback_enrollments','callback_configs','callback_events','callback_deliveries','callback_attempts','callback_audits','callback_tenant_scheduler'] LOOP
 EXECUTE format('ALTER TABLE __SCHEMA__.%I ENABLE ROW LEVEL SECURITY',t); EXECUTE format('ALTER TABLE __SCHEMA__.%I FORCE ROW LEVEL SECURITY',t);
 EXECUTE format('CREATE POLICY tenant_isolation ON __SCHEMA__.%I TO __ROLE__ USING(tenant_scope=NULLIF(current_setting(''smesh.tenant_scope'',true),'''')) WITH CHECK(tenant_scope=NULLIF(current_setting(''smesh.tenant_scope'',true),''''))',t);
 EXECUTE format('CREATE POLICY callback_internal ON __SCHEMA__.%I TO __MIGRATOR__ USING(current_setting(''smesh.internal_global'',true)=''callback-worker-v1'') WITH CHECK(current_setting(''smesh.internal_global'',true)=''callback-worker-v1'')',t);
 END LOOP; END $$;
GRANT SELECT,INSERT,UPDATE ON __SCHEMA__.callback_configs TO __ROLE__;
GRANT SELECT ON __SCHEMA__.callback_enrollments,__SCHEMA__.callback_events,__SCHEMA__.callback_deliveries,__SCHEMA__.callback_attempts TO __ROLE__;
CREATE POLICY callback_retained_internal ON __SCHEMA__.retained_authority_usage TO __MIGRATOR__
 USING(current_setting('smesh.internal_global',true)='callback-worker-v1')
 WITH CHECK(current_setting('smesh.internal_global',true)='callback-worker-v1');
REVOKE ALL ON __SCHEMA__.callback_policy_snapshots,__SCHEMA__.callback_audits FROM PUBLIC,__ROLE__;

CREATE TABLE __SCHEMA__.callback_worker_session_secret(singleton smallint PRIMARY KEY CHECK(singleton=1),proof text NOT NULL CHECK(proof ~ '^[0-9a-f]{64}$'));
INSERT INTO __SCHEMA__.callback_worker_session_secret VALUES(1,encode(sha256(convert_to(gen_random_uuid()::text||gen_random_uuid()::text,'UTF8')),'hex'));
CREATE TABLE __SCHEMA__.callback_worker_sessions(backend_pid integer PRIMARY KEY,session_nonce uuid NOT NULL,registered_at timestamptz NOT NULL DEFAULT clock_timestamp());
REVOKE ALL ON __SCHEMA__.callback_worker_session_secret,__SCHEMA__.callback_worker_sessions FROM PUBLIC,__ROLE__;
CREATE FUNCTION __SCHEMA__.register_callback_worker_session(candidate text) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE nonce uuid:=gen_random_uuid(); BEGIN IF candidate IS NULL OR NOT EXISTS(SELECT 1 FROM __SCHEMA__.callback_worker_session_secret WHERE singleton=1 AND proof=candidate) THEN RAISE EXCEPTION 'invalid callback worker proof'; END IF;
 CREATE TEMP TABLE IF NOT EXISTS callback_worker_capability(session_nonce uuid NOT NULL) ON COMMIT PRESERVE ROWS; TRUNCATE pg_temp.callback_worker_capability; INSERT INTO pg_temp.callback_worker_capability VALUES(nonce);
 INSERT INTO __SCHEMA__.callback_worker_sessions VALUES(pg_backend_pid(),nonce,clock_timestamp()) ON CONFLICT(backend_pid) DO UPDATE SET session_nonce=EXCLUDED.session_nonce,registered_at=EXCLUDED.registered_at; RETURN nonce; END $$;
CREATE FUNCTION __SCHEMA__.callback_worker_session_valid() RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN
 IF to_regclass('pg_temp.callback_worker_capability') IS NULL THEN RETURN false; END IF; RETURN EXISTS(SELECT 1 FROM __SCHEMA__.callback_worker_sessions s JOIN pg_temp.callback_worker_capability c USING(session_nonce) WHERE s.backend_pid=pg_backend_pid()); END $$;
REVOKE ALL ON FUNCTION __SCHEMA__.register_callback_worker_session(text),__SCHEMA__.callback_worker_session_valid() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION __SCHEMA__.register_callback_worker_session(text) TO __ROLE__;
CREATE FUNCTION __SCHEMA__.cancel_callback_config_deliveries(wanted_tenant text,wanted_task text,wanted_config text) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ DECLARE changed bigint; BEGIN
 IF wanted_tenant IS DISTINCT FROM NULLIF(current_setting('smesh.tenant_scope',true),'') THEN RAISE EXCEPTION 'invalid callback tenant'; END IF; PERFORM set_config('smesh.internal_global','callback-worker-v1',true);
 UPDATE __SCHEMA__.callback_deliveries SET state='canceled',lease_owner=NULL,lease_token=NULL,lease_until=NULL,updated_at=__SCHEMA__.db_millis() WHERE tenant_scope=wanted_tenant AND task_id=wanted_task AND config_id=wanted_config AND (state IN ('pending','retry') OR (state='leased' AND lease_until<=__SCHEMA__.db_millis())); GET DIAGNOSTICS changed=ROW_COUNT; RETURN changed; END $$;
REVOKE ALL ON FUNCTION __SCHEMA__.cancel_callback_config_deliveries(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION __SCHEMA__.cancel_callback_config_deliveries(text,text,text) TO __ROLE__;
CREATE FUNCTION __SCHEMA__.enqueue_terminal_callbacks(wanted_tenant text,wanted_task text,wanted_revision bigint,event text,event_payload bytea,event_digest text,egress_bytes bigint,occurred bigint) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ DECLARE active_count bigint; pending_count bigint; max_pending_value bigint; max_payload integer; max_delivery_age bigint; config_record record; test_fault text:=NULLIF(current_setting('smesh.test_callback_terminal_fault',true),''); BEGIN
 IF wanted_tenant IS DISTINCT FROM NULLIF(current_setting('smesh.tenant_scope',true),'') OR wanted_revision<1 OR event_digest IS DISTINCT FROM 'sha256:'||encode(sha256(event_payload),'hex') OR egress_bytes<octet_length(event_payload) THEN RAISE EXCEPTION 'invalid callback terminal event'; END IF;
 PERFORM set_config('smesh.internal_global','callback-worker-v1',true); PERFORM pg_advisory_xact_lock(hashtextextended('callback:'||wanted_tenant,0));
 IF NOT EXISTS(SELECT 1 FROM __SCHEMA__.tasks WHERE tenant_scope=wanted_tenant AND task_id=wanted_task AND revision=wanted_revision AND state IN ('"TASK_STATE_COMPLETED"','"TASK_STATE_FAILED"','"TASK_STATE_CANCELED"','"TASK_STATE_REJECTED"')) THEN RAISE EXCEPTION 'callback task is not terminal'; END IF;
 SELECT max_pending,max_payload_bytes,max_delivery_age_ms INTO max_pending_value,max_payload,max_delivery_age FROM __SCHEMA__.callback_policy_snapshots ORDER BY policy_revision DESC LIMIT 1; IF NOT FOUND THEN RETURN 0; END IF; IF octet_length(event_payload)>max_payload THEN RAISE EXCEPTION 'callback terminal payload exceeds policy'; END IF;
 SELECT count(*) INTO active_count FROM __SCHEMA__.callback_configs WHERE tenant_scope=wanted_tenant AND task_id=wanted_task AND state='active'; IF active_count=0 THEN RETURN 0; END IF;
 SELECT count(*) INTO pending_count FROM __SCHEMA__.callback_deliveries WHERE tenant_scope=wanted_tenant AND state IN ('pending','retry','leased'); IF pending_count+active_count>max_pending_value THEN RAISE EXCEPTION 'callback pending capacity reached'; END IF;
 IF test_fault='before_event_insert' THEN RAISE EXCEPTION 'injected callback terminal enqueue fault'; END IF;
 INSERT INTO __SCHEMA__.callback_events VALUES(wanted_tenant,event,wanted_task,wanted_revision,event_payload,event_digest,egress_bytes,occurred,occurred+max_delivery_age) ON CONFLICT DO NOTHING;
 INSERT INTO __SCHEMA__.callback_tenant_scheduler VALUES(wanted_tenant,nextval('__SCHEMA__.callback_tenant_served_sequence')) ON CONFLICT(tenant_scope) DO NOTHING;
 FOR config_record IN SELECT tenant_scope,task_id,config_id FROM __SCHEMA__.callback_configs WHERE tenant_scope=wanted_tenant AND task_id=wanted_task AND state='active' ORDER BY config_id LOOP
  IF test_fault='before_delivery_insert' THEN RAISE EXCEPTION 'injected callback terminal enqueue fault'; END IF;
  INSERT INTO __SCHEMA__.callback_deliveries(tenant_scope,event_id,task_id,config_id,state,available_at,created_at,updated_at) VALUES(config_record.tenant_scope,event,config_record.task_id,config_record.config_id,'pending',occurred,occurred,occurred) ON CONFLICT DO NOTHING;
  IF test_fault='after_delivery_insert' THEN RAISE EXCEPTION 'injected callback terminal enqueue fault'; END IF;
 END LOOP;
 IF test_fault='before_config_terminal_close' THEN RAISE EXCEPTION 'injected callback terminal enqueue fault'; END IF;
 UPDATE __SCHEMA__.callback_configs SET state='terminal_closed',updated_at=occurred WHERE tenant_scope=wanted_tenant AND task_id=wanted_task AND state='active';
 IF test_fault='after_callback_rows' THEN RAISE EXCEPTION 'injected callback terminal enqueue fault'; END IF;
 RETURN active_count; END $$;
REVOKE ALL ON FUNCTION __SCHEMA__.enqueue_terminal_callbacks(text,text,bigint,text,bytea,text,bigint,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION __SCHEMA__.enqueue_terminal_callbacks(text,text,bigint,text,bytea,text,bigint,bigint) TO __ROLE__;

CREATE FUNCTION __SCHEMA__.claim_callback_deliveries(owner text,token text,lease_ms bigint,max_rows integer,max_attempts integer)
RETURNS TABLE(tenant_scope text,event_id text,task_id text,config_id text,canonical_url text,enrollment_id text,enrollment_generation bigint,payload bytea,payload_digest text,attempt_no integer,lease_epoch bigint,lease_until bigint,owner_account_id text,principal_scope text,event_created_at bigint,event_expires_at bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ DECLARE now_ms bigint:=__SCHEMA__.db_millis(); selected_tenant text; BEGIN
 IF NOT __SCHEMA__.callback_worker_session_valid() OR max_rows<1 OR max_rows>1000 OR lease_ms<1000 OR lease_ms>300000 OR max_attempts<1 OR max_attempts>32 THEN RAISE EXCEPTION 'invalid callback claim'; END IF;
 PERFORM set_config('smesh.internal_global','callback-worker-v1',true);
 WITH expired AS MATERIALIZED (SELECT d.tenant_scope,d.event_id,d.config_id,d.attempt_count,d.lease_epoch,d.updated_at,CASE WHEN d.attempt_count>=max_attempts THEN 'dead' ELSE 'retry' END AS outcome FROM __SCHEMA__.callback_deliveries d WHERE d.state='leased' AND d.lease_until<=now_ms FOR UPDATE), recorded AS (INSERT INTO __SCHEMA__.callback_attempts(tenant_scope,event_id,config_id,attempt_no,lease_epoch,started_at,finished_at,outcome,category,evidence_digest) SELECT x.tenant_scope,x.event_id,x.config_id,x.attempt_count,x.lease_epoch,x.updated_at,now_ms,x.outcome,'lease_expired','sha256:'||encode(sha256(convert_to('callback lease expired','UTF8')),'hex') FROM expired x ON CONFLICT DO NOTHING RETURNING callback_attempts.tenant_scope,callback_attempts.event_id,callback_attempts.config_id) UPDATE __SCHEMA__.callback_deliveries d SET state=expired.outcome,available_at=now_ms,last_error_digest='sha256:'||encode(sha256(convert_to('callback lease expired','UTF8')),'hex'),lease_owner=NULL,lease_token=NULL,lease_until=NULL,updated_at=now_ms FROM expired WHERE d.tenant_scope=expired.tenant_scope AND d.event_id=expired.event_id AND d.config_id=expired.config_id AND EXISTS(SELECT 1 FROM recorded r WHERE r.tenant_scope=d.tenant_scope AND r.event_id=d.event_id AND r.config_id=d.config_id);
 SELECT s.tenant_scope INTO selected_tenant FROM __SCHEMA__.callback_tenant_scheduler s WHERE EXISTS(SELECT 1 FROM __SCHEMA__.callback_deliveries d JOIN __SCHEMA__.callback_configs c USING(tenant_scope,task_id,config_id) WHERE d.tenant_scope=s.tenant_scope AND d.state IN ('pending','retry') AND d.available_at<=now_ms AND d.attempt_count<max_attempts AND c.state IN ('active','terminal_closed')) ORDER BY s.last_served_sequence,s.tenant_scope FOR UPDATE OF s SKIP LOCKED LIMIT 1;
 IF selected_tenant IS NULL THEN RETURN; END IF;
 UPDATE __SCHEMA__.callback_tenant_scheduler AS scheduler SET last_served_sequence=nextval('__SCHEMA__.callback_tenant_served_sequence') WHERE scheduler.tenant_scope=selected_tenant;
 RETURN QUERY WITH due AS (SELECT d.tenant_scope,d.event_id,d.config_id FROM __SCHEMA__.callback_deliveries d JOIN __SCHEMA__.callback_configs c USING(tenant_scope,task_id,config_id) WHERE d.tenant_scope=selected_tenant AND d.state IN ('pending','retry') AND d.available_at<=now_ms AND d.attempt_count<max_attempts AND c.state IN ('active','terminal_closed') ORDER BY d.available_at,d.event_id,d.config_id FOR UPDATE OF d SKIP LOCKED LIMIT max_rows),
 claimed AS (UPDATE __SCHEMA__.callback_deliveries d SET state='leased',attempt_count=d.attempt_count+1,lease_owner=owner,lease_token=token,lease_epoch=d.lease_epoch+1,lease_until=now_ms+lease_ms,updated_at=now_ms FROM due WHERE d.tenant_scope=due.tenant_scope AND d.event_id=due.event_id AND d.config_id=due.config_id RETURNING d.*)
 SELECT d.tenant_scope,d.event_id,d.task_id,d.config_id,c.canonical_url,c.enrollment_id,c.enrollment_generation,e.payload,e.payload_digest,d.attempt_count,d.lease_epoch,d.lease_until,c.owner_account_id,c.principal_scope,e.created_at,e.expires_at FROM claimed d JOIN __SCHEMA__.callback_configs c USING(tenant_scope,task_id,config_id) JOIN __SCHEMA__.callback_events e USING(tenant_scope,event_id) ORDER BY d.tenant_scope,d.event_id,d.config_id; END $$;
CREATE FUNCTION __SCHEMA__.renew_callback_delivery(wanted_tenant text,wanted_event text,wanted_config text,owner text,token text,epoch bigint,lease_ms bigint) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ DECLARE now_ms bigint:=__SCHEMA__.db_millis(); until_ms bigint:=now_ms+lease_ms; BEGIN IF NOT __SCHEMA__.callback_worker_session_valid() OR lease_ms<1000 OR lease_ms>300000 THEN RAISE EXCEPTION 'invalid callback renewal'; END IF; PERFORM set_config('smesh.internal_global','callback-worker-v1',true); UPDATE __SCHEMA__.callback_deliveries SET lease_until=until_ms,updated_at=now_ms WHERE tenant_scope=wanted_tenant AND event_id=wanted_event AND config_id=wanted_config AND state='leased' AND lease_owner=owner AND lease_token=token AND lease_epoch=epoch AND lease_until>now_ms; IF FOUND THEN RETURN until_ms; END IF; RETURN NULL; END $$;
CREATE FUNCTION __SCHEMA__.finish_callback_delivery(wanted_tenant text,wanted_event text,wanted_config text,owner text,token text,epoch bigint,next_state text,category_value text,evidence text,retry_at bigint) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ DECLARE now_ms bigint:=__SCHEMA__.db_millis(); row_value record; finalized bigint; BEGIN
 IF NOT __SCHEMA__.callback_worker_session_valid() OR next_state NOT IN ('delivered','retry','dead','canceled') OR (evidence IS NOT NULL AND evidence !~ '^sha256:[0-9a-f]{64}$') THEN RAISE EXCEPTION 'invalid callback finish'; END IF; PERFORM set_config('smesh.internal_global','callback-worker-v1',true);
 UPDATE __SCHEMA__.callback_deliveries SET state=next_state,available_at=COALESCE(retry_at,now_ms),last_error_digest=evidence,lease_owner=NULL,lease_token=NULL,lease_until=NULL,updated_at=now_ms WHERE tenant_scope=wanted_tenant AND event_id=wanted_event AND config_id=wanted_config AND state='leased' AND lease_owner=owner AND lease_token=token AND lease_epoch=epoch AND lease_until>now_ms RETURNING * INTO row_value; IF NOT FOUND THEN RAISE EXCEPTION 'stale callback delivery fence'; END IF;
 INSERT INTO __SCHEMA__.callback_attempts(tenant_scope,event_id,config_id,attempt_no,lease_epoch,started_at,finished_at,outcome,category,evidence_digest) VALUES(row_value.tenant_scope,row_value.event_id,row_value.config_id,row_value.attempt_count,row_value.lease_epoch,now_ms,now_ms,next_state,category_value,evidence);
 UPDATE __SCHEMA__.callback_configs c SET state='revoked',updated_at=now_ms WHERE c.tenant_scope=row_value.tenant_scope AND c.task_id=row_value.task_id AND c.config_id=row_value.config_id AND c.state='draining' AND NOT EXISTS(SELECT 1 FROM __SCHEMA__.callback_deliveries d WHERE d.tenant_scope=c.tenant_scope AND d.task_id=c.task_id AND d.config_id=c.config_id AND d.state='leased'); GET DIAGNOSTICS finalized=ROW_COUNT; IF finalized>1 THEN RAISE EXCEPTION 'callback drain finalization escaped exact key'; END IF; RETURN next_state; END $$;
REVOKE ALL ON FUNCTION __SCHEMA__.claim_callback_deliveries(text,text,bigint,integer,integer),__SCHEMA__.renew_callback_delivery(text,text,text,text,text,bigint,bigint),__SCHEMA__.finish_callback_delivery(text,text,text,text,text,bigint,text,text,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION __SCHEMA__.claim_callback_deliveries(text,text,bigint,integer,integer),__SCHEMA__.renew_callback_delivery(text,text,text,text,text,bigint,bigint),__SCHEMA__.finish_callback_delivery(text,text,text,text,text,bigint,text,text,text,bigint) TO __ROLE__;

DO $$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY['callback_configs','callback_events','callback_deliveries','callback_attempts','callback_tenant_scheduler'] LOOP EXECUTE format('CREATE TRIGGER retained_authority_accounting AFTER INSERT OR UPDATE OR DELETE ON __SCHEMA__.%I FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.account_retained_authority_row()',t); END LOOP; END $$;
