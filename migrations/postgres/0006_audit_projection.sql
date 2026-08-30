-- Optional starts-at-enable durable audit projection. No historical scan is performed.
CREATE TABLE __SCHEMA__.audit_projection_control(
 singleton smallint PRIMARY KEY CHECK(singleton=1), enabled boolean NOT NULL
);
INSERT INTO __SCHEMA__.audit_projection_control VALUES(1,false);
CREATE TABLE __SCHEMA__.audit_projection_session_secret(
 singleton smallint PRIMARY KEY CHECK(singleton=1),
 proof text NOT NULL CHECK(proof ~ '^[0-9a-f]{64}$')
);
INSERT INTO __SCHEMA__.audit_projection_session_secret
VALUES(1,encode(sha256(convert_to(gen_random_uuid()::text||gen_random_uuid()::text,'UTF8')),'hex'));
CREATE TABLE __SCHEMA__.audit_projection_sessions(
 backend_pid integer PRIMARY KEY,
 session_nonce uuid NOT NULL,
 registered_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON __SCHEMA__.audit_projection_session_secret,__SCHEMA__.audit_projection_sessions FROM PUBLIC,__ROLE__;

CREATE FUNCTION __SCHEMA__.register_audit_projection_session(candidate text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE nonce uuid:=gen_random_uuid();
BEGIN
 IF candidate IS NULL
    OR NOT EXISTS(SELECT 1 FROM __SCHEMA__.audit_projection_session_secret WHERE singleton=1 AND proof=candidate)
 THEN RAISE EXCEPTION 'invalid audit projection session proof'; END IF;
 CREATE TEMP TABLE IF NOT EXISTS audit_projection_capability(session_nonce uuid NOT NULL) ON COMMIT PRESERVE ROWS;
 TRUNCATE pg_temp.audit_projection_capability;
 INSERT INTO pg_temp.audit_projection_capability VALUES(nonce);
 INSERT INTO __SCHEMA__.audit_projection_sessions(backend_pid,session_nonce)
 VALUES(pg_backend_pid(),nonce)
 ON CONFLICT(backend_pid) DO UPDATE SET session_nonce=EXCLUDED.session_nonce,registered_at=clock_timestamp();
 RETURN nonce;
END $fn$;
CREATE FUNCTION __SCHEMA__.audit_projection_session_valid() RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
 IF to_regclass('pg_temp.audit_projection_capability') IS NULL THEN RETURN false; END IF;
 RETURN EXISTS(
   SELECT 1 FROM __SCHEMA__.audit_projection_sessions s
   JOIN pg_temp.audit_projection_capability c USING(session_nonce)
   WHERE s.backend_pid=pg_backend_pid()
 );
END $fn$;
REVOKE ALL ON FUNCTION __SCHEMA__.register_audit_projection_session(text),__SCHEMA__.audit_projection_session_valid() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION __SCHEMA__.register_audit_projection_session(text) TO __ROLE__;
CREATE TABLE __SCHEMA__.audit_projection_outbox(
 tenant_scope text NOT NULL,
 event_id text NOT NULL UNIQUE CHECK(event_id ~ '^sha256:[0-9a-f]{64}$'),
 source text NOT NULL CHECK(source IN ('authorization_decisions','task_events','cancellation_intents','quota_denial_audits','quota_override_audits','quota_policy_reconciliation_audits','artifact_corruption_audits','artifact_key_audits','artifact_migration_plans','artifact_backup_jobs','artifact_restore_jobs','artifact_key_rotation_plans')),
 source_pk_digest text NOT NULL CHECK(source_pk_digest ~ '^sha256:[0-9a-f]{64}$'),
 event_kind text NOT NULL CHECK(event_kind IN ('authorization_decided','task_terminal','task_canceled','quota_denied','quota_overridden','quota_reconciled','artifact_corruption_detected','artifact_key_changed','artifact_operator_completed')),
 occurred_at bigint NOT NULL,
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','leased','delivered','dead')),
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 10),
 lease_owner text, lease_token text, lease_epoch bigint NOT NULL DEFAULT 0 CHECK(lease_epoch>=0),
 lease_expires_at bigint, available_at bigint NOT NULL, delivered_at bigint, dead_at bigint, last_error_digest text,
 PRIMARY KEY(tenant_scope,event_id),
 CHECK((state='leased')=(lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)),
 CHECK((state='delivered')=(delivered_at IS NOT NULL)),
 CHECK((state='dead')=(dead_at IS NOT NULL)),
 CHECK(last_error_digest IS NULL OR last_error_digest ~ '^sha256:[0-9a-f]{64}$')
);
CREATE INDEX audit_projection_claim ON __SCHEMA__.audit_projection_outbox(state,available_at,tenant_scope,occurred_at,event_id);
CREATE INDEX audit_projection_tenant_claim ON __SCHEMA__.audit_projection_outbox(tenant_scope,state,available_at,occurred_at,event_id);
ALTER TABLE __SCHEMA__.audit_projection_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.audit_projection_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON __SCHEMA__.audit_projection_outbox TO __ROLE__
 USING(tenant_scope=NULLIF(current_setting('smesh.tenant_scope',true),''))
 WITH CHECK(tenant_scope=NULLIF(current_setting('smesh.tenant_scope',true),''));
CREATE POLICY audit_projection_internal ON __SCHEMA__.audit_projection_outbox TO __MIGRATOR__
 USING(current_setting('smesh.internal_global',true)='audit-projector-v1')
 WITH CHECK(current_setting('smesh.internal_global',true)='audit-projector-v1');

CREATE FUNCTION __SCHEMA__.enqueue_audit_projection() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE row_data jsonb:=to_jsonb(NEW); tenant text; primary_value text; revision text; occurred bigint; material text;
BEGIN
 IF NOT (SELECT enabled FROM __SCHEMA__.audit_projection_control WHERE singleton=1)
    OR NOT __SCHEMA__.audit_projection_session_valid()
 THEN RETURN NEW; END IF;
 tenant:=row_data->>'tenant_scope';
 primary_value:=COALESCE(row_data->>TG_ARGV[2],'');
 revision:=CASE WHEN TG_NARGS>4 THEN COALESCE(row_data->>TG_ARGV[4],'0') ELSE '0' END;
 occurred:=COALESCE((row_data->>TG_ARGV[3])::bigint,__SCHEMA__.db_millis());
 material:='smesh-audit-projection/v1'||chr(31)||TG_ARGV[0]||chr(31)||tenant||chr(31)||primary_value||chr(31)||revision;
 PERFORM set_config('smesh.internal_global','audit-projector-v1',true);
 INSERT INTO __SCHEMA__.audit_projection_outbox(tenant_scope,event_id,source,source_pk_digest,event_kind,occurred_at,available_at)
 VALUES(tenant,'sha256:'||encode(sha256(convert_to(material,'UTF8')),'hex'),TG_ARGV[0],
        'sha256:'||encode(sha256(convert_to('pk'||chr(31)||material,'UTF8')),'hex'),TG_ARGV[1],occurred,occurred)
 ON CONFLICT(event_id) DO NOTHING;
 RETURN NEW;
END $fn$;
REVOKE ALL ON FUNCTION __SCHEMA__.enqueue_audit_projection() FROM PUBLIC;

CREATE TRIGGER audit_projection_authorization AFTER INSERT ON __SCHEMA__.authorization_decisions FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.enqueue_audit_projection('authorization_decisions','authorization_decided','decision_id','decided_at','policy_revision');
CREATE TRIGGER audit_projection_task_terminal AFTER INSERT ON __SCHEMA__.task_events FOR EACH ROW WHEN (NEW.to_state IN ('"TASK_STATE_COMPLETED"','"TASK_STATE_FAILED"','"TASK_STATE_REJECTED"')) EXECUTE FUNCTION __SCHEMA__.enqueue_audit_projection('task_events','task_terminal','task_id','created_at','event_seq');
CREATE TRIGGER audit_projection_task_canceled AFTER INSERT ON __SCHEMA__.task_events FOR EACH ROW WHEN (NEW.to_state='"TASK_STATE_CANCELED"') EXECUTE FUNCTION __SCHEMA__.enqueue_audit_projection('task_events','task_canceled','task_id','created_at','event_seq');
CREATE TRIGGER audit_projection_cancellation AFTER INSERT ON __SCHEMA__.cancellation_intents FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.enqueue_audit_projection('cancellation_intents','task_canceled','dispatch_id','requested_at');
CREATE TRIGGER audit_projection_quota_denial AFTER INSERT ON __SCHEMA__.quota_denial_audits FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.enqueue_audit_projection('quota_denial_audits','quota_denied','decision_key','denied_at');
CREATE TRIGGER audit_projection_quota_override AFTER INSERT ON __SCHEMA__.quota_override_audits FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.enqueue_audit_projection('quota_override_audits','quota_overridden','override_id','created_at');
CREATE TRIGGER audit_projection_quota_reconciliation AFTER INSERT ON __SCHEMA__.quota_policy_reconciliation_audits FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.enqueue_audit_projection('quota_policy_reconciliation_audits','quota_reconciled','reconciliation_id','created_at');
CREATE TRIGGER audit_projection_artifact_corruption AFTER INSERT ON __SCHEMA__.artifact_corruption_audits FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.enqueue_audit_projection('artifact_corruption_audits','artifact_corruption_detected','audit_id','detected_at');
CREATE TRIGGER audit_projection_artifact_key AFTER INSERT ON __SCHEMA__.artifact_key_audits FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.enqueue_audit_projection('artifact_key_audits','artifact_key_changed','audit_id','created_at');
CREATE TRIGGER audit_projection_artifact_migration AFTER UPDATE ON __SCHEMA__.artifact_migration_plans FOR EACH ROW WHEN (OLD.state IS DISTINCT FROM NEW.state AND NEW.state IN ('completed','failed')) EXECUTE FUNCTION __SCHEMA__.enqueue_audit_projection('artifact_migration_plans','artifact_operator_completed','plan_id','completed_at');
CREATE TRIGGER audit_projection_artifact_backup AFTER UPDATE ON __SCHEMA__.artifact_backup_jobs FOR EACH ROW WHEN (OLD.state IS DISTINCT FROM NEW.state AND NEW.state IN ('sealed','failed')) EXECUTE FUNCTION __SCHEMA__.enqueue_audit_projection('artifact_backup_jobs','artifact_operator_completed','backup_id','sealed_at');
CREATE TRIGGER audit_projection_artifact_restore AFTER UPDATE ON __SCHEMA__.artifact_restore_jobs FOR EACH ROW WHEN (OLD.state IS DISTINCT FROM NEW.state AND NEW.state IN ('enabled','failed')) EXECUTE FUNCTION __SCHEMA__.enqueue_audit_projection('artifact_restore_jobs','artifact_operator_completed','restore_id','enabled_at');
CREATE TRIGGER audit_projection_artifact_rotation AFTER UPDATE ON __SCHEMA__.artifact_key_rotation_plans FOR EACH ROW WHEN (OLD.state IS DISTINCT FROM NEW.state AND NEW.state IN ('completed','failed')) EXECUTE FUNCTION __SCHEMA__.enqueue_audit_projection('artifact_key_rotation_plans','artifact_operator_completed','rotation_id','completed_at');

CREATE FUNCTION __SCHEMA__.claim_audit_projection(owner text,token text,lease_ms bigint,max_rows integer)
RETURNS TABLE(tenant_scope text,event_id text,source text,source_pk_digest text,event_kind text,occurred_at bigint,lease_epoch bigint,lease_expires_at bigint,attempts integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE now_ms bigint:=__SCHEMA__.db_millis();
BEGIN
 IF NOT __SCHEMA__.audit_projection_session_valid() OR max_rows<1 OR max_rows>1000 OR lease_ms<1 OR lease_ms>300000 THEN RAISE EXCEPTION 'invalid audit projection claim'; END IF;
 PERFORM set_config('smesh.internal_global','audit-projector-v1',true);
 UPDATE __SCHEMA__.audit_projection_outbox o SET state=CASE WHEN o.attempts>=10 THEN 'dead' ELSE 'pending' END,dead_at=CASE WHEN o.attempts>=10 THEN now_ms ELSE NULL END,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,available_at=now_ms WHERE o.state='leased' AND o.lease_expires_at<=now_ms;
 RETURN QUERY WITH ranked AS (
   SELECT o.tenant_scope,o.event_id,o.attempts,o.available_at,o.occurred_at,
          row_number() OVER(PARTITION BY o.tenant_scope ORDER BY o.attempts,o.available_at,o.occurred_at,o.event_id) AS tenant_rank
   FROM __SCHEMA__.audit_projection_outbox o
   WHERE o.state='pending' AND o.available_at<=now_ms AND o.attempts<10
 ), due AS (
   SELECT o.tenant_scope,o.event_id FROM __SCHEMA__.audit_projection_outbox o
   JOIN ranked r USING(tenant_scope,event_id)
   ORDER BY r.tenant_rank,r.attempts,r.available_at,r.tenant_scope,r.occurred_at,r.event_id
   FOR UPDATE OF o SKIP LOCKED LIMIT max_rows
 ), claimed AS (
   UPDATE __SCHEMA__.audit_projection_outbox o SET state='leased',attempts=o.attempts+1,lease_owner=owner,lease_token=token,lease_epoch=o.lease_epoch+1,lease_expires_at=now_ms+lease_ms
   FROM due d WHERE o.tenant_scope=d.tenant_scope AND o.event_id=d.event_id
   RETURNING o.tenant_scope,o.event_id,o.source,o.source_pk_digest,o.event_kind,o.occurred_at,o.lease_epoch,o.lease_expires_at,o.attempts
 ) SELECT * FROM claimed ORDER BY tenant_scope,occurred_at,event_id;
END $fn$;

CREATE FUNCTION __SCHEMA__.commit_audit_projection(wanted_event text,owner text,token text,epoch bigint) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$ DECLARE changed integer; now_ms bigint:=__SCHEMA__.db_millis(); BEGIN
 IF NOT __SCHEMA__.audit_projection_session_valid() THEN RAISE EXCEPTION 'invalid audit projection session'; END IF;
 PERFORM set_config('smesh.internal_global','audit-projector-v1',true);
 UPDATE __SCHEMA__.audit_projection_outbox SET state='delivered',delivered_at=now_ms,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE event_id=wanted_event AND state='leased' AND lease_owner=owner AND lease_token=token AND lease_epoch=epoch AND lease_expires_at>now_ms;
 GET DIAGNOSTICS changed=ROW_COUNT; RETURN changed=1; END $fn$;
CREATE FUNCTION __SCHEMA__.fail_audit_projection(wanted_event text,owner text,token text,epoch bigint,error_digest text,retry_ms bigint) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$ DECLARE changed integer; result text; now_ms bigint:=__SCHEMA__.db_millis(); BEGIN
 IF NOT __SCHEMA__.audit_projection_session_valid() OR retry_ms<0 OR retry_ms>300000 OR error_digest !~ '^sha256:[0-9a-f]{64}$' THEN RAISE EXCEPTION 'invalid audit projection failure'; END IF;
 PERFORM set_config('smesh.internal_global','audit-projector-v1',true);
 UPDATE __SCHEMA__.audit_projection_outbox SET state=CASE WHEN attempts>=10 THEN 'dead' ELSE 'pending' END,dead_at=CASE WHEN attempts>=10 THEN now_ms ELSE NULL END,available_at=now_ms+retry_ms,last_error_digest=error_digest,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE event_id=wanted_event AND state='leased' AND lease_owner=owner AND lease_token=token AND lease_epoch=epoch AND lease_expires_at>now_ms RETURNING state INTO result;
 GET DIAGNOSTICS changed=ROW_COUNT; RETURN CASE WHEN changed=1 THEN result ELSE 'leased' END; END $fn$;
CREATE FUNCTION __SCHEMA__.cleanup_audit_projection(retention_ms bigint,max_rows integer) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$ DECLARE changed bigint; now_ms bigint:=__SCHEMA__.db_millis(); BEGIN
 IF NOT __SCHEMA__.audit_projection_session_valid() OR retention_ms<0 OR max_rows<1 OR max_rows>1000 THEN RAISE EXCEPTION 'invalid audit projection cleanup'; END IF;
 PERFORM set_config('smesh.internal_global','audit-projector-v1',true);
 WITH doomed AS (SELECT ctid FROM __SCHEMA__.audit_projection_outbox WHERE (state='delivered' AND delivered_at<=now_ms-retention_ms) OR (state='dead' AND dead_at<=now_ms-retention_ms) ORDER BY COALESCE(delivered_at,dead_at),tenant_scope,event_id FOR UPDATE SKIP LOCKED LIMIT max_rows) DELETE FROM __SCHEMA__.audit_projection_outbox o USING doomed d WHERE o.ctid=d.ctid;
 GET DIAGNOSTICS changed=ROW_COUNT; RETURN changed; END $fn$;

REVOKE ALL ON FUNCTION __SCHEMA__.claim_audit_projection(text,text,bigint,integer),__SCHEMA__.commit_audit_projection(text,text,text,bigint),__SCHEMA__.fail_audit_projection(text,text,text,bigint,text,bigint),__SCHEMA__.cleanup_audit_projection(bigint,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION __SCHEMA__.claim_audit_projection(text,text,bigint,integer),__SCHEMA__.commit_audit_projection(text,text,text,bigint),__SCHEMA__.fail_audit_projection(text,text,text,bigint,text,bigint),__SCHEMA__.cleanup_audit_projection(bigint,integer) TO __ROLE__;
REVOKE ALL ON __SCHEMA__.audit_projection_outbox FROM __ROLE__;
REVOKE ALL ON __SCHEMA__.audit_projection_control FROM PUBLIC,__ROLE__;
