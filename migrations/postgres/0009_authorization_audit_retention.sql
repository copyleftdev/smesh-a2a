-- Bounded operator-only authorization-decision retention. Revisions 1-8 remain byte-immutable.
-- A v9 source records whether projection was required at insert. Required sources are
-- eligible only with terminal projection evidence; disabled-at-insert sources are explicit.
ALTER TABLE __SCHEMA__.schema_migrations DROP CONSTRAINT schema_migrations_logical_schema_version_check;
ALTER TABLE __SCHEMA__.schema_migrations ADD CONSTRAINT schema_migrations_logical_schema_version_check CHECK((revision=9 AND logical_schema_version=9) OR (revision=8 AND logical_schema_version=8) OR (revision=7 AND logical_schema_version=7) OR (revision NOT IN (7,8,9) AND logical_schema_version=6));
ALTER TABLE __SCHEMA__.store_metadata DROP CONSTRAINT store_metadata_schema_version_check;
ALTER TABLE __SCHEMA__.store_metadata ADD CONSTRAINT store_metadata_schema_version_check CHECK(schema_version IN (6,7,8,9));

ALTER TABLE __SCHEMA__.authorization_decisions
 ADD COLUMN projection_required boolean NOT NULL DEFAULT false,
 ADD COLUMN projection_terminal boolean NOT NULL DEFAULT false,
 ADD COLUMN projection_source_pk_digest text;
CREATE POLICY authorization_retention_migration ON __SCHEMA__.authorization_decisions
 TO __MIGRATOR__
 USING(current_setting('smesh.authorization_retention',true)='migrate-v1')
 WITH CHECK(current_setting('smesh.authorization_retention',true)='migrate-v1');
CREATE POLICY authorization_projection_migration ON __SCHEMA__.audit_projection_outbox
 FOR SELECT TO __MIGRATOR__
 USING(current_setting('smesh.authorization_retention',true)='migrate-v1');
SELECT set_config('smesh.authorization_retention','migrate-v1',true);
ALTER TABLE __SCHEMA__.authorization_decisions DISABLE TRIGGER authorization_decisions_no_update;
ALTER TABLE __SCHEMA__.authorization_decisions DISABLE TRIGGER retained_authority_accounting;
UPDATE __SCHEMA__.authorization_decisions SET projection_source_pk_digest=
   'sha256:'||encode(sha256(convert_to(
     'pk'||chr(31)||'smesh-audit-projection/v1'||chr(31)||'authorization_decisions'||chr(31)||
     tenant_scope||chr(31)||decision_id||chr(31)||policy_revision::text,'UTF8')),'hex');
ALTER TABLE __SCHEMA__.authorization_decisions
 ALTER COLUMN projection_source_pk_digest SET NOT NULL,
 ADD CONSTRAINT authorization_decisions_projection_digest_check
 CHECK(projection_source_pk_digest ~ '^sha256:[0-9a-f]{64}$');
CREATE INDEX authorization_decisions_projection_source
 ON __SCHEMA__.authorization_decisions(tenant_scope,projection_source_pk_digest);

-- A populated v8 catalog has no obligation bit. Existing durable projection evidence is
-- the only safe proof that projection was enabled when that source was inserted.
UPDATE __SCHEMA__.authorization_decisions d SET projection_required=true
WHERE EXISTS(
 SELECT 1 FROM __SCHEMA__.audit_projection_outbox p
 WHERE p.tenant_scope=d.tenant_scope AND p.source='authorization_decisions'
   AND p.source_pk_digest=d.projection_source_pk_digest
);
UPDATE __SCHEMA__.authorization_decisions d SET projection_terminal=true
WHERE EXISTS(
 SELECT 1 FROM __SCHEMA__.audit_projection_outbox p
 WHERE p.tenant_scope=d.tenant_scope AND p.source='authorization_decisions'
   AND p.source_pk_digest=d.projection_source_pk_digest
   AND p.state IN ('delivered','dead')
);
ALTER TABLE __SCHEMA__.authorization_decisions ENABLE TRIGGER retained_authority_accounting;
ALTER TABLE __SCHEMA__.authorization_decisions ENABLE TRIGGER authorization_decisions_no_update;
DROP POLICY authorization_retention_migration ON __SCHEMA__.authorization_decisions;
DROP POLICY authorization_projection_migration ON __SCHEMA__.audit_projection_outbox;
SELECT set_config('smesh.authorization_retention','',true);

CREATE FUNCTION __SCHEMA__.mark_authorization_projection_requirement() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
 NEW.projection_source_pk_digest :=
   'sha256:'||encode(sha256(convert_to(
     'pk'||chr(31)||'smesh-audit-projection/v1'||chr(31)||'authorization_decisions'||chr(31)||
     NEW.tenant_scope||chr(31)||NEW.decision_id||chr(31)||NEW.policy_revision::text,'UTF8')),'hex');
 NEW.projection_required :=
   (SELECT enabled FROM __SCHEMA__.audit_projection_control WHERE singleton=1)
   AND __SCHEMA__.audit_projection_session_valid();
 NEW.projection_terminal := false;
 RETURN NEW;
END $fn$;
CREATE TRIGGER authorization_projection_requirement
 BEFORE INSERT ON __SCHEMA__.authorization_decisions FOR EACH ROW
 EXECUTE FUNCTION __SCHEMA__.mark_authorization_projection_requirement();

CREATE FUNCTION __SCHEMA__.guard_authorization_decision_update() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
 IF current_user='__MIGRATOR__'
    AND current_setting('smesh.internal_global',true)='audit-projector-v1'
    AND NOT OLD.projection_terminal AND NEW.projection_terminal
    AND (to_jsonb(NEW)-'projection_terminal')=(to_jsonb(OLD)-'projection_terminal')
 THEN RETURN NEW; END IF;
 RAISE EXCEPTION 'authorization audit is immutable';
END $fn$;
DROP TRIGGER authorization_decisions_no_update ON __SCHEMA__.authorization_decisions;
CREATE TRIGGER authorization_decisions_no_update BEFORE UPDATE ON __SCHEMA__.authorization_decisions
 FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.guard_authorization_decision_update();
CREATE POLICY authorization_projection_terminal_update ON __SCHEMA__.authorization_decisions
 FOR UPDATE TO __MIGRATOR__
 USING(current_setting('smesh.internal_global',true)='audit-projector-v1')
 WITH CHECK(current_setting('smesh.internal_global',true)='audit-projector-v1');
CREATE POLICY authorization_projection_retained_accounting ON __SCHEMA__.retained_authority_usage
 TO __MIGRATOR__
 USING(current_setting('smesh.internal_global',true)='audit-projector-v1')
 WITH CHECK(current_setting('smesh.internal_global',true)='audit-projector-v1');

CREATE FUNCTION __SCHEMA__.mark_authorization_projection_terminal() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
 IF NEW.source='authorization_decisions' AND NEW.state IN ('delivered','dead') THEN
  PERFORM set_config('smesh.internal_global','audit-projector-v1',true);
  UPDATE __SCHEMA__.authorization_decisions d SET projection_terminal=true
  WHERE d.tenant_scope=NEW.tenant_scope
    AND d.projection_source_pk_digest=NEW.source_pk_digest
    AND NOT d.projection_terminal;
 END IF;
 RETURN NEW;
END $fn$;
CREATE TRIGGER authorization_projection_terminal
 AFTER INSERT OR UPDATE OF state ON __SCHEMA__.audit_projection_outbox FOR EACH ROW
 EXECUTE FUNCTION __SCHEMA__.mark_authorization_projection_terminal();

CREATE TABLE __SCHEMA__.authorization_retention_diagnostics(
 tenant_scope text PRIMARY KEY,
 run_count bigint NOT NULL CHECK(run_count>0),
 total_deleted bigint NOT NULL CHECK(total_deleted>=0),
 last_deleted integer NOT NULL CHECK(last_deleted BETWEEN 0 AND 1000),
 last_projection_blocked integer NOT NULL CHECK(last_projection_blocked BETWEEN 0 AND 1000),
 last_has_more boolean NOT NULL,
 last_oldest_remaining bigint,
 last_cutoff bigint NOT NULL,
 last_run_at bigint NOT NULL
);
ALTER TABLE __SCHEMA__.authorization_retention_diagnostics ENABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.authorization_retention_diagnostics FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON __SCHEMA__.authorization_retention_diagnostics TO __ROLE__
 USING(tenant_scope=NULLIF(current_setting('smesh.tenant_scope',true),''))
 WITH CHECK(tenant_scope=NULLIF(current_setting('smesh.tenant_scope',true),''));
CREATE POLICY authorization_retention_internal ON __SCHEMA__.authorization_retention_diagnostics TO __MIGRATOR__
 USING(current_setting('smesh.authorization_retention',true)='cleanup-v1')
 WITH CHECK(current_setting('smesh.authorization_retention',true)='cleanup-v1');
CREATE INDEX audit_projection_authorization_source
 ON __SCHEMA__.audit_projection_outbox(tenant_scope,source,source_pk_digest,state);
CREATE INDEX authorization_decisions_retention_due
 ON __SCHEMA__.authorization_decisions(tenant_scope,decided_at,decision_order)
 WHERE NOT projection_required OR projection_terminal;
CREATE INDEX authorization_decisions_retention_blocked
 ON __SCHEMA__.authorization_decisions(tenant_scope,decided_at,decision_order)
 WHERE projection_required AND NOT projection_terminal;
CREATE POLICY authorization_retention_projection ON __SCHEMA__.audit_projection_outbox
 FOR ALL TO __MIGRATOR__
 USING(source='authorization_decisions' AND current_setting('smesh.authorization_retention',true)='cleanup-v1')
 WITH CHECK(source='authorization_decisions' AND current_setting('smesh.authorization_retention',true)='cleanup-v1');
CREATE POLICY authorization_projection_retention_source ON __SCHEMA__.authorization_decisions
 FOR SELECT TO __MIGRATOR__
 USING(current_setting('smesh.internal_global',true)='audit-projector-v1');

CREATE FUNCTION __SCHEMA__.guard_authorization_decision_retention() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
 IF TG_OP='DELETE' AND current_user='__MIGRATOR__'
    AND current_setting('smesh.authorization_retention',true)='cleanup-v1'
 THEN RETURN OLD; END IF;
 RAISE EXCEPTION 'authorization audit is immutable';
END $fn$;
DROP TRIGGER authorization_decisions_no_delete ON __SCHEMA__.authorization_decisions;
CREATE TRIGGER authorization_decisions_no_delete BEFORE DELETE ON __SCHEMA__.authorization_decisions
 FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.guard_authorization_decision_retention();

CREATE FUNCTION __SCHEMA__.cleanup_authorization_decisions(tenant text,retention_ms bigint,max_rows integer)
RETURNS TABLE(deleted bigint,projection_blocked bigint,has_more boolean,oldest_remaining bigint,cutoff bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE
 now_ms bigint:=__SCHEMA__.db_millis();
 cutoff_ms bigint;
 changed bigint:=0;
 blocked bigint:=0;
 more boolean:=false;
 oldest bigint;
BEGIN
 IF tenant IS NULL OR octet_length(tenant)<1 OR octet_length(tenant)>64
    OR retention_ms IS NULL OR retention_ms<0 OR retention_ms>315576000000
    OR max_rows IS NULL OR max_rows<1 OR max_rows>1000
 THEN RAISE EXCEPTION 'invalid authorization retention cleanup'; END IF;
 cutoff_ms:=now_ms-retention_ms;
 PERFORM set_config('smesh.tenant_scope',tenant,true);
 PERFORM set_config('smesh.internal_global','claim-v1',true);
 PERFORM set_config('smesh.authorization_retention','cleanup-v1',true);

 SELECT count(*) INTO blocked FROM (
   SELECT 1 FROM __SCHEMA__.authorization_decisions d
   WHERE d.tenant_scope=tenant AND d.decided_at<=cutoff_ms
     AND d.projection_required AND NOT d.projection_terminal
   ORDER BY d.decided_at,d.decision_order LIMIT max_rows
 ) blocked_rows;

 WITH eligible AS MATERIALIZED (
   SELECT d.ctid,d.tenant_scope,d.projection_source_pk_digest,d.projection_required,
          p.event_id
   FROM __SCHEMA__.authorization_decisions d
   LEFT JOIN LATERAL (
     SELECT o.event_id FROM __SCHEMA__.audit_projection_outbox o
     WHERE o.tenant_scope=d.tenant_scope AND o.source='authorization_decisions'
       AND o.source_pk_digest=d.projection_source_pk_digest
       AND o.state IN ('delivered','dead')
     ORDER BY o.event_id LIMIT 1
   ) p ON true
   WHERE d.tenant_scope=tenant AND d.decided_at<=cutoff_ms
     AND (NOT d.projection_required OR d.projection_terminal)
   ORDER BY d.decided_at,d.decision_order
   FOR UPDATE OF d SKIP LOCKED LIMIT max_rows
 ), removed_projection AS (
   DELETE FROM __SCHEMA__.audit_projection_outbox o USING eligible e
   WHERE e.projection_required AND o.tenant_scope=e.tenant_scope
     AND o.source='authorization_decisions'
     AND o.source_pk_digest=e.projection_source_pk_digest
     AND o.state IN ('delivered','dead')
   RETURNING o.event_id
 ), removed_source AS (
   DELETE FROM __SCHEMA__.authorization_decisions d USING eligible e
   WHERE d.ctid=e.ctid
     AND (NOT e.projection_required OR EXISTS(SELECT 1 FROM removed_projection p WHERE p.event_id=e.event_id))
   RETURNING d.ctid
 )
 SELECT COALESCE(sum(1),0)::bigint INTO changed FROM removed_source;

 SELECT EXISTS(
   SELECT 1 FROM __SCHEMA__.authorization_decisions d
   WHERE d.tenant_scope=tenant AND d.decided_at<=cutoff_ms
     AND (NOT d.projection_required OR (d.projection_terminal AND EXISTS(
       SELECT 1 FROM __SCHEMA__.audit_projection_outbox o
       WHERE o.tenant_scope=d.tenant_scope AND o.source='authorization_decisions'
         AND o.source_pk_digest=d.projection_source_pk_digest
         AND o.state IN ('delivered','dead')
     )))
   LIMIT 1
 ) INTO more;
 SELECT d.decided_at INTO oldest FROM __SCHEMA__.authorization_decisions d
 WHERE d.tenant_scope=tenant ORDER BY d.decided_at,d.decision_order LIMIT 1;
 INSERT INTO __SCHEMA__.authorization_retention_diagnostics(
   tenant_scope,run_count,total_deleted,last_deleted,last_projection_blocked,
   last_has_more,last_oldest_remaining,last_cutoff,last_run_at)
 VALUES(tenant,1,changed,changed::integer,blocked::integer,more,oldest,cutoff_ms,now_ms)
 ON CONFLICT(tenant_scope) DO UPDATE SET
   run_count=__SCHEMA__.authorization_retention_diagnostics.run_count+1,
   total_deleted=__SCHEMA__.authorization_retention_diagnostics.total_deleted+EXCLUDED.last_deleted,
   last_deleted=EXCLUDED.last_deleted,
   last_projection_blocked=EXCLUDED.last_projection_blocked,
   last_has_more=EXCLUDED.last_has_more,
   last_oldest_remaining=EXCLUDED.last_oldest_remaining,
   last_cutoff=EXCLUDED.last_cutoff,
   last_run_at=EXCLUDED.last_run_at;
 RETURN QUERY SELECT changed,blocked,more,oldest,cutoff_ms;
END $fn$;

-- Generic projection retention must preserve terminal authorization evidence until
-- source cleanup removes both rows atomically. Candidate and source probes are bounded.
CREATE OR REPLACE FUNCTION __SCHEMA__.cleanup_audit_projection(retention_ms bigint,max_rows integer) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE changed bigint; now_ms bigint:=__SCHEMA__.db_millis();
BEGIN
 IF NOT __SCHEMA__.audit_projection_session_valid()
    OR retention_ms IS NULL OR retention_ms<0
    OR max_rows IS NULL OR max_rows<1 OR max_rows>1000
 THEN RAISE EXCEPTION 'invalid audit projection cleanup'; END IF;
 PERFORM set_config('smesh.internal_global','audit-projector-v1',true);
 WITH candidates AS MATERIALIZED (
   SELECT o.ctid
   FROM __SCHEMA__.audit_projection_outbox o
   WHERE o.source<>'authorization_decisions'
     AND ((o.state='delivered' AND o.delivered_at<=now_ms-retention_ms)
       OR (o.state='dead' AND o.dead_at<=now_ms-retention_ms))
   ORDER BY COALESCE(o.delivered_at,o.dead_at),o.tenant_scope,o.event_id
   FOR UPDATE OF o SKIP LOCKED LIMIT max_rows
 )
 DELETE FROM __SCHEMA__.audit_projection_outbox o USING candidates c WHERE o.ctid=c.ctid;
 GET DIAGNOSTICS changed=ROW_COUNT; RETURN changed;
END $fn$;

REVOKE ALL ON FUNCTION __SCHEMA__.mark_authorization_projection_requirement(),__SCHEMA__.mark_authorization_projection_terminal(),__SCHEMA__.guard_authorization_decision_update(),__SCHEMA__.guard_authorization_decision_retention(),__SCHEMA__.cleanup_authorization_decisions(text,bigint,integer) FROM PUBLIC,__ROLE__;
GRANT EXECUTE ON FUNCTION __SCHEMA__.cleanup_authorization_decisions(text,bigint,integer) TO __MIGRATOR__;
REVOKE ALL ON __SCHEMA__.authorization_retention_diagnostics FROM PUBLIC,__ROLE__;
