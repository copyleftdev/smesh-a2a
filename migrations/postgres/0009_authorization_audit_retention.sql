-- Bounded tenant-scoped authorization-decision retention. Revisions 1-8 remain byte-immutable.
-- A source decision is eligible only after its age horizon and when its optional
-- projection is absent (projection was disabled at insert) or terminal.
ALTER TABLE __SCHEMA__.schema_migrations DROP CONSTRAINT schema_migrations_logical_schema_version_check;
ALTER TABLE __SCHEMA__.schema_migrations ADD CONSTRAINT schema_migrations_logical_schema_version_check CHECK((revision=9 AND logical_schema_version=9) OR (revision=8 AND logical_schema_version=8) OR (revision=7 AND logical_schema_version=7) OR (revision NOT IN (7,8,9) AND logical_schema_version=6));
ALTER TABLE __SCHEMA__.store_metadata DROP CONSTRAINT store_metadata_schema_version_check;
ALTER TABLE __SCHEMA__.store_metadata ADD CONSTRAINT store_metadata_schema_version_check CHECK(schema_version IN (6,7,8,9));

CREATE TABLE __SCHEMA__.authorization_retention_diagnostics(
 tenant_scope text PRIMARY KEY,
 run_count bigint NOT NULL CHECK(run_count>0),
 total_deleted bigint NOT NULL CHECK(total_deleted>=0),
 last_deleted integer NOT NULL CHECK(last_deleted BETWEEN 0 AND 1000),
 last_projection_blocked integer NOT NULL CHECK(last_projection_blocked BETWEEN 0 AND 1000),
 last_live_rows bigint NOT NULL CHECK(last_live_rows>=0),
 last_cutoff bigint NOT NULL,
 last_run_at bigint NOT NULL
);
ALTER TABLE __SCHEMA__.authorization_retention_diagnostics ENABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.authorization_retention_diagnostics FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON __SCHEMA__.authorization_retention_diagnostics TO __ROLE__
 USING(tenant_scope=NULLIF(current_setting('smesh.tenant_scope',true),''))
 WITH CHECK(tenant_scope=NULLIF(current_setting('smesh.tenant_scope',true),''));
CREATE POLICY authorization_retention_internal ON __SCHEMA__.authorization_retention_diagnostics
 USING(current_setting('smesh.authorization_retention',true)='cleanup-v1')
 WITH CHECK(current_setting('smesh.authorization_retention',true)='cleanup-v1');
CREATE INDEX audit_projection_authorization_source
 ON __SCHEMA__.audit_projection_outbox(tenant_scope,source,source_pk_digest,state);
CREATE POLICY authorization_retention_projection ON __SCHEMA__.audit_projection_outbox
 FOR SELECT TO __MIGRATOR__
 USING(source='authorization_decisions' AND current_setting('smesh.authorization_retention',true)='cleanup-v1');

CREATE FUNCTION __SCHEMA__.guard_authorization_decision_retention() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
 IF TG_OP='DELETE'
    AND current_setting('smesh.authorization_retention',true)='cleanup-v1'
 THEN RETURN OLD; END IF;
 RAISE EXCEPTION 'authorization audit is immutable';
END $fn$;
DROP TRIGGER authorization_decisions_no_delete ON __SCHEMA__.authorization_decisions;
CREATE TRIGGER authorization_decisions_no_delete BEFORE DELETE ON __SCHEMA__.authorization_decisions
 FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.guard_authorization_decision_retention();

CREATE FUNCTION __SCHEMA__.cleanup_authorization_decisions(retention_ms bigint,max_rows integer)
RETURNS TABLE(deleted bigint,projection_blocked bigint,live_rows bigint,oldest_remaining bigint,cutoff bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE
 tenant text:=NULLIF(current_setting('smesh.tenant_scope',true),'');
 now_ms bigint:=__SCHEMA__.db_millis();
 cutoff_ms bigint;
 changed bigint;
 blocked bigint;
 remaining bigint;
 oldest bigint;
BEGIN
 IF tenant IS NULL OR retention_ms<0 OR retention_ms>315576000000
    OR max_rows<1 OR max_rows>1000
 THEN RAISE EXCEPTION 'invalid authorization retention cleanup'; END IF;
 cutoff_ms:=now_ms-retention_ms;
 PERFORM set_config('smesh.internal_global','claim-v1',true);
 PERFORM set_config('smesh.authorization_retention','cleanup-v1',true);

 SELECT count(*) INTO blocked FROM (
   SELECT 1 FROM __SCHEMA__.authorization_decisions d
   WHERE d.tenant_scope=tenant AND d.decided_at<=cutoff_ms
     AND EXISTS(
       SELECT 1 FROM __SCHEMA__.audit_projection_outbox p
       WHERE p.tenant_scope=d.tenant_scope
         AND p.source='authorization_decisions'
         AND p.source_pk_digest='sha256:'||encode(sha256(convert_to(
           'pk'||chr(31)||'smesh-audit-projection/v1'||chr(31)||'authorization_decisions'||chr(31)||
           d.tenant_scope||chr(31)||d.decision_id||chr(31)||d.policy_revision::text,'UTF8')),'hex')
         AND p.state NOT IN ('delivered','dead'))
   ORDER BY d.decided_at,d.decision_order LIMIT max_rows
 ) blocked_rows;

 WITH eligible AS (
   SELECT d.ctid FROM __SCHEMA__.authorization_decisions d
   WHERE d.tenant_scope=tenant AND d.decided_at<=cutoff_ms
     AND NOT EXISTS(
       SELECT 1 FROM __SCHEMA__.audit_projection_outbox p
       WHERE p.tenant_scope=d.tenant_scope
         AND p.source='authorization_decisions'
         AND p.source_pk_digest='sha256:'||encode(sha256(convert_to(
           'pk'||chr(31)||'smesh-audit-projection/v1'||chr(31)||'authorization_decisions'||chr(31)||
           d.tenant_scope||chr(31)||d.decision_id||chr(31)||d.policy_revision::text,'UTF8')),'hex')
         AND p.state NOT IN ('delivered','dead'))
   ORDER BY d.decided_at,d.decision_order
   FOR UPDATE OF d SKIP LOCKED LIMIT max_rows
 )
 DELETE FROM __SCHEMA__.authorization_decisions d USING eligible e WHERE d.ctid=e.ctid;
 GET DIAGNOSTICS changed=ROW_COUNT;

 SELECT count(*),min(decided_at) INTO remaining,oldest
 FROM __SCHEMA__.authorization_decisions WHERE tenant_scope=tenant;
 INSERT INTO __SCHEMA__.authorization_retention_diagnostics(
   tenant_scope,run_count,total_deleted,last_deleted,last_projection_blocked,
   last_live_rows,last_cutoff,last_run_at)
 VALUES(tenant,1,changed,changed::integer,blocked::integer,remaining,cutoff_ms,now_ms)
 ON CONFLICT(tenant_scope) DO UPDATE SET
   run_count=__SCHEMA__.authorization_retention_diagnostics.run_count+1,
   total_deleted=__SCHEMA__.authorization_retention_diagnostics.total_deleted+EXCLUDED.last_deleted,
   last_deleted=EXCLUDED.last_deleted,
   last_projection_blocked=EXCLUDED.last_projection_blocked,
   last_live_rows=EXCLUDED.last_live_rows,
   last_cutoff=EXCLUDED.last_cutoff,
   last_run_at=EXCLUDED.last_run_at;
 PERFORM set_config('smesh.internal_global','',true);
 PERFORM set_config('smesh.authorization_retention','',true);
 RETURN QUERY SELECT changed,blocked,remaining,oldest,cutoff_ms;
END $fn$;

REVOKE ALL ON FUNCTION __SCHEMA__.guard_authorization_decision_retention(),__SCHEMA__.cleanup_authorization_decisions(bigint,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION __SCHEMA__.cleanup_authorization_decisions(bigint,integer) TO __ROLE__;
REVOKE ALL ON __SCHEMA__.authorization_retention_diagnostics FROM PUBLIC,__ROLE__;
