-- Persist exact per-admission runtime authorization scope without fabricating legacy provenance.
ALTER TABLE __SCHEMA__.schema_migrations DROP CONSTRAINT schema_migrations_logical_schema_version_check;
ALTER TABLE __SCHEMA__.schema_migrations ADD CONSTRAINT schema_migrations_logical_schema_version_check CHECK((revision=12 AND logical_schema_version=12) OR (revision=11 AND logical_schema_version=11) OR (revision=10 AND logical_schema_version=10) OR (revision=9 AND logical_schema_version=9) OR (revision=8 AND logical_schema_version=8) OR (revision=7 AND logical_schema_version=7) OR (revision NOT IN (7,8,9,10,11,12) AND logical_schema_version=6));
ALTER TABLE __SCHEMA__.store_metadata DROP CONSTRAINT store_metadata_schema_version_check;
ALTER TABLE __SCHEMA__.store_metadata ADD CONSTRAINT store_metadata_schema_version_check CHECK(schema_version IN (6,7,8,9,10,11,12));

LOCK TABLE __SCHEMA__.tasks,__SCHEMA__.idempotency_records,__SCHEMA__.retained_authority_usage,__SCHEMA__.quota_policy_versions IN ACCESS EXCLUSIVE MODE;
ALTER TABLE __SCHEMA__.tasks DISABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.idempotency_records DISABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.retained_authority_usage DISABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.quota_policy_versions DISABLE ROW LEVEL SECURITY;
CREATE TEMP TABLE smesh_runtime_authority_task_bytes ON COMMIT DROP AS
 SELECT tenant_scope,task_id,owner_account_id,principal_scope,__SCHEMA__.row_retained_bytes(t) AS retained_bytes
 FROM __SCHEMA__.tasks t;
CREATE TEMP TABLE smesh_runtime_authority_idempotency_bytes ON COMMIT DROP AS
 SELECT tenant_scope,message_id,__SCHEMA__.retained_account(to_jsonb(i)) AS account_id,
        __SCHEMA__.retained_principal(to_jsonb(i)) AS principal_scope,
        __SCHEMA__.row_retained_bytes(i) AS retained_bytes
 FROM __SCHEMA__.idempotency_records i;

ALTER TABLE __SCHEMA__.tasks
 ADD COLUMN IF NOT EXISTS visibility text CHECK(visibility IN ('own','tenant')),
 ADD COLUMN authorization_decision_id text;
ALTER TABLE __SCHEMA__.idempotency_records
 ADD COLUMN authorization_principal_scope text,
 ADD COLUMN authorization_authentication_method text,
 ADD COLUMN authorization_visibility text CHECK(authorization_visibility IN ('own','tenant')),
 ADD COLUMN authorization_policy_id text,
 ADD COLUMN authorization_policy_revision bigint CHECK(authorization_policy_revision IS NULL OR authorization_policy_revision>0),
 ADD COLUMN authorization_policy_digest text,
 ADD COLUMN authorization_decision_id text,
 ADD COLUMN authorization_decided_at bigint;
CREATE INDEX idempotency_runtime_authorization_decision
 ON __SCHEMA__.idempotency_records(tenant_scope,authorization_decision_id)
 WHERE authorization_decision_id IS NOT NULL;

-- Prefer the authenticated runtime principal on idempotency rows while
-- preserving the legacy principal/account fallback for pre-revision-12 rows.
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
 principal := value->>'authorization_principal_scope';
 IF principal IS NOT NULL AND principal<>'' THEN RETURN principal; END IF;
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

-- Adding a nullable column changes to_jsonb(row), hence retained byte accounting,
-- even though legacy provenance remains NULL. Reconcile that exact structural delta.
WITH task_deltas AS (
 SELECT o.tenant_scope,o.owner_account_id,o.principal_scope,
        n.retained_bytes-o.retained_bytes AS retained_delta
 FROM smesh_runtime_authority_task_bytes o
 JOIN (
  SELECT tenant_scope,task_id,__SCHEMA__.row_retained_bytes(t) AS retained_bytes
  FROM __SCHEMA__.tasks t
 ) n USING(tenant_scope,task_id)
), idempotency_deltas AS (
 SELECT o.tenant_scope,o.account_id,o.principal_scope,
        n.retained_bytes-o.retained_bytes AS retained_delta
 FROM smesh_runtime_authority_idempotency_bytes o
 JOIN (
  SELECT tenant_scope,message_id,__SCHEMA__.row_retained_bytes(i) AS retained_bytes
  FROM __SCHEMA__.idempotency_records i
 ) n USING(tenant_scope,message_id)
), authority_deltas AS (
 SELECT tenant_scope,owner_account_id AS account_id,principal_scope,retained_delta FROM task_deltas
 UNION ALL
 SELECT tenant_scope,account_id,principal_scope,retained_delta FROM idempotency_deltas
), scope_deltas AS (
 SELECT d.tenant_scope,s.scope_kind,s.scope_id,sum(d.retained_delta) AS retained_delta
 FROM authority_deltas d
 CROSS JOIN LATERAL (VALUES
  ('tenant',d.tenant_scope),
  ('account',d.account_id),
  ('principal',d.principal_scope)
 ) s(scope_kind,scope_id)
 GROUP BY d.tenant_scope,s.scope_kind,s.scope_id
)
UPDATE __SCHEMA__.retained_authority_usage u
SET retained_bytes=u.retained_bytes+d.retained_delta
FROM scope_deltas d
WHERE u.tenant_scope=d.tenant_scope
  AND u.scope_kind=d.scope_kind
  AND u.scope_id=d.scope_id;

-- Structural migration bytes remain subject to the same active retained-authority
-- limits as ordinary trigger-accounted writes. A migration must not create an
-- already-over-budget authority ledger merely because ALTER TABLE bypasses row
-- accounting triggers.
DO $do$ DECLARE r record; retained_limit bigint; BEGIN
 FOR r IN SELECT tenant_scope,scope_kind,retained_bytes FROM __SCHEMA__.retained_authority_usage LOOP
  SELECT CASE r.scope_kind
    WHEN 'tenant' THEN (canonical_json::jsonb#>>'{limits,retainedAuthorityBytes,tenant}')::bigint
    WHEN 'account' THEN (canonical_json::jsonb#>>'{limits,retainedAuthorityBytes,account}')::bigint
    ELSE (canonical_json::jsonb#>>'{limits,retainedAuthorityBytes,principal}')::bigint
   END INTO retained_limit
  FROM __SCHEMA__.quota_policy_versions
  WHERE tenant_scope=r.tenant_scope AND lifecycle='active';
  retained_limit:=COALESCE(retained_limit,67108864);
  IF r.retained_bytes>retained_limit THEN
   RAISE EXCEPTION 'retained authority % quota exceeded',r.scope_kind USING ERRCODE='53000';
  END IF;
 END LOOP;
END $do$;

-- Re-authenticate every materialized scope before RLS, ledger, and catalog reseal.
DO $do$ DECLARE r record; expected bigint; tenant text; scope text; BEGIN
 PERFORM set_config('smesh.internal_global','diag-v1',true);
 FOR r IN SELECT * FROM __SCHEMA__.retained_authority_usage LOOP
  expected:=CASE r.scope_kind
   WHEN 'tenant' THEN __SCHEMA__.retained_authority_oracle(r.tenant_scope,NULL)+__SCHEMA__.artifact_retained_oracle(r.tenant_scope,NULL)+__SCHEMA__.callback_retained_oracle(r.tenant_scope,NULL)
   WHEN 'account' THEN __SCHEMA__.retained_authority_account_oracle(r.tenant_scope,r.scope_id)+__SCHEMA__.artifact_retained_account_oracle(r.tenant_scope,r.scope_id)+__SCHEMA__.callback_retained_account_oracle(r.tenant_scope,r.scope_id)
   ELSE __SCHEMA__.retained_authority_oracle(r.tenant_scope,r.scope_id)+__SCHEMA__.artifact_retained_oracle(r.tenant_scope,r.scope_id)+__SCHEMA__.callback_retained_oracle(r.tenant_scope,r.scope_id) END;
  IF r.retained_bytes<>expected THEN RAISE EXCEPTION 'retained authority materialization mismatch' USING ERRCODE='XX001'; END IF;
 END LOOP;
 FOR tenant IN SELECT * FROM __SCHEMA__.authority_tenants_bounded() LOOP
  PERFORM set_config('smesh.tenant_scope',tenant,true);
  expected:=__SCHEMA__.retained_authority_oracle(tenant,NULL)+__SCHEMA__.artifact_retained_oracle(tenant,NULL)+__SCHEMA__.callback_retained_oracle(tenant,NULL);
  IF NOT EXISTS(SELECT 1 FROM __SCHEMA__.retained_authority_usage u WHERE u.tenant_scope=tenant AND u.scope_kind='tenant' AND u.scope_id=tenant AND u.retained_bytes=expected) THEN RAISE EXCEPTION 'retained authority materialization mismatch' USING ERRCODE='XX001'; END IF;
  FOR scope IN SELECT scope_id FROM (SELECT x AS scope_id FROM __SCHEMA__.authority_retained_scopes_bounded(tenant,'account') x UNION SELECT x FROM __SCHEMA__.artifact_retained_scopes_bounded(tenant,'account') x UNION SELECT x FROM __SCHEMA__.callback_retained_scopes_bounded(tenant,'account') x UNION SELECT scope_id FROM __SCHEMA__.retained_authority_usage WHERE tenant_scope=tenant AND scope_kind='account') scopes LOOP
   expected:=__SCHEMA__.retained_authority_account_oracle(tenant,scope)+__SCHEMA__.artifact_retained_account_oracle(tenant,scope)+__SCHEMA__.callback_retained_account_oracle(tenant,scope);
   IF NOT EXISTS(SELECT 1 FROM __SCHEMA__.retained_authority_usage u WHERE u.tenant_scope=tenant AND u.scope_kind='account' AND u.scope_id=scope AND u.retained_bytes=expected) THEN RAISE EXCEPTION 'retained authority materialization mismatch' USING ERRCODE='XX001'; END IF;
  END LOOP;
  FOR scope IN SELECT scope_id FROM (SELECT x AS scope_id FROM __SCHEMA__.authority_retained_scopes_bounded(tenant,'principal') x UNION SELECT x FROM __SCHEMA__.artifact_retained_scopes_bounded(tenant,'principal') x UNION SELECT x FROM __SCHEMA__.callback_retained_scopes_bounded(tenant,'principal') x UNION SELECT scope_id FROM __SCHEMA__.retained_authority_usage WHERE tenant_scope=tenant AND scope_kind='principal') scopes LOOP
   expected:=__SCHEMA__.retained_authority_oracle(tenant,scope)+__SCHEMA__.artifact_retained_oracle(tenant,scope)+__SCHEMA__.callback_retained_oracle(tenant,scope);
   IF NOT EXISTS(SELECT 1 FROM __SCHEMA__.retained_authority_usage u WHERE u.tenant_scope=tenant AND u.scope_kind='principal' AND u.scope_id=scope AND u.retained_bytes=expected) THEN RAISE EXCEPTION 'retained authority materialization mismatch' USING ERRCODE='XX001'; END IF;
  END LOOP;
 END LOOP;
END $do$;

-- Revision 9 retention predates durable runtime provenance. Keep an authorization
-- decision while unfinished outbox work still authenticates through it, then
-- delete the decision and terminal projection atomically once work is terminal.
CREATE OR REPLACE FUNCTION __SCHEMA__.cleanup_authorization_decisions(tenant text,retention_ms bigint,max_rows integer)
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
     AND NOT EXISTS(
       SELECT 1 FROM __SCHEMA__.idempotency_records i
       JOIN __SCHEMA__.outbox runtime_outbox
         ON runtime_outbox.tenant_scope=i.tenant_scope
        AND runtime_outbox.message_id=i.message_id
        AND runtime_outbox.task_id=i.task_id
       WHERE i.tenant_scope=d.tenant_scope
         AND i.authorization_decision_id=d.decision_id
         AND runtime_outbox.state IN ('pending','leased')
     )
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
     AND NOT EXISTS(
       SELECT 1 FROM __SCHEMA__.idempotency_records i
       JOIN __SCHEMA__.outbox runtime_outbox
         ON runtime_outbox.tenant_scope=i.tenant_scope
        AND runtime_outbox.message_id=i.message_id
        AND runtime_outbox.task_id=i.task_id
       WHERE i.tenant_scope=d.tenant_scope
         AND i.authorization_decision_id=d.decision_id
         AND runtime_outbox.state IN ('pending','leased')
     )
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

ALTER TABLE __SCHEMA__.retained_authority_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.retained_authority_usage FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.idempotency_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.idempotency_records FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.tasks FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.quota_policy_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.quota_policy_versions FORCE ROW LEVEL SECURITY;

CREATE TRIGGER tasks_runtime_authority_immutable BEFORE UPDATE OF principal_scope,authentication_method,authorization_policy_id,authorization_policy_revision,authorization_policy_digest,visibility,authorization_decision_id ON __SCHEMA__.tasks
 FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_identity_change('principal_scope','authentication_method','authorization_policy_id','authorization_policy_revision','authorization_policy_digest','visibility','authorization_decision_id');
CREATE TRIGGER idempotency_runtime_authority_immutable BEFORE UPDATE OF authorization_principal_scope,authorization_authentication_method,authorization_visibility,authorization_policy_id,authorization_policy_revision,authorization_policy_digest,authorization_decision_id,authorization_decided_at ON __SCHEMA__.idempotency_records
 FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_identity_change('authorization_principal_scope','authorization_authentication_method','authorization_visibility','authorization_policy_id','authorization_policy_revision','authorization_policy_digest','authorization_decision_id','authorization_decided_at');

-- Revision 11 did not seal column ACLs. Normalize every explicit UPDATE grant,
-- including PUBLIC and roles inherited by the runtime credential, before
-- installing the revision-12 allowlist.
REVOKE UPDATE ON __SCHEMA__.tasks FROM PUBLIC;
REVOKE UPDATE ON __SCHEMA__.tasks FROM __ROLE__;
REVOKE UPDATE(created_order,tenant_scope,task_id,context_id,state,status_timestamp,revision,task_json,owner_account_id,principal_scope,authentication_method,authorization_policy_id,authorization_policy_revision,authorization_policy_digest,visibility,authorization_decision_id) ON __SCHEMA__.tasks FROM PUBLIC;
REVOKE UPDATE(created_order,tenant_scope,task_id,context_id,state,status_timestamp,revision,task_json,owner_account_id,principal_scope,authentication_method,authorization_policy_id,authorization_policy_revision,authorization_policy_digest,visibility,authorization_decision_id) ON __SCHEMA__.tasks FROM __ROLE__;
DO $do$ DECLARE acl_row record; grantee_sql text; BEGIN
 FOR acl_row IN
  SELECT DISTINCT x.grantee
  FROM pg_class c
  CROSS JOIN LATERAL aclexplode(c.relacl) x
  WHERE c.oid='__SCHEMA__.tasks'::regclass AND x.privilege_type='UPDATE'
    AND x.grantee<>c.relowner
 LOOP
  grantee_sql:=CASE WHEN acl_row.grantee=0 THEN 'PUBLIC' ELSE quote_ident(pg_get_userbyid(acl_row.grantee)) END;
  EXECUTE format('REVOKE UPDATE ON __SCHEMA__.tasks FROM %s',grantee_sql);
 END LOOP;
 FOR acl_row IN
  SELECT a.attname,x.grantee
  FROM pg_attribute a
  CROSS JOIN LATERAL aclexplode(a.attacl) x
  WHERE a.attrelid='__SCHEMA__.tasks'::regclass AND a.attnum>0 AND NOT a.attisdropped
    AND x.privilege_type='UPDATE'
 LOOP
  grantee_sql:=CASE WHEN acl_row.grantee=0 THEN 'PUBLIC' ELSE quote_ident(pg_get_userbyid(acl_row.grantee)) END;
  EXECUTE format('REVOKE UPDATE(%I) ON __SCHEMA__.tasks FROM %s',acl_row.attname,grantee_sql);
 END LOOP;
END $do$;
GRANT SELECT,INSERT,DELETE ON __SCHEMA__.tasks TO __ROLE__;
GRANT UPDATE(state,status_timestamp,revision,task_json) ON __SCHEMA__.tasks TO __ROLE__;
DO $do$ BEGIN
 IF EXISTS(
  SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) x
  WHERE c.oid='__SCHEMA__.tasks'::regclass AND x.privilege_type='UPDATE'
    AND x.grantee<>c.relowner
 ) OR EXISTS(
  SELECT 1
  FROM pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) x
  WHERE a.attrelid='__SCHEMA__.tasks'::regclass AND a.attnum>0 AND NOT a.attisdropped
    AND x.privilege_type='UPDATE'
    AND (x.grantee<>(SELECT oid FROM pg_roles WHERE rolname='__ROLE__')
      OR a.attname NOT IN ('state','status_timestamp','revision','task_json'))
 ) OR 4<>(
  SELECT count(*)
  FROM pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) x
  WHERE a.attrelid='__SCHEMA__.tasks'::regclass AND a.attnum>0 AND NOT a.attisdropped
    AND x.privilege_type='UPDATE'
    AND x.grantee=(SELECT oid FROM pg_roles WHERE rolname='__ROLE__')
 ) THEN
  RAISE EXCEPTION 'unexpected task UPDATE ACL after runtime authority migration' USING ERRCODE='42501';
 END IF;
END $do$;
