-- Revision 8 is append-only. It closes rolling-policy and callback retained-accounting gaps.
ALTER TABLE __SCHEMA__.schema_migrations DROP CONSTRAINT schema_migrations_logical_schema_version_check;
ALTER TABLE __SCHEMA__.schema_migrations ADD CONSTRAINT schema_migrations_logical_schema_version_check CHECK((revision=8 AND logical_schema_version=8) OR (revision=7 AND logical_schema_version=7) OR (revision NOT IN (7,8) AND logical_schema_version=6));
ALTER TABLE __SCHEMA__.store_metadata DROP CONSTRAINT store_metadata_schema_version_check;
ALTER TABLE __SCHEMA__.store_metadata ADD CONSTRAINT store_metadata_schema_version_check CHECK(schema_version IN (6,7,8));

CREATE OR REPLACE FUNCTION __SCHEMA__.retained_principal(value jsonb) RETURNS text
LANGUAGE plpgsql STABLE SET search_path=pg_catalog AS $fn$
DECLARE principal text; binding text; account text; task text; config text; event text;
BEGIN
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
END $fn$;

CREATE OR REPLACE FUNCTION __SCHEMA__.retained_account(value jsonb) RETURNS text
LANGUAGE plpgsql STABLE SET search_path=pg_catalog AS $fn$
DECLARE account text; binding text; task text; config text; event text;
BEGIN
 account := COALESCE(value->>'owner_account_id',value->>'actor_account_id',value->>'account_id');
 IF account IS NOT NULL THEN RETURN account; END IF;
 binding := COALESCE(value->>'binding_digest',value->>'mutation_binding_digest');
 IF binding IS NOT NULL THEN
  SELECT i.account_id INTO account FROM __SCHEMA__.quota_intents i
   WHERE i.tenant_scope=value->>'tenant_scope' AND i.binding_digest=binding;
  IF account IS NOT NULL THEN RETURN account; END IF;
 END IF;
 config := value->>'config_id';
 IF config IS NOT NULL THEN
  task := value->>'task_id'; event := value->>'event_id';
  IF task IS NOT NULL THEN
   SELECT c.owner_account_id INTO account FROM __SCHEMA__.callback_configs c
    WHERE c.tenant_scope=value->>'tenant_scope' AND c.task_id=task AND c.config_id=config;
  ELSIF event IS NOT NULL THEN
   SELECT c.owner_account_id INTO account FROM __SCHEMA__.callback_deliveries d
    JOIN __SCHEMA__.callback_configs c USING(tenant_scope,task_id,config_id)
    WHERE d.tenant_scope=value->>'tenant_scope' AND d.event_id=event AND d.config_id=config;
  END IF;
  IF account IS NOT NULL THEN RETURN account; END IF;
 END IF;
 task := value->>'task_id';
 IF task IS NOT NULL THEN
  SELECT t.owner_account_id INTO account FROM __SCHEMA__.tasks t
   WHERE t.tenant_scope=value->>'tenant_scope' AND t.task_id=task;
 END IF;
 RETURN account;
END $fn$;

CREATE FUNCTION __SCHEMA__.callback_retained_oracle(wanted_tenant text,wanted_principal text) RETURNS bigint
LANGUAGE plpgsql STABLE SET search_path=pg_catalog AS $fn$
DECLARE t text; total numeric:=0; part numeric;
BEGIN
 FOREACH t IN ARRAY ARRAY['callback_configs','callback_events','callback_deliveries','callback_attempts','callback_tenant_scheduler'] LOOP
  EXECUTE format('SELECT COALESCE(sum(__SCHEMA__.row_retained_bytes(r)),0) FROM __SCHEMA__.%I r WHERE tenant_scope=$1 AND ($2 IS NULL OR __SCHEMA__.retained_principal(to_jsonb(r))=$2)',t)
   INTO part USING wanted_tenant,wanted_principal;
  total:=total+part;
  IF total>9223372036854775807 THEN RAISE EXCEPTION 'callback retained authority oracle overflow'; END IF;
 END LOOP;
 RETURN total::bigint;
END $fn$;

CREATE FUNCTION __SCHEMA__.callback_retained_account_oracle(wanted_tenant text,wanted_account text) RETURNS bigint
LANGUAGE plpgsql STABLE SET search_path=pg_catalog AS $fn$
DECLARE t text; total numeric:=0; part numeric;
BEGIN
 FOREACH t IN ARRAY ARRAY['callback_configs','callback_events','callback_deliveries','callback_attempts','callback_tenant_scheduler'] LOOP
  EXECUTE format('SELECT COALESCE(sum(__SCHEMA__.row_retained_bytes(r)),0) FROM __SCHEMA__.%I r WHERE tenant_scope=$1 AND __SCHEMA__.retained_account(to_jsonb(r))=$2',t)
   INTO part USING wanted_tenant,wanted_account;
  total:=total+part;
  IF total>9223372036854775807 THEN RAISE EXCEPTION 'callback retained authority account oracle overflow'; END IF;
 END LOOP;
 RETURN total::bigint;
END $fn$;

CREATE FUNCTION __SCHEMA__.callback_retained_scopes_bounded(wanted_tenant text,wanted_kind text) RETURNS SETOF text
LANGUAGE plpgsql STABLE SET search_path=pg_catalog AS $fn$
BEGIN
 IF wanted_tenant IS DISTINCT FROM NULLIF(current_setting('smesh.tenant_scope',true),'') OR wanted_kind NOT IN ('account','principal') THEN
  RAISE EXCEPTION 'invalid callback retained scope';
 END IF;
 IF wanted_kind='account' THEN
  RETURN QUERY SELECT DISTINCT owner_account_id FROM __SCHEMA__.callback_configs
   WHERE tenant_scope=wanted_tenant ORDER BY owner_account_id;
 ELSE
  RETURN QUERY SELECT DISTINCT principal_scope FROM __SCHEMA__.callback_configs
   WHERE tenant_scope=wanted_tenant ORDER BY principal_scope;
 END IF;
END $fn$;

GRANT SELECT ON __SCHEMA__.callback_policy_snapshots,__SCHEMA__.callback_tenant_scheduler TO __ROLE__;
REVOKE ALL ON FUNCTION __SCHEMA__.callback_retained_oracle(text,text),__SCHEMA__.callback_retained_account_oracle(text,text),__SCHEMA__.callback_retained_scopes_bounded(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION __SCHEMA__.callback_retained_oracle(text,text),__SCHEMA__.callback_retained_account_oracle(text,text),__SCHEMA__.callback_retained_scopes_bounded(text,text) TO __ROLE__;
