-- Durable candidate generations and independently signed semantic evidence.
ALTER TABLE __SCHEMA__.schema_migrations DROP CONSTRAINT schema_migrations_logical_schema_version_check;
ALTER TABLE __SCHEMA__.schema_migrations ADD CONSTRAINT schema_migrations_logical_schema_version_check CHECK((revision=13 AND logical_schema_version=13) OR (revision=12 AND logical_schema_version=12) OR (revision=11 AND logical_schema_version=11) OR (revision=10 AND logical_schema_version=10) OR (revision=9 AND logical_schema_version=9) OR (revision=8 AND logical_schema_version=8) OR (revision=7 AND logical_schema_version=7) OR (revision NOT IN (7,8,9,10,11,12,13) AND logical_schema_version=6));
ALTER TABLE __SCHEMA__.store_metadata DROP CONSTRAINT store_metadata_schema_version_check;
ALTER TABLE __SCHEMA__.store_metadata ADD CONSTRAINT store_metadata_schema_version_check CHECK(schema_version IN (6,7,8,9,10,11,12,13));

CREATE TABLE __SCHEMA__.completion_policy_versions(
 tenant_scope text NOT NULL CHECK(octet_length(tenant_scope) BETWEEN 1 AND 64),
 policy_id text NOT NULL CHECK(octet_length(policy_id) BETWEEN 1 AND 128),
 policy_revision bigint NOT NULL CHECK(policy_revision>0),
 canonical_json jsonb NOT NULL CHECK(octet_length(canonical_json::text)<=16384),
 policy_digest text NOT NULL CHECK(policy_digest ~ '^sha256:[0-9a-f]{64}$'),
 required_roles jsonb NOT NULL,
 owner_account_id text NOT NULL CHECK(octet_length(owner_account_id) BETWEEN 1 AND 256),
 principal_scope text NOT NULL CHECK(octet_length(principal_scope) BETWEEN 1 AND 512),
 created_at bigint NOT NULL,
 PRIMARY KEY(tenant_scope,policy_id,policy_revision)
);
CREATE TABLE __SCHEMA__.issuer_enrollments(
 tenant_scope text NOT NULL CHECK(octet_length(tenant_scope) BETWEEN 1 AND 64),
 issuer_identity text NOT NULL CHECK(octet_length(issuer_identity) BETWEEN 1 AND 512),
 issuer_role text NOT NULL CHECK(issuer_role IN ('text-concordance-review/v1','text-concordance-test/v1','text-concordance-contradiction/v1')),
 public_key text NOT NULL CHECK(public_key ~ '^[A-Za-z0-9_-]{43}$'),
 valid_from bigint NOT NULL,
 expires_at bigint NOT NULL CHECK(expires_at>valid_from),
 revoked_at bigint,
 owner_account_id text NOT NULL CHECK(octet_length(owner_account_id) BETWEEN 1 AND 256),
 principal_scope text NOT NULL CHECK(octet_length(principal_scope) BETWEEN 1 AND 512),
 created_at bigint NOT NULL,
 PRIMARY KEY(tenant_scope,issuer_identity),
 UNIQUE(tenant_scope,issuer_role),
 UNIQUE(tenant_scope,public_key)
);
CREATE TABLE __SCHEMA__.candidate_generations(
 tenant_scope text NOT NULL CHECK(octet_length(tenant_scope) BETWEEN 1 AND 64),
 candidate_generation_id text NOT NULL CHECK(candidate_generation_id ~ '^sha256:[0-9a-f]{64}$'),
 task_id text NOT NULL CHECK(octet_length(task_id) BETWEEN 1 AND 256),
 context_id text NOT NULL CHECK(octet_length(context_id) BETWEEN 1 AND 256),
 request_digest text NOT NULL CHECK(request_digest ~ '^sha256:[0-9a-f]{64}$'),
 artifact_set_digest text NOT NULL CHECK(artifact_set_digest ~ '^sha256:[0-9a-f]{64}$'),
 dispatch_id text NOT NULL CHECK(octet_length(dispatch_id) BETWEEN 1 AND 256),
 attempt bigint NOT NULL CHECK(attempt>=0),
 fence bigint NOT NULL CHECK(fence>=0),
 completion_policy text NOT NULL CHECK(octet_length(completion_policy) BETWEEN 1 AND 128),
 completion_policy_revision bigint NOT NULL CHECK(completion_policy_revision>0),
 proposal_json jsonb NOT NULL CHECK(octet_length(proposal_json::text)<=1048576),
 state text NOT NULL CHECK(state IN ('open','sealed','canceled','conflicted')),
 owner_account_id text NOT NULL CHECK(octet_length(owner_account_id) BETWEEN 1 AND 256),
 principal_scope text NOT NULL CHECK(octet_length(principal_scope) BETWEEN 1 AND 512),
 created_at bigint NOT NULL,
 sealed_at bigint,
 completion_receipt jsonb,
 PRIMARY KEY(tenant_scope,candidate_generation_id),
 UNIQUE(tenant_scope,task_id,dispatch_id,attempt,fence,completion_policy,completion_policy_revision),
 FOREIGN KEY(tenant_scope,task_id) REFERENCES __SCHEMA__.tasks(tenant_scope,task_id),
 FOREIGN KEY(tenant_scope,completion_policy,completion_policy_revision) REFERENCES __SCHEMA__.completion_policy_versions(tenant_scope,policy_id,policy_revision)
);
CREATE TABLE __SCHEMA__.candidate_artifacts(
 tenant_scope text NOT NULL CHECK(octet_length(tenant_scope) BETWEEN 1 AND 64),
 candidate_generation_id text NOT NULL,
 ordinal bigint NOT NULL CHECK(ordinal>=0),
 task_id text NOT NULL CHECK(octet_length(task_id) BETWEEN 1 AND 256),
 name text NOT NULL CHECK(octet_length(name) BETWEEN 1 AND 512),
 media_type text NOT NULL CHECK(octet_length(media_type) BETWEEN 1 AND 256),
 artifact_digest text NOT NULL CHECK(artifact_digest ~ '^sha256:[0-9a-f]{64}$'),
 artifact_bytes bytea NOT NULL CHECK(octet_length(artifact_bytes)<=1048576),
 owner_account_id text NOT NULL CHECK(octet_length(owner_account_id) BETWEEN 1 AND 256),
 principal_scope text NOT NULL CHECK(octet_length(principal_scope) BETWEEN 1 AND 512),
 created_at bigint NOT NULL,
 PRIMARY KEY(tenant_scope,candidate_generation_id,ordinal),
 FOREIGN KEY(tenant_scope,candidate_generation_id) REFERENCES __SCHEMA__.candidate_generations(tenant_scope,candidate_generation_id)
);
CREATE TABLE __SCHEMA__.issuer_evidence(
 tenant_scope text NOT NULL CHECK(octet_length(tenant_scope) BETWEEN 1 AND 64),
 candidate_generation_id text NOT NULL,
 issuer_role text NOT NULL CHECK(issuer_role IN ('text-concordance-review/v1','text-concordance-test/v1','text-concordance-contradiction/v1')),
 issuer_identity text NOT NULL CHECK(octet_length(issuer_identity) BETWEEN 1 AND 512),
 decision text NOT NULL CHECK(decision IN ('approve','clear')),
 task_id text NOT NULL CHECK(octet_length(task_id) BETWEEN 1 AND 256),
 evidence_json jsonb NOT NULL CHECK(octet_length(evidence_json::text)<=16384),
 evidence_digest text NOT NULL CHECK(evidence_digest ~ '^sha256:[0-9a-f]{64}$'),
 signature text NOT NULL CHECK(signature ~ '^[A-Za-z0-9_-]{86}$'),
 public_key text NOT NULL CHECK(public_key ~ '^[A-Za-z0-9_-]{43}$'),
 owner_account_id text NOT NULL CHECK(octet_length(owner_account_id) BETWEEN 1 AND 256),
 principal_scope text NOT NULL CHECK(octet_length(principal_scope) BETWEEN 1 AND 512),
 accepted_at bigint NOT NULL,
 PRIMARY KEY(tenant_scope,candidate_generation_id,issuer_role),
 UNIQUE(tenant_scope,candidate_generation_id,issuer_identity),
 FOREIGN KEY(tenant_scope,candidate_generation_id) REFERENCES __SCHEMA__.candidate_generations(tenant_scope,candidate_generation_id)
);
CREATE TABLE __SCHEMA__.evidence_conflicts(
 tenant_scope text NOT NULL CHECK(octet_length(tenant_scope) BETWEEN 1 AND 64),
 conflict_id text NOT NULL CHECK(octet_length(conflict_id) BETWEEN 1 AND 256),
 candidate_generation_id text NOT NULL,
 task_id text NOT NULL CHECK(octet_length(task_id) BETWEEN 1 AND 256),
 issuer_role text,
 observed_digest text NOT NULL CHECK(observed_digest ~ '^sha256:[0-9a-f]{64}$'),
 conflict_kind text NOT NULL CHECK(conflict_kind IN ('candidate','evidence','artifact')),
 owner_account_id text NOT NULL CHECK(octet_length(owner_account_id) BETWEEN 1 AND 256),
 principal_scope text NOT NULL CHECK(octet_length(principal_scope) BETWEEN 1 AND 512),
 observed_at bigint NOT NULL,
 PRIMARY KEY(tenant_scope,conflict_id),
 FOREIGN KEY(tenant_scope,candidate_generation_id) REFERENCES __SCHEMA__.candidate_generations(tenant_scope,candidate_generation_id)
);

CREATE FUNCTION __SCHEMA__.reject_semantic_evidence_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN RAISE EXCEPTION 'semantic evidence authority row is immutable' USING ERRCODE='55000'; END $fn$;
CREATE FUNCTION __SCHEMA__.freeze_candidate_artifact_set() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE candidate_state text;
BEGIN
 SELECT state INTO candidate_state
   FROM __SCHEMA__.candidate_generations
  WHERE tenant_scope=NEW.tenant_scope AND candidate_generation_id=NEW.candidate_generation_id
  FOR UPDATE;
 IF candidate_state IS DISTINCT FROM 'open' OR EXISTS(
    SELECT 1 FROM __SCHEMA__.candidate_artifacts
     WHERE tenant_scope=NEW.tenant_scope AND candidate_generation_id=NEW.candidate_generation_id
 ) THEN
  RAISE EXCEPTION 'semantic candidate artifact set is frozen' USING ERRCODE='55000';
 END IF;
 RETURN NEW;
END $fn$;
CREATE FUNCTION __SCHEMA__.guard_issuer_revocation() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
 IF OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL OR NEW.revoked_at<OLD.valid_from THEN
  RAISE EXCEPTION 'semantic issuer revocation is irreversible' USING ERRCODE='55000';
 END IF;
 RETURN NEW;
END $fn$;
CREATE FUNCTION __SCHEMA__.guard_candidate_transition() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
 IF NEW.completion_receipt IS DISTINCT FROM OLD.completion_receipt AND NOT(
    OLD.state='open' AND NEW.state='open' AND OLD.completion_receipt IS NULL
    AND NEW.completion_receipt IS NOT NULL AND NEW.sealed_at IS NOT DISTINCT FROM OLD.sealed_at
 ) THEN
  RAISE EXCEPTION 'semantic approval receipt transition is invalid' USING ERRCODE='55000';
 END IF;
 IF NEW.state IS DISTINCT FROM OLD.state AND NOT(
    OLD.state='open' AND (
      (NEW.state='sealed' AND NEW.completion_receipt IS NOT NULL AND NEW.completion_receipt IS NOT DISTINCT FROM OLD.completion_receipt AND OLD.sealed_at IS NULL AND NEW.sealed_at IS NOT NULL)
      OR (NEW.state IN ('canceled','conflicted') AND NEW.completion_receipt IS NOT DISTINCT FROM OLD.completion_receipt AND NEW.sealed_at IS NOT DISTINCT FROM OLD.sealed_at)
    )
 ) THEN
  RAISE EXCEPTION 'semantic candidate state transition is invalid' USING ERRCODE='55000';
 END IF;
 IF NEW.sealed_at IS DISTINCT FROM OLD.sealed_at AND NOT(OLD.state='open' AND NEW.state='sealed' AND OLD.sealed_at IS NULL AND NEW.sealed_at IS NOT NULL) THEN
  RAISE EXCEPTION 'semantic candidate seal transition is invalid' USING ERRCODE='55000';
 END IF;
 RETURN NEW;
END $fn$;
CREATE TRIGGER completion_policy_versions_immutable BEFORE UPDATE OR DELETE ON __SCHEMA__.completion_policy_versions FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_semantic_evidence_mutation();
CREATE TRIGGER issuer_enrollments_identity BEFORE UPDATE OF tenant_scope,issuer_identity,issuer_role,public_key,valid_from,expires_at,owner_account_id,principal_scope,created_at ON __SCHEMA__.issuer_enrollments FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_semantic_evidence_mutation();
CREATE TRIGGER issuer_enrollments_revocation BEFORE UPDATE OF revoked_at ON __SCHEMA__.issuer_enrollments FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.guard_issuer_revocation();
CREATE TRIGGER candidate_generations_identity BEFORE UPDATE OF tenant_scope,candidate_generation_id,task_id,context_id,request_digest,artifact_set_digest,dispatch_id,attempt,fence,completion_policy,completion_policy_revision,proposal_json,owner_account_id,principal_scope,created_at ON __SCHEMA__.candidate_generations FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_semantic_evidence_mutation();
CREATE TRIGGER candidate_generations_transition BEFORE UPDATE OF state,sealed_at,completion_receipt ON __SCHEMA__.candidate_generations FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.guard_candidate_transition();
CREATE TRIGGER candidate_artifacts_freeze BEFORE INSERT ON __SCHEMA__.candidate_artifacts FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.freeze_candidate_artifact_set();
CREATE TRIGGER candidate_artifacts_immutable BEFORE UPDATE OR DELETE ON __SCHEMA__.candidate_artifacts FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_semantic_evidence_mutation();
CREATE TRIGGER issuer_evidence_immutable BEFORE UPDATE OR DELETE ON __SCHEMA__.issuer_evidence FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_semantic_evidence_mutation();
CREATE TRIGGER evidence_conflicts_immutable BEFORE UPDATE OR DELETE ON __SCHEMA__.evidence_conflicts FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_semantic_evidence_mutation();

ALTER TABLE __SCHEMA__.completion_policy_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.completion_policy_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.issuer_enrollments ENABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.issuer_enrollments FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.candidate_generations ENABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.candidate_generations FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.candidate_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.candidate_artifacts FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.issuer_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.issuer_evidence FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.evidence_conflicts ENABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.evidence_conflicts FORCE ROW LEVEL SECURITY;
DO $do$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['completion_policy_versions','issuer_enrollments','candidate_generations','candidate_artifacts','issuer_evidence','evidence_conflicts'] LOOP
  EXECUTE format('CREATE POLICY tenant_isolation ON __SCHEMA__.%I TO __ROLE__ USING(tenant_scope=NULLIF(current_setting(''smesh.tenant_scope'',true),'''')) WITH CHECK(tenant_scope=NULLIF(current_setting(''smesh.tenant_scope'',true),''''))',t);
  EXECUTE format('CREATE TRIGGER retained_authority_accounting AFTER INSERT OR UPDATE OR DELETE ON __SCHEMA__.%I FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.account_retained_authority_row()',t);
  EXECUTE format('REVOKE ALL ON __SCHEMA__.%I FROM PUBLIC,__ROLE__',t);
  EXECUTE format('GRANT SELECT,INSERT ON __SCHEMA__.%I TO __ROLE__',t);
 END LOOP;
END $do$;
GRANT UPDATE(revoked_at) ON __SCHEMA__.issuer_enrollments TO __ROLE__;
-- Column-scoped UPDATE is the minimum PostgreSQL privilege required for
-- SELECT ... FOR UPDATE; the immutable trigger still rejects every mutation.
GRANT UPDATE(signature) ON __SCHEMA__.issuer_evidence TO __ROLE__;
GRANT UPDATE(state,sealed_at,completion_receipt) ON __SCHEMA__.candidate_generations TO __ROLE__;
REVOKE ALL ON FUNCTION __SCHEMA__.reject_semantic_evidence_mutation() FROM PUBLIC,__ROLE__;
REVOKE ALL ON FUNCTION __SCHEMA__.freeze_candidate_artifact_set() FROM PUBLIC,__ROLE__;
REVOKE ALL ON FUNCTION __SCHEMA__.guard_issuer_revocation() FROM PUBLIC,__ROLE__;
REVOKE ALL ON FUNCTION __SCHEMA__.guard_candidate_transition() FROM PUBLIC,__ROLE__;
