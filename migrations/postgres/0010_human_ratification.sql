-- Durable human-ratification packet authority.
-- Historical rows cannot reconstruct their original authentication provenance. They are
-- explicitly marked legacy-principal/trusted-local; only post-v10 admissions overwrite
-- both bindings from server-derived OwnedTaskScope before ratification is possible.
ALTER TABLE __SCHEMA__.schema_migrations DROP CONSTRAINT schema_migrations_logical_schema_version_check;
ALTER TABLE __SCHEMA__.schema_migrations ADD CONSTRAINT schema_migrations_logical_schema_version_check CHECK((revision=10 AND logical_schema_version=10) OR (revision=9 AND logical_schema_version=9) OR (revision=8 AND logical_schema_version=8) OR (revision=7 AND logical_schema_version=7) OR (revision NOT IN (7,8,9,10) AND logical_schema_version=6));
ALTER TABLE __SCHEMA__.store_metadata DROP CONSTRAINT store_metadata_schema_version_check;
ALTER TABLE __SCHEMA__.store_metadata ADD CONSTRAINT store_metadata_schema_version_check CHECK(schema_version IN (6,7,8,9,10));

ALTER TABLE __SCHEMA__.tasks
 ADD COLUMN principal_scope text NOT NULL DEFAULT 'legacy-principal'
   CHECK(octet_length(principal_scope) BETWEEN 1 AND 256),
 ADD COLUMN authentication_method text NOT NULL DEFAULT 'trusted-local'
   CHECK(octet_length(authentication_method) BETWEEN 1 AND 64),
 ADD COLUMN authorization_policy_id text NOT NULL DEFAULT 'legacy-policy'
   CHECK(octet_length(authorization_policy_id) BETWEEN 1 AND 128),
 ADD COLUMN authorization_policy_revision bigint NOT NULL DEFAULT 0
   CHECK(authorization_policy_revision>=0),
 ADD COLUMN authorization_policy_digest text NOT NULL DEFAULT 'sha256:0000000000000000000000000000000000000000000000000000000000000000'
   CHECK(octet_length(authorization_policy_digest) BETWEEN 1 AND 256);

CREATE TABLE __SCHEMA__.ratification_key_check(
 singleton smallint PRIMARY KEY CHECK(singleton=1),
 version smallint NOT NULL CHECK(version=1),
 key_generation text NOT NULL CHECK(key_generation ~ '^sha256:[0-9a-f]{64}$'),
 check_seal text NOT NULL CHECK(octet_length(check_seal)=43)
);
REVOKE ALL ON __SCHEMA__.ratification_key_check FROM PUBLIC,__ROLE__;

CREATE TABLE __SCHEMA__.ratification_packets(
 tenant_scope text NOT NULL CHECK(octet_length(tenant_scope) BETWEEN 1 AND 128),
 task_id text NOT NULL,
 generation bigint NOT NULL CHECK(generation>0),
 task_revision bigint NOT NULL CHECK(task_revision>0),
 checkpoint_hash text NOT NULL CHECK(checkpoint_hash ~ '^sha256:[0-9a-f]{64}$'),
 packet_hash text NOT NULL CHECK(packet_hash ~ '^sha256:[0-9a-f]{64}$'),
 packet_seal text NOT NULL,
 packet_json text NOT NULL,
 approved_task_json text NOT NULL,
 approved_result_json text NOT NULL,
 approved_transcript_json text NOT NULL,
 state text NOT NULL CHECK(state IN ('awaiting_review','reviewed','approved','rejected','amended','canceled','superseded')),
 revision bigint NOT NULL DEFAULT 0 CHECK(revision>=0),
 reviewer_account_id text,
 head_receipt_hash text,
 created_at bigint NOT NULL,
 updated_at bigint NOT NULL CHECK(updated_at>=created_at),
 PRIMARY KEY(tenant_scope,task_id,generation),
 UNIQUE(tenant_scope,packet_hash),
 FOREIGN KEY(tenant_scope,task_id) REFERENCES __SCHEMA__.tasks(tenant_scope,task_id) ON DELETE RESTRICT,
 CHECK((revision=0 AND reviewer_account_id IS NULL AND head_receipt_hash IS NULL)
    OR (revision>0 AND reviewer_account_id IS NOT NULL AND head_receipt_hash IS NOT NULL))
);
CREATE UNIQUE INDEX ratification_packets_active ON __SCHEMA__.ratification_packets(tenant_scope,task_id)
 WHERE state IN ('awaiting_review','reviewed');

CREATE TABLE __SCHEMA__.ratification_events(
 tenant_scope text NOT NULL,
 task_id text NOT NULL,
 generation bigint NOT NULL,
 revision bigint NOT NULL CHECK(revision>0),
 account_id text NOT NULL CHECK(octet_length(account_id) BETWEEN 1 AND 128),
 action text NOT NULL CHECK(action IN ('review','approve','reject','amend')),
 command_digest text NOT NULL CHECK(command_digest ~ '^sha256:[0-9a-f]{64}$'),
 idempotency_key text NOT NULL CHECK(octet_length(idempotency_key) BETWEEN 1 AND 128),
 receipt_json text NOT NULL,
 receipt_hash text NOT NULL CHECK(receipt_hash ~ '^sha256:[0-9a-f]{64}$'),
 receipt_seal text NOT NULL,
 previous_receipt_hash text,
 occurred_at bigint NOT NULL,
 PRIMARY KEY(tenant_scope,task_id,generation,revision),
 UNIQUE(tenant_scope,account_id,idempotency_key),
 FOREIGN KEY(tenant_scope,task_id,generation)
   REFERENCES __SCHEMA__.ratification_packets(tenant_scope,task_id,generation) ON DELETE RESTRICT
);
CREATE INDEX ratification_events_packet ON __SCHEMA__.ratification_events(tenant_scope,task_id,generation,revision);

CREATE FUNCTION __SCHEMA__.guard_ratification_packet_identity() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
 IF (to_jsonb(NEW)-'state'-'revision'-'reviewer_account_id'-'head_receipt_hash'-'updated_at')
    = (to_jsonb(OLD)-'state'-'revision'-'reviewer_account_id'-'head_receipt_hash'-'updated_at')
 THEN RETURN NEW; END IF;
 RAISE EXCEPTION 'ratification packet identity is immutable';
END $fn$;
CREATE TRIGGER ratification_packets_identity_immutable BEFORE UPDATE ON __SCHEMA__.ratification_packets
 FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.guard_ratification_packet_identity();
CREATE FUNCTION __SCHEMA__.reject_ratification_packet_delete() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN RAISE EXCEPTION 'ratification packet is immutable'; END $fn$;
CREATE TRIGGER ratification_packets_no_delete BEFORE DELETE ON __SCHEMA__.ratification_packets
 FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_ratification_packet_delete();
CREATE FUNCTION __SCHEMA__.reject_ratification_event_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN RAISE EXCEPTION 'ratification event is immutable'; END $fn$;
CREATE TRIGGER ratification_events_no_update BEFORE UPDATE ON __SCHEMA__.ratification_events
 FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_ratification_event_mutation();
CREATE TRIGGER ratification_events_no_delete BEFORE DELETE ON __SCHEMA__.ratification_events
 FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_ratification_event_mutation();

ALTER TABLE __SCHEMA__.ratification_packets ENABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.ratification_packets FORCE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.ratification_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.ratification_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON __SCHEMA__.ratification_packets TO __ROLE__
 USING(tenant_scope=NULLIF(current_setting('smesh.tenant_scope',true),''))
 WITH CHECK(tenant_scope=NULLIF(current_setting('smesh.tenant_scope',true),''));
CREATE POLICY tenant_isolation ON __SCHEMA__.ratification_events TO __ROLE__
 USING(tenant_scope=NULLIF(current_setting('smesh.tenant_scope',true),''))
 WITH CHECK(tenant_scope=NULLIF(current_setting('smesh.tenant_scope',true),''));

REVOKE ALL ON __SCHEMA__.ratification_packets,__SCHEMA__.ratification_events FROM PUBLIC,__ROLE__;
GRANT SELECT,INSERT,UPDATE ON __SCHEMA__.ratification_packets TO __ROLE__;
GRANT SELECT,INSERT ON __SCHEMA__.ratification_events TO __ROLE__;
REVOKE DELETE ON __SCHEMA__.ratification_packets FROM __ROLE__;
REVOKE UPDATE,DELETE ON __SCHEMA__.ratification_events FROM __ROLE__;
REVOKE ALL ON FUNCTION __SCHEMA__.guard_ratification_packet_identity(),__SCHEMA__.reject_ratification_packet_delete(),__SCHEMA__.reject_ratification_event_mutation() FROM PUBLIC,__ROLE__;
