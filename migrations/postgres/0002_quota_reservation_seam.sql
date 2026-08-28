CREATE TABLE __SCHEMA__.quota_reservations(
 tenant_scope text NOT NULL CHECK(octet_length(tenant_scope) BETWEEN 1 AND 64 AND tenant_scope ~ '^[!-~]+$'),
 reservation_id text NOT NULL CHECK(octet_length(reservation_id) BETWEEN 1 AND 256 AND reservation_id ~ '^[!-~]+$'),
 account_id text NOT NULL CHECK(octet_length(account_id) BETWEEN 1 AND 64 AND account_id ~ '^[!-~]+$'),
 principal_scope text NOT NULL CHECK(octet_length(principal_scope) BETWEEN 1 AND 256 AND principal_scope ~ '^[!-~]+$'),
 operation text NOT NULL CHECK(octet_length(operation) BETWEEN 1 AND 128 AND operation ~ '^[!-~]+$'),
 dimension text NOT NULL CHECK(octet_length(dimension) BETWEEN 1 AND 128 AND dimension ~ '^[!-~]+$'),
 units bigint NOT NULL CHECK(units > 0),
 task_id text NOT NULL CHECK(octet_length(task_id) BETWEEN 1 AND 4096),
 expires_at bigint NOT NULL CHECK(expires_at BETWEEN 1 AND 253402300799999),
 metadata_json text CHECK(octet_length(metadata_json)<=4096 AND __SCHEMA__.json_text_valid(metadata_json)),
 created_at bigint NOT NULL CHECK(created_at BETWEEN 1 AND 253402300799999),
 PRIMARY KEY(tenant_scope,reservation_id),
 FOREIGN KEY(tenant_scope,task_id) REFERENCES __SCHEMA__.tasks(tenant_scope,task_id) ON DELETE RESTRICT,
 CHECK(expires_at > created_at)
);
CREATE INDEX quota_reservations_principal_state ON __SCHEMA__.quota_reservations(tenant_scope,account_id,principal_scope,operation,dimension,expires_at,reservation_id);
CREATE TRIGGER quota_reservations_identity_immutable BEFORE UPDATE ON __SCHEMA__.quota_reservations FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_identity_change('tenant_scope','reservation_id','account_id','principal_scope','operation','dimension','task_id');
ALTER TABLE __SCHEMA__.quota_reservations ENABLE ROW LEVEL SECURITY;
ALTER TABLE __SCHEMA__.quota_reservations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON __SCHEMA__.quota_reservations FOR ALL TO __ROLE__ USING (tenant_scope=NULLIF(current_setting('smesh.tenant_scope',true),'')) WITH CHECK (tenant_scope=NULLIF(current_setting('smesh.tenant_scope',true),''));
GRANT SELECT,INSERT ON __SCHEMA__.quota_reservations TO __ROLE__;
