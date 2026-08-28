# PostgreSQL logical tenant schema (target for issue #13)

This is the logical PostgreSQL mapping corresponding to the enabled SQLite schema-v5 authorization boundary. It keeps a future PostgreSQL adapter aligned with the enforced ownership and audit model; it is not itself a deployed PostgreSQL migration.

```sql
CREATE TABLE tasks (
  tenant_id text NOT NULL,
  task_id text NOT NULL,
  owner_account_id text NOT NULL,
  context_id text NOT NULL,
  state text NOT NULL,
  revision bigint NOT NULL CHECK (revision > 0),
  task_json jsonb NOT NULL,
  PRIMARY KEY (tenant_id, task_id)
);

CREATE TABLE authorization_decisions (
  decision_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  policy_id text NOT NULL,
  policy_revision bigint NOT NULL CHECK (policy_revision > 0),
  policy_digest bytea NOT NULL CHECK (octet_length(policy_digest) = 32),
  actor_account_id text,
  tenant_id text,
  operation text NOT NULL,
  outcome text NOT NULL CHECK (outcome IN ('allow', 'deny')),
  reason_code text NOT NULL,
  resource_digest bytea NOT NULL CHECK (octet_length(resource_digest) = 32),
  task_tenant_id text,
  task_id text,
  decided_at timestamptz NOT NULL,
  FOREIGN KEY (task_tenant_id, task_id) REFERENCES tasks(tenant_id, task_id),
  CHECK ((task_tenant_id IS NULL) = (task_id IS NULL))
);

CREATE INDEX authorization_decisions_tenant_time
  ON authorization_decisions(tenant_id, decided_at, decision_id);
```

All task children (`task_events`, idempotency, outbox/attempts, receiver inbox/frames/effects, stream transcripts/frames, and cancellation intents) must begin their keys and foreign keys with `tenant_id`. Worker claims use `FOR UPDATE SKIP LOCKED`; application authorization and existence-safe predicates remain required even if PostgreSQL RLS is later added.
