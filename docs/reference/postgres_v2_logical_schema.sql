-- NON-EXECUTABLE LOGICAL REFERENCE DDL ONLY.
-- SQLite schema v5 tenant ownership / authorization-audit mapping.
-- A PostgreSQL adapter must own a transactional migration ledger and must not
-- execute this reference file directly. Claim workers with FOR UPDATE SKIP LOCKED.

CREATE TABLE tasks (
    created_order BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_scope TEXT NOT NULL CHECK (octet_length(tenant_scope) BETWEEN 1 AND 64),
    task_id TEXT NOT NULL UNIQUE,
    owner_account_id TEXT NOT NULL CHECK (octet_length(owner_account_id) BETWEEN 1 AND 64),
    context_id TEXT NOT NULL,
    state TEXT NOT NULL,
    status_timestamp TIMESTAMPTZ,
    revision BIGINT NOT NULL CHECK (revision > 0),
    task_json JSONB NOT NULL,
    UNIQUE (tenant_scope, task_id)
);
CREATE INDEX tasks_tenant_owner_time
    ON tasks(tenant_scope, owner_account_id, status_timestamp, task_id);
CREATE INDEX tasks_tenant_context_state_time
    ON tasks(tenant_scope, context_id, state, status_timestamp, task_id);

-- Schema-v6 frozen ListTasks query families. Keep separate tenant/owner shapes;
-- production queries must not use an optional-owner OR predicate.
CREATE INDEX tasks_tenant_time_v6
    ON tasks(tenant_scope, status_timestamp DESC NULLS LAST, task_id ASC);
CREATE INDEX tasks_tenant_state_time_v6
    ON tasks(tenant_scope, state, status_timestamp DESC NULLS LAST, task_id ASC);
CREATE INDEX tasks_tenant_context_time_v6
    ON tasks(tenant_scope, context_id, status_timestamp DESC NULLS LAST, task_id ASC);
CREATE INDEX tasks_tenant_context_state_time_v6
    ON tasks(tenant_scope, context_id, state, status_timestamp DESC NULLS LAST, task_id ASC);
CREATE INDEX tasks_tenant_owner_time_v6
    ON tasks(tenant_scope, owner_account_id, status_timestamp DESC NULLS LAST, task_id ASC);
CREATE INDEX tasks_tenant_owner_state_time_v6
    ON tasks(tenant_scope, owner_account_id, state, status_timestamp DESC NULLS LAST, task_id ASC);
CREATE INDEX tasks_tenant_owner_context_time_v6
    ON tasks(tenant_scope, owner_account_id, context_id, status_timestamp DESC NULLS LAST, task_id ASC);
CREATE INDEX tasks_tenant_owner_context_state_time_v6
    ON tasks(tenant_scope, owner_account_id, context_id, state, status_timestamp DESC NULLS LAST, task_id ASC);

CREATE TABLE list_snapshots (
    snapshot_id BYTEA PRIMARY KEY CHECK (octet_length(snapshot_id) = 32),
    scope_digest TEXT NOT NULL,
    query_digest TEXT NOT NULL,
    total_size BIGINT NOT NULL CHECK (total_size >= 0),
    page_size INTEGER NOT NULL CHECK (page_size BETWEEN 1 AND 100),
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at > issued_at),
    projection_version SMALLINT NOT NULL CHECK (projection_version = 1),
    frozen_bytes BIGINT NOT NULL CHECK (frozen_bytes >= 0),
    metadata_digest BYTEA NOT NULL CHECK (octet_length(metadata_digest) = 32)
);
CREATE INDEX list_snapshots_expiry ON list_snapshots(expires_at, snapshot_id);

CREATE TABLE list_snapshot_entries (
    snapshot_id BYTEA NOT NULL REFERENCES list_snapshots(snapshot_id) ON DELETE CASCADE,
    ordinal BIGINT NOT NULL CHECK (ordinal >= 0),
    task_id TEXT NOT NULL,
    task_revision BIGINT NOT NULL CHECK (task_revision > 0),
    task_digest TEXT NOT NULL CHECK (octet_length(task_digest) = 71),
    task_json JSONB NOT NULL,
    PRIMARY KEY (snapshot_id, ordinal),
    UNIQUE (snapshot_id, task_id)
);

CREATE TABLE list_page_tokens (
    token_hash BYTEA PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    snapshot_id BYTEA NOT NULL REFERENCES list_snapshots(snapshot_id) ON DELETE CASCADE,
    next_position BIGINT NOT NULL CHECK (next_position > 0),
    scope_digest TEXT NOT NULL,
    query_digest TEXT NOT NULL,
    token_version SMALLINT NOT NULL CHECK (token_version = 1),
    key_generation SMALLINT NOT NULL CHECK (key_generation = 1),
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at > issued_at),
    UNIQUE (snapshot_id, next_position)
);

CREATE TABLE task_events (
    event_order BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_scope TEXT NOT NULL,
    task_id TEXT NOT NULL,
    event_seq BIGINT NOT NULL CHECK (event_seq > 0),
    task_revision BIGINT NOT NULL CHECK (task_revision > 0),
    event_kind TEXT NOT NULL,
    from_state TEXT,
    to_state TEXT NOT NULL,
    event_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_scope, task_id, event_seq),
    FOREIGN KEY (tenant_scope, task_id) REFERENCES tasks(tenant_scope, task_id) ON DELETE RESTRICT
);
CREATE INDEX task_events_task_revision ON task_events(tenant_scope, task_id, task_revision);

CREATE TABLE idempotency_records (
    tenant_scope TEXT NOT NULL,
    actor_account_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    digest_version SMALLINT NOT NULL CHECK (digest_version IN (1, 2)),
    request_digest TEXT NOT NULL,
    task_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('in_progress', 'completed')),
    admission_result_json JSONB NOT NULL,
    final_result_json JSONB,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_scope, actor_account_id, message_id),
    FOREIGN KEY (tenant_scope, task_id) REFERENCES tasks(tenant_scope, task_id) ON DELETE RESTRICT
);

CREATE TABLE outbox (
    outbox_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_scope TEXT NOT NULL,
    dispatch_id TEXT NOT NULL,
    dispatch_identity_version SMALLINT NOT NULL CHECK (dispatch_identity_version IN (1, 2)),
    task_id TEXT NOT NULL,
    actor_account_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    causative_revision BIGINT NOT NULL CHECK (causative_revision > 0),
    payload_json JSONB NOT NULL,
    payload_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'leased', 'delivered', 'dead', 'superseded')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    max_attempts INTEGER NOT NULL CHECK (max_attempts > 0),
    available_at TIMESTAMPTZ NOT NULL,
    lease_owner TEXT,
    lease_token TEXT,
    lease_until TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_scope, outbox_id),
    UNIQUE (tenant_scope, dispatch_id),
    UNIQUE (tenant_scope, actor_account_id, message_id),
    FOREIGN KEY (tenant_scope, task_id) REFERENCES tasks(tenant_scope, task_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope, actor_account_id, message_id)
      REFERENCES idempotency_records(tenant_scope, actor_account_id, message_id) ON DELETE RESTRICT
);
CREATE INDEX outbox_due ON outbox(state, available_at, lease_until, outbox_id);
CREATE INDEX outbox_tenant_task_state ON outbox(tenant_scope, task_id, state);

CREATE TABLE outbox_attempts (
    tenant_scope TEXT NOT NULL,
    outbox_id BIGINT NOT NULL,
    attempt_no INTEGER NOT NULL CHECK (attempt_no > 0),
    lease_token TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    outcome TEXT,
    error TEXT,
    next_attempt_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_scope, outbox_id, attempt_no),
    FOREIGN KEY (tenant_scope, outbox_id)
      REFERENCES outbox(tenant_scope, outbox_id) ON DELETE RESTRICT
);

CREATE TABLE authorization_decisions (
    decision_order BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    decision_id TEXT NOT NULL UNIQUE,
    tenant_scope TEXT NOT NULL,
    actor_account_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    policy_revision BIGINT NOT NULL CHECK (policy_revision > 0),
    policy_digest TEXT NOT NULL,
    operation TEXT NOT NULL,
    effect TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
    reason TEXT NOT NULL,
    resource_kind TEXT NOT NULL,
    resource_digest TEXT NOT NULL, -- keyed/HMAC digest; never a raw unknown resource id
    task_id TEXT,
    decided_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (tenant_scope, task_id) REFERENCES tasks(tenant_scope, task_id) ON DELETE RESTRICT
);
CREATE INDEX authorization_decisions_tenant_time
    ON authorization_decisions(tenant_scope, decided_at, decision_order);
CREATE INDEX authorization_decisions_actor_time
    ON authorization_decisions(tenant_scope, actor_account_id, decided_at);
CREATE INDEX authorization_decisions_resource_time
    ON authorization_decisions(tenant_scope, resource_digest, decided_at);

-- Production adapter requirements:
-- * reject UPDATE/DELETE on task ownership and authorization_decisions;
-- * set `SET LOCAL smesh.tenant_scope = ...` and use RLS as defense in depth;
-- * retain existence-safe application authorization and durable decision audit;
-- * new digest-v2 rows bind tenant + actor + invocation + semantic request;
-- * migrated digest-v1 and dispatch-v1 rows remain opaque compatibility identities.
