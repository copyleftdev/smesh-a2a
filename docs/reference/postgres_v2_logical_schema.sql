-- NON-EXECUTABLE LOGICAL REFERENCE DDL ONLY.
-- This file is intentionally outside migrations/. It is not a standalone,
-- versioned, or transactional PostgreSQL migration and MUST NOT be executed.
-- A future PostgreSQL adapter must provide an owned migration ledger,
-- explicit prerequisites, and one rollback-safe transaction before using it.
--
-- Logical PostgreSQL v2 schema corresponding to the SQLite durable lifecycle model.
-- The PostgreSQL adapter (# future deployment wiring) must claim with
-- SELECT ... FOR UPDATE SKIP LOCKED and fence every finish by lease_token.
CREATE TABLE task_events (
    event_order BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_scope TEXT NOT NULL,
    task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE RESTRICT,
    event_seq BIGINT NOT NULL CHECK (event_seq > 0),
    task_revision BIGINT NOT NULL CHECK (task_revision > 0),
    event_kind TEXT NOT NULL,
    from_state TEXT,
    to_state TEXT NOT NULL,
    event_json TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    UNIQUE (tenant_scope, task_id, event_seq)
);
CREATE INDEX task_events_task_revision ON task_events(tenant_scope, task_id, task_revision);

CREATE TABLE idempotency_records (
    tenant_scope TEXT NOT NULL,
    message_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE RESTRICT,
    state TEXT NOT NULL CHECK (state IN ('in_progress', 'completed')),
    admission_result_json TEXT NOT NULL,
    final_result_json TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (tenant_scope, message_id)
);
CREATE INDEX idempotency_records_task ON idempotency_records(tenant_scope, task_id);

CREATE TABLE outbox (
    outbox_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    dispatch_id TEXT NOT NULL UNIQUE,
    tenant_scope TEXT NOT NULL,
    task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE RESTRICT,
    message_id TEXT NOT NULL,
    causative_revision BIGINT NOT NULL CHECK (causative_revision > 0),
    payload_json TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'leased', 'delivered', 'dead', 'superseded')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    max_attempts INTEGER NOT NULL CHECK (max_attempts > 0),
    available_at BIGINT NOT NULL,
    lease_owner TEXT,
    lease_token TEXT,
    lease_until BIGINT,
    last_error TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE INDEX outbox_due ON outbox(state, available_at, lease_until, outbox_id);
CREATE INDEX outbox_task_state ON outbox(task_id, state);
CREATE UNIQUE INDEX outbox_message_identity ON outbox(tenant_scope, message_id);

CREATE TABLE outbox_attempts (
    outbox_id BIGINT NOT NULL REFERENCES outbox(outbox_id) ON DELETE RESTRICT,
    attempt_no INTEGER NOT NULL CHECK (attempt_no > 0),
    lease_token TEXT NOT NULL,
    started_at BIGINT NOT NULL,
    finished_at BIGINT,
    outcome TEXT,
    error TEXT,
    next_attempt_at BIGINT,
    PRIMARY KEY (outbox_id, attempt_no)
);
