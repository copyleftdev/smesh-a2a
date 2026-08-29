#![cfg_attr(not(unix), allow(dead_code))]

use std::fmt::Write as _;
use std::fs::File;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use a2a::{
    A2AError, ListTasksRequest, ListTasksResponse, Message, Part, Role, SendMessageRequest,
    SendMessageResponse, StreamResponse, Task, TaskArtifactUpdateEvent, TaskStatusUpdateEvent,
};
use a2a_server::TaskStore;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac as _};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use thiserror::Error;

use crate::{
    AdmissionOutcome, AdmissionRecord, AtomicRecordCounts, AttemptDisposition,
    AuthorizationAuditInput, AuthorizationDecisionEffect, CancellationOutcome,
    DurableDispatchEnvelope, DurableReceiverResult, DurableReceiverTermination, InputLimits,
    MeshEvent, MeshRequest, OutboxLease, OwnedTaskScope, ReceiverAdmission, ReceiverLease,
    SendMessageAdmission, StreamTranscriptBatch, SubscriptionCursor, TaskEventBatch,
    TransitionOutcome, VisibilityScope, authorized_message_identity, canonical_send_message_digest,
    canonical_send_message_digest_v2, content_digest, durable_authority::valid_bounded_identity,
};

const SCHEMA_VERSION: i64 = 6;
const V5_SCHEMA_VERSION: i64 = 5;
const V4_SCHEMA_VERSION: i64 = 4;
const V2_SCHEMA_VERSION: i64 = 2;
const V3_SCHEMA_VERSION: i64 = 3;
const APPLICATION_ID: i64 = 0x534D_4132;
const MAX_TASK_JSON_BYTES: usize = 1024 * 1024;
const MAX_STORE_JSON_BYTES: usize = 64 * 1024 * 1024;
const MAX_ATOMIC_JSON_BYTES: usize = 1024 * 1024;
const MAX_ATOMIC_TEXT_BYTES: usize = 4096;
const MAX_OUTBOX_ATTEMPTS: u32 = 1_000;
const STREAM_TRANSCRIPT_VERSION: i64 = 1;
const MAX_STREAM_FRAMES: usize = 1_024;
const STREAM_INTERRUPTION_PREFIX: &str = "durable stream interrupted: ";
/// Fixed compatibility scope used only by [`SqliteTaskStore::open`] for a new development DB.
pub use crate::TRUSTED_SINGLE_TENANT_SCOPE;
pub const DEV_ONLY_ACCOUNT_ID: &str = "smesh-dev-only-account";
const LEGACY_V4_SENTINEL_SCOPE: &str = "smesh:trusted-single-tenant:v1";
const MAX_AUTHORIZATION_DECISIONS: usize = 65_536;
const PAGE_TOKEN_VERSION: i64 = 1;
const PAGE_TOKEN_KEY_GENERATION: i64 = 1;
const MAX_PAGE_TOKEN_BYTES: usize = 4096;
const SNAPSHOT_TTL_MILLIS: i64 = 5 * 60 * 1_000;
const MAX_ACTIVE_SNAPSHOTS: i64 = 128;
const MAX_SNAPSHOT_BYTES: i64 = 64 * 1024 * 1024;
type PageTokenRow = (Vec<u8>, i64, String, String, i64, i64, i64, i64, i64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyTenantBinding {
    tenant_scope: String,
    owner_account_id: String,
    policy_id: String,
    policy_revision: u64,
    policy_digest: String,
}

#[allow(clippy::missing_errors_doc)]
impl LegacyTenantBinding {
    pub fn new(
        tenant_scope: impl Into<String>,
        owner_account_id: impl Into<String>,
        policy_id: impl Into<String>,
        policy_revision: u64,
        policy_digest: impl Into<String>,
    ) -> Result<Self, SqliteStoreError> {
        let value = Self {
            tenant_scope: tenant_scope.into(),
            owner_account_id: owner_account_id.into(),
            policy_id: policy_id.into(),
            policy_revision,
            policy_digest: policy_digest.into(),
        };
        if !valid_bounded_identity(&value.tenant_scope)
            || !valid_bounded_identity(&value.owner_account_id)
            || !valid_bounded_identity(&value.policy_id)
            || value.policy_revision == 0
            || value.policy_digest.is_empty()
            || value.policy_digest.len() > 256
        {
            return Err(SqliteStoreError::InvalidSchema);
        }
        Ok(value)
    }

    fn development() -> Self {
        Self::new(
            TRUSTED_SINGLE_TENANT_SCOPE,
            DEV_ONLY_ACCOUNT_ID,
            "smesh-dev-only-policy",
            1,
            content_digest(b"smesh-dev-only-policy/v1"),
        )
        .expect("fixed development binding is valid")
    }
}

const V1_SCHEMA_SQL: &str = "CREATE TABLE store_metadata (
     singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
     schema_version INTEGER NOT NULL,
     migration_hash TEXT NOT NULL,
     cursor_key BLOB NOT NULL CHECK (length(cursor_key) = 32),
     receipt_key BLOB NOT NULL CHECK (length(receipt_key) = 32)
 );
 CREATE TABLE tasks (
     created_order INTEGER PRIMARY KEY AUTOINCREMENT,
     task_id TEXT NOT NULL UNIQUE,
     context_id TEXT NOT NULL,
     state TEXT NOT NULL,
     status_timestamp TEXT,
     revision INTEGER NOT NULL CHECK (revision > 0),
     task_json TEXT NOT NULL
 );
 CREATE INDEX tasks_context_state_time
     ON tasks(context_id, state, status_timestamp, task_id);";
const ATOMIC_SCHEMA_SQL: &str = "CREATE TABLE task_events (
     event_order INTEGER PRIMARY KEY AUTOINCREMENT,
     tenant_scope TEXT NOT NULL,
     task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE RESTRICT,
     event_seq INTEGER NOT NULL CHECK (event_seq > 0),
     task_revision INTEGER NOT NULL CHECK (task_revision > 0),
     event_kind TEXT NOT NULL,
     from_state TEXT,
     to_state TEXT NOT NULL,
     event_json TEXT NOT NULL,
     created_at INTEGER NOT NULL,
     UNIQUE(tenant_scope, task_id, event_seq)
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
     created_at INTEGER NOT NULL,
     updated_at INTEGER NOT NULL,
     PRIMARY KEY(tenant_scope, message_id)
 );
 CREATE INDEX idempotency_records_task ON idempotency_records(tenant_scope, task_id);
 CREATE TABLE outbox (
     outbox_id INTEGER PRIMARY KEY AUTOINCREMENT,
     dispatch_id TEXT NOT NULL UNIQUE,
     tenant_scope TEXT NOT NULL,
     task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE RESTRICT,
     causative_revision INTEGER NOT NULL CHECK (causative_revision > 0),
     payload_json TEXT NOT NULL,
     payload_digest TEXT NOT NULL,
     state TEXT NOT NULL CHECK (state IN ('pending', 'leased', 'delivered', 'dead', 'superseded')),
     attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
     max_attempts INTEGER NOT NULL CHECK (max_attempts > 0),
     available_at INTEGER NOT NULL,
     lease_owner TEXT,
     lease_token TEXT,
     lease_until INTEGER,
     last_error TEXT,
     created_at INTEGER NOT NULL,
     updated_at INTEGER NOT NULL
 );
 CREATE INDEX outbox_due ON outbox(state, available_at, lease_until, outbox_id);
 CREATE INDEX outbox_task_state ON outbox(task_id, state);
 CREATE TABLE outbox_attempts (
     outbox_id INTEGER NOT NULL REFERENCES outbox(outbox_id) ON DELETE RESTRICT,
     attempt_no INTEGER NOT NULL CHECK (attempt_no > 0),
     lease_token TEXT NOT NULL,
     started_at INTEGER NOT NULL,
     finished_at INTEGER,
     outcome TEXT,
     error TEXT,
     next_attempt_at INTEGER,
     PRIMARY KEY(outbox_id, attempt_no)
 );
";
const V2_SCHEMA_SQL: &str = "CREATE TABLE store_metadata (
     singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
     schema_version INTEGER NOT NULL,
     migration_hash TEXT NOT NULL,
     cursor_key BLOB NOT NULL CHECK (length(cursor_key) = 32),
     receipt_key BLOB NOT NULL CHECK (length(receipt_key) = 32)
 );
 CREATE TABLE tasks (
     created_order INTEGER PRIMARY KEY AUTOINCREMENT,
     task_id TEXT NOT NULL UNIQUE,
     context_id TEXT NOT NULL,
     state TEXT NOT NULL,
     status_timestamp TEXT,
     revision INTEGER NOT NULL CHECK (revision > 0),
     task_json TEXT NOT NULL
 );
 CREATE INDEX tasks_context_state_time
     ON tasks(context_id, state, status_timestamp, task_id);
 CREATE TABLE task_events (
     event_order INTEGER PRIMARY KEY AUTOINCREMENT,
     tenant_scope TEXT NOT NULL,
     task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE RESTRICT,
     event_seq INTEGER NOT NULL CHECK (event_seq > 0),
     task_revision INTEGER NOT NULL CHECK (task_revision > 0),
     event_kind TEXT NOT NULL,
     from_state TEXT,
     to_state TEXT NOT NULL,
     event_json TEXT NOT NULL,
     created_at INTEGER NOT NULL,
     UNIQUE(tenant_scope, task_id, event_seq)
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
     created_at INTEGER NOT NULL,
     updated_at INTEGER NOT NULL,
     PRIMARY KEY(tenant_scope, message_id)
 );
 CREATE INDEX idempotency_records_task ON idempotency_records(tenant_scope, task_id);
 CREATE TABLE outbox (
     outbox_id INTEGER PRIMARY KEY AUTOINCREMENT,
     dispatch_id TEXT NOT NULL UNIQUE,
     tenant_scope TEXT NOT NULL,
     task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE RESTRICT,
     causative_revision INTEGER NOT NULL CHECK (causative_revision > 0),
     payload_json TEXT NOT NULL,
     payload_digest TEXT NOT NULL,
     state TEXT NOT NULL CHECK (state IN ('pending', 'leased', 'delivered', 'dead', 'superseded')),
     attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
     max_attempts INTEGER NOT NULL CHECK (max_attempts > 0),
     available_at INTEGER NOT NULL,
     lease_owner TEXT,
     lease_token TEXT,
     lease_until INTEGER,
     last_error TEXT,
     created_at INTEGER NOT NULL,
     updated_at INTEGER NOT NULL
 );
 CREATE INDEX outbox_due ON outbox(state, available_at, lease_until, outbox_id);
 CREATE INDEX outbox_task_state ON outbox(task_id, state);
 CREATE TABLE outbox_attempts (
     outbox_id INTEGER NOT NULL REFERENCES outbox(outbox_id) ON DELETE RESTRICT,
     attempt_no INTEGER NOT NULL CHECK (attempt_no > 0),
     lease_token TEXT NOT NULL,
     started_at INTEGER NOT NULL,
     finished_at INTEGER,
     outcome TEXT,
     error TEXT,
     next_attempt_at INTEGER,
     PRIMARY KEY(outbox_id, attempt_no)
 );
";
const RECEIVER_SCHEMA_SQL: &str = "CREATE TABLE receiver_inbox (
     tenant_scope TEXT NOT NULL,
     dispatch_id TEXT NOT NULL,
     payload_digest TEXT NOT NULL,
     payload_json TEXT NOT NULL,
     task_id TEXT NOT NULL,
     context_id TEXT NOT NULL,
     state TEXT NOT NULL CHECK (state IN ('processing', 'completed')),
     lease_epoch INTEGER NOT NULL CHECK (lease_epoch > 0),
     lease_owner TEXT,
     lease_token TEXT,
     lease_until INTEGER,
     completion_kind TEXT CHECK (completion_kind IS NULL OR completion_kind IN
         ('success', 'input_required', 'auth_required')),
     termination_json TEXT,
     frame_count INTEGER CHECK (frame_count IS NULL OR frame_count >= 0),
     transcript_digest TEXT,
     accepted_at INTEGER NOT NULL,
     completed_at INTEGER,
     updated_at INTEGER NOT NULL,
     PRIMARY KEY(tenant_scope, dispatch_id),
     CHECK ((state = 'processing' AND completion_kind IS NULL AND termination_json IS NULL AND frame_count IS NULL
             AND transcript_digest IS NULL AND completed_at IS NULL
             AND lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_until IS NOT NULL)
         OR (state = 'completed' AND completion_kind IS NOT NULL
             AND ((completion_kind = 'success' AND termination_json IS NULL)
                  OR (completion_kind IN ('input_required', 'auth_required') AND termination_json IS NOT NULL))
             AND frame_count IS NOT NULL
             AND transcript_digest IS NOT NULL AND completed_at IS NOT NULL
             AND lease_owner IS NULL AND lease_token IS NULL AND lease_until IS NULL))
 );
 CREATE INDEX receiver_inbox_reclaim
     ON receiver_inbox(state, lease_until, accepted_at, dispatch_id);
 CREATE TABLE receiver_frames (
     tenant_scope TEXT NOT NULL,
     dispatch_id TEXT NOT NULL,
     frame_seq INTEGER NOT NULL CHECK (frame_seq > 0),
     frame_version INTEGER NOT NULL CHECK (frame_version = 1),
     frame_kind TEXT NOT NULL CHECK (frame_kind IN ('mesh_event', 'dispatch_error')),
     frame_json TEXT NOT NULL,
     frame_digest TEXT NOT NULL,
     created_at INTEGER NOT NULL,
     PRIMARY KEY(tenant_scope, dispatch_id, frame_seq),
     FOREIGN KEY(tenant_scope, dispatch_id)
       REFERENCES receiver_inbox(tenant_scope, dispatch_id) ON DELETE RESTRICT
 );
 CREATE TABLE loopback_effects (
     tenant_scope TEXT NOT NULL,
     dispatch_id TEXT NOT NULL,
     effect_kind TEXT NOT NULL CHECK (effect_kind = 'accepted'),
     committed_at INTEGER NOT NULL,
     PRIMARY KEY(tenant_scope, dispatch_id),
     FOREIGN KEY(tenant_scope, dispatch_id)
       REFERENCES receiver_inbox(tenant_scope, dispatch_id) ON DELETE RESTRICT
 );
 CREATE TABLE stream_transcripts (
     tenant_scope TEXT NOT NULL,
     message_id TEXT NOT NULL,
     dispatch_id TEXT NOT NULL UNIQUE REFERENCES outbox(dispatch_id) ON DELETE RESTRICT,
     task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE RESTRICT,
     transcript_version INTEGER NOT NULL CHECK (transcript_version = 1),
     state TEXT NOT NULL CHECK (state IN ('open', 'terminal', 'interrupted')),
     frame_count INTEGER NOT NULL CHECK (frame_count >= 0 AND frame_count <= 1024),
     transcript_digest TEXT,
     terminal_seq INTEGER,
     interruption_error TEXT,
     created_at INTEGER NOT NULL,
     updated_at INTEGER NOT NULL,
     PRIMARY KEY(tenant_scope, message_id),
     CHECK ((state = 'open' AND frame_count > 0 AND transcript_digest IS NOT NULL
             AND terminal_seq IS NULL AND interruption_error IS NULL)
         OR (state = 'terminal' AND frame_count > 0 AND transcript_digest IS NOT NULL
             AND terminal_seq = frame_count AND interruption_error IS NULL)
         OR (state = 'interrupted' AND transcript_digest IS NOT NULL
             AND terminal_seq IS NULL AND interruption_error IS NOT NULL))
 );
 CREATE INDEX stream_transcripts_task
     ON stream_transcripts(tenant_scope, task_id, state);
 CREATE TABLE stream_frames (
     tenant_scope TEXT NOT NULL,
     message_id TEXT NOT NULL,
     frame_seq INTEGER NOT NULL CHECK (frame_seq > 0 AND frame_seq <= 1024),
     frame_version INTEGER NOT NULL CHECK (frame_version = 1),
     frame_kind TEXT NOT NULL CHECK (frame_kind IN
         ('task', 'message', 'status_update', 'artifact_update')),
     frame_json TEXT NOT NULL,
     frame_digest TEXT NOT NULL,
     created_at INTEGER NOT NULL,
     PRIMARY KEY(tenant_scope, message_id, frame_seq),
     FOREIGN KEY(tenant_scope, message_id)
       REFERENCES stream_transcripts(tenant_scope, message_id) ON DELETE RESTRICT
 );
";
const CANCELLATION_SCHEMA_SQL: &str = "CREATE TABLE cancellation_intents (
     tenant_scope TEXT NOT NULL,
     dispatch_id TEXT NOT NULL REFERENCES outbox(dispatch_id) ON DELETE RESTRICT,
     task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE RESTRICT,
     state TEXT NOT NULL CHECK (state IN ('requested', 'receiver_canceled')),
     requested_at INTEGER NOT NULL,
     completed_at INTEGER,
     PRIMARY KEY(tenant_scope, dispatch_id),
     CHECK ((state = 'requested' AND completed_at IS NULL)
         OR (state = 'receiver_canceled' AND completed_at IS NOT NULL))
 );
 CREATE INDEX cancellation_intents_task
     ON cancellation_intents(tenant_scope, task_id, state);";
const V4_OUTBOX_TABLE_SQL: &str = "CREATE TABLE outbox_v4 (
     outbox_id INTEGER PRIMARY KEY AUTOINCREMENT,
     dispatch_id TEXT NOT NULL UNIQUE,
     tenant_scope TEXT NOT NULL,
     task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE RESTRICT,
     message_id TEXT NOT NULL,
     causative_revision INTEGER NOT NULL CHECK (causative_revision > 0),
     payload_json TEXT NOT NULL,
     payload_digest TEXT NOT NULL,
     state TEXT NOT NULL CHECK (state IN ('pending', 'leased', 'delivered', 'dead', 'superseded')),
     attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
     max_attempts INTEGER NOT NULL CHECK (max_attempts > 0),
     available_at INTEGER NOT NULL,
     lease_owner TEXT,
     lease_token TEXT,
     lease_until INTEGER,
     last_error TEXT,
     created_at INTEGER NOT NULL,
     updated_at INTEGER NOT NULL
 );";
const OUTBOX_MESSAGE_BINDING_SQL: &str =
    "CREATE UNIQUE INDEX outbox_message_identity ON outbox(tenant_scope, message_id);";
const OUTBOX_MESSAGE_IMMUTABILITY_SQL: &str = "CREATE TRIGGER outbox_message_immutable
 BEFORE UPDATE OF message_id ON outbox
 WHEN NEW.message_id IS NOT OLD.message_id
 BEGIN SELECT RAISE(ABORT, 'outbox message identity is immutable'); END;";
const V5_SCHEMA_SQL: &str = "CREATE TABLE store_identity (
 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
 tenant_scope TEXT NOT NULL CHECK(length(CAST(tenant_scope AS BLOB)) BETWEEN 1 AND 64),
 owner_account_id TEXT NOT NULL CHECK(length(CAST(owner_account_id AS BLOB)) BETWEEN 1 AND 64),
 policy_id TEXT NOT NULL CHECK(length(CAST(policy_id AS BLOB)) BETWEEN 1 AND 64),
 policy_revision INTEGER NOT NULL CHECK(policy_revision > 0),
 policy_digest TEXT NOT NULL CHECK(length(CAST(policy_digest AS BLOB)) BETWEEN 1 AND 256)
 );
 CREATE INDEX tasks_tenant_owner_time
 ON tasks(tenant_scope, owner_account_id, status_timestamp, task_id);
 CREATE TABLE authorization_decisions (
     decision_order INTEGER PRIMARY KEY AUTOINCREMENT,
     decision_id TEXT NOT NULL UNIQUE CHECK(length(CAST(decision_id AS BLOB)) BETWEEN 1 AND 256),
     tenant_scope TEXT NOT NULL CHECK(length(CAST(tenant_scope AS BLOB)) BETWEEN 1 AND 64),
     actor_account_id TEXT NOT NULL CHECK(length(CAST(actor_account_id AS BLOB)) BETWEEN 1 AND 64),
     policy_id TEXT NOT NULL CHECK(length(CAST(policy_id AS BLOB)) BETWEEN 1 AND 64),
     policy_revision INTEGER NOT NULL CHECK(policy_revision > 0),
     policy_digest TEXT NOT NULL CHECK(length(CAST(policy_digest AS BLOB)) BETWEEN 1 AND 256),
     operation TEXT NOT NULL CHECK(length(CAST(operation AS BLOB)) BETWEEN 1 AND 256),
     effect TEXT NOT NULL CHECK(effect IN ('allow', 'deny')),
     reason TEXT NOT NULL CHECK(length(CAST(reason AS BLOB)) BETWEEN 1 AND 256),
     resource_kind TEXT NOT NULL CHECK(length(CAST(resource_kind AS BLOB)) BETWEEN 1 AND 256),
     resource_digest TEXT NOT NULL CHECK(length(CAST(resource_digest AS BLOB)) BETWEEN 1 AND 256),
     task_id TEXT,
     decided_at INTEGER NOT NULL,
     FOREIGN KEY(task_id) REFERENCES tasks(task_id) ON DELETE RESTRICT
 );
 CREATE INDEX authorization_decisions_tenant_time ON authorization_decisions(tenant_scope, decided_at, decision_order);
 CREATE INDEX authorization_decisions_actor_time ON authorization_decisions(tenant_scope, actor_account_id, decided_at);
 CREATE INDEX authorization_decisions_resource_time ON authorization_decisions(tenant_scope, resource_digest, decided_at);
 CREATE TRIGGER tasks_ownership_immutable BEFORE UPDATE OF tenant_scope, owner_account_id ON tasks
 WHEN NEW.tenant_scope IS NOT OLD.tenant_scope OR NEW.owner_account_id IS NOT OLD.owner_account_id
 BEGIN SELECT RAISE(ABORT, 'task ownership is immutable'); END;
 CREATE TRIGGER authorization_decisions_no_update BEFORE UPDATE ON authorization_decisions
 BEGIN SELECT RAISE(ABORT, 'authorization decisions are append-only'); END;
 CREATE TRIGGER authorization_decisions_no_delete BEFORE DELETE ON authorization_decisions
 BEGIN SELECT RAISE(ABORT, 'authorization decisions are append-only'); END;
 CREATE TRIGGER authorization_decisions_task_scope BEFORE INSERT ON authorization_decisions
 WHEN NEW.task_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM tasks t WHERE t.task_id=NEW.task_id AND t.tenant_scope=NEW.tenant_scope)
 BEGIN SELECT RAISE(ABORT, 'authorization task scope mismatch'); END;
 CREATE TRIGGER task_events_tenant_match BEFORE INSERT ON task_events
 WHEN NOT EXISTS(SELECT 1 FROM tasks t WHERE t.task_id=NEW.task_id AND t.tenant_scope=NEW.tenant_scope)
 BEGIN SELECT RAISE(ABORT, 'task event tenant mismatch'); END;
 CREATE TRIGGER idempotency_tenant_match BEFORE INSERT ON idempotency_records
 WHEN NOT EXISTS(SELECT 1 FROM tasks t WHERE t.task_id=NEW.task_id AND t.tenant_scope=NEW.tenant_scope)
 BEGIN SELECT RAISE(ABORT, 'idempotency tenant mismatch'); END;
 CREATE TRIGGER outbox_tenant_match BEFORE INSERT ON outbox
 WHEN NOT EXISTS(SELECT 1 FROM tasks t WHERE t.task_id=NEW.task_id AND t.tenant_scope=NEW.tenant_scope)
 BEGIN SELECT RAISE(ABORT, 'outbox tenant mismatch'); END;
 CREATE TRIGGER stream_transcripts_tenant_match BEFORE INSERT ON stream_transcripts
 WHEN NOT EXISTS(SELECT 1 FROM tasks t WHERE t.task_id=NEW.task_id AND t.tenant_scope=NEW.tenant_scope)
 BEGIN SELECT RAISE(ABORT, 'stream tenant mismatch'); END;
 CREATE TRIGGER cancellation_tenant_match BEFORE INSERT ON cancellation_intents
 WHEN NOT EXISTS(SELECT 1 FROM tasks t WHERE t.task_id=NEW.task_id AND t.tenant_scope=NEW.tenant_scope)
 BEGIN SELECT RAISE(ABORT, 'cancellation tenant mismatch'); END;
 CREATE TRIGGER task_events_identity_update BEFORE UPDATE OF tenant_scope, task_id ON task_events
 WHEN NEW.tenant_scope IS NOT OLD.tenant_scope OR NEW.task_id IS NOT OLD.task_id
 BEGIN SELECT RAISE(ABORT, 'task event identity is immutable'); END;
 CREATE TRIGGER idempotency_identity_update BEFORE UPDATE OF tenant_scope, message_id, task_id ON idempotency_records
 WHEN NEW.tenant_scope IS NOT OLD.tenant_scope OR NEW.message_id IS NOT OLD.message_id OR NEW.task_id IS NOT OLD.task_id
 BEGIN SELECT RAISE(ABORT, 'idempotency identity is immutable'); END;
 CREATE TRIGGER outbox_identity_update BEFORE UPDATE OF dispatch_id, tenant_scope, task_id, message_id ON outbox
 WHEN NEW.dispatch_id IS NOT OLD.dispatch_id OR NEW.tenant_scope IS NOT OLD.tenant_scope OR NEW.task_id IS NOT OLD.task_id OR NEW.message_id IS NOT OLD.message_id
 BEGIN SELECT RAISE(ABORT, 'outbox identity is immutable'); END;
 CREATE TRIGGER outbox_attempts_identity_update BEFORE UPDATE OF outbox_id, attempt_no ON outbox_attempts
 WHEN NEW.outbox_id IS NOT OLD.outbox_id OR NEW.attempt_no IS NOT OLD.attempt_no
 BEGIN SELECT RAISE(ABORT, 'outbox attempt identity is immutable'); END;
 CREATE TRIGGER receiver_inbox_task_match BEFORE INSERT ON receiver_inbox
 WHEN NOT EXISTS(SELECT 1 FROM outbox o WHERE o.dispatch_id=NEW.dispatch_id AND o.task_id=NEW.task_id AND o.tenant_scope=NEW.tenant_scope)
 BEGIN SELECT RAISE(ABORT, 'receiver inbox task mismatch'); END;
 CREATE TRIGGER receiver_inbox_identity_update BEFORE UPDATE OF tenant_scope, dispatch_id, task_id, context_id ON receiver_inbox
 WHEN NEW.tenant_scope IS NOT OLD.tenant_scope OR NEW.dispatch_id IS NOT OLD.dispatch_id OR NEW.task_id IS NOT OLD.task_id OR NEW.context_id IS NOT OLD.context_id
 BEGIN SELECT RAISE(ABORT, 'receiver inbox identity is immutable'); END;
 CREATE TRIGGER receiver_frames_identity_update BEFORE UPDATE OF tenant_scope, dispatch_id, frame_seq ON receiver_frames
 WHEN NEW.tenant_scope IS NOT OLD.tenant_scope OR NEW.dispatch_id IS NOT OLD.dispatch_id OR NEW.frame_seq IS NOT OLD.frame_seq
 BEGIN SELECT RAISE(ABORT, 'receiver frame identity is immutable'); END;
 CREATE TRIGGER loopback_effects_identity_update BEFORE UPDATE OF tenant_scope, dispatch_id, effect_kind ON loopback_effects
 WHEN NEW.tenant_scope IS NOT OLD.tenant_scope OR NEW.dispatch_id IS NOT OLD.dispatch_id OR NEW.effect_kind IS NOT OLD.effect_kind
 BEGIN SELECT RAISE(ABORT, 'receiver effect identity is immutable'); END;
 CREATE TRIGGER stream_transcripts_identity_update BEFORE UPDATE OF tenant_scope, message_id, dispatch_id, task_id ON stream_transcripts
 WHEN NEW.tenant_scope IS NOT OLD.tenant_scope OR NEW.message_id IS NOT OLD.message_id OR NEW.dispatch_id IS NOT OLD.dispatch_id OR NEW.task_id IS NOT OLD.task_id
 BEGIN SELECT RAISE(ABORT, 'stream transcript identity is immutable'); END;
 CREATE TRIGGER stream_frames_identity_update BEFORE UPDATE OF tenant_scope, message_id, frame_seq ON stream_frames
 WHEN NEW.tenant_scope IS NOT OLD.tenant_scope OR NEW.message_id IS NOT OLD.message_id OR NEW.frame_seq IS NOT OLD.frame_seq
 BEGIN SELECT RAISE(ABORT, 'stream frame identity is immutable'); END;
 CREATE TRIGGER cancellation_identity_update BEFORE UPDATE OF tenant_scope, dispatch_id, task_id ON cancellation_intents
 WHEN NEW.tenant_scope IS NOT OLD.tenant_scope OR NEW.dispatch_id IS NOT OLD.dispatch_id OR NEW.task_id IS NOT OLD.task_id
 BEGIN SELECT RAISE(ABORT, 'cancellation identity is immutable'); END;";
const V6_SCHEMA_SQL: &str = "CREATE TABLE list_snapshots (
 snapshot_id BLOB PRIMARY KEY CHECK(length(snapshot_id)=32),
 scope_digest TEXT NOT NULL CHECK(length(CAST(scope_digest AS BLOB)) BETWEEN 1 AND 256),
 query_digest TEXT NOT NULL CHECK(length(CAST(query_digest AS BLOB)) BETWEEN 1 AND 256),
 total_size INTEGER NOT NULL CHECK(total_size >= 0),
 page_size INTEGER NOT NULL CHECK(page_size BETWEEN 1 AND 100),
 issued_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL CHECK(expires_at > issued_at),
 projection_version INTEGER NOT NULL CHECK(projection_version = 1),
 frozen_bytes INTEGER NOT NULL CHECK(frozen_bytes >= 0),
 metadata_digest BLOB NOT NULL CHECK(length(metadata_digest)=32)
 );
 CREATE INDEX list_snapshots_expiry ON list_snapshots(expires_at,snapshot_id);
 CREATE TABLE list_snapshot_entries (
 snapshot_id BLOB NOT NULL REFERENCES list_snapshots(snapshot_id) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
 task_id TEXT NOT NULL,
 task_revision INTEGER NOT NULL CHECK(task_revision > 0),
 task_digest TEXT NOT NULL CHECK(length(CAST(task_digest AS BLOB)) = 71),
 task_json TEXT NOT NULL CHECK(json_valid(task_json)),
 PRIMARY KEY(snapshot_id,ordinal),
 UNIQUE(snapshot_id,task_id)
 );
 CREATE TABLE list_page_tokens (
 token_hash BLOB PRIMARY KEY CHECK(length(token_hash)=32),
 snapshot_id BLOB NOT NULL REFERENCES list_snapshots(snapshot_id) ON DELETE CASCADE,
 next_position INTEGER NOT NULL CHECK(next_position > 0),
 scope_digest TEXT NOT NULL CHECK(length(CAST(scope_digest AS BLOB)) BETWEEN 1 AND 256),
 query_digest TEXT NOT NULL CHECK(length(CAST(query_digest AS BLOB)) BETWEEN 1 AND 256),
 token_version INTEGER NOT NULL CHECK(token_version = 1),
 key_generation INTEGER NOT NULL CHECK(key_generation = 1),
 issued_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL CHECK(expires_at > issued_at),
 UNIQUE(snapshot_id,next_position)
 );
 CREATE INDEX list_page_tokens_snapshot ON list_page_tokens(snapshot_id,next_position);
 CREATE INDEX tasks_tenant_time_v6 ON tasks(tenant_scope,status_timestamp DESC,task_id ASC);
 CREATE INDEX tasks_tenant_state_time_v6 ON tasks(tenant_scope,state,status_timestamp DESC,task_id ASC);
 CREATE INDEX tasks_tenant_context_time_v6 ON tasks(tenant_scope,context_id,status_timestamp DESC,task_id ASC);
 CREATE INDEX tasks_tenant_context_state_time_v6 ON tasks(tenant_scope,context_id,state,status_timestamp DESC,task_id ASC);
 CREATE INDEX tasks_tenant_owner_time_v6 ON tasks(tenant_scope,owner_account_id,status_timestamp DESC,task_id ASC);
 CREATE INDEX tasks_tenant_owner_state_time_v6 ON tasks(tenant_scope,owner_account_id,state,status_timestamp DESC,task_id ASC);
 CREATE INDEX tasks_tenant_owner_context_time_v6 ON tasks(tenant_scope,owner_account_id,context_id,status_timestamp DESC,task_id ASC);
 CREATE INDEX tasks_tenant_owner_context_state_time_v6 ON tasks(tenant_scope,owner_account_id,context_id,state,status_timestamp DESC,task_id ASC);";

#[derive(Debug, Error)]
pub enum SqliteStoreError {
    #[error("persistent task-store path is a symbolic link")]
    SymbolicLink,
    #[error("persistent task-store schema is unsupported or corrupt")]
    InvalidSchema,
    #[error("persistent task-store initialization failed")]
    Initialization,
    #[error("persistent task-store contains more tasks than the configured capacity")]
    Capacity,
    #[error("persistent task store is already open by another writer")]
    AlreadyOpen,
    #[error("persistent task store is unsupported on this platform")]
    UnsupportedPlatform,
}

#[derive(Clone)]
pub struct SqliteTaskStore {
    connection: Arc<Mutex<Option<Connection>>>,
    ownership_lock: Arc<Mutex<Option<File>>>,
    admission: Arc<tokio::sync::Semaphore>,
    cursor_key: Arc<[u8; 32]>,
    receipt_key: Arc<[u8; 32]>,
    max_tasks: usize,
    default_scope: Arc<str>,
    default_account: Arc<str>,
}

#[allow(clippy::missing_errors_doc)]
impl SqliteTaskStore {
    /// Open or create a versioned SQLite task store.
    ///
    /// # Errors
    ///
    /// Returns an error for symbolic-link paths, unknown/corrupt schemas, or initialization failure.
    pub async fn open(path: impl AsRef<Path>, max_tasks: usize) -> Result<Self, SqliteStoreError> {
        Self::open_inner(path, max_tasks, None, true).await
    }

    /// Open a store and explicitly bind any legacy v1-v4 records to one validated owner.
    pub async fn open_with_legacy_binding(
        path: impl AsRef<Path>,
        max_tasks: usize,
        binding: LegacyTenantBinding,
    ) -> Result<Self, SqliteStoreError> {
        Self::open_inner(path, max_tasks, Some(binding), false).await
    }

    async fn open_inner(
        path: impl AsRef<Path>,
        max_tasks: usize,
        binding: Option<LegacyTenantBinding>,
        dev_new_only: bool,
    ) -> Result<Self, SqliteStoreError> {
        #[cfg(not(unix))]
        {
            let _ = (path, max_tasks, binding, dev_new_only);
            Err(SqliteStoreError::UnsupportedPlatform)
        }

        #[cfg(unix)]
        {
            let path = path.as_ref().to_path_buf();
            prepare_secure_path(&path)?;
            let ownership_lock = acquire_ownership_lock(&path)?;
            let capacity = max_tasks.max(1);
            let (connection, cursor_key, receipt_key, default_scope, default_account) =
                tokio::task::spawn_blocking(move || {
                    open_database(&path, capacity, binding, dev_new_only)
                })
                .await
                .map_err(|_| SqliteStoreError::Initialization)??;
            secure_permissions(&connection)?;
            Ok(Self {
                connection: Arc::new(Mutex::new(Some(connection))),
                ownership_lock: Arc::new(Mutex::new(Some(ownership_lock))),
                admission: Arc::new(tokio::sync::Semaphore::new(1)),
                cursor_key: Arc::new(cursor_key),
                receipt_key: Arc::new(receipt_key),
                max_tasks: capacity,
                default_scope: Arc::from(default_scope),
                default_account: Arc::from(default_account),
            })
        }
    }

    /// Atomically create an owned task, its first event, and the corresponding allow audit.
    pub async fn create_scoped(
        &self,
        scope: &OwnedTaskScope,
        task: Task,
        audit: AuthorizationAuditInput,
    ) -> Result<u64, A2AError> {
        if audit.effect != AuthorizationDecisionEffect::Allow
            || audit.tenant_scope != scope.tenant_scope
            || audit.actor_account_id != scope.owner_account_id
        {
            return Err(A2AError::invalid_request(
                "allow audit does not match task scope",
            ));
        }
        let encoded = encode_task(&task)?;
        let state = state_key(&task)?;
        let timestamp = task.status.timestamp.map(|value| value.to_rfc3339());
        let tenant = scope.tenant_scope.clone();
        let owner = scope.owner_account_id.clone();
        let max_tasks = self.max_tasks;
        self.run(move |connection| {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| A2AError::internal("scoped create transaction failed"))?;
            let count: i64 = tx.query_row("SELECT COUNT(*) FROM tasks", [], |row| row.get(0))
                .map_err(|_| A2AError::internal("task count failed"))?;
            if usize::try_from(count).unwrap_or(usize::MAX) >= max_tasks {
                return Err(A2AError::internal("task store capacity reached"));
            }
            tx.execute(
                "INSERT INTO tasks(task_id,context_id,state,status_timestamp,revision,task_json,tenant_scope,owner_account_id)
                 VALUES(?1,?2,?3,?4,1,?5,?6,?7)",
                params![task.id, task.context_id, state, timestamp, encoded, tenant, owner],
            ).map_err(|_| A2AError::internal("scoped task insert failed"))?;
            tx.execute(
                "INSERT INTO task_events(tenant_scope,task_id,event_seq,task_revision,event_kind,from_state,to_state,event_json,created_at)
                 VALUES(?1,?2,1,1,'authorized_admitted',NULL,?3,?4,?5)",
                params![tenant, task.id, state, encoded, audit.decided_at],
            ).map_err(|_| A2AError::internal("scoped event append failed"))?;
            insert_authorization_audit(&tx, &audit)?;
            ensure_atomic_capacity(&tx)?;
            ensure_authorization_capacity(&tx)?;
            tx.commit().map_err(|_| A2AError::internal("scoped create commit failed"))?;
            Ok(1)
        }).await
    }

    /// Existence-safe task read scoped by server-resolved tenant and visibility.
    pub async fn get_scoped(
        &self,
        scope: &OwnedTaskScope,
        task_id: &str,
    ) -> Result<Option<Task>, A2AError> {
        let tenant = scope.tenant_scope.clone();
        let owner = scope.owner_account_id.clone();
        let own_only = scope.visibility == crate::authorization::VisibilityScope::Own;
        let task_id = task_id.to_owned();
        self.run(move |connection| {
            let encoded: Option<String> = connection
                .query_row(
                    "SELECT task_json FROM tasks WHERE tenant_scope=?1 AND task_id=?2
                 AND (?3=0 OR owner_account_id=?4)",
                    params![tenant, task_id, i64::from(own_only), owner],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|_| A2AError::internal("scoped task lookup failed"))?;
            encoded.as_deref().map(decode_task).transpose()
        })
        .await
    }

    /// Read through the ownership predicate and audit before returning.
    pub async fn get_authorized(
        &self,
        scope: &OwnedTaskScope,
        task_id: &str,
        audit: AuthorizationAuditInput,
    ) -> Result<Option<Task>, A2AError> {
        if audit.tenant_scope != scope.tenant_scope
            || audit.actor_account_id != scope.owner_account_id
            || audit.effect != AuthorizationDecisionEffect::Allow
        {
            return Err(A2AError::invalid_request(
                "authorization audit scope mismatch",
            ));
        }
        let tenant = scope.tenant_scope.clone();
        let owner = scope.owner_account_id.clone();
        let own_only = scope.visibility == crate::authorization::VisibilityScope::Own;
        let task_id = task_id.to_owned();
        self.run(move |connection| {
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| A2AError::internal("authorized task lookup transaction failed"))?;
            let encoded: Option<String> = tx
                .query_row(
                    "SELECT task_json FROM tasks WHERE tenant_scope=?1 AND task_id=?2
                     AND (?3=0 OR owner_account_id=?4)",
                    params![tenant, task_id, i64::from(own_only), owner],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|_| A2AError::internal("authorized task lookup failed"))?;
            let task = encoded.as_deref().map(decode_task).transpose()?;
            let decision = if task.is_some() {
                audit.decided(AuthorizationDecisionEffect::Allow, "visible_resource", None)
            } else {
                audit.decided(
                    AuthorizationDecisionEffect::Deny,
                    "resource_unavailable",
                    None,
                )
            };
            insert_authorization_audit(&tx, &decision)?;
            ensure_authorization_capacity(&tx)?;
            tx.commit()
                .map_err(|_| A2AError::internal("authorized task lookup commit failed"))?;
            Ok(task)
        })
        .await
    }

    /// List only tasks visible in the resolved tenant/owner scope.
    pub async fn list_scoped(&self, scope: &OwnedTaskScope) -> Result<Vec<Task>, A2AError> {
        let tenant = scope.tenant_scope.clone();
        let owner = scope.owner_account_id.clone();
        let own_only = scope.visibility == crate::authorization::VisibilityScope::Own;
        self.run(move |connection| {
            let mut statement = connection.prepare(
                "SELECT task_json FROM tasks WHERE tenant_scope=?1 AND (?2=0 OR owner_account_id=?3) ORDER BY created_order"
            ).map_err(|_| A2AError::internal("scoped task list failed"))?;
            let rows = statement.query_map(params![tenant, i64::from(own_only), owner], |row| row.get::<_, String>(0))
                .map_err(|_| A2AError::internal("scoped task list failed"))?;
            rows.map(|row| row.map_err(|_| A2AError::internal("scoped task list failed")).and_then(|encoded| decode_task(&encoded))).collect()
        }).await
    }

    /// List visible rows, binding pagination to an opaque authorization scope,
    /// and commit the allow audit before the response is returned.
    pub async fn list_authorized(
        &self,
        scope: &OwnedTaskScope,
        request: &ListTasksRequest,
        audit: AuthorizationAuditInput,
        cursor_scope_digest: &str,
    ) -> Result<ListTasksResponse, A2AError> {
        if audit.tenant_scope != scope.tenant_scope
            || audit.actor_account_id != scope.owner_account_id
            || audit.effect != AuthorizationDecisionEffect::Allow
            || cursor_scope_digest.is_empty()
            || cursor_scope_digest.len() > 256
        {
            return Err(A2AError::invalid_request(
                "authorization list scope mismatch",
            ));
        }
        let tenant = scope.tenant_scope.clone();
        let owner = scope.owner_account_id.clone();
        let own_only = scope.visibility == crate::authorization::VisibilityScope::Own;
        let scoped_request = request.clone();
        let scope_digest = cursor_scope_digest.to_owned();
        let cursor_key = *self.cursor_key;
        // Durable page-token expiry is wall-clock based so it remains coherent across
        // process restart. The injected audit clock remains audit evidence only.
        let now = chrono::Utc::now().timestamp_millis();
        let decision = audit.decided(AuthorizationDecisionEffect::Allow, "visible_set", None);
        self.run(move |connection| {
            frozen_list_transaction(
                connection,
                &tenant,
                &owner,
                own_only,
                &scoped_request,
                &scope_digest,
                &cursor_key,
                now,
                Some(&decision),
            )
        })
        .await
    }

    /// Append a durable deny decision. Failure is returned and must fail the request closed.
    pub async fn append_denied_authorization_decision(
        &self,
        audit: AuthorizationAuditInput,
    ) -> Result<(), A2AError> {
        if audit.effect != AuthorizationDecisionEffect::Deny || audit.task_id.is_some() {
            return Err(A2AError::invalid_request(
                "deny audit cannot claim a resolved task",
            ));
        }
        self.run(move |connection| {
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| A2AError::internal("authorization audit transaction failed"))?;
            insert_authorization_audit(&tx, &audit)?;
            ensure_authorization_capacity(&tx)?;
            tx.commit()
                .map_err(|_| A2AError::internal("authorization audit commit failed"))
        })
        .await
    }

    /// Append a standalone authorization decision for an operation with no
    /// supported resource mutation. Audit failure fails the request closed.
    pub async fn append_authorization_decision(
        &self,
        audit: AuthorizationAuditInput,
    ) -> Result<(), A2AError> {
        if audit.task_id.is_some() {
            return Err(A2AError::invalid_request(
                "standalone audit cannot claim a resolved task",
            ));
        }
        self.run(move |connection| {
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| A2AError::internal("authorization audit transaction failed"))?;
            insert_authorization_audit(&tx, &audit)?;
            ensure_authorization_capacity(&tx)?;
            tx.commit()
                .map_err(|_| A2AError::internal("authorization audit commit failed"))
        })
        .await
    }

    pub async fn authorization_decision_count(&self) -> Result<u64, A2AError> {
        self.run(|connection| {
            connection
                .query_row("SELECT COUNT(*) FROM authorization_decisions", [], |row| {
                    row.get::<_, u64>(0)
                })
                .map_err(|_| A2AError::internal("authorization audit count failed"))
        })
        .await
    }

    /// Produce a stable keyed digest for authorization audit resources.
    ///
    /// The persisted cursor key is gateway-local secret material, so a foreign
    /// identifier cannot be recovered with an offline dictionary over the
    /// append-only audit table.
    pub(crate) fn authorization_resource_digest(&self, resource: &str) -> Result<String, A2AError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.cursor_key.as_ref())
            .map_err(|_| A2AError::internal("authorization audit digest initialization failed"))?;
        mac.update(b"smesh-authorization-resource-v1\0");
        mac.update(resource.as_bytes());
        Ok(format!("hmac-sha256:{:x}", mac.finalize().into_bytes()))
    }

    #[must_use]
    pub fn completion_receipt_key(&self) -> [u8; 32] {
        *self.receipt_key
    }

    /// Check canonical message replay/conflict without consulting mutable task state.
    ///
    /// # Errors
    ///
    /// Returns an A2A conflict for a bound message with different semantics, or an
    /// internal error when the durable replay record is corrupt or unavailable.
    pub async fn replay_send_message(
        &self,
        request: &SendMessageRequest,
        streaming: bool,
    ) -> Result<Option<SendMessageResponse>, A2AError> {
        let message_id = request.message.message_id.clone();
        if message_id.is_empty() {
            return Ok(None);
        }
        let digest = canonical_send_message_digest(request, streaming)?;
        self.run(move |connection| {
            let row: Option<(String, String, Option<String>)> = connection
                .query_row(
                    "SELECT request_digest, admission_result_json, final_result_json
                     FROM idempotency_records WHERE tenant_scope = ?1 AND message_id = ?2",
                    params![TRUSTED_SINGLE_TENANT_SCOPE, message_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(|_| A2AError::internal("idempotency replay lookup failed"))?;
            let Some((stored_digest, admission, final_result)) = row else {
                return Ok(None);
            };
            if stored_digest != digest {
                return Err(A2AError::invalid_request(
                    "idempotency key is already bound to different request semantics",
                ));
            }
            serde_json::from_str(final_result.as_deref().unwrap_or(&admission))
                .map(Some)
                .map_err(|_| A2AError::internal("stored idempotency result is corrupt"))
        })
        .await
    }

    /// Replay only an idempotency record owned by the resolved scope. Foreign
    /// and absent records share the same joined query and return `None`.
    pub async fn replay_authorized(
        &self,
        scope: &OwnedTaskScope,
        actor_account_id: &str,
        request: &SendMessageRequest,
        streaming: bool,
        audit: AuthorizationAuditInput,
    ) -> Result<Option<SendMessageResponse>, A2AError> {
        if audit.tenant_scope != scope.tenant_scope
            || actor_account_id != audit.actor_account_id
            || audit.actor_account_id != scope.owner_account_id
            || audit.effect != AuthorizationDecisionEffect::Allow
        {
            return Err(A2AError::invalid_request(
                "authorized replay scope mismatch",
            ));
        }
        let storage_id = authorized_message_identity(
            &scope.tenant_scope,
            actor_account_id,
            &request.message.message_id,
        );
        let digest = canonical_send_message_digest_v2(
            &scope.tenant_scope,
            actor_account_id,
            request,
            streaming,
        )?;
        let tenant = scope.tenant_scope.clone();
        let owner = scope.owner_account_id.clone();
        let own_only = scope.visibility == crate::authorization::VisibilityScope::Own;
        self.run(move |connection| {
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| A2AError::internal("authorized replay transaction failed"))?;
            let row: Option<(String, String, Option<String>, String)> = tx.query_row(
                "SELECT i.request_digest, i.admission_result_json, i.final_result_json, i.task_id
                 FROM idempotency_records i JOIN tasks t
                   ON t.tenant_scope=i.tenant_scope AND t.task_id=i.task_id
                 WHERE i.tenant_scope=?1 AND i.message_id=?2
                   AND (?3=0 OR t.owner_account_id=?4)",
                params![tenant, storage_id, i64::from(own_only), owner],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            ).optional().map_err(|_| A2AError::internal("authorized replay lookup failed"))?;
            let Some((stored_digest, admission, final_result, _task_id)) = row else {
                return Ok(None);
            };
            if stored_digest != digest {
                return Err(A2AError::invalid_request(
                    "idempotency key is already bound to different request semantics",
                ));
            }
            let replay = serde_json::from_str(final_result.as_deref().unwrap_or(&admission))
                .map_err(|_| A2AError::internal("stored idempotency result is corrupt"))?;
            let decision = audit.decided(
                AuthorizationDecisionEffect::Allow,
                "idempotent_replay",
                None,
            );
            insert_authorization_audit(&tx, &decision)?;
            ensure_authorization_capacity(&tx)?;
            tx.commit()
                .map_err(|_| A2AError::internal("authorized replay commit failed"))?;
            Ok(Some(replay))
        })
        .await
    }

    /// Admit a complete semantic `SendMessage` command using the canonical request digest.
    ///
    /// # Errors
    ///
    /// Returns an A2A error when message identity is inconsistent or admission fails.
    pub async fn admit_send_message(
        &self,
        command: SendMessageAdmission,
    ) -> Result<AdmissionOutcome, A2AError> {
        self.admit_send_message_inner(command, None).await
    }

    /// Authorize and atomically admit a new task with immutable ownership and
    /// its allow decision in the admission transaction.
    pub async fn authorize_and_admit(
        &self,
        scope: &OwnedTaskScope,
        command: SendMessageAdmission,
        audit: AuthorizationAuditInput,
    ) -> Result<AdmissionOutcome, A2AError> {
        if audit.tenant_scope != scope.tenant_scope
            || audit.actor_account_id != scope.owner_account_id
            || audit.effect != AuthorizationDecisionEffect::Allow
        {
            return Err(A2AError::invalid_request(
                "authorized admission scope mismatch",
            ));
        }
        self.admit_send_message_inner(command, Some((scope.clone(), audit)))
            .await
    }

    async fn admit_send_message_inner(
        &self,
        command: SendMessageAdmission,
        authorization: Option<(OwnedTaskScope, AuthorizationAuditInput)>,
    ) -> Result<AdmissionOutcome, A2AError> {
        let history_matches =
            command.task.history.as_deref() == Some(std::slice::from_ref(&command.request.message));
        let identity_matches = command
            .request
            .message
            .task_id
            .as_deref()
            .is_none_or(|task_id| task_id == command.task.id)
            && command
                .request
                .message
                .context_id
                .as_deref()
                .is_none_or(|context_id| context_id == command.task.context_id);
        if !history_matches
            || !identity_matches
            || command.task.status.state != a2a::TaskState::Submitted
            || command.task.status.message.is_some()
            || command.task.artifacts.is_some()
            || !final_result_matches_task(&command.original_result, &command.task)
        {
            return Err(A2AError::invalid_params(
                "admission task and result must exactly match the canonical request",
            ));
        }
        let digest = if let Some((scope, audit)) = authorization.as_ref() {
            canonical_send_message_digest_v2(
                &scope.tenant_scope,
                &audit.actor_account_id,
                &command.request,
                command.streaming,
            )?
        } else {
            canonical_send_message_digest(&command.request, command.streaming)?
        };
        let dispatch = MeshRequest::from_a2a(
            command.task.id.clone(),
            command.task.context_id.clone(),
            &command.request.message,
            command.input_limits,
        )
        .map_err(|error| A2AError::invalid_params(error.to_string()))?;
        let causative_request = command.request.clone();
        self.admit_message(
            command.task,
            digest,
            command.original_result,
            dispatch,
            command.now,
            command.max_attempts,
            command.streaming,
            causative_request,
            authorization,
        )
        .await
    }

    /// Atomically reserve message identity, create the task/event, and enqueue dispatch.
    ///
    /// # Errors
    ///
    /// Returns an A2A error for invalid identity/payload bounds, conflicts, capacity,
    /// serialization failures, or any transactional storage failure.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn admit_message(
        &self,
        task: Task,
        request_digest: impl Into<String>,
        original_result: SendMessageResponse,
        request: MeshRequest,
        now: i64,
        max_attempts: u32,
        streaming: bool,
        causative_request: SendMessageRequest,
        authorization: Option<(OwnedTaskScope, AuthorizationAuditInput)>,
    ) -> Result<AdmissionOutcome, A2AError> {
        let (tenant_scope, owner_account_id) = authorization.as_ref().map_or_else(
            || {
                (
                    self.default_scope.to_string(),
                    self.default_account.to_string(),
                )
            },
            |(scope, _)| (scope.tenant_scope.clone(), scope.owner_account_id.clone()),
        );
        let authorization_audit = authorization.map(|(_, audit)| audit);
        let identity_version = if authorization_audit.is_some() { 2 } else { 1 };
        let actor_account_id = authorization_audit
            .as_ref()
            .map(|audit| audit.actor_account_id.clone());
        let causative_request_json = if identity_version == 2 {
            Some(
                serde_json::to_string(&causative_request)
                    .map_err(|_| A2AError::internal("failed to encode causative request"))?,
            )
        } else {
            None
        };
        let invocation_kind =
            (identity_version == 2).then_some(if streaming { "streaming" } else { "unary" });
        let request_digest = request_digest.into();
        let raw_message_id = task
            .history
            .as_ref()
            .and_then(|history| history.last())
            .map(|message| message.message_id.clone())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                A2AError::invalid_params("messageId is required for durable admission")
            })?;
        let message_id = authorization_audit.as_ref().map_or_else(
            || raw_message_id.clone(),
            |audit| {
                authorized_message_identity(&tenant_scope, &audit.actor_account_id, &raw_message_id)
            },
        );
        if message_id.len() > 4096 {
            return Err(A2AError::invalid_params(
                "messageId exceeds durable storage limit",
            ));
        }
        if request_digest.is_empty()
            || request_digest.len() > 256
            || max_attempts == 0
            || max_attempts > MAX_OUTBOX_ATTEMPTS
            || request.task_id != task.id
            || request.context_id != task.context_id
            || !response_matches_task(&original_result, &task.id)
        {
            return Err(A2AError::invalid_params("invalid durable admission"));
        }
        let dispatch_id =
            content_digest(format!("{tenant_scope}\0send-message\0{message_id}").as_bytes());
        let encoded_task = encode_task(&task)?;
        let state = state_key(&task)?;
        let timestamp = task.status.timestamp.map(|value| value.to_rfc3339());
        let result_json = serde_json::to_string(&original_result)
            .map_err(|_| A2AError::internal("failed to encode idempotency result"))?;
        let payload_json = serde_json::to_string(&request)
            .map_err(|_| A2AError::internal("failed to encode outbox payload"))?;
        if result_json.len() > MAX_ATOMIC_JSON_BYTES || payload_json.len() > MAX_ATOMIC_JSON_BYTES {
            return Err(A2AError::invalid_params(
                "durable admission payload exceeds limit",
            ));
        }
        let payload_digest = content_digest(payload_json.as_bytes());
        let initial_stream_frame = StreamResponse::Task(task.clone());
        let initial_stream_json = serde_json::to_string(&initial_stream_frame)
            .map_err(|_| A2AError::internal("failed to encode initial stream frame"))?;
        let initial_stream_digest = content_digest(
            &serde_json::to_vec(&vec![initial_stream_frame])
                .map_err(|_| A2AError::internal("failed to digest initial stream frame"))?,
        );
        let max_tasks = self.max_tasks;
        self.run(move |connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| A2AError::internal("atomic admission transaction failed"))?;
            let existing: Option<(String, String, Option<String>)> = transaction
                .query_row(
                    "SELECT request_digest, admission_result_json, final_result_json
                     FROM idempotency_records
                     WHERE tenant_scope = ?1 AND message_id = ?2",
                    params![tenant_scope, message_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(|_| A2AError::internal("idempotency lookup failed"))?;
            if let Some((stored_digest, admission_json, final_json)) = existing {
                if stored_digest != request_digest || admission_json != result_json {
                    return Err(A2AError::invalid_request(
                        "idempotency key is already bound to different request or admission semantics",
                    ));
                }
                let replay_json = final_json.as_deref().unwrap_or(&admission_json);
                let replay = serde_json::from_str(replay_json)
                    .map_err(|_| A2AError::internal("stored idempotency result is corrupt"))?;
                return Ok(AdmissionOutcome::Replay(replay));
            }
            let count: i64 = transaction
                .query_row("SELECT COUNT(*) FROM tasks", [], |row| row.get(0))
                .map_err(|_| A2AError::internal("persistent task count failed"))?;
            if usize::try_from(count).unwrap_or(usize::MAX) >= max_tasks {
                return Err(A2AError::internal("task store capacity reached"));
            }
            for (sql, added) in [
                (
                    "SELECT COALESCE(SUM(length(CAST(task_json AS BLOB))), 0) FROM tasks",
                    encoded_task.len(),
                ),
                (
                    "SELECT COALESCE(SUM(length(CAST(event_json AS BLOB))), 0) FROM task_events",
                    encoded_task.len(),
                ),
                (
                    "SELECT COALESCE(SUM(length(CAST(admission_result_json AS BLOB))) + SUM(COALESCE(length(CAST(final_result_json AS BLOB)), 0)), 0) FROM idempotency_records",
                    result_json.len(),
                ),
                (
                    "SELECT COALESCE(SUM(length(CAST(payload_json AS BLOB))) + SUM(COALESCE(length(CAST(last_error AS BLOB)), 0)), 0) FROM outbox",
                    payload_json.len(),
                ),
            ] {
                let bytes: i64 = transaction
                    .query_row(sql, [], |row| row.get(0))
                    .map_err(|_| A2AError::internal("durable aggregate size query failed"))?;
                if usize::try_from(bytes)
                    .unwrap_or(usize::MAX)
                    .saturating_add(added)
                    > MAX_STORE_JSON_BYTES
                {
                    return Err(A2AError::internal("durable store byte capacity reached"));
                }
            }
            transaction
                .execute(
                    "INSERT INTO tasks(task_id, context_id, state, status_timestamp, revision, task_json,
                         tenant_scope, owner_account_id)
                     VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7)",
                    params![task.id, task.context_id, state, timestamp, encoded_task,
                        tenant_scope, owner_account_id],
                )
                .map_err(|_| A2AError::invalid_request("task already exists"))?;
            transaction
                .execute(
                    "INSERT INTO task_events(
                         tenant_scope, task_id, event_seq, task_revision, event_kind,
                         from_state, to_state, event_json, created_at
                     ) VALUES (?1, ?2, 1, 1, 'admitted', NULL, ?3, ?4, ?5)",
                    params![tenant_scope, task.id, state, encoded_task, now],
                )
                .map_err(|_| A2AError::internal("atomic event append failed"))?;
            transaction
                .execute(
                    "INSERT INTO idempotency_records(
                         tenant_scope, message_id, request_digest, task_id, state,
                         admission_result_json, final_result_json, created_at, updated_at,
                         digest_version, actor_account_id, causative_request_json, invocation_kind
                     ) VALUES (?1, ?2, ?3, ?4, 'in_progress', ?5, NULL, ?6, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        tenant_scope,
                        message_id,
                        request_digest,
                        task.id,
                        result_json,
                        now,
                        identity_version,
                        actor_account_id,
                        causative_request_json,
                        invocation_kind,
                    ],
                )
                .map_err(|_| A2AError::internal("idempotency reservation failed"))?;
            transaction
                .execute(
                    "INSERT INTO outbox(
                         dispatch_id, tenant_scope, task_id, message_id, causative_revision,
                         payload_json, payload_digest, state, attempt_count,
                         max_attempts, available_at, created_at, updated_at,
                         dispatch_identity_version
                     ) VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, 'pending', 0, ?7, ?8, ?8, ?8, ?9)",
                    params![
                        dispatch_id,
                        tenant_scope,
                        task.id,
                        message_id,
                        payload_json,
                        payload_digest,
                        max_attempts,
                        now,
                        identity_version
                    ],
                )
                .map_err(|_| A2AError::internal("atomic outbox enqueue failed"))?;
            if streaming {
                transaction
                    .execute(
                        "INSERT INTO stream_transcripts(
                             tenant_scope, message_id, dispatch_id, task_id, transcript_version,
                             state, frame_count, transcript_digest, created_at, updated_at)
                         VALUES (?1, ?2, ?3, ?4, 1, 'open', 1, ?5, ?6, ?6)",
                        params![
                            tenant_scope,
                            message_id,
                            dispatch_id,
                            task.id,
                            initial_stream_digest,
                            now
                        ],
                    )
                    .map_err(|_| A2AError::internal("stream transcript admission failed"))?;
                transaction
                    .execute(
                        "INSERT INTO stream_frames(tenant_scope, message_id, frame_seq,
                             frame_version, frame_kind, frame_json, frame_digest, created_at)
                         VALUES (?1, ?2, 1, 1, 'task', ?3, ?4, ?5)",
                        params![
                            tenant_scope,
                            message_id,
                            initial_stream_json,
                            content_digest(initial_stream_json.as_bytes()),
                            now
                        ],
                    )
                    .map_err(|_| A2AError::internal("initial stream frame append failed"))?;
            }
            if let Some(audit) = authorization_audit.as_ref() {
                let decision = audit.clone().decided(
                    AuthorizationDecisionEffect::Allow,
                    "admission_committed",
                    None,
                );
                insert_authorization_audit(&transaction, &decision)?;
                ensure_authorization_capacity(&transaction)?;
            }
            ensure_atomic_capacity(&transaction)?;
            ensure_stream_capacity(&transaction)?;
            transaction
                .commit()
                .map_err(|_| A2AError::internal("atomic admission commit failed"))?;
            Ok(AdmissionOutcome::Admitted(AdmissionRecord {
                task_id: task.id,
                revision: 1,
                dispatch_id,
            }))
        })
        .await
    }

    /// Atomically append a continuation to an interrupted task and enqueue its stable dispatch.
    ///
    /// # Errors
    ///
    /// Returns an A2A error for invalid state/identity, oversized data, or transaction failure.
    #[allow(clippy::too_many_lines)] // The transaction deliberately keeps every continuation write linear.
    pub async fn admit_continuation(
        &self,
        command: SendMessageAdmission,
    ) -> Result<AdmissionOutcome, A2AError> {
        self.admit_continuation_inner(command, None).await
    }

    pub async fn authorize_and_continue(
        &self,
        scope: &OwnedTaskScope,
        command: SendMessageAdmission,
        audit: AuthorizationAuditInput,
    ) -> Result<AdmissionOutcome, A2AError> {
        if audit.tenant_scope != scope.tenant_scope
            || audit.actor_account_id != scope.owner_account_id
            || audit.effect != AuthorizationDecisionEffect::Allow
        {
            return Err(A2AError::invalid_request(
                "authorized continuation scope mismatch",
            ));
        }
        self.admit_continuation_inner(command, Some((scope.clone(), audit)))
            .await
    }

    #[allow(clippy::too_many_lines)]
    async fn admit_continuation_inner(
        &self,
        command: SendMessageAdmission,
        authorization: Option<(OwnedTaskScope, AuthorizationAuditInput)>,
    ) -> Result<AdmissionOutcome, A2AError> {
        let message_id = command.request.message.message_id.clone();
        if message_id.is_empty()
            || message_id.len() > 4096
            || command.max_attempts == 0
            || command.max_attempts > MAX_OUTBOX_ATTEMPTS
            || !final_result_matches_task(&command.original_result, &command.task)
            || command
                .request
                .message
                .task_id
                .as_deref()
                .is_some_and(|task_id| task_id != command.task.id)
            || command
                .request
                .message
                .context_id
                .as_deref()
                .is_some_and(|context_id| context_id != command.task.context_id)
        {
            return Err(A2AError::invalid_params("invalid durable continuation"));
        }
        let (tenant_scope, owner_account_id, own_only, authorization_audit) = authorization
            .map_or_else(
                || {
                    (
                        self.default_scope.to_string(),
                        self.default_account.to_string(),
                        false,
                        None,
                    )
                },
                |(scope, audit)| {
                    (
                        scope.tenant_scope,
                        scope.owner_account_id,
                        scope.visibility == crate::authorization::VisibilityScope::Own,
                        Some(audit),
                    )
                },
            );
        let identity_version = if authorization_audit.is_some() { 2 } else { 1 };
        let raw_message_id = message_id;
        let message_id = authorization_audit.as_ref().map_or_else(
            || raw_message_id.clone(),
            |audit| {
                authorized_message_identity(&tenant_scope, &audit.actor_account_id, &raw_message_id)
            },
        );
        let digest = if let Some(audit) = authorization_audit.as_ref() {
            canonical_send_message_digest_v2(
                &tenant_scope,
                &audit.actor_account_id,
                &command.request,
                command.streaming,
            )?
        } else {
            canonical_send_message_digest(&command.request, command.streaming)?
        };
        let dispatch_id =
            content_digest(format!("{tenant_scope}\0send-message\0{message_id}").as_bytes());
        let now = command.now;
        let max_attempts = command.max_attempts;
        let streaming = command.streaming;
        let expected_task = command.task;
        let request = command.request;
        let actor_account_id = authorization_audit
            .as_ref()
            .map(|audit| audit.actor_account_id.clone());
        let causative_request_json = if identity_version == 2 {
            Some(
                serde_json::to_string(&request)
                    .map_err(|_| A2AError::internal("failed to encode causative request"))?,
            )
        } else {
            None
        };
        let invocation_kind =
            (identity_version == 2).then_some(if streaming { "streaming" } else { "unary" });
        let input_limits = command.input_limits;
        self.run(move |connection| {
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| A2AError::internal("continuation transaction failed"))?;
            let existing: Option<(String, String, Option<String>)> = tx
                .query_row(
                    "SELECT request_digest, admission_result_json, final_result_json
                     FROM idempotency_records WHERE tenant_scope = ?1 AND message_id = ?2",
                    params![tenant_scope, message_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(|_| A2AError::internal("continuation idempotency lookup failed"))?;
            if let Some((stored_digest, admission, final_result)) = existing {
                if stored_digest != digest {
                    return Err(A2AError::invalid_request(
                        "idempotency key is already bound to different request or continuation semantics",
                    ));
                }
                let replay = serde_json::from_str(final_result.as_deref().unwrap_or(&admission))
                    .map(AdmissionOutcome::Replay)
                    .map_err(|_| A2AError::internal("stored continuation result is corrupt"))?;
                if let Some(audit) = authorization_audit.as_ref() {
                    let decision = audit.clone().decided(AuthorizationDecisionEffect::Allow,
                        "continuation_replay", None);
                    insert_authorization_audit(&tx, &decision)?;
                    ensure_authorization_capacity(&tx)?;
                    tx.commit().map_err(|_| A2AError::internal("continuation replay commit failed"))?;
                }
                return Ok(replay);
            }
            let (durable_json, state, revision, durable_context): (String, String, u64, String) = tx
                .query_row(
                    "SELECT task_json, state, revision, context_id FROM tasks
                     WHERE tenant_scope=?1 AND task_id=?2 AND (?3=0 OR owner_account_id=?4)",
                    params![tenant_scope, expected_task.id, i64::from(own_only), owner_account_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(|_| A2AError::internal("continuation task lookup failed"))?
                .ok_or_else(|| A2AError::task_not_found(&expected_task.id))?;
            if !matches!(state.as_str(), "\"TASK_STATE_INPUT_REQUIRED\"" | "\"TASK_STATE_AUTH_REQUIRED\"") {
                return Err(A2AError::unsupported_operation("task no longer accepts continuation"));
            }
            let mut task = decode_task(&durable_json)?;
            if task.id != expected_task.id
                || durable_context != expected_task.context_id
                || task.context_id != durable_context
                || task != expected_task
            {
                return Err(A2AError::invalid_params("continuation task identity mismatch"));
            }
            task.history
                .get_or_insert_with(Vec::new)
                .push(request.message.clone());
            task.status.state = a2a::TaskState::Working;
            task.status.message = None;
            task.status.timestamp = chrono::DateTime::from_timestamp_millis(now);
            let task_json = encode_task(&task)?;
            let admission_result = SendMessageResponse::Task(task.clone());
            let result_json = serde_json::to_string(&admission_result)
                .map_err(|_| A2AError::internal("failed to encode continuation admission"))?;
            let dispatch = MeshRequest::from_a2a(
                task.id.clone(),
                task.context_id.clone(),
                &request.message,
                input_limits,
            )
            .map_err(|error| A2AError::invalid_params(error.to_string()))?;
            let payload_json = serde_json::to_string(&dispatch)
                .map_err(|_| A2AError::internal("failed to encode continuation dispatch"))?;
            let payload_digest = content_digest(payload_json.as_bytes());
            let next_revision = revision.checked_add(1)
                .ok_or_else(|| A2AError::internal("persistent task revision exhausted"))?;
            let working_state = state_key(&task)?;
            tx.execute(
                "UPDATE tasks SET state = ?2, status_timestamp = ?3, revision = ?4, task_json = ?5
                 WHERE task_id = ?1 AND revision = ?6 AND state = ?7 AND tenant_scope=?8",
                params![task.id, working_state,
                    task.status.timestamp.map(|value| value.to_rfc3339()), next_revision,
                    task_json, revision, state, tenant_scope],
            ).map_err(|_| A2AError::internal("continuation task update failed"))?;
            let event_seq: i64 = tx.query_row(
                "SELECT COALESCE(MAX(event_seq), 0) + 1 FROM task_events
                 WHERE tenant_scope = ?1 AND task_id = ?2",
                params![tenant_scope, task.id], |row| row.get(0),
            ).map_err(|_| A2AError::internal("continuation event sequence failed"))?;
            tx.execute(
                "INSERT INTO task_events(tenant_scope, task_id, event_seq, task_revision,
                     event_kind, from_state, to_state, event_json, created_at)
                 VALUES (?1, ?2, ?3, ?4, 'continued', ?5, ?6, ?7, ?8)",
                params![tenant_scope, task.id, event_seq, next_revision, state,
                    working_state, task_json, now],
            ).map_err(|_| A2AError::internal("continuation event append failed"))?;
            tx.execute(
                "INSERT INTO idempotency_records(tenant_scope, message_id, request_digest, task_id,
                     state, admission_result_json, created_at, updated_at, digest_version,
                     actor_account_id, causative_request_json, invocation_kind)
                 VALUES (?1, ?2, ?3, ?4, 'in_progress', ?5, ?6, ?6, ?7, ?8, ?9, ?10)",
                params![tenant_scope, message_id, digest, task.id, result_json, now,
                    identity_version, actor_account_id, causative_request_json, invocation_kind],
            ).map_err(|_| A2AError::internal("continuation idempotency reservation failed"))?;
            tx.execute(
                "INSERT INTO outbox(dispatch_id, tenant_scope, task_id, message_id, causative_revision,
                     payload_json, payload_digest, state, max_attempts, available_at, created_at,
                     updated_at, dispatch_identity_version)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', ?8, ?9, ?9, ?9, ?10)",
                params![dispatch_id, tenant_scope, task.id, message_id,
                    next_revision, payload_json, payload_digest, max_attempts, now,
                    identity_version],
            ).map_err(|_| A2AError::internal("continuation outbox enqueue failed"))?;
            if streaming {
                let initial = StreamResponse::Task(task.clone());
                let initial_json = serde_json::to_string(&initial)
                    .map_err(|_| A2AError::internal("failed to encode continuation stream"))?;
                let initial_digest = content_digest(
                    &serde_json::to_vec(&vec![initial.clone()])
                        .map_err(|_| A2AError::internal("failed to digest continuation stream"))?,
                );
                tx.execute(
                    "INSERT INTO stream_transcripts(tenant_scope, message_id, dispatch_id, task_id,
                         transcript_version, state, frame_count, transcript_digest, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, 1, 'open', 1, ?5, ?6, ?6)",
                    params![tenant_scope, message_id, dispatch_id, task.id,
                        initial_digest, now],
                ).map_err(|_| A2AError::internal("continuation stream admission failed"))?;
                tx.execute(
                    "INSERT INTO stream_frames(tenant_scope, message_id, frame_seq, frame_version,
                         frame_kind, frame_json, frame_digest, created_at)
                     VALUES (?1, ?2, 1, 1, 'task', ?3, ?4, ?5)",
                    params![tenant_scope, message_id, initial_json,
                        content_digest(initial_json.as_bytes()), now],
                ).map_err(|_| A2AError::internal("continuation initial stream append failed"))?;
            }
            if let Some(audit) = authorization_audit.as_ref() {
                let decision = audit.clone().decided(
                    AuthorizationDecisionEffect::Allow,
                    "continuation_committed",
                    None,
                );
                insert_authorization_audit(&tx, &decision)?;
                ensure_authorization_capacity(&tx)?;
            }
            ensure_atomic_capacity(&tx)?;
            ensure_stream_capacity(&tx)?;
            tx.commit().map_err(|_| A2AError::internal("continuation commit failed"))?;
            Ok(AdmissionOutcome::Admitted(AdmissionRecord {
                task_id: task.id,
                revision: next_revision,
                dispatch_id,
            }))
        }).await
    }

    /// Claim one due intent with a unique fencing token using an injected clock.
    ///
    /// # Errors
    ///
    /// Returns an A2A error for invalid lease bounds or transactional storage failure.
    #[allow(clippy::too_many_lines, clippy::type_complexity)] // Claim also atomically reaps an expired final attempt.
    pub async fn claim_outbox(
        &self,
        lease_owner: impl Into<String>,
        now: i64,
        lease_duration: i64,
    ) -> Result<Option<OutboxLease>, A2AError> {
        let lease_owner = lease_owner.into();
        if lease_owner.is_empty()
            || lease_owner.len() > MAX_ATOMIC_TEXT_BYTES
            || lease_duration <= 0
        {
            return Err(A2AError::invalid_params("invalid outbox lease"));
        }
        self.run(move |connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| A2AError::internal("outbox claim transaction failed"))?;
            validate_atomic_records(&transaction)
                .map_err(|_| A2AError::internal("durable outbox binding is corrupt"))?;
            let expired_final: Option<(i64, String, String, String, i64, i64, String, String)> = transaction
                .query_row(
                    "SELECT outbox_id, tenant_scope, dispatch_id, task_id, attempt_count, max_attempts,
                            payload_json, payload_digest
                     FROM outbox
                     WHERE state = 'leased' AND lease_until <= ?1
                       AND (attempt_count >= max_attempts OR EXISTS (
                           SELECT 1 FROM receiver_inbox receiver
                           WHERE receiver.tenant_scope = outbox.tenant_scope
                             AND receiver.dispatch_id = outbox.dispatch_id
                             AND receiver.payload_digest = outbox.payload_digest
                             AND receiver.state IN ('processing', 'completed')
                       ))
                     ORDER BY lease_until, outbox_id LIMIT 1",
                    [now],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                            row.get(7)?,
                        ))
                    },
                )
                .optional()
                .map_err(|_| A2AError::internal("expired final attempt lookup failed"))?;
            if let Some((outbox_id, tenant_scope, dispatch_id, task_id, attempt_no, max_attempts, payload, payload_digest)) = expired_final {
                let receiver: Option<(String, String, Option<i64>)> = transaction
                    .query_row(
                        "SELECT payload_digest, state, lease_until FROM receiver_inbox
                         WHERE tenant_scope = ?1 AND dispatch_id = ?2",
                        params![tenant_scope, dispatch_id],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .optional()
                    .map_err(|_| A2AError::internal("final attempt receiver lookup failed"))?;
                if let Some((receiver_digest, receiver_state, receiver_lease_until)) = receiver {
                    if receiver_digest != payload_digest {
                        return Err(A2AError::internal(
                            "receiver dispatch identity is bound to a conflicting payload",
                        ));
                    }
                    if receiver_state == "processing"
                        && receiver_lease_until.is_some_and(|lease_until| lease_until > now)
                    {
                        transaction.commit().map_err(|_| {
                            A2AError::internal("final attempt receiver wait commit failed")
                        })?;
                        return Ok(None);
                    }
                    let lease_until = now
                        .checked_add(lease_duration)
                        .ok_or_else(|| A2AError::invalid_params("outbox lease time overflow"))?;
                    let entropy: [u8; 32] = rand::random();
                    let lease_token = content_digest(
                        [dispatch_id.as_bytes(), lease_owner.as_bytes(), &now.to_le_bytes(), &entropy]
                            .concat()
                            .as_slice(),
                    );
                    transaction
                        .execute(
                            "UPDATE outbox SET lease_owner = ?2, lease_token = ?3,
                                 lease_until = ?4, updated_at = ?5
                             WHERE outbox_id = ?1 AND state = 'leased'
                               AND attempt_count = ?6 AND lease_until <= ?5",
                            params![outbox_id, lease_owner, lease_token, lease_until, now, attempt_no],
                        )
                        .map_err(|_| A2AError::internal("final attempt reconciliation claim failed"))?;
                    transaction
                        .execute(
                            "UPDATE outbox_attempts SET lease_token = ?3, started_at = ?4,
                                 finished_at = NULL, outcome = NULL, error = NULL, next_attempt_at = NULL
                             WHERE outbox_id = ?1 AND attempt_no = ?2 AND finished_at IS NULL",
                            params![outbox_id, attempt_no, lease_token, now],
                        )
                        .map_err(|_| A2AError::internal("final attempt reconciliation fence failed"))?;
                    ensure_atomic_capacity(&transaction)?;
                    transaction.commit().map_err(|_| {
                        A2AError::internal("final attempt reconciliation claim commit failed")
                    })?;
                    let request: MeshRequest = serde_json::from_str(&payload)
                        .map_err(|_| A2AError::internal("outbox payload is corrupt"))?;
                    return Ok(Some(OutboxLease {
                        tenant_scope,
                        outbox_id,
                        dispatch_id,
                        task_id,
                        attempt_no: u32::try_from(attempt_no)
                            .map_err(|_| A2AError::internal("outbox attempt is corrupt"))?,
                        max_attempts: u32::try_from(max_attempts)
                            .map_err(|_| A2AError::internal("outbox bound is corrupt"))?,
                        lease_owner,
                        lease_token,
                        lease_until,
                        request,
                        execution_reservation: None,
                    }));
                }
                let error = "final outbox attempt lease expired before receiver acceptance";
                transaction
                    .execute(
                        "UPDATE outbox_attempts SET finished_at = ?2, outcome = 'dead', error = ?3
                         WHERE outbox_id = ?1 AND finished_at IS NULL",
                        params![outbox_id, now, error],
                    )
                    .map_err(|_| A2AError::internal("expired final attempt close failed"))?;
                let was_terminal: bool = transaction
                    .query_row(
                        "SELECT state IN ('\"TASK_STATE_COMPLETED\"', '\"TASK_STATE_FAILED\"',
                                          '\"TASK_STATE_CANCELED\"', '\"TASK_STATE_REJECTED\"')
                         FROM tasks WHERE task_id = ?1",
                        [&task_id],
                        |row| row.get(0),
                    )
                    .map_err(|_| A2AError::internal("expired final task arbitration failed"))?;
                dead_letter_task(&transaction, &task_id, &dispatch_id, error, now)?;
                transaction
                    .execute(
                        "UPDATE outbox SET state = ?2, lease_owner = NULL, lease_token = NULL,
                             lease_until = NULL, last_error = ?3, updated_at = ?4
                         WHERE outbox_id = ?1",
                        params![outbox_id, if was_terminal { "superseded" } else { "dead" }, error, now],
                    )
                    .map_err(|_| A2AError::internal("expired final dead-letter failed"))?;
                ensure_atomic_capacity(&transaction)?;
                transaction
                    .commit()
                    .map_err(|_| A2AError::internal("expired final attempt commit failed"))?;
                return Ok(None);
            }
            let row: Option<(i64, String, String, String, i64, i64, String)> = transaction
                .query_row(
                    "SELECT outbox_id, tenant_scope, dispatch_id, task_id, attempt_count, max_attempts, payload_json
                     FROM outbox
                     WHERE ((state = 'pending' AND available_at <= ?1)
                         OR (state = 'leased' AND lease_until <= ?1))
                       AND attempt_count < max_attempts
                     ORDER BY available_at, outbox_id LIMIT 1",
                    [now],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                        ))
                    },
                )
                .optional()
                .map_err(|_| A2AError::internal("outbox claim lookup failed"))?;
            let Some((outbox_id, tenant_scope, dispatch_id, task_id, attempts, max_attempts, payload)) = row else {
                return Ok(None);
            };
            let attempt_no = attempts
                .checked_add(1)
                .ok_or_else(|| A2AError::internal("outbox attempt counter exhausted"))?;
            let lease_until = now
                .checked_add(lease_duration)
                .ok_or_else(|| A2AError::invalid_params("outbox lease time overflow"))?;
            let entropy: [u8; 32] = rand::random();
            let lease_token = content_digest(
                [dispatch_id.as_bytes(), lease_owner.as_bytes(), &now.to_le_bytes(), &entropy]
                    .concat()
                    .as_slice(),
            );
            let changed = transaction
                .execute(
                    "UPDATE outbox SET state = 'leased', attempt_count = ?2,
                         lease_owner = ?3, lease_token = ?4, lease_until = ?5, updated_at = ?6
                     WHERE outbox_id = ?1
                       AND ((state = 'pending' AND available_at <= ?6)
                         OR (state = 'leased' AND lease_until <= ?6))",
                    params![outbox_id, attempt_no, lease_owner, lease_token, lease_until, now],
                )
                .map_err(|_| A2AError::internal("outbox claim update failed"))?;
            if changed != 1 {
                return Ok(None);
            }
            transaction
                .execute(
                    "UPDATE outbox_attempts SET finished_at = ?2, outcome = 'lease_expired'
                     WHERE outbox_id = ?1 AND finished_at IS NULL",
                    params![outbox_id, now],
                )
                .map_err(|_| A2AError::internal("expired outbox attempt close failed"))?;
            transaction
                .execute(
                    "INSERT INTO outbox_attempts(outbox_id, attempt_no, lease_token, started_at)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![outbox_id, attempt_no, lease_token, now],
                )
                .map_err(|_| A2AError::internal("outbox attempt append failed"))?;
            ensure_atomic_capacity(&transaction)?;
            transaction
                .commit()
                .map_err(|_| A2AError::internal("outbox claim commit failed"))?;
            let request: MeshRequest = serde_json::from_str(&payload)
                .map_err(|_| A2AError::internal("outbox payload is corrupt"))?;
            Ok(Some(OutboxLease {
                tenant_scope,
                outbox_id,
                dispatch_id,
                task_id,
                attempt_no: u32::try_from(attempt_no)
                    .map_err(|_| A2AError::internal("outbox attempt is corrupt"))?,
                max_attempts: u32::try_from(max_attempts)
                    .map_err(|_| A2AError::internal("outbox bound is corrupt"))?,
                lease_owner,
                lease_token,
                lease_until,
                request,
                execution_reservation: None,
            }))
        })
        .await
    }

    /// Acknowledge only the currently fenced lease.
    ///
    /// # Errors
    ///
    /// Returns an A2A error if the acknowledgement transaction cannot complete.
    pub async fn ack_outbox(&self, lease: &OutboxLease, now: i64) -> Result<bool, A2AError> {
        let lease = lease.clone();
        self.run(move |connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| A2AError::internal("outbox acknowledgement transaction failed"))?;
            let changed = transaction
                .execute(
                    "UPDATE outbox SET state = 'delivered', lease_owner = NULL,
                         lease_token = NULL, lease_until = NULL, updated_at = ?3
                     WHERE outbox_id = ?1 AND state = 'leased' AND lease_token = ?2
                       AND lease_owner = ?4 AND attempt_count = ?5 AND max_attempts = ?6
                       AND lease_until = ?7 AND lease_until > ?3 AND task_id = ?8
                       AND tenant_scope = ?9 AND dispatch_id = ?10",
                    params![
                        lease.outbox_id,
                        lease.lease_token,
                        now,
                        lease.lease_owner,
                        lease.attempt_no,
                        lease.max_attempts,
                        lease.lease_until,
                        lease.task_id,
                        lease.tenant_scope,
                        lease.dispatch_id
                    ],
                )
                .map_err(|_| A2AError::internal("outbox acknowledgement failed"))?;
            if changed == 1 {
                transaction
                    .execute(
                        "UPDATE outbox_attempts SET finished_at = ?3, outcome = 'delivered'
                         WHERE outbox_id = ?1 AND attempt_no = ?2 AND finished_at IS NULL",
                        params![lease.outbox_id, lease.attempt_no, now],
                    )
                    .map_err(|_| A2AError::internal("outbox attempt close failed"))?;
            }
            transaction
                .commit()
                .map_err(|_| A2AError::internal("outbox acknowledgement commit failed"))?;
            Ok(changed == 1)
        })
        .await
    }

    /// Finish a fenced attempt by scheduling a retry or atomically dead-lettering it.
    ///
    /// # Errors
    ///
    /// Returns an A2A error for oversized diagnostics or transactional storage failure.
    #[allow(clippy::too_many_lines)] // Fence, cancellation arbitration, and attempt outcome share one transaction.
    pub async fn finish_outbox_attempt(
        &self,
        lease: &OutboxLease,
        disposition: AttemptDisposition,
        now: i64,
    ) -> Result<TransitionOutcome, A2AError> {
        let lease = lease.clone();
        self.run(move |connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| A2AError::internal("outbox finish transaction failed"))?;
            let durable: Option<(i64, i64, String, i64, String, String)> = transaction
                .query_row(
                    "SELECT attempt_count, max_attempts, lease_owner, lease_until, task_id,
                            payload_digest FROM outbox
                     WHERE outbox_id = ?1 AND state = 'leased' AND lease_token = ?2
                       AND tenant_scope = ?3 AND dispatch_id = ?4 AND task_id = ?5",
                    params![
                        lease.outbox_id,
                        lease.lease_token,
                        lease.tenant_scope,
                        lease.dispatch_id,
                        lease.task_id
                    ],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                        ))
                    },
                )
                .optional()
                .map_err(|_| A2AError::internal("outbox fence lookup failed"))?;
            let Some((attempt_no, max_attempts, owner, lease_until, task_id, payload_digest)) =
                durable
            else {
                return Ok(TransitionOutcome::Stale);
            };
            if attempt_no != i64::from(lease.attempt_no)
                || max_attempts != i64::from(lease.max_attempts)
                || owner != lease.lease_owner
                || lease_until != lease.lease_until
                || task_id != lease.task_id
                || lease_until <= now
            {
                return Ok(TransitionOutcome::Stale);
            }
            let cancellation_won: bool = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM cancellation_intents
                     WHERE tenant_scope = ?1 AND dispatch_id = ?2 AND task_id = ?3
                       AND state = 'requested')",
                    params![lease.tenant_scope, lease.dispatch_id, lease.task_id],
                    |row| row.get(0),
                )
                .map_err(|_| A2AError::internal("outbox cancellation arbitration failed"))?;
            if cancellation_won {
                return Ok(TransitionOutcome::Stale);
            }
            let exhausted = attempt_no >= max_attempts;
            let would_dead_letter = match &disposition {
                AttemptDisposition::Retry { .. } => exhausted,
                AttemptDisposition::Permanent { .. } => true,
            };
            if would_dead_letter {
                let receiver: Option<(String, String)> = transaction
                    .query_row(
                        "SELECT payload_digest, state FROM receiver_inbox
                         WHERE tenant_scope = ?1 AND dispatch_id = ?2",
                        params![lease.tenant_scope, lease.dispatch_id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()
                    .map_err(|_| A2AError::internal("outbox finish receiver lookup failed"))?;
                if let Some((receiver_digest, receiver_state)) = receiver {
                    if receiver_digest != payload_digest {
                        return Err(A2AError::internal(
                            "receiver dispatch identity is bound to a conflicting payload",
                        ));
                    }
                    if matches!(receiver_state.as_str(), "processing" | "completed") {
                        // Never dead-letter an effect that the receiver has accepted. Fence
                        // this caller immediately and leave the final attempt reclaimable;
                        // claim/recovery will reconcile the durable receiver transcript.
                        let entropy: [u8; 32] = rand::random();
                        let reconciliation_token = content_digest(
                            [
                                lease.dispatch_id.as_bytes(),
                                b"finish-reconciliation",
                                &now.to_le_bytes(),
                                &entropy,
                            ]
                            .concat()
                            .as_slice(),
                        );
                        transaction
                            .execute(
                                "UPDATE outbox SET lease_owner = 'receiver-reconciliation',
                                     lease_token = ?3, lease_until = ?4, updated_at = ?4
                                 WHERE outbox_id = ?1 AND lease_token = ?2",
                                params![
                                    lease.outbox_id,
                                    lease.lease_token,
                                    reconciliation_token,
                                    now
                                ],
                            )
                            .map_err(|_| {
                                A2AError::internal("outbox finish reconciliation fence failed")
                            })?;
                        transaction
                            .execute(
                                "UPDATE outbox_attempts SET lease_token = ?3, started_at = ?4,
                                     finished_at = NULL, outcome = NULL, error = NULL,
                                     next_attempt_at = NULL
                                 WHERE outbox_id = ?1 AND attempt_no = ?2
                                   AND finished_at IS NULL",
                                params![
                                    lease.outbox_id,
                                    lease.attempt_no,
                                    reconciliation_token,
                                    now
                                ],
                            )
                            .map_err(|_| {
                                A2AError::internal("outbox finish reconciliation attempt failed")
                            })?;
                        ensure_atomic_capacity(&transaction)?;
                        transaction.commit().map_err(|_| {
                            A2AError::internal("outbox finish reconciliation commit failed")
                        })?;
                        return Ok(TransitionOutcome::Applied);
                    }
                }
            }
            let (dead, error, available_at) = match disposition {
                AttemptDisposition::Retry {
                    available_at,
                    error,
                } => (exhausted, error, Some(available_at)),
                AttemptDisposition::Permanent { error } => (true, error, None),
            };
            if error.len() > MAX_ATOMIC_TEXT_BYTES {
                return Err(A2AError::invalid_params(
                    "outbox error diagnostic exceeds limit",
                ));
            }
            let outcome = if dead { "dead" } else { "retry" };
            transaction
                .execute(
                    "UPDATE outbox_attempts SET finished_at = ?3, outcome = ?4, error = ?5,
                         next_attempt_at = ?6
                     WHERE outbox_id = ?1 AND attempt_no = ?2 AND lease_token = ?7
                       AND finished_at IS NULL",
                    params![
                        lease.outbox_id,
                        lease.attempt_no,
                        now,
                        outcome,
                        error,
                        available_at,
                        lease.lease_token
                    ],
                )
                .map_err(|_| A2AError::internal("outbox attempt close failed"))?;
            if !dead {
                transaction
                    .execute(
                        "UPDATE outbox SET state = 'pending', available_at = ?3,
                             lease_owner = NULL, lease_token = NULL, lease_until = NULL,
                             last_error = ?4, updated_at = ?5
                         WHERE outbox_id = ?1 AND lease_token = ?2",
                        params![lease.outbox_id, lease.lease_token, available_at, error, now],
                    )
                    .map_err(|_| A2AError::internal("outbox retry schedule failed"))?;
                ensure_atomic_capacity(&transaction)?;
                transaction
                    .commit()
                    .map_err(|_| A2AError::internal("outbox retry commit failed"))?;
                return Ok(TransitionOutcome::Applied);
            }
            transaction
                .execute(
                    "UPDATE outbox SET state = 'dead', lease_owner = NULL, lease_token = NULL,
                         lease_until = NULL, last_error = ?3, updated_at = ?4
                     WHERE outbox_id = ?1 AND lease_token = ?2",
                    params![lease.outbox_id, lease.lease_token, error, now],
                )
                .map_err(|_| A2AError::internal("outbox dead-letter failed"))?;
            dead_letter_task(
                &transaction,
                &lease.task_id,
                &lease.dispatch_id,
                &error,
                now,
            )?;
            ensure_atomic_capacity(&transaction)?;
            transaction
                .commit()
                .map_err(|_| A2AError::internal("outbox dead-letter commit failed"))?;
            Ok(TransitionOutcome::DeadLettered)
        })
        .await
    }

    /// Commit a revision/state-checked lifecycle transition and immutable final replay result.
    ///
    /// # Errors
    ///
    /// Returns an A2A error for identity mismatch, encoding failure, a missing task,
    /// or transactional storage failure. Stale revisions are represented in the outcome.
    #[allow(clippy::too_many_lines)]
    pub async fn commit_transition(
        &self,
        task_id: &str,
        expected_revision: u64,
        task: Task,
        event_kind: impl Into<String>,
        final_result: Option<SendMessageResponse>,
        now: i64,
    ) -> Result<TransitionOutcome, A2AError> {
        let task_id = task_id.to_owned();
        let event_kind = event_kind.into();
        if task.id != task_id
            || event_kind.is_empty()
            || event_kind.len() > MAX_ATOMIC_TEXT_BYTES
            || (task.status.state.is_terminal() && final_result.is_none())
            || final_result
                .as_ref()
                .is_some_and(|result| !final_result_matches_task(result, &task))
        {
            return Err(A2AError::invalid_params(
                "transition identity, event kind, or terminal final result is invalid",
            ));
        }
        let encoded = encode_task(&task)?;
        let next_state = state_key(&task)?;
        let timestamp = task.status.timestamp.map(|value| value.to_rfc3339());
        let final_json = final_result
            .map(|result| serde_json::to_string(&result))
            .transpose()
            .map_err(|_| A2AError::internal("failed to encode final idempotency result"))?;
        self.run(move |connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| A2AError::internal("lifecycle transaction failed"))?;
            let current: Option<(String, String, u64)> = transaction
                .query_row(
                    "SELECT task_json, state, revision FROM tasks WHERE task_id = ?1",
                    [&task_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(|_| A2AError::internal("lifecycle lookup failed"))?;
            let Some((current_json, current_state, revision)) = current else {
                return Err(A2AError::task_not_found(&task_id));
            };
            if current_json == encoded {
                if let Some(proposed) = final_json.as_deref() {
                    let durable = transaction
                        .query_row(
                            "SELECT final_result_json FROM idempotency_records
                             WHERE tenant_scope = ?1 AND task_id = ?2",
                            params![TRUSTED_SINGLE_TENANT_SCOPE, task_id],
                            |row| row.get::<_, Option<String>>(0),
                        )
                        .optional()
                        .map_err(|_| A2AError::internal("idempotency replay lookup failed"))?
                        .flatten();
                    if durable.as_deref() != Some(proposed) {
                        return Ok(TransitionOutcome::Stale);
                    }
                }
                return Ok(TransitionOutcome::Idempotent);
            }
            let current_task = decode_task(&current_json)?;
            if revision != expected_revision || current_task.status.state.is_terminal() {
                return Ok(TransitionOutcome::Stale);
            }
            if !legal_transition(&current_task.status.state, &task.status.state) {
                return Ok(TransitionOutcome::Stale);
            }
            let next_revision = revision
                .checked_add(1)
                .ok_or_else(|| A2AError::internal("persistent task revision exhausted"))?;
            let changed = transaction
                .execute(
                    "UPDATE tasks SET context_id = ?2, state = ?3, status_timestamp = ?4,
                         revision = ?5, task_json = ?6
                     WHERE task_id = ?1 AND revision = ?7
                       AND state NOT IN ('\"TASK_STATE_COMPLETED\"', '\"TASK_STATE_FAILED\"',
                                         '\"TASK_STATE_CANCELED\"', '\"TASK_STATE_REJECTED\"')",
                    params![task_id, task.context_id, next_state, timestamp, next_revision, encoded, expected_revision],
                )
                .map_err(|_| A2AError::internal("lifecycle CAS failed"))?;
            if changed != 1 {
                return Ok(TransitionOutcome::Stale);
            }
            let event_seq: i64 = transaction
                .query_row(
                    "SELECT COALESCE(MAX(event_seq), 0) + 1 FROM task_events
                     WHERE tenant_scope = ?1 AND task_id = ?2",
                    params![TRUSTED_SINGLE_TENANT_SCOPE, task_id],
                    |row| row.get(0),
                )
                .map_err(|_| A2AError::internal("event sequence lookup failed"))?;
            transaction
                .execute(
                    "INSERT INTO task_events(tenant_scope, task_id, event_seq, task_revision,
                         event_kind, from_state, to_state, event_json, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![TRUSTED_SINGLE_TENANT_SCOPE, task_id, event_seq, next_revision,
                        event_kind, current_state, next_state, encoded, now],
                )
                .map_err(|_| A2AError::internal("event append failed"))?;
            if let Some(final_json) = final_json {
                transaction
                    .execute(
                        "UPDATE idempotency_records SET state = 'completed',
                             final_result_json = COALESCE(final_result_json, ?2), updated_at = ?3
                         WHERE tenant_scope = ?1 AND task_id = ?4",
                        params![TRUSTED_SINGLE_TENANT_SCOPE, final_json, now, task_id],
                    )
                    .map_err(|_| A2AError::internal("idempotency completion failed"))?;
            }
            if task.status.state.is_terminal() {
                transaction
                    .execute(
                        "UPDATE outbox_attempts SET finished_at = ?2, outcome = 'superseded'
                         WHERE finished_at IS NULL AND outbox_id IN
                             (SELECT outbox_id FROM outbox WHERE task_id = ?1 AND state = 'leased')",
                        params![task_id, now],
                    )
                    .map_err(|_| A2AError::internal("terminal outbox attempt arbitration failed"))?;
                transaction
                    .execute(
                        "UPDATE outbox SET state = CASE WHEN state = 'delivered' THEN state ELSE 'superseded' END,
                             lease_owner = NULL, lease_token = NULL, lease_until = NULL, updated_at = ?2
                         WHERE task_id = ?1 AND state IN ('pending', 'leased', 'delivered')",
                        params![task_id, now],
                    )
                    .map_err(|_| A2AError::internal("terminal outbox arbitration failed"))?;
            }
            ensure_atomic_capacity(&transaction)?;
            transaction
                .commit()
                .map_err(|_| A2AError::internal("lifecycle commit failed"))?;
            Ok(TransitionOutcome::Applied)
        })
        .await
    }

    /// Return the immutable completed replay bound to a semantic message identity.
    ///
    /// # Errors
    ///
    /// Returns an internal error if the replay record cannot be read or decoded.
    pub async fn final_result_for_message(
        &self,
        message_id: &str,
    ) -> Result<Option<SendMessageResponse>, A2AError> {
        self.final_result_for_message_scoped(TRUSTED_SINGLE_TENANT_SCOPE, message_id)
            .await
    }

    pub async fn final_result_for_message_scoped(
        &self,
        tenant_scope: &str,
        message_id: &str,
    ) -> Result<Option<SendMessageResponse>, A2AError> {
        let tenant_scope = tenant_scope.to_owned();
        let message_id = message_id.to_owned();
        self.run(move |connection| {
            let encoded: Option<String> = connection
                .query_row(
                    "SELECT final_result_json FROM idempotency_records
                     WHERE tenant_scope = ?1 AND message_id = ?2 AND state = 'completed'",
                    params![tenant_scope, message_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|_| A2AError::internal("idempotency replay lookup failed"))?;
            encoded
                .map(|value| {
                    serde_json::from_str(&value)
                        .map_err(|_| A2AError::internal("stored idempotency result is corrupt"))
                })
                .transpose()
        })
        .await
    }

    /// Persist cancellation authority or atomically cancel an unclaimed intent.
    ///
    /// # Errors
    ///
    /// Returns protocol errors for missing/terminal tasks and internal errors when the
    /// revision-fenced cancellation transaction cannot be committed.
    #[allow(clippy::too_many_lines)]
    pub async fn request_cancellation(
        &self,
        task_id: &str,
        now: i64,
    ) -> Result<CancellationOutcome, A2AError> {
        self.request_cancellation_scope(
            OwnedTaskScope::new(
                self.default_scope.to_string(),
                self.default_account.to_string(),
                crate::authorization::VisibilityScope::Tenant,
            )?,
            task_id,
            now,
            None,
        )
        .await
    }

    pub async fn cancel_authorized(
        &self,
        scope: &OwnedTaskScope,
        task_id: &str,
        now: i64,
        audit: AuthorizationAuditInput,
    ) -> Result<CancellationOutcome, A2AError> {
        if audit.tenant_scope != scope.tenant_scope
            || audit.actor_account_id != scope.owner_account_id
            || audit.effect != AuthorizationDecisionEffect::Allow
        {
            return Err(A2AError::invalid_request(
                "authorized cancellation scope mismatch",
            ));
        }
        self.request_cancellation_scope(scope.clone(), task_id, now, Some(audit))
            .await
    }

    #[allow(clippy::too_many_lines)]
    async fn request_cancellation_scope(
        &self,
        scope: OwnedTaskScope,
        task_id: &str,
        now: i64,
        audit: Option<AuthorizationAuditInput>,
    ) -> Result<CancellationOutcome, A2AError> {
        let tenant_scope = scope.tenant_scope;
        let owner_account_id = scope.owner_account_id;
        let own_only = scope.visibility == crate::authorization::VisibilityScope::Own;
        let task_id = task_id.to_owned();
        self.run(move |connection| {
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| A2AError::internal("cancellation transaction failed"))?;
            let row: Option<(String, i64, String, String, String)> = tx.query_row(
                "SELECT task.task_json, task.revision, identity.message_id,
                        outbox.dispatch_id, outbox.state
                 FROM tasks task
                 JOIN outbox ON outbox.tenant_scope = ?1 AND outbox.task_id = task.task_id
                 JOIN idempotency_records identity ON identity.tenant_scope = outbox.tenant_scope
                   AND identity.message_id = outbox.message_id
                   AND identity.task_id = outbox.task_id
                 WHERE task.tenant_scope=?1 AND task.task_id = ?2
                   AND (?3=0 OR task.owner_account_id=?4)
                 ORDER BY outbox.state IN ('pending', 'leased', 'delivered') DESC,
                          outbox.outbox_id DESC LIMIT 1",
                params![tenant_scope, task_id, i64::from(own_only), owner_account_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            ).optional().map_err(|_| A2AError::internal("cancellation lookup failed"))?;
            let Some((task_json, revision, message_id, dispatch_id, _outbox_state)) = row else {
                return Err(A2AError::task_not_found(&task_id));
            };
            let mut task = decode_task(&task_json)?;
            if task.status.state.is_terminal() {
                return Err(A2AError::task_not_cancelable(&task_id));
            }
            let receiver_state: Option<String> = tx.query_row(
                "SELECT state FROM receiver_inbox WHERE tenant_scope = ?1 AND dispatch_id = ?2",
                params![tenant_scope, dispatch_id], |row| row.get(0),
            ).optional().map_err(|_| A2AError::internal("cancellation receiver lookup failed"))?;
            let active_state = matches!(task.status.state,
                a2a::TaskState::Submitted | a2a::TaskState::Working);
            if active_state && receiver_state.is_some() {
                if receiver_state.as_deref() == Some("processing") {
                    tx.execute(
                        "INSERT INTO cancellation_intents(
                             tenant_scope, dispatch_id, task_id, state, requested_at)
                         VALUES (?1, ?2, ?3, 'requested', ?4)
                         ON CONFLICT(tenant_scope, dispatch_id) DO NOTHING",
                        params![tenant_scope, dispatch_id, task_id, now],
                    ).map_err(|_| A2AError::internal("cancellation intent commit failed"))?;
                }
                if let Some(audit) = audit.as_ref() {
                    let decision = audit.clone().decided(AuthorizationDecisionEffect::Allow,
                        "cancellation_requested", None);
                    insert_authorization_audit(&tx, &decision)?;
                    ensure_authorization_capacity(&tx)?;
                }
                tx.commit().map_err(|_| A2AError::internal("cancellation intent transaction failed"))?;
                return Ok(CancellationOutcome::AwaitReceiver { dispatch_id, message_id });
            }

            let previous_state = state_key(&task)?;
            let mut message = Message::new(Role::Agent, vec![Part::text("SMESH task canceled")]);
            message.message_id = format!("cancel-{}", &content_digest(dispatch_id.as_bytes())[..32]);
            message.task_id = Some(task.id.clone());
            message.context_id = Some(task.context_id.clone());
            task.status = a2a::TaskStatus {
                state: a2a::TaskState::Canceled,
                message: Some(message),
                timestamp: chrono::DateTime::from_timestamp_millis(now),
            };
            let canceled_json = encode_task(&task)?;
            let canceled_state = state_key(&task)?;
            let next_revision = revision.checked_add(1)
                .ok_or_else(|| A2AError::internal("persistent task revision exhausted"))?;
            let changed = tx.execute(
                "UPDATE tasks SET state = ?2, status_timestamp = ?3, revision = ?4, task_json = ?5
                 WHERE task_id = ?1 AND revision = ?6 AND tenant_scope=?7
                   AND state NOT IN ('\"TASK_STATE_COMPLETED\"', '\"TASK_STATE_FAILED\"',
                                     '\"TASK_STATE_CANCELED\"', '\"TASK_STATE_REJECTED\"')",
                params![task_id, canceled_state, task.status.timestamp.map(|value| value.to_rfc3339()),
                    next_revision, canceled_json, revision, tenant_scope],
            ).map_err(|_| A2AError::internal("cancellation task commit failed"))?;
            if changed != 1 { return Err(A2AError::task_not_cancelable(&task_id)); }
            let event_seq: i64 = tx.query_row(
                "SELECT COALESCE(MAX(event_seq), 0) + 1 FROM task_events
                 WHERE tenant_scope = ?1 AND task_id = ?2",
                params![tenant_scope, task_id], |row| row.get(0),
            ).map_err(|_| A2AError::internal("cancellation event sequence failed"))?;
            tx.execute(
                "INSERT INTO task_events(tenant_scope, task_id, event_seq, task_revision,
                     event_kind, from_state, to_state, event_json, created_at)
                 VALUES (?1, ?2, ?3, ?4, 'durable_canceled', ?5, ?6, ?7, ?8)",
                params![tenant_scope, task_id, event_seq, next_revision,
                    previous_state, canceled_state, canceled_json, now],
            ).map_err(|_| A2AError::internal("cancellation event append failed"))?;
            append_canceled_public_terminal(&tx, &tenant_scope, &dispatch_id, &task, now)?;
            let final_json = serde_json::to_string(&SendMessageResponse::Task(task.clone()))
                .map_err(|_| A2AError::internal("failed to encode cancellation result"))?;
            tx.execute(
                "UPDATE idempotency_records SET state = 'completed', final_result_json = ?2,
                     updated_at = ?3 WHERE tenant_scope = ?1 AND message_id = ?4
                     AND task_id = ?5 AND state = 'in_progress' AND final_result_json IS NULL",
                params![tenant_scope, final_json, now, message_id, task_id],
            ).map_err(|_| A2AError::internal("cancellation replay commit failed"))?;
            tx.execute(
                "UPDATE outbox_attempts SET finished_at = ?2, outcome = 'superseded'
                 WHERE finished_at IS NULL AND outbox_id =
                     (SELECT outbox_id FROM outbox WHERE dispatch_id = ?1)",
                params![dispatch_id, now],
            ).map_err(|_| A2AError::internal("cancellation attempt close failed"))?;
            tx.execute(
                "UPDATE outbox SET state = 'superseded', lease_owner = NULL, lease_token = NULL,
                     lease_until = NULL, updated_at = ?2 WHERE dispatch_id = ?1 AND state != 'dead'",
                params![dispatch_id, now],
            ).map_err(|_| A2AError::internal("cancellation outbox supersede failed"))?;
            if let Some(audit) = audit.as_ref() {
                let decision = audit.clone().decided(
                    AuthorizationDecisionEffect::Allow,
                    "cancellation_committed",
                    None,
                );
                insert_authorization_audit(&tx, &decision)?;
                ensure_authorization_capacity(&tx)?;
            }
            ensure_atomic_capacity(&tx)?;
            ensure_stream_capacity(&tx)?;
            tx.commit().map_err(|_| A2AError::internal("cancellation commit failed"))?;
            Ok(CancellationOutcome::Canceled(task))
        }).await
    }

    pub(crate) async fn cancellation_requested(&self, dispatch_id: &str) -> Result<bool, A2AError> {
        let dispatch_id = dispatch_id.to_owned();
        self.run(move |connection| {
            connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM cancellation_intents c
                     JOIN outbox o ON o.tenant_scope=c.tenant_scope AND o.dispatch_id=c.dispatch_id
                     WHERE c.dispatch_id = ?1 AND c.state = 'requested')",
                    params![dispatch_id],
                    |row| row.get(0),
                )
                .map_err(|_| A2AError::internal("cancellation intent lookup failed"))
        })
        .await
    }

    /// Read committed public stream frames strictly after `last_sequence`.
    pub(crate) async fn stream_frames_after(
        &self,
        message_id: &str,
        last_sequence: usize,
    ) -> Result<StreamTranscriptBatch, A2AError> {
        self.stream_frames_after_scoped(TRUSTED_SINGLE_TENANT_SCOPE, message_id, last_sequence)
            .await
    }

    pub(crate) async fn stream_frames_after_scoped(
        &self,
        tenant_scope: &str,
        message_id: &str,
        last_sequence: usize,
    ) -> Result<StreamTranscriptBatch, A2AError> {
        let tenant_scope = tenant_scope.to_owned();
        let message_id = message_id.to_owned();
        self.run(move |connection| {
            let metadata: Option<(String, i64, Option<String>, Option<String>)> = connection
                .query_row(
                    "SELECT state, frame_count, transcript_digest, interruption_error
                     FROM stream_transcripts WHERE tenant_scope = ?1 AND message_id = ?2",
                    params![tenant_scope, message_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(|_| A2AError::internal("stream transcript lookup failed"))?;
            let Some((state, frame_count, transcript_digest, interruption)) = metadata else {
                return Err(A2AError::invalid_request(
                    "message identity is not bound to a streaming request",
                ));
            };
            let all = load_public_stream_frames(
                connection,
                &tenant_scope,
                &message_id,
                frame_count,
                transcript_digest.as_deref(),
                &state,
                interruption.as_deref(),
            )?;
            if last_sequence > all.len() {
                return Err(A2AError::internal("stream replay cursor is corrupt"));
            }
            Ok(StreamTranscriptBatch {
                frames: all.into_iter().skip(last_sequence).collect(),
                closed: state != "open",
                interruption,
            })
        })
        .await
    }

    /// Append the committed working/progress frame for an active streaming dispatch.
    pub(crate) async fn append_stream_progress(
        &self,
        tenant_scope: &str,
        dispatch_id: &str,
        frame: StreamResponse,
        now: i64,
    ) -> Result<Option<StreamResponse>, A2AError> {
        if !matches!(&frame, StreamResponse::StatusUpdate(update)
            if update.status.state == a2a::TaskState::Working)
        {
            return Err(A2AError::invalid_params(
                "invalid durable stream progress frame",
            ));
        }
        let tenant_scope = tenant_scope.to_owned();
        let dispatch_id = dispatch_id.to_owned();
        let encoded = serde_json::to_string(&frame)
            .map_err(|_| A2AError::internal("failed to encode stream progress frame"))?;
        self.run(move |connection| {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| A2AError::internal("stream progress transaction failed"))?;
            let metadata: Option<(String, i64, String)> = tx.query_row(
                "SELECT message_id, frame_count, transcript_digest FROM stream_transcripts
                 WHERE tenant_scope = ?1 AND dispatch_id = ?2 AND state = 'open'",
                params![tenant_scope, dispatch_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            ).optional().map_err(|_| A2AError::internal("stream progress lookup failed"))?;
            let Some((message_id, count, digest)) = metadata else { return Ok(None); };
            let mut frames = load_public_stream_frames(&tx, &tenant_scope,
                &message_id, count, Some(&digest), "open", None)?;
            if let Some(existing) = frames.iter().find(|existing| matches!(existing,
                StreamResponse::StatusUpdate(update) if update.status.state == a2a::TaskState::Working))
            {
                return Ok(Some(existing.clone()));
            }
            frames.push(frame.clone());
            let sequence = i64::try_from(frames.len())
                .map_err(|_| A2AError::internal("stream progress sequence exhausted"))?;
            tx.execute(
                "INSERT INTO stream_frames(tenant_scope, message_id, frame_seq, frame_version,
                     frame_kind, frame_json, frame_digest, created_at)
                 VALUES (?1, ?2, ?3, 1, 'status_update', ?4, ?5, ?6)",
                params![tenant_scope, message_id, sequence, encoded,
                    content_digest(encoded.as_bytes()), now],
            ).map_err(|_| A2AError::internal("stream progress append failed"))?;
            let transcript = serde_json::to_vec(&frames)
                .map_err(|_| A2AError::internal("stream progress digest failed"))?;
            tx.execute(
                "UPDATE stream_transcripts SET frame_count = ?3, transcript_digest = ?4,
                     updated_at = ?5 WHERE tenant_scope = ?1 AND message_id = ?2 AND state = 'open'",
                params![tenant_scope, message_id, sequence,
                    content_digest(&transcript), now],
            ).map_err(|_| A2AError::internal("stream progress metadata failed"))?;
            ensure_stream_capacity(&tx)?;
            tx.commit().map_err(|_| A2AError::internal("stream progress commit failed"))?;
            Ok(Some(frame))
        }).await
    }

    /// Atomically capture the authoritative task and a tail cursor.
    pub(crate) async fn subscription_snapshot(
        &self,
        task_id: &str,
    ) -> Result<Option<(Task, SubscriptionCursor)>, A2AError> {
        self.subscription_snapshot_scope(
            self.default_scope.to_string(),
            self.default_account.to_string(),
            false,
            task_id,
        )
        .await
    }

    pub(crate) async fn subscription_snapshot_authorized(
        &self,
        scope: &OwnedTaskScope,
        task_id: &str,
    ) -> Result<Option<(Task, SubscriptionCursor)>, A2AError> {
        self.subscription_snapshot_scope(
            scope.tenant_scope.clone(),
            scope.owner_account_id.clone(),
            scope.visibility == crate::authorization::VisibilityScope::Own,
            task_id,
        )
        .await
    }

    async fn subscription_snapshot_scope(
        &self,
        tenant_scope: String,
        owner_account_id: String,
        own_only: bool,
        task_id: &str,
    ) -> Result<Option<(Task, SubscriptionCursor)>, A2AError> {
        let task_id = task_id.to_owned();
        self.run(move |connection| {
            #[allow(clippy::type_complexity)]
            let row: Option<(
                String,
                i64,
                Option<String>,
                Option<i64>,
                Option<String>,
            )> = connection
                .query_row(
                    "SELECT task.task_json, task.revision, stream.message_id, stream.frame_count,
                            stream.transcript_digest
                     FROM tasks task LEFT JOIN stream_transcripts stream
                       ON stream.tenant_scope = ?1 AND stream.task_id = task.task_id
                      AND stream.state = 'open'
                     WHERE task.tenant_scope=?1 AND task.task_id = ?2
                       AND (?3=0 OR task.owner_account_id=?4)",
                    params![tenant_scope, task_id, i64::from(own_only), owner_account_id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .optional()
                .map_err(|_| A2AError::internal("subscription snapshot lookup failed"))?;
            row.map(|(encoded, revision, message_id, cursor, digest)| {
                let mut task: Task = serde_json::from_str(&encoded)
                    .map_err(|_| A2AError::internal("subscription task is corrupt"))?;
                let cursor = match (message_id, cursor, digest) {
                    (Some(message_id), Some(cursor), Some(digest)) => {
                        let frames = load_public_stream_frames(
                            connection,
                            &tenant_scope,
                            &message_id,
                            cursor,
                            Some(&digest),
                            "open",
                            None,
                        )?;
                        for frame in frames.into_iter().skip(1) {
                            match frame {
                                StreamResponse::StatusUpdate(update) => task.status = update.status,
                                StreamResponse::ArtifactUpdate(update) => task
                                    .artifacts
                                    .get_or_insert_with(Vec::new)
                                    .push(update.artifact),
                                StreamResponse::Task(_) | StreamResponse::Message(_) => {}
                            }
                        }
                        SubscriptionCursor::Transcript {
                            message_id,
                            cursor: usize::try_from(cursor).map_err(|_| {
                                A2AError::internal("subscription cursor is corrupt")
                            })?,
                        }
                    }
                    (None, None, None) => SubscriptionCursor::TaskRevision(
                        u64::try_from(revision)
                            .map_err(|_| A2AError::internal("subscription revision is corrupt"))?,
                    ),
                    _ => return Err(A2AError::internal("subscription cursor is corrupt")),
                };
                Ok((task, cursor))
            })
            .transpose()
        })
        .await
    }

    pub(crate) async fn task_events_after(
        &self,
        task_id: &str,
        last_revision: u64,
    ) -> Result<TaskEventBatch, A2AError> {
        self.task_events_after_scope(
            self.default_scope.to_string(),
            self.default_account.to_string(),
            false,
            task_id,
            last_revision,
        )
        .await
    }

    pub(crate) async fn task_events_after_scoped(
        &self,
        scope: &OwnedTaskScope,
        task_id: &str,
        last_revision: u64,
    ) -> Result<TaskEventBatch, A2AError> {
        self.task_events_after_scope(
            scope.tenant_scope.clone(),
            scope.owner_account_id.clone(),
            scope.visibility == crate::authorization::VisibilityScope::Own,
            task_id,
            last_revision,
        )
        .await
    }

    async fn task_events_after_scope(
        &self,
        tenant_scope: String,
        owner_account_id: String,
        own_only: bool,
        task_id: &str,
        last_revision: u64,
    ) -> Result<TaskEventBatch, A2AError> {
        let task_id = task_id.to_owned();
        self.run(move |connection| {
            let mut statement = connection
                .prepare(
                    "SELECT event_json, task_revision FROM task_events e
                     WHERE e.tenant_scope = ?1 AND e.task_id = ?2 AND e.task_revision > ?3
                       AND EXISTS(SELECT 1 FROM tasks t WHERE t.tenant_scope=e.tenant_scope
                         AND t.task_id=e.task_id AND (?4=0 OR t.owner_account_id=?5))
                     ORDER BY task_revision",
                )
                .map_err(|_| A2AError::internal("subscription event lookup failed"))?;
            let rows = statement
                .query_map(
                    params![
                        tenant_scope,
                        task_id,
                        last_revision,
                        i64::from(own_only),
                        owner_account_id
                    ],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
                )
                .map_err(|_| A2AError::internal("subscription event lookup failed"))?;
            let baseline: Option<String> = connection
                .query_row(
                    "SELECT event_json FROM task_events e
                     WHERE e.tenant_scope = ?1 AND e.task_id = ?2 AND e.task_revision <= ?3
                       AND EXISTS(SELECT 1 FROM tasks t WHERE t.tenant_scope=e.tenant_scope
                         AND t.task_id=e.task_id AND (?4=0 OR t.owner_account_id=?5))
                     ORDER BY task_revision DESC LIMIT 1",
                    params![
                        tenant_scope,
                        task_id,
                        last_revision,
                        i64::from(own_only),
                        owner_account_id
                    ],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|_| A2AError::internal("subscription baseline lookup failed"))?;
            let mut previous = baseline
                .map(|encoded| {
                    serde_json::from_str::<Task>(&encoded)
                        .map_err(|_| A2AError::internal("subscription baseline task is corrupt"))
                })
                .transpose()?;
            let mut frames = Vec::new();
            let mut cursor = last_revision;
            let mut terminal = false;
            for row in rows {
                let (encoded, revision) =
                    row.map_err(|_| A2AError::internal("subscription event row is corrupt"))?;
                let task: Task = serde_json::from_str(&encoded)
                    .map_err(|_| A2AError::internal("subscription event task is corrupt"))?;
                cursor = u64::try_from(revision)
                    .map_err(|_| A2AError::internal("subscription event revision is corrupt"))?;
                let previous_artifacts = previous
                    .as_ref()
                    .and_then(|task| task.artifacts.as_deref())
                    .unwrap_or_default();
                for artifact in task.artifacts.as_deref().unwrap_or_default() {
                    if !previous_artifacts
                        .iter()
                        .any(|existing| existing.artifact_id == artifact.artifact_id)
                    {
                        frames.push(StreamResponse::ArtifactUpdate(TaskArtifactUpdateEvent {
                            task_id: task.id.clone(),
                            context_id: task.context_id.clone(),
                            artifact: artifact.clone(),
                            append: Some(false),
                            last_chunk: Some(true),
                            metadata: None,
                        }));
                    }
                }
                if previous
                    .as_ref()
                    .is_none_or(|previous| previous.status != task.status)
                {
                    frames.push(StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
                        task_id: task.id.clone(),
                        context_id: task.context_id.clone(),
                        status: task.status.clone(),
                        metadata: None,
                    }));
                }
                terminal = task.status.state.is_terminal();
                previous = Some(task);
            }
            Ok(TaskEventBatch {
                frames,
                closed: terminal,
                last_revision: cursor,
            })
        })
        .await
    }

    /// Accept, replay, or reclaim a stable receiver dispatch identity.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid/conflicting envelopes or transactional failure.
    #[allow(clippy::too_many_lines)]
    pub async fn begin_receive(
        &self,
        envelope: DurableDispatchEnvelope,
        lease_owner: &str,
        now: i64,
        lease_duration: i64,
    ) -> Result<ReceiverAdmission, A2AError> {
        let lease_owner = lease_owner.to_owned();
        let payload_json = serde_json::to_string(&envelope.request)
            .map_err(|_| A2AError::internal("failed to encode receiver payload"))?;
        if !valid_bounded_identity(&envelope.tenant_scope)
            || envelope.dispatch_id.is_empty()
            || envelope.dispatch_id.len() > 256
            || envelope.payload_digest != content_digest(payload_json.as_bytes())
            || !receiver_request_is_valid(&envelope.request, payload_json.len())
            || lease_owner.is_empty()
            || lease_owner.len() > MAX_ATOMIC_TEXT_BYTES
            || lease_duration <= 0
            || envelope.request.task_id.is_empty()
            || envelope.request.context_id.is_empty()
        {
            return Err(A2AError::invalid_params(
                "invalid durable receiver envelope",
            ));
        }
        self.run(move |connection| {
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| A2AError::internal("receiver admission transaction failed"))?;
            let tenant_scope = envelope.tenant_scope.clone();
            let owned_outbox: Option<(i64, String)> = tx
                .query_row(
                    "SELECT attempt_count, lease_token FROM outbox WHERE tenant_scope=?1 AND dispatch_id=?2
                 AND task_id=?3 AND payload_digest=?4 AND state='leased' AND lease_token IS NOT NULL",
                    params![
                        tenant_scope,
                        envelope.dispatch_id,
                        envelope.request.task_id,
                        envelope.payload_digest
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|_| A2AError::internal("receiver outbox ownership lookup failed"))?;
            let Some((sender_attempt, sender_token)) = owned_outbox else {
                return Err(A2AError::invalid_params(
                    "invalid durable receiver envelope",
                ));
            };
            #[allow(clippy::type_complexity)]
            let existing: Option<(
                String,
                String,
                i64,
                i64,
                Option<i64>,
                Option<String>,
                Option<String>,
                Option<String>,
            )> = tx
                .query_row(
                    "SELECT payload_digest, state, lease_epoch, COALESCE(lease_until, 0),
                            frame_count, transcript_digest, completion_kind, termination_json
                 FROM receiver_inbox WHERE tenant_scope = ?1 AND dispatch_id = ?2",
                    params![tenant_scope, envelope.dispatch_id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                            row.get(7)?,
                        ))
                    },
                )
                .optional()
                .map_err(|_| A2AError::internal("receiver inbox lookup failed"))?;
            if let Some((
                digest,
                state,
                epoch,
                lease_until,
                frame_count,
                transcript_digest,
                completion_kind,
                termination_json,
            )) = existing
            {
                if digest != envelope.payload_digest {
                    return Err(A2AError::invalid_request(
                        "dispatch identity is already bound to a different payload",
                    ));
                }
                if state == "completed" {
                    let frame_count = frame_count
                        .ok_or_else(|| A2AError::internal("receiver replay metadata is corrupt"))?;
                    let transcript_digest = transcript_digest
                        .ok_or_else(|| A2AError::internal("receiver replay metadata is corrupt"))?;
                    let events = load_receiver_frames(
                        &tx,
                        &tenant_scope,
                        &envelope.dispatch_id,
                        frame_count,
                        &transcript_digest,
                    )?;
                    let termination = decode_receiver_termination(
                        completion_kind.as_deref(),
                        termination_json.as_deref(),
                    )?;
                    validate_receiver_outcome(&events, &termination)?;
                    return Ok(match termination {
                        DurableReceiverTermination::Success => ReceiverAdmission::Replay(events),
                        termination => ReceiverAdmission::ReplayOutcome(DurableReceiverResult {
                            events,
                            termination,
                        }),
                    });
                }
                if lease_until > now {
                    return Ok(ReceiverAdmission::Busy);
                }
                let next_epoch = epoch
                    .checked_add(1)
                    .ok_or_else(|| A2AError::internal("receiver lease epoch exhausted"))?;
                let lease_until = now
                    .checked_add(lease_duration)
                    .ok_or_else(|| A2AError::invalid_params("receiver lease time overflow"))?;
                let entropy: [u8; 32] = rand::random();
                let token = content_digest(
                    [
                        envelope.dispatch_id.as_bytes(),
                        lease_owner.as_bytes(),
                        &next_epoch.to_le_bytes(),
                        &entropy,
                    ]
                    .concat()
                    .as_slice(),
                );
                let changed = tx
                    .execute(
                        "UPDATE receiver_inbox SET lease_epoch = ?3, lease_owner = ?4,
                         lease_token = ?5, lease_until = ?6, updated_at = ?7
                     WHERE tenant_scope = ?1 AND dispatch_id = ?2 AND state = 'processing'
                       AND lease_epoch = ?8 AND lease_until <= ?7",
                        params![
                            tenant_scope,
                            envelope.dispatch_id,
                            next_epoch,
                            lease_owner,
                            token,
                            lease_until,
                            now,
                            epoch
                        ],
                    )
                    .map_err(|_| A2AError::internal("receiver reclaim failed"))?;
                if changed != 1 {
                    return Ok(ReceiverAdmission::Busy);
                }
                tx.commit()
                    .map_err(|_| A2AError::internal("receiver reclaim commit failed"))?;
                return Ok(ReceiverAdmission::Execute(ReceiverLease {
                    tenant_scope: tenant_scope.clone(),
                    task_id: envelope.request.task_id,
                    dispatch_id: envelope.dispatch_id,
                    payload_digest: envelope.payload_digest,
                    sender_attempt_no: u32::try_from(sender_attempt)
                        .map_err(|_| A2AError::internal("sender attempt is corrupt"))?,
                    sender_lease_token: sender_token,
                    lease_owner,
                    lease_token: token,
                    lease_epoch: u64::try_from(next_epoch)
                        .map_err(|_| A2AError::internal("receiver lease epoch is corrupt"))?,
                    lease_until,
                    execution_reservation: None,
                }));
            }
            let lease_until = now
                .checked_add(lease_duration)
                .ok_or_else(|| A2AError::invalid_params("receiver lease time overflow"))?;
            let entropy: [u8; 32] = rand::random();
            let token = content_digest(
                [
                    envelope.dispatch_id.as_bytes(),
                    lease_owner.as_bytes(),
                    &now.to_le_bytes(),
                    &entropy,
                ]
                .concat()
                .as_slice(),
            );
            tx.execute(
                "INSERT INTO receiver_inbox(tenant_scope, dispatch_id, payload_digest,
                     payload_json, task_id, context_id, state, lease_epoch, lease_owner,
                     lease_token, lease_until, accepted_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'processing', 1, ?7, ?8, ?9, ?10, ?10)",
                params![
                    tenant_scope,
                    envelope.dispatch_id,
                    envelope.payload_digest,
                    payload_json,
                    envelope.request.task_id,
                    envelope.request.context_id,
                    lease_owner,
                    token,
                    lease_until,
                    now
                ],
            )
            .map_err(|_| A2AError::internal("receiver acceptance failed"))?;
            ensure_receiver_capacity(&tx)?;
            tx.commit()
                .map_err(|_| A2AError::internal("receiver acceptance commit failed"))?;
            Ok(ReceiverAdmission::Execute(ReceiverLease {
                tenant_scope,
                task_id: envelope.request.task_id,
                dispatch_id: envelope.dispatch_id,
                payload_digest: envelope.payload_digest,
                sender_attempt_no: u32::try_from(sender_attempt)
                    .map_err(|_| A2AError::internal("sender attempt is corrupt"))?,
                sender_lease_token: sender_token,
                lease_owner,
                lease_token: token,
                lease_epoch: 1,
                lease_until,
                execution_reservation: None,
            }))
        })
        .await
    }

    /// Atomically persist an exact receiver transcript and fence completion.
    ///
    /// # Errors
    ///
    /// Returns an error for stale leases, oversized frames, or transactional failure.
    pub async fn complete_receive(
        &self,
        lease: &ReceiverLease,
        events: &[MeshEvent],
        now: i64,
    ) -> Result<(), A2AError> {
        self.complete_receive_inner(
            lease,
            events,
            DurableReceiverTermination::Success,
            now,
            false,
            false,
        )
        .await
    }

    /// Commit the owned loopback effect and transcript in the same transaction.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale lease, invalid transcript, capacity, or commit failure.
    pub async fn complete_loopback_receive(
        &self,
        lease: &ReceiverLease,
        events: &[MeshEvent],
        now: i64,
    ) -> Result<(), A2AError> {
        self.complete_receive_inner(
            lease,
            events,
            DurableReceiverTermination::Success,
            now,
            true,
            false,
        )
        .await
    }

    /// Commit an immutable loopback interruption or success outcome.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid outcome, stale receiver fence, capacity,
    /// or transactional persistence failure.
    pub async fn complete_loopback_outcome(
        &self,
        lease: &ReceiverLease,
        outcome: &DurableReceiverResult,
        now: i64,
    ) -> Result<(), A2AError> {
        self.complete_receive_inner(
            lease,
            &outcome.events,
            outcome.termination.clone(),
            now,
            true,
            false,
        )
        .await
    }

    pub(crate) async fn complete_canceled_receive(
        &self,
        lease: &ReceiverLease,
        events: &[MeshEvent],
        now: i64,
    ) -> Result<(), A2AError> {
        self.complete_receive_inner(
            lease,
            events,
            DurableReceiverTermination::Success,
            now,
            false,
            true,
        )
        .await
    }

    #[allow(clippy::too_many_lines)] // Validation, frames, effect, and fence must stay visibly atomic.
    async fn complete_receive_inner(
        &self,
        lease: &ReceiverLease,
        events: &[MeshEvent],
        termination: DurableReceiverTermination,
        now: i64,
        loopback_effect: bool,
        completion_canceled: bool,
    ) -> Result<(), A2AError> {
        validate_receiver_outcome(events, &termination)?;
        let (completion_kind, termination_json) = encode_receiver_termination(&termination)?;
        let lease = lease.clone();
        let events = events.to_vec();
        let encoded = events
            .iter()
            .map(|event| {
                serde_json::to_string(event)
                    .map_err(|_| A2AError::internal("failed to encode receiver frame"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if encoded.len() > 1024
            || encoded
                .iter()
                .any(|frame| frame.len() > MAX_ATOMIC_JSON_BYTES)
        {
            return Err(A2AError::invalid_params(
                "receiver transcript exceeds limit",
            ));
        }
        let transcript = serde_json::to_vec(&events)
            .map_err(|_| A2AError::internal("failed to digest receiver transcript"))?;
        if transcript.len() > MAX_STORE_JSON_BYTES {
            return Err(A2AError::invalid_params(
                "receiver transcript exceeds byte limit",
            ));
        }
        let transcript_digest = content_digest(&transcript);
        self.run(move |connection| {
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| A2AError::internal("receiver completion transaction failed"))?;
            let valid: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM receiver_inbox WHERE tenant_scope = ?1
                     AND dispatch_id = ?2 AND payload_digest = ?3 AND state = 'processing'
                     AND lease_owner = ?4 AND lease_token = ?5 AND lease_epoch = ?6
                     AND lease_until = ?7 AND lease_until > ?8
                     AND (EXISTS(SELECT 1 FROM cancellation_intents cancel
                          WHERE cancel.tenant_scope = ?1 AND cancel.dispatch_id = ?2
                            AND cancel.state = 'requested')) = ?9)",
                    params![
                        lease.tenant_scope,
                        lease.dispatch_id,
                        lease.payload_digest,
                        lease.lease_owner,
                        lease.lease_token,
                        lease.lease_epoch,
                        lease.lease_until,
                        now,
                        completion_canceled
                    ],
                    |row| row.get(0),
                )
                .map_err(|_| A2AError::internal("receiver completion fence lookup failed"))?;
            if !valid {
                return Err(A2AError::internal("stale receiver completion lease"));
            }
            if completion_canceled {
                let changed = tx.execute(
                    "UPDATE cancellation_intents SET state = 'receiver_canceled', completed_at = ?3
                     WHERE tenant_scope = ?1 AND dispatch_id = ?2 AND state = 'requested'",
                    params![lease.tenant_scope, lease.dispatch_id, now],
                ).map_err(|_| A2AError::internal("receiver cancellation transcript arbitration failed"))?;
                if changed != 1 {
                    return Err(A2AError::internal("stale receiver cancellation intent"));
                }
            }
            if loopback_effect {
                tx.execute(
                    "INSERT INTO loopback_effects(tenant_scope, dispatch_id, effect_kind, committed_at)
                     VALUES (?1, ?2, 'accepted', ?3)",
                    params![lease.tenant_scope, lease.dispatch_id, now],
                )
                .map_err(|_| A2AError::internal("loopback effect commit failed"))?;
            }
            for (index, frame) in encoded.iter().enumerate() {
                let sequence = i64::try_from(index + 1)
                    .map_err(|_| A2AError::internal("receiver frame sequence exhausted"))?;
                tx.execute(
                    "INSERT INTO receiver_frames(tenant_scope, dispatch_id, frame_seq,
                         frame_version, frame_kind, frame_json, frame_digest, created_at)
                     VALUES (?1, ?2, ?3, 1, 'mesh_event', ?4, ?5, ?6)",
                    params![
                        lease.tenant_scope,
                        lease.dispatch_id,
                        sequence,
                        frame,
                        content_digest(frame.as_bytes()),
                        now
                    ],
                )
                .map_err(|_| A2AError::internal("receiver frame append failed"))?;
            }
            let changed = tx
                .execute(
                    "UPDATE receiver_inbox SET state = 'completed', completion_kind = ?3,
                     termination_json = ?4, frame_count = ?5, transcript_digest = ?6,
                     completed_at = ?7, updated_at = ?7,
                     lease_owner = NULL, lease_token = NULL, lease_until = NULL
                 WHERE tenant_scope = ?1 AND dispatch_id = ?2 AND state = 'processing'
                   AND lease_token = ?8 AND lease_epoch = ?9",
                    params![
                        lease.tenant_scope,
                        lease.dispatch_id,
                        completion_kind,
                        termination_json,
                        encoded.len(),
                        transcript_digest,
                        now,
                        lease.lease_token,
                        lease.lease_epoch
                    ],
                )
                .map_err(|_| A2AError::internal("receiver completion failed"))?;
            if changed != 1 {
                return Err(A2AError::internal("stale receiver completion lease"));
            }
            ensure_receiver_capacity(&tx)?;
            tx.commit()
                .map_err(|_| A2AError::internal("receiver completion commit failed"))
        })
        .await
    }

    /// Atomically commit sender terminal state, exact replay result, and fenced outbox ack.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid results, stale/corrupt state, or transactional failure.
    #[allow(clippy::too_many_lines)] // One transaction intentionally exposes every sender write.
    pub async fn commit_delivery(
        &self,
        lease: &OutboxLease,
        task: Task,
        final_result: SendMessageResponse,
        public_transcript: &[StreamResponse],
        now: i64,
    ) -> Result<TransitionOutcome, A2AError> {
        if task.id != lease.task_id
            || !is_dispatch_closed(&task.status.state)
            || !final_result_matches_task(&final_result, &task)
        {
            return Err(A2AError::invalid_params("invalid durable delivery result"));
        }
        let lease = lease.clone();
        let task_json = encode_task(&task)?;
        let state = state_key(&task)?;
        let timestamp = task.status.timestamp.map(|value| value.to_rfc3339());
        let final_json = serde_json::to_string(&final_result)
            .map_err(|_| A2AError::internal("failed to encode durable delivery result"))?;
        validate_terminal_public_transcript(public_transcript, &task)?;
        let public_transcript = public_transcript.to_vec();
        let transcript_frames = public_transcript
            .iter()
            .map(|frame| {
                serde_json::to_string(frame)
                    .map_err(|_| A2AError::internal("failed to encode public stream frame"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let transcript_json = serde_json::to_vec(&public_transcript)
            .map_err(|_| A2AError::internal("failed to encode public stream transcript"))?;
        if transcript_frames.len() > MAX_STREAM_FRAMES
            || transcript_json.len() > MAX_STORE_JSON_BYTES
            || transcript_frames
                .iter()
                .any(|frame| frame.len() > MAX_ATOMIC_JSON_BYTES)
        {
            return Err(A2AError::invalid_params(
                "public stream transcript exceeds limit",
            ));
        }
        let transcript_digest = content_digest(&transcript_json);
        self.run(move |connection| {
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| A2AError::internal("durable delivery transaction failed"))?;
            let causative: Option<i64> = tx.query_row(
                "SELECT causative_revision FROM outbox WHERE outbox_id = ?1 AND dispatch_id = ?2
                     AND task_id = ?3 AND state = 'leased' AND lease_owner = ?4
                     AND lease_token = ?5 AND attempt_count = ?6 AND lease_until = ?7
                     AND lease_until > ?8 AND tenant_scope = ?9",
                params![lease.outbox_id, lease.dispatch_id, lease.task_id, lease.lease_owner,
                    lease.lease_token, lease.attempt_no, lease.lease_until, now, lease.tenant_scope],
                |row| row.get(0),
            ).optional().map_err(|_| A2AError::internal("durable delivery fence lookup failed"))?;
            let Some(revision) = causative else {
                return Ok(TransitionOutcome::Stale);
            };
            let (current, previous_state): (i64, String) = tx
                .query_row(
                    "SELECT revision, state FROM tasks WHERE tenant_scope = ?1 AND task_id = ?2",
                    params![lease.tenant_scope, lease.task_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|_| A2AError::internal("durable delivery task lookup failed"))?;
            if current != revision {
                return Ok(TransitionOutcome::Stale);
            }
            let stream_message_id: Option<(String, i64, String)> = tx
                .query_row(
                    "SELECT message_id, frame_count, transcript_digest FROM stream_transcripts
                 WHERE tenant_scope = ?1 AND dispatch_id = ?2 AND task_id = ?3 AND state = 'open'",
                    params![lease.tenant_scope, lease.dispatch_id, lease.task_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(|_| A2AError::internal("public stream fence lookup failed"))?;
            let stream_message_id = stream_message_id
                .map(|(message_id, persisted_count, persisted_digest)| {
                    let persisted = load_public_stream_frames(
                        &tx,
                        &lease.tenant_scope,
                        &message_id,
                        persisted_count,
                        Some(&persisted_digest),
                        "open",
                        None,
                    )?;
                    let persisted_count = usize::try_from(persisted_count)
                        .map_err(|_| A2AError::internal("public stream cursor is corrupt"))?;
                    if persisted_count > public_transcript.len()
                        || persisted != public_transcript[..persisted_count]
                    {
                        return Err(A2AError::internal(
                            "persisted public stream prefix diverges from delivery transcript",
                        ));
                    }
                    Ok((message_id, persisted_count))
                })
                .transpose()?;
            let next_revision = revision
                .checked_add(1)
                .ok_or_else(|| A2AError::internal("persistent task revision exhausted"))?;
            tx.execute(
                "UPDATE tasks SET context_id = ?2, state = ?3, status_timestamp = ?4,
                     revision = ?5, task_json = ?6 WHERE task_id = ?1 AND revision = ?7
                     AND tenant_scope = ?8",
                params![
                    lease.task_id,
                    task.context_id,
                    state,
                    timestamp,
                    next_revision,
                    task_json,
                    revision,
                    lease.tenant_scope
                ],
            )
            .map_err(|_| A2AError::internal("durable delivery task commit failed"))?;
            let event_seq: i64 = tx
                .query_row(
                    "SELECT COALESCE(MAX(event_seq), 0) + 1 FROM task_events
                 WHERE tenant_scope = ?1 AND task_id = ?2",
                    params![lease.tenant_scope, lease.task_id],
                    |row| row.get(0),
                )
                .map_err(|_| A2AError::internal("durable delivery event sequence failed"))?;
            tx.execute(
                "INSERT INTO task_events(tenant_scope, task_id, event_seq, task_revision,
                     event_kind, from_state, to_state, event_json, created_at)
                 VALUES (?1, ?2, ?3, ?4, 'durable_completed', ?5, ?6, ?7, ?8)",
                params![
                    lease.tenant_scope,
                    lease.task_id,
                    event_seq,
                    next_revision,
                    previous_state,
                    state,
                    task_json,
                    now
                ],
            )
            .map_err(|_| A2AError::internal("durable delivery event append failed"))?;
            if let Some((message_id, persisted_count)) = stream_message_id {
                for (index, frame) in transcript_frames.iter().enumerate().skip(persisted_count) {
                    let sequence = i64::try_from(index + 1)
                        .map_err(|_| A2AError::internal("public stream sequence exhausted"))?;
                    tx.execute(
                        "INSERT INTO stream_frames(tenant_scope, message_id, frame_seq,
                             frame_version, frame_kind, frame_json, frame_digest, created_at)
                         VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?7)",
                        params![
                            lease.tenant_scope,
                            message_id,
                            sequence,
                            public_stream_kind(&public_transcript[index]),
                            frame,
                            content_digest(frame.as_bytes()),
                            now
                        ],
                    )
                    .map_err(|_| A2AError::internal("public stream frame append failed"))?;
                }
                let changed = tx
                    .execute(
                        "UPDATE stream_transcripts SET state = 'terminal', frame_count = ?3,
                         transcript_digest = ?4, terminal_seq = ?3, updated_at = ?5
                     WHERE tenant_scope = ?1 AND message_id = ?2 AND state = 'open'",
                        params![
                            lease.tenant_scope,
                            message_id,
                            transcript_frames.len(),
                            transcript_digest,
                            now
                        ],
                    )
                    .map_err(|_| A2AError::internal("public stream completion failed"))?;
                if changed != 1 {
                    return Err(A2AError::internal("stale public stream completion"));
                }
            }
            tx.execute(
                "UPDATE idempotency_records SET state = 'completed', final_result_json = ?2,
                     updated_at = ?3 WHERE tenant_scope = ?1 AND task_id = ?4
                     AND message_id = (SELECT message_id FROM outbox WHERE outbox_id = ?5)
                     AND state = 'in_progress'",
                params![
                    lease.tenant_scope,
                    final_json,
                    now,
                    lease.task_id,
                    lease.outbox_id
                ],
            )
            .map_err(|_| A2AError::internal("durable delivery replay commit failed"))?;
            tx.execute(
                "UPDATE outbox SET state = 'delivered', lease_owner = NULL, lease_token = NULL,
                     lease_until = NULL, updated_at = ?3 WHERE outbox_id = ?1 AND lease_token = ?2",
                params![lease.outbox_id, lease.lease_token, now],
            )
            .map_err(|_| A2AError::internal("durable delivery ack failed"))?;
            tx.execute(
                "UPDATE outbox_attempts SET finished_at = ?3, outcome = 'delivered'
                 WHERE outbox_id = ?1 AND attempt_no = ?2 AND finished_at IS NULL",
                params![lease.outbox_id, lease.attempt_no, now],
            )
            .map_err(|_| A2AError::internal("durable delivery attempt close failed"))?;
            ensure_atomic_capacity(&tx)?;
            ensure_stream_capacity(&tx)?;
            tx.commit()
                .map_err(|_| A2AError::internal("durable delivery commit failed"))?;
            Ok(TransitionOutcome::Applied)
        })
        .await
    }

    #[doc(hidden)]
    pub async fn atomic_record_counts(&self) -> Result<AtomicRecordCounts, A2AError> {
        self.run(move |connection| {
            let count = |table: &str| -> Result<u64, A2AError> {
                let sql = format!("SELECT COUNT(*) FROM {table}");
                let value: i64 = connection
                    .query_row(&sql, [], |row| row.get(0))
                    .map_err(|_| A2AError::internal("atomic record count failed"))?;
                u64::try_from(value)
                    .map_err(|_| A2AError::internal("atomic record count is corrupt"))
            };
            Ok(AtomicRecordCounts {
                tasks: count("tasks")?,
                events: count("task_events")?,
                idempotency_records: count("idempotency_records")?,
                outbox: count("outbox")?,
            })
        })
        .await
    }

    /// Count effects durably committed by the owned loopback adapter.
    ///
    /// # Errors
    ///
    /// Returns an error when the shared store is closed or the query is corrupt.
    pub async fn durable_effect_count(&self) -> Result<u64, A2AError> {
        self.run(move |connection| {
            let value: i64 = connection
                .query_row("SELECT COUNT(*) FROM loopback_effects", [], |row| {
                    row.get(0)
                })
                .map_err(|_| A2AError::internal("loopback effect count failed"))?;
            u64::try_from(value).map_err(|_| A2AError::internal("loopback effect count is corrupt"))
        })
        .await
    }

    #[cfg(test)]
    pub(crate) async fn execute_test_batch(&self, sql: &'static str) -> Result<(), A2AError> {
        self.run(move |connection| {
            connection
                .execute_batch(sql)
                .map_err(|error| A2AError::internal(format!("test fault install failed: {error}")))
        })
        .await
    }

    /// Synchronously close shared admission, SQLite, and ownership state.
    ///
    /// Used only by fail-safe owner drop after its worker has been aborted. Closing
    /// the semaphore rejects router-clone work; taking the mutexes waits for any
    /// already-running bounded SQLite operation before releasing the process lock.
    pub(crate) fn close_shared_sync(&self) {
        self.admission.close();
        if let Ok(mut connection) = self.connection.lock() {
            connection.take();
        }
        if let Ok(mut ownership_lock) = self.ownership_lock.lock() {
            ownership_lock.take();
        }
    }

    /// Relinquish the shared SQLite connection and process ownership lock for all clones.
    ///
    /// # Errors
    ///
    /// Returns an error if shared state cannot be locked or the close worker fails.
    pub async fn shutdown_shared(&self) -> Result<(), A2AError> {
        let permit = tokio::time::timeout(
            Duration::from_secs(5),
            Arc::clone(&self.admission).acquire_owned(),
        )
        .await
        .map_err(|_| {
            A2AError::internal("persistent task store shutdown timed out acquiring admission")
        })?
        .map_err(|_| A2AError::internal("persistent task store is closed"))?;
        let connection = Arc::clone(&self.connection);
        let ownership_lock = Arc::clone(&self.ownership_lock);
        tokio::time::timeout(
            Duration::from_secs(5),
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let connection = connection
                    .lock()
                    .map_err(|_| A2AError::internal("persistent task store lock failed"))?
                    .take();
                drop(connection);
                ownership_lock
                    .lock()
                    .map_err(|_| A2AError::internal("persistent ownership lock failed"))?
                    .take();
                Ok(())
            }),
        )
        .await
        .map_err(|_| A2AError::internal("persistent task store shutdown timed out"))?
        .map_err(|_| A2AError::internal("persistent task store shutdown failed"))?
    }

    async fn run<R, F>(&self, operation: F) -> Result<R, A2AError>
    where
        R: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<R, A2AError> + Send + 'static,
    {
        let permit = Arc::clone(&self.admission)
            .acquire_owned()
            .await
            .map_err(|_| A2AError::internal("persistent task store is closed"))?;
        let connection = Arc::clone(&self.connection);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut guard = connection
                .lock()
                .map_err(|_| A2AError::internal("persistent task store lock failed"))?;
            let connection = guard
                .as_mut()
                .ok_or_else(|| A2AError::internal("persistent task store is closed"))?;
            operation(connection)
        })
        .await
        .map_err(|_| A2AError::internal("persistent task store worker failed"))?
    }
}

fn append_canceled_public_terminal(
    tx: &rusqlite::Transaction<'_>,
    tenant_scope: &str,
    dispatch_id: &str,
    task: &Task,
    now: i64,
) -> Result<(), A2AError> {
    let metadata: Option<(String, i64, String)> = tx
        .query_row(
            "SELECT message_id, frame_count, transcript_digest FROM stream_transcripts
         WHERE tenant_scope = ?1 AND dispatch_id = ?2 AND state = 'open'",
            params![tenant_scope, dispatch_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| A2AError::internal("cancellation stream lookup failed"))?;
    let Some((message_id, frame_count, digest)) = metadata else {
        return Ok(());
    };
    let mut frames = load_public_stream_frames(
        tx,
        tenant_scope,
        &message_id,
        frame_count,
        Some(&digest),
        "open",
        None,
    )?;
    let terminal = StreamResponse::StatusUpdate(a2a::TaskStatusUpdateEvent {
        task_id: task.id.clone(),
        context_id: task.context_id.clone(),
        status: task.status.clone(),
        metadata: None,
    });
    frames.push(terminal.clone());
    validate_terminal_public_transcript(&frames, task)?;
    let encoded = serde_json::to_string(&terminal)
        .map_err(|_| A2AError::internal("failed to encode cancellation stream frame"))?;
    let sequence = i64::try_from(frames.len())
        .map_err(|_| A2AError::internal("cancellation stream sequence exhausted"))?;
    tx.execute(
        "INSERT INTO stream_frames(tenant_scope, message_id, frame_seq, frame_version,
             frame_kind, frame_json, frame_digest, created_at)
         VALUES (?1, ?2, ?3, 1, 'status_update', ?4, ?5, ?6)",
        params![
            tenant_scope,
            message_id,
            sequence,
            encoded,
            content_digest(encoded.as_bytes()),
            now
        ],
    )
    .map_err(|_| A2AError::internal("cancellation stream append failed"))?;
    let transcript = serde_json::to_vec(&frames)
        .map_err(|_| A2AError::internal("cancellation stream digest failed"))?;
    tx.execute(
        "UPDATE stream_transcripts SET state = 'terminal', frame_count = ?3,
             transcript_digest = ?4, terminal_seq = ?3, updated_at = ?5
         WHERE tenant_scope = ?1 AND message_id = ?2 AND state = 'open'",
        params![
            tenant_scope,
            message_id,
            sequence,
            content_digest(&transcript),
            now
        ],
    )
    .map_err(|_| A2AError::internal("cancellation stream completion failed"))?;
    Ok(())
}

fn load_receiver_frames(
    connection: &Connection,
    tenant_scope: &str,
    dispatch_id: &str,
    expected_count: i64,
    expected_transcript_digest: &str,
) -> Result<Vec<MeshEvent>, A2AError> {
    let mut statement = connection
        .prepare(
            "SELECT frame_seq, frame_version, frame_kind, frame_json, frame_digest
         FROM receiver_frames
         WHERE tenant_scope = ?1 AND dispatch_id = ?2 ORDER BY frame_seq",
        )
        .map_err(|_| A2AError::internal("receiver replay query failed"))?;
    let rows = statement
        .query_map(params![tenant_scope, dispatch_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|_| A2AError::internal("receiver replay query failed"))?;
    let mut events = Vec::new();
    for (index, row) in rows.enumerate() {
        let (sequence, version, kind, encoded, digest) =
            row.map_err(|_| A2AError::internal("receiver replay record is corrupt"))?;
        if sequence != i64::try_from(index + 1).unwrap_or(i64::MAX)
            || version != 1
            || kind != "mesh_event"
            || digest != content_digest(encoded.as_bytes())
            || encoded.len() > MAX_ATOMIC_JSON_BYTES
        {
            return Err(A2AError::internal("receiver replay transcript is corrupt"));
        }
        events.push(
            serde_json::from_str(&encoded)
                .map_err(|_| A2AError::internal("receiver replay frame is corrupt"))?,
        );
    }
    let transcript = serde_json::to_vec(&events)
        .map_err(|_| A2AError::internal("receiver replay transcript is corrupt"))?;
    if i64::try_from(events.len()).ok() != Some(expected_count)
        || content_digest(&transcript) != expected_transcript_digest
    {
        return Err(A2AError::internal("receiver replay transcript is corrupt"));
    }
    Ok(events)
}

fn encode_receiver_termination(
    termination: &DurableReceiverTermination,
) -> Result<(&'static str, Option<String>), A2AError> {
    let (kind, payload) = match termination {
        DurableReceiverTermination::Success => ("success", None),
        DurableReceiverTermination::InputRequired { .. } => (
            "input_required",
            Some(
                serde_json::to_string(termination)
                    .map_err(|_| A2AError::internal("failed to encode receiver termination"))?,
            ),
        ),
        DurableReceiverTermination::AuthRequired { .. } => (
            "auth_required",
            Some(
                serde_json::to_string(termination)
                    .map_err(|_| A2AError::internal("failed to encode receiver termination"))?,
            ),
        ),
    };
    if payload
        .as_ref()
        .is_some_and(|value| value.len() > MAX_ATOMIC_JSON_BYTES)
    {
        return Err(A2AError::invalid_params(
            "receiver termination exceeds limit",
        ));
    }
    Ok((kind, payload))
}

fn decode_receiver_termination(
    kind: Option<&str>,
    payload: Option<&str>,
) -> Result<DurableReceiverTermination, A2AError> {
    match (kind, payload) {
        (Some("success"), None) => Ok(DurableReceiverTermination::Success),
        (Some(expected @ ("input_required" | "auth_required")), Some(encoded))
            if encoded.len() <= MAX_ATOMIC_JSON_BYTES =>
        {
            let termination: DurableReceiverTermination = serde_json::from_str(encoded)
                .map_err(|_| A2AError::internal("receiver termination is corrupt"))?;
            let actual = match termination {
                DurableReceiverTermination::InputRequired { ref message }
                    if !message.is_empty() =>
                {
                    "input_required"
                }
                DurableReceiverTermination::AuthRequired { ref message } if !message.is_empty() => {
                    "auth_required"
                }
                _ => return Err(A2AError::internal("receiver termination is corrupt")),
            };
            if actual != expected {
                return Err(A2AError::internal("receiver termination is corrupt"));
            }
            Ok(termination)
        }
        _ => Err(A2AError::internal("receiver termination is corrupt")),
    }
}

fn validate_receiver_outcome(
    events: &[MeshEvent],
    termination: &DurableReceiverTermination,
) -> Result<(), A2AError> {
    match termination {
        DurableReceiverTermination::Success => validate_completed_receiver_transcript(events),
        DurableReceiverTermination::InputRequired { message }
        | DurableReceiverTermination::AuthRequired { message } => {
            if message.is_empty()
                || message.len() > MAX_ATOMIC_TEXT_BYTES
                || events
                    .iter()
                    .any(|event| matches!(event, MeshEvent::Completed { .. }))
            {
                return Err(A2AError::invalid_agent_response());
            }
            Ok(())
        }
    }
}

fn validate_completed_receiver_transcript(events: &[MeshEvent]) -> Result<(), A2AError> {
    let completed = events
        .iter()
        .filter(|event| matches!(event, MeshEvent::Completed { .. }))
        .count();
    if completed != 1 || !matches!(events.last(), Some(MeshEvent::Completed { .. })) {
        return Err(A2AError::invalid_agent_response());
    }
    Ok(())
}

fn public_stream_kind(frame: &StreamResponse) -> &'static str {
    match frame {
        StreamResponse::Task(_) => "task",
        StreamResponse::Message(_) => "message",
        StreamResponse::StatusUpdate(_) => "status_update",
        StreamResponse::ArtifactUpdate(_) => "artifact_update",
    }
}

fn is_dispatch_closed(state: &a2a::TaskState) -> bool {
    state.is_terminal()
        || matches!(
            state,
            a2a::TaskState::InputRequired | a2a::TaskState::AuthRequired
        )
}

fn validate_terminal_public_transcript(
    frames: &[StreamResponse],
    final_task: &Task,
) -> Result<(), A2AError> {
    if frames.is_empty() || frames.len() > MAX_STREAM_FRAMES {
        return Err(A2AError::invalid_agent_response());
    }
    let Some(StreamResponse::Task(initial)) = frames.first() else {
        return Err(A2AError::invalid_agent_response());
    };
    if is_dispatch_closed(&initial.status.state)
        || frames
            .iter()
            .filter(|frame| matches!(frame, StreamResponse::Task(_)))
            .count()
            != 1
    {
        return Err(A2AError::invalid_agent_response());
    }
    let mut reconstructed = initial.clone();
    let mut terminal_count = 0;
    for (index, frame) in frames.iter().enumerate().skip(1) {
        match frame {
            StreamResponse::Task(_) | StreamResponse::Message(_) => {
                return Err(A2AError::invalid_agent_response());
            }
            StreamResponse::StatusUpdate(update) => {
                if update.task_id != final_task.id || update.context_id != final_task.context_id {
                    return Err(A2AError::invalid_agent_response());
                }
                reconstructed.status = update.status.clone();
                if is_dispatch_closed(&update.status.state) {
                    terminal_count += 1;
                    if index + 1 != frames.len() {
                        return Err(A2AError::invalid_agent_response());
                    }
                }
            }
            StreamResponse::ArtifactUpdate(update) => {
                if update.task_id != final_task.id || update.context_id != final_task.context_id {
                    return Err(A2AError::invalid_agent_response());
                }
                reconstructed
                    .artifacts
                    .get_or_insert_with(Vec::new)
                    .push(update.artifact.clone());
            }
        }
    }
    if terminal_count != 1 || reconstructed != *final_task {
        return Err(A2AError::invalid_agent_response());
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn load_public_stream_frames(
    connection: &Connection,
    tenant_scope: &str,
    message_id: &str,
    expected_count: i64,
    expected_digest: Option<&str>,
    state: &str,
    interruption: Option<&str>,
) -> Result<Vec<StreamResponse>, A2AError> {
    if interruption.is_some_and(|value| value.len() > MAX_ATOMIC_TEXT_BYTES)
        || expected_count < 0
        || usize::try_from(expected_count).unwrap_or(usize::MAX) > MAX_STREAM_FRAMES
        || !matches!(state, "open" | "terminal" | "interrupted")
        || (state == "open"
            && (expected_count <= 0 || expected_digest.is_none() || interruption.is_some()))
        || (state == "terminal"
            && (expected_count == 0 || expected_digest.is_none() || interruption.is_some()))
        || (state == "interrupted" && (expected_digest.is_none() || interruption.is_none()))
    {
        return Err(A2AError::internal("public stream transcript is corrupt"));
    }
    let mut statement = connection
        .prepare(
            "SELECT frame_seq, frame_version, frame_kind, frame_json, frame_digest
             FROM stream_frames WHERE tenant_scope = ?1 AND message_id = ?2 ORDER BY frame_seq",
        )
        .map_err(|_| A2AError::internal("public stream replay query failed"))?;
    let rows = statement
        .query_map(params![tenant_scope, message_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|_| A2AError::internal("public stream replay query failed"))?;
    let mut frames = Vec::new();
    for (index, row) in rows.enumerate() {
        let (sequence, version, kind, encoded, digest) =
            row.map_err(|_| A2AError::internal("public stream frame is corrupt"))?;
        let frame: StreamResponse = serde_json::from_str(&encoded)
            .map_err(|_| A2AError::internal("public stream frame is corrupt"))?;
        if sequence != i64::try_from(index + 1).unwrap_or(i64::MAX)
            || version != STREAM_TRANSCRIPT_VERSION
            || kind != public_stream_kind(&frame)
            || digest != content_digest(encoded.as_bytes())
            || encoded.len() > MAX_ATOMIC_JSON_BYTES
        {
            return Err(A2AError::internal("public stream frame is corrupt"));
        }
        frames.push(frame);
    }
    if i64::try_from(frames.len()).ok() != Some(expected_count) {
        return Err(A2AError::internal("public stream transcript is corrupt"));
    }
    if let Some(expected_digest) = expected_digest {
        let encoded = serde_json::to_vec(&frames)
            .map_err(|_| A2AError::internal("public stream transcript is corrupt"))?;
        if encoded.len() > MAX_STORE_JSON_BYTES || content_digest(&encoded) != expected_digest {
            return Err(A2AError::internal("public stream transcript is corrupt"));
        }
    }
    if state == "terminal" {
        let encoded_result: String = connection
            .query_row(
                "SELECT identity.final_result_json
                 FROM stream_transcripts stream
                 JOIN idempotency_records identity
                   ON identity.tenant_scope = stream.tenant_scope
                  AND identity.message_id = stream.message_id
                 WHERE stream.tenant_scope = ?1 AND stream.message_id = ?2",
                params![tenant_scope, message_id],
                |row| row.get(0),
            )
            .map_err(|_| A2AError::internal("canonical stream result is corrupt"))?;
        let final_result: SendMessageResponse = serde_json::from_str(&encoded_result)
            .map_err(|_| A2AError::internal("canonical stream result is corrupt"))?;
        let SendMessageResponse::Task(final_task) = final_result else {
            return Err(A2AError::internal("canonical stream result is corrupt"));
        };
        validate_terminal_public_transcript(&frames, &final_task)
            .map_err(|_| A2AError::internal("public stream terminal transcript is corrupt"))?;
    } else if frames.iter().any(|frame| match frame {
        StreamResponse::Task(task) => is_dispatch_closed(&task.status.state),
        StreamResponse::StatusUpdate(update) => is_dispatch_closed(&update.status.state),
        StreamResponse::Message(_) | StreamResponse::ArtifactUpdate(_) => false,
    }) {
        return Err(A2AError::internal(
            "public stream interrupted transcript contains terminal frame",
        ));
    }
    Ok(frames)
}

fn receiver_request_is_valid(request: &MeshRequest, payload_bytes: usize) -> bool {
    payload_bytes <= MAX_ATOMIC_JSON_BYTES
        && !request.protocol.is_empty()
        && request.protocol.len() <= MAX_ATOMIC_TEXT_BYTES
        && !request.task_id.is_empty()
        && request.task_id.len() <= MAX_ATOMIC_TEXT_BYTES
        && !request.context_id.is_empty()
        && request.context_id.len() <= MAX_ATOMIC_TEXT_BYTES
        && request.text.len() <= MAX_ATOMIC_JSON_BYTES
}

fn response_matches_task(response: &SendMessageResponse, task_id: &str) -> bool {
    match response {
        SendMessageResponse::Task(task) => task.id == task_id,
        SendMessageResponse::Message(message) => message.task_id.as_deref() == Some(task_id),
    }
}

fn final_result_matches_task(response: &SendMessageResponse, task: &Task) -> bool {
    match response {
        SendMessageResponse::Task(result_task) => result_task == task,
        SendMessageResponse::Message(message) => {
            message.task_id.as_deref() == Some(task.id.as_str())
                && task.status.message.as_ref() == Some(message)
        }
    }
}

fn final_result_matches_persisted_event(
    connection: &Connection,
    tenant_scope: &str,
    task_id: &str,
    encoded_result: &str,
) -> Result<bool, SqliteStoreError> {
    let result: SendMessageResponse =
        serde_json::from_str(encoded_result).map_err(|_| SqliteStoreError::InvalidSchema)?;
    let mut statement = connection
        .prepare(
            "SELECT event_json FROM task_events
             WHERE tenant_scope = ?1 AND task_id = ?2 ORDER BY event_seq",
        )
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    let rows = statement
        .query_map(params![tenant_scope, task_id], |row| {
            row.get::<_, String>(0)
        })
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    for row in rows {
        let task: Task = serde_json::from_str(&row.map_err(|_| SqliteStoreError::InvalidSchema)?)
            .map_err(|_| SqliteStoreError::InvalidSchema)?;
        if final_result_matches_task(&result, &task) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn ensure_receiver_capacity(connection: &Connection) -> Result<(), A2AError> {
    let bytes: i64 = connection
        .query_row(
            "SELECT (SELECT COALESCE(SUM(length(CAST(tenant_scope AS BLOB)) +
             length(CAST(dispatch_id AS BLOB)) + length(CAST(payload_digest AS BLOB)) +
             length(CAST(payload_json AS BLOB)) + length(CAST(task_id AS BLOB)) +
             length(CAST(context_id AS BLOB)) + COALESCE(length(CAST(lease_owner AS BLOB)), 0) +
             COALESCE(length(CAST(lease_token AS BLOB)), 0) +
             COALESCE(length(CAST(transcript_digest AS BLOB)), 0) +
             COALESCE(length(CAST(termination_json AS BLOB)), 0)), 0) FROM receiver_inbox) +
         (SELECT COALESCE(SUM(length(CAST(frame_json AS BLOB)) +
             length(CAST(frame_digest AS BLOB))), 0) FROM receiver_frames) +
         (SELECT COALESCE(SUM(length(CAST(tenant_scope AS BLOB)) +
             length(CAST(dispatch_id AS BLOB)) + length(CAST(effect_kind AS BLOB))), 0)
             FROM loopback_effects)",
            [],
            |row| row.get(0),
        )
        .map_err(|_| A2AError::internal("receiver aggregate size query failed"))?;
    if usize::try_from(bytes).unwrap_or(usize::MAX) > MAX_STORE_JSON_BYTES {
        return Err(A2AError::internal("receiver store byte capacity reached"));
    }
    Ok(())
}

fn ensure_stream_capacity(connection: &Connection) -> Result<(), A2AError> {
    let bytes: i64 = connection
        .query_row(
            "SELECT (SELECT COALESCE(SUM(length(CAST(tenant_scope AS BLOB)) +
                 length(CAST(message_id AS BLOB)) + length(CAST(dispatch_id AS BLOB)) +
                 length(CAST(task_id AS BLOB)) + length(CAST(state AS BLOB)) +
                 COALESCE(length(CAST(transcript_digest AS BLOB)), 0) +
                 COALESCE(length(CAST(interruption_error AS BLOB)), 0)), 0)
                 FROM stream_transcripts) +
             (SELECT COALESCE(SUM(length(CAST(tenant_scope AS BLOB)) +
                 length(CAST(message_id AS BLOB)) + length(CAST(frame_kind AS BLOB)) +
                 length(CAST(frame_json AS BLOB)) + length(CAST(frame_digest AS BLOB))), 0)
                 FROM stream_frames)",
            [],
            |row| row.get(0),
        )
        .map_err(|_| A2AError::internal("stream aggregate size query failed"))?;
    if usize::try_from(bytes).unwrap_or(usize::MAX) > MAX_STORE_JSON_BYTES {
        return Err(A2AError::internal(
            "stream transcript byte capacity reached",
        ));
    }
    Ok(())
}

fn ensure_atomic_capacity(connection: &Connection) -> Result<(), A2AError> {
    for expression in [
        "SELECT COALESCE(SUM(length(CAST(task_id AS BLOB)) + length(CAST(context_id AS BLOB)) + length(CAST(state AS BLOB)) + COALESCE(length(CAST(status_timestamp AS BLOB)), 0) + length(CAST(task_json AS BLOB))), 0) FROM tasks",
        "SELECT COALESCE(SUM(length(CAST(tenant_scope AS BLOB)) + length(CAST(task_id AS BLOB)) + length(CAST(event_kind AS BLOB)) + COALESCE(length(CAST(from_state AS BLOB)), 0) + length(CAST(to_state AS BLOB)) + length(CAST(event_json AS BLOB))), 0) FROM task_events",
        "SELECT COALESCE(SUM(length(CAST(tenant_scope AS BLOB)) + length(CAST(message_id AS BLOB)) + length(CAST(request_digest AS BLOB)) + length(CAST(task_id AS BLOB)) + length(CAST(state AS BLOB)) + length(CAST(admission_result_json AS BLOB)) + COALESCE(length(CAST(final_result_json AS BLOB)), 0)), 0) FROM idempotency_records",
        "SELECT COALESCE(SUM(length(CAST(dispatch_id AS BLOB)) + length(CAST(tenant_scope AS BLOB)) + length(CAST(task_id AS BLOB)) + length(CAST(payload_json AS BLOB)) + length(CAST(payload_digest AS BLOB)) + length(CAST(state AS BLOB)) + COALESCE(length(CAST(lease_owner AS BLOB)), 0) + COALESCE(length(CAST(lease_token AS BLOB)), 0) + COALESCE(length(CAST(last_error AS BLOB)), 0)), 0) FROM outbox",
        "SELECT COALESCE(SUM(length(CAST(lease_token AS BLOB)) + COALESCE(length(CAST(outcome AS BLOB)), 0) + COALESCE(length(CAST(error AS BLOB)), 0)), 0) FROM outbox_attempts",
        "SELECT COALESCE(SUM(length(CAST(decision_id AS BLOB)) + length(CAST(tenant_scope AS BLOB)) + length(CAST(actor_account_id AS BLOB)) + length(CAST(policy_id AS BLOB)) + length(CAST(policy_digest AS BLOB)) + length(CAST(operation AS BLOB)) + length(CAST(reason AS BLOB)) + length(CAST(resource_kind AS BLOB)) + length(CAST(resource_digest AS BLOB)) + COALESCE(length(CAST(task_id AS BLOB)), 0)), 0) FROM authorization_decisions",
    ] {
        let bytes: i64 = connection
            .query_row(expression, [], |row| row.get(0))
            .map_err(|_| A2AError::internal("durable aggregate size query failed"))?;
        if usize::try_from(bytes).unwrap_or(usize::MAX) > MAX_STORE_JSON_BYTES {
            return Err(A2AError::internal("durable store byte capacity reached"));
        }
    }
    Ok(())
}

fn legal_transition(from: &a2a::TaskState, to: &a2a::TaskState) -> bool {
    use a2a::TaskState;
    if from == to {
        return true;
    }
    match from {
        TaskState::Unspecified => {
            matches!(
                to,
                TaskState::Submitted | TaskState::Failed | TaskState::Rejected
            )
        }
        TaskState::Submitted => matches!(
            to,
            TaskState::Working
                | TaskState::InputRequired
                | TaskState::AuthRequired
                | TaskState::Completed
                | TaskState::Failed
                | TaskState::Canceled
                | TaskState::Rejected
        ),
        TaskState::Working => matches!(
            to,
            TaskState::InputRequired
                | TaskState::AuthRequired
                | TaskState::Completed
                | TaskState::Failed
                | TaskState::Canceled
                | TaskState::Rejected
        ),
        TaskState::InputRequired | TaskState::AuthRequired => matches!(
            to,
            TaskState::Working | TaskState::Failed | TaskState::Canceled | TaskState::Rejected
        ),
        TaskState::Completed | TaskState::Failed | TaskState::Canceled | TaskState::Rejected => {
            false
        }
    }
}

#[allow(clippy::too_many_lines)] // Terminal task, replay, and stream interruption remain atomic.
fn dead_letter_task(
    transaction: &rusqlite::Transaction<'_>,
    task_id: &str,
    dispatch_id: &str,
    error: &str,
    now: i64,
) -> Result<(), A2AError> {
    let current: Option<(String, String, u64, String)> = transaction
        .query_row(
            "SELECT task_json, state, revision, tenant_scope FROM tasks WHERE task_id = ?1",
            [task_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|_| A2AError::internal("dead-letter task lookup failed"))?;
    let Some((encoded, from_state, revision, tenant_scope)) = current else {
        return Err(A2AError::task_not_found(task_id));
    };
    let mut task = decode_task(&encoded)?;
    if task.status.state.is_terminal() {
        return Ok(());
    }
    if !legal_transition(&task.status.state, &a2a::TaskState::Failed) {
        return Err(A2AError::unsupported_operation(
            "task state cannot transition to dead-letter failure",
        ));
    }
    task.status.state = a2a::TaskState::Failed;
    task.status.timestamp = chrono::DateTime::from_timestamp_millis(now);
    let mut message = Message::new(
        Role::Agent,
        vec![Part::text(format!(
            "Dispatch dead-lettered after bounded retries: {error}"
        ))],
    );
    message.task_id = Some(task.id.clone());
    message.context_id = Some(task.context_id.clone());
    task.status.message = Some(message);
    let task_json = encode_task(&task)?;
    let state = state_key(&task)?;
    let next_revision = revision
        .checked_add(1)
        .ok_or_else(|| A2AError::internal("persistent task revision exhausted"))?;
    transaction
        .execute(
            "UPDATE tasks SET state = ?2, status_timestamp = ?3, revision = ?4, task_json = ?5
             WHERE task_id = ?1 AND revision = ?6",
            params![
                task_id,
                state,
                task.status.timestamp.map(|value| value.to_rfc3339()),
                next_revision,
                task_json,
                revision
            ],
        )
        .map_err(|_| A2AError::internal("dead-letter task CAS failed"))?;
    let event_seq: i64 = transaction
        .query_row(
            "SELECT COALESCE(MAX(event_seq), 0) + 1 FROM task_events
             WHERE tenant_scope = ?1 AND task_id = ?2",
            params![tenant_scope, task_id],
            |row| row.get(0),
        )
        .map_err(|_| A2AError::internal("dead-letter event sequence failed"))?;
    transaction
        .execute(
            "INSERT INTO task_events(tenant_scope, task_id, event_seq, task_revision,
                 event_kind, from_state, to_state, event_json, created_at)
             VALUES (?1, ?2, ?3, ?4, 'dead_lettered', ?5, ?6, ?7, ?8)",
            params![
                tenant_scope,
                task_id,
                event_seq,
                next_revision,
                from_state,
                state,
                task_json,
                now
            ],
        )
        .map_err(|_| A2AError::internal("dead-letter event append failed"))?;
    let final_json = serde_json::to_string(&SendMessageResponse::Task(task))
        .map_err(|_| A2AError::internal("dead-letter result encoding failed"))?;
    transaction
        .execute(
            "UPDATE idempotency_records SET state = 'completed', final_result_json = ?2,
                 updated_at = ?3
             WHERE tenant_scope = ?1 AND task_id = ?4 AND state = 'in_progress'
               AND message_id = (SELECT message_id FROM outbox WHERE dispatch_id = ?5)",
            params![tenant_scope, final_json, now, task_id, dispatch_id],
        )
        .map_err(|_| A2AError::internal("dead-letter idempotency completion failed"))?;
    let diagnostic_limit = MAX_ATOMIC_TEXT_BYTES - STREAM_INTERRUPTION_PREFIX.len();
    let mut diagnostic_end = error.len().min(diagnostic_limit);
    while !error.is_char_boundary(diagnostic_end) {
        diagnostic_end -= 1;
    }
    let mut interruption = String::with_capacity(STREAM_INTERRUPTION_PREFIX.len() + diagnostic_end);
    interruption.push_str(STREAM_INTERRUPTION_PREFIX);
    interruption.push_str(&error[..diagnostic_end]);
    transaction
        .execute(
            "UPDATE stream_transcripts SET state = 'interrupted',
                 interruption_error = ?2, updated_at = ?3
             WHERE tenant_scope = ?1 AND task_id = ?4 AND dispatch_id = ?5 AND state = 'open'",
            params![tenant_scope, interruption, now, task_id, dispatch_id],
        )
        .map_err(|_| A2AError::internal("dead-letter stream interruption failed"))?;
    ensure_stream_capacity(transaction)?;
    Ok(())
}

#[allow(clippy::too_many_lines, clippy::type_complexity)]
fn open_database(
    path: &Path,
    max_tasks: usize,
    binding: Option<LegacyTenantBinding>,
    dev_new_only: bool,
) -> Result<(Connection, [u8; 32], [u8; 32], String, String), SqliteStoreError> {
    let mut connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| SqliteStoreError::Initialization)?;
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    if !matches!(
        version,
        0 | 1
            | V2_SCHEMA_VERSION
            | V3_SCHEMA_VERSION
            | V4_SCHEMA_VERSION
            | V5_SCHEMA_VERSION
            | SCHEMA_VERSION
    ) {
        return Err(SqliteStoreError::InvalidSchema);
    }
    let application_id: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    if version != 0 && application_id != APPLICATION_ID {
        return Err(SqliteStoreError::InvalidSchema);
    }
    if version == 0 {
        let user_tables: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| SqliteStoreError::InvalidSchema)?;
        if user_tables != 0 {
            return Err(SqliteStoreError::InvalidSchema);
        }
    }
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|_| SqliteStoreError::Initialization)?;
    connection
        .pragma_update(None, "trusted_schema", false)
        .map_err(|_| SqliteStoreError::Initialization)?;
    connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(|_| SqliteStoreError::Initialization)?;
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .map_err(|_| SqliteStoreError::Initialization)?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(|_| SqliteStoreError::Initialization)?;
    let integrity: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    if integrity != "ok" {
        return Err(SqliteStoreError::InvalidSchema);
    }
    let selected_binding = if version == 0 {
        binding.unwrap_or_else(LegacyTenantBinding::development)
    } else if version < SCHEMA_VERSION {
        if dev_new_only {
            return Err(SqliteStoreError::InvalidSchema);
        }
        binding.ok_or(SqliteStoreError::InvalidSchema)?
    } else {
        binding.unwrap_or_else(LegacyTenantBinding::development)
    };
    let (cursor_key, receipt_key) = match version {
        0 => initialize_schema(&mut connection, &selected_binding),
        1 => {
            migrate_v1_to_v2(&mut connection, max_tasks)?;
            migrate_v2_to_v3(&mut connection, max_tasks)?;
            migrate_v3_to_v4(&mut connection, max_tasks)?;
            migrate_v4_to_v5(&mut connection, max_tasks, &selected_binding)?;
            migrate_v5_to_v6(&mut connection)
        }
        V2_SCHEMA_VERSION => {
            migrate_v2_to_v3(&mut connection, max_tasks)?;
            migrate_v3_to_v4(&mut connection, max_tasks)?;
            migrate_v4_to_v5(&mut connection, max_tasks, &selected_binding)?;
            migrate_v5_to_v6(&mut connection)
        }
        V3_SCHEMA_VERSION => {
            migrate_v3_to_v4(&mut connection, max_tasks)?;
            migrate_v4_to_v5(&mut connection, max_tasks, &selected_binding)?;
            migrate_v5_to_v6(&mut connection)
        }
        V4_SCHEMA_VERSION => {
            migrate_v4_to_v5(&mut connection, max_tasks, &selected_binding)?;
            migrate_v5_to_v6(&mut connection)
        }
        V5_SCHEMA_VERSION => migrate_v5_to_v6(&mut connection),
        SCHEMA_VERSION => validate_schema(&connection),
        _ => Err(SqliteStoreError::InvalidSchema),
    }?;
    validate_foreign_keys(&connection)?;
    validate_snapshot_chains(&connection, None)?;
    validate_persisted_records(&connection, max_tasks)?;
    validate_atomic_records(&connection)?;
    validate_receiver_records(&connection)?;
    validate_stream_records(&connection)?;
    validate_cancellation_records(&connection)?;
    validate_tenant_authorization_records(&connection)?;
    recover_orphaned_tasks(&mut connection)?;
    let identity: (String, String) = connection
        .query_row(
            "SELECT tenant_scope, owner_account_id FROM store_identity WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    Ok((connection, cursor_key, receipt_key, identity.0, identity.1))
}

fn validate_foreign_keys(connection: &Connection) -> Result<(), SqliteStoreError> {
    let violations: i64 = connection
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    if violations == 0 {
        Ok(())
    } else {
        Err(SqliteStoreError::InvalidSchema)
    }
}

#[allow(clippy::too_many_lines)]
fn validate_snapshot_chains(
    connection: &Connection,
    only_snapshot: Option<&[u8]>,
) -> Result<(), SqliteStoreError> {
    let key: Vec<u8> = connection
        .query_row(
            "SELECT cursor_key FROM store_metadata WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    let cursor_key: [u8; 32] = key
        .try_into()
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    let now = chrono::Utc::now().timestamp_millis();
    let mut snapshots = connection.prepare(
        "SELECT snapshot_id,scope_digest,query_digest,total_size,page_size,issued_at,expires_at,
                projection_version,frozen_bytes,metadata_digest FROM list_snapshots
         WHERE ?1 IS NULL OR snapshot_id=?1",
    ).map_err(|_| SqliteStoreError::InvalidSchema)?;
    let rows = snapshots
        .query_map([only_snapshot], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, Vec<u8>>(9)?,
            ))
        })
        .map_err(|_| SqliteStoreError::InvalidSchema)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    drop(snapshots);

    for (
        id,
        scope,
        query,
        total,
        page_size,
        issued,
        expires,
        projection,
        frozen_bytes,
        stored_metadata,
    ) in rows
    {
        if id.len() != 32
            || scope.is_empty()
            || query.is_empty()
            || total <= page_size
            || !(1..=100).contains(&page_size)
            || issued < 0
            || issued > now
            || issued.checked_add(SNAPSHOT_TTL_MILLIS) != Some(expires)
            || projection != 1
            || frozen_bytes < 0
            || stored_metadata.len() != 32
        {
            return Err(SqliteStoreError::InvalidSchema);
        }
        let mut statement = connection
            .prepare(
                "SELECT ordinal,task_id,task_revision,task_digest,task_json
             FROM list_snapshot_entries WHERE snapshot_id=?1 ORDER BY ordinal",
            )
            .map_err(|_| SqliteStoreError::InvalidSchema)?;
        let entries = statement
            .query_map([&id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(|_| SqliteStoreError::InvalidSchema)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| SqliteStoreError::InvalidSchema)?;
        if i64::try_from(entries.len()).ok() != Some(total) {
            return Err(SqliteStoreError::InvalidSchema);
        }
        let mut bytes = 0_i64;
        let mut seals = Vec::with_capacity(entries.len());
        let mut previous: Option<Task> = None;
        for (expected_ordinal, (ordinal, task_id, revision, digest, encoded)) in
            entries.iter().enumerate()
        {
            if *ordinal != i64::try_from(expected_ordinal).unwrap_or(i64::MAX) || *revision <= 0 {
                return Err(SqliteStoreError::InvalidSchema);
            }
            let task = decode_task(encoded).map_err(|_| SqliteStoreError::InvalidSchema)?;
            if task.id != *task_id || *digest != content_digest(encoded.as_bytes()) {
                return Err(SqliteStoreError::InvalidSchema);
            }
            if let Some(left) = previous.as_ref() {
                let invalid = match (left.status.timestamp, task.status.timestamp) {
                    (None, Some(_)) => true,
                    (Some(left_time), Some(right_time)) => {
                        left_time < right_time || (left_time == right_time && left.id > task.id)
                    }
                    (None, None) => left.id > task.id,
                    (Some(_), None) => false,
                };
                if invalid {
                    return Err(SqliteStoreError::InvalidSchema);
                }
            }
            let revision_exists: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM task_events WHERE task_id=?1 AND task_revision=?2)",
                params![task_id, revision], |row| row.get(0),
            ).map_err(|_| SqliteStoreError::InvalidSchema)?;
            if !revision_exists {
                return Err(SqliteStoreError::InvalidSchema);
            }
            bytes = bytes
                .checked_add(
                    i64::try_from(encoded.len()).map_err(|_| SqliteStoreError::InvalidSchema)?,
                )
                .ok_or(SqliteStoreError::InvalidSchema)?;
            seals.push((*ordinal, task_id.clone(), *revision, digest.clone()));
            previous = Some(task);
        }
        if bytes != frozen_bytes {
            return Err(SqliteStoreError::InvalidSchema);
        }
        let expected_metadata = snapshot_metadata_digest(
            &cursor_key,
            &id,
            &scope,
            &query,
            total,
            page_size,
            issued,
            expires,
            projection,
            frozen_bytes,
            &seals,
        );
        if !bool::from(expected_metadata.ct_eq(stored_metadata.as_slice())) {
            return Err(SqliteStoreError::InvalidSchema);
        }
        let mut token_statement = connection.prepare(
            "SELECT next_position,token_hash,scope_digest,query_digest,token_version,key_generation,
                    issued_at,expires_at FROM list_page_tokens WHERE snapshot_id=?1 ORDER BY next_position",
        ).map_err(|_| SqliteStoreError::InvalidSchema)?;
        let tokens = token_statement
            .query_map([&id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            })
            .map_err(|_| SqliteStoreError::InvalidSchema)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| SqliteStoreError::InvalidSchema)?;
        let expected_count = usize::try_from((total - 1) / page_size)
            .map_err(|_| SqliteStoreError::InvalidSchema)?;
        if tokens.len() != expected_count {
            return Err(SqliteStoreError::InvalidSchema);
        }
        for (
            index,
            (
                position,
                stored_hash,
                token_scope,
                token_query,
                version,
                generation,
                token_issued,
                token_expires,
            ),
        ) in tokens.iter().enumerate()
        {
            let expected_position = i64::try_from(index + 1)
                .ok()
                .and_then(|step| step.checked_mul(page_size))
                .ok_or(SqliteStoreError::InvalidSchema)?;
            let (_, expected_hash) =
                derive_page_token(&cursor_key, &id, expected_position, &expected_metadata)
                    .map_err(|_| SqliteStoreError::InvalidSchema)?;
            if *position != expected_position
                || stored_hash.len() != 32
                || !bool::from(expected_hash.ct_eq(stored_hash.as_slice()))
                || token_scope != &scope
                || token_query != &query
                || *version != PAGE_TOKEN_VERSION
                || *generation != PAGE_TOKEN_KEY_GENERATION
                || *token_issued != issued
                || *token_expires != expires
            {
                return Err(SqliteStoreError::InvalidSchema);
            }
        }
    }
    Ok(())
}

fn validate_persisted_records(
    connection: &Connection,
    max_tasks: usize,
) -> Result<(), SqliteStoreError> {
    let (count, aggregate_bytes): (i64, i64) = connection
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(length(CAST(task_id AS BLOB)) + length(CAST(context_id AS BLOB)) + length(CAST(state AS BLOB)) + COALESCE(length(CAST(status_timestamp AS BLOB)), 0) + length(CAST(task_json AS BLOB))), 0) FROM tasks",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    if usize::try_from(count).unwrap_or(usize::MAX) > max_tasks
        || usize::try_from(aggregate_bytes).unwrap_or(usize::MAX) > MAX_STORE_JSON_BYTES
    {
        return Err(SqliteStoreError::Capacity);
    }
    let mut statement = connection
        .prepare(
            "SELECT task_id, context_id, state, status_timestamp, revision, task_json FROM tasks",
        )
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
            ))
        })
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    for row in rows {
        let (task_id, context_id, state, timestamp, revision, encoded) =
            row.map_err(|_| SqliteStoreError::InvalidSchema)?;
        if revision <= 0
            || (revision == i64::MAX
                && !matches!(
                    state.as_str(),
                    "\"TASK_STATE_COMPLETED\""
                        | "\"TASK_STATE_FAILED\""
                        | "\"TASK_STATE_CANCELED\""
                        | "\"TASK_STATE_REJECTED\""
                ))
            || !persisted_task_matches(
                &task_id,
                &context_id,
                &state,
                timestamp.as_deref(),
                &encoded,
            )
        {
            return Err(SqliteStoreError::InvalidSchema);
        }
    }
    Ok(())
}

fn validate_pre_v4_atomic_records(connection: &Connection) -> Result<(), SqliteStoreError> {
    let bytes: i64 = connection
        .query_row(
            "SELECT
                 (SELECT COALESCE(SUM(length(CAST(event_json AS BLOB))), 0) FROM task_events) +
                 (SELECT COALESCE(SUM(length(CAST(admission_result_json AS BLOB)) +
                     COALESCE(length(CAST(final_result_json AS BLOB)), 0)), 0)
                    FROM idempotency_records) +
                 (SELECT COALESCE(SUM(length(CAST(payload_json AS BLOB)) +
                     COALESCE(length(CAST(last_error AS BLOB)), 0)), 0) FROM outbox)",
            [],
            |row| row.get(0),
        )
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    if usize::try_from(bytes).unwrap_or(usize::MAX) > MAX_STORE_JSON_BYTES {
        return Err(SqliteStoreError::Capacity);
    }
    let mut events = connection
        .prepare(
            "SELECT tenant_scope, task_id, task_revision, event_kind, to_state, event_json
             FROM task_events",
        )
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    let rows = events
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    for row in rows {
        let (scope, task_id, revision, event_kind, state, encoded) =
            row.map_err(|_| SqliteStoreError::InvalidSchema)?;
        let task: Task =
            serde_json::from_str(&encoded).map_err(|_| SqliteStoreError::InvalidSchema)?;
        if !valid_bounded_identity(&scope)
            || revision <= 0
            || event_kind.is_empty()
            || event_kind.len() > MAX_ATOMIC_TEXT_BYTES
            || task.id != task_id
            || !state_key(&task).is_ok_and(|actual| actual == state)
            || encoded.len() > MAX_ATOMIC_JSON_BYTES
        {
            return Err(SqliteStoreError::InvalidSchema);
        }
    }
    drop(events);

    let invalid_json: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM idempotency_records
                 WHERE json_valid(admission_result_json) = 0
                    OR (final_result_json IS NOT NULL AND json_valid(final_result_json) = 0)
                    OR ((state = 'completed') != (final_result_json IS NOT NULL))
                 UNION ALL
                 SELECT 1 FROM outbox
                 WHERE json_valid(payload_json) = 0
                    OR attempt_count < 0 OR max_attempts <= 0
                    OR attempt_count > max_attempts)",
            [],
            |row| row.get(0),
        )
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    if invalid_json {
        return Err(SqliteStoreError::InvalidSchema);
    }
    let mut outbox = connection
        .prepare("SELECT tenant_scope, dispatch_id, payload_json, payload_digest FROM outbox")
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    let rows = outbox
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    for row in rows {
        let (scope, dispatch_id, payload, digest) =
            row.map_err(|_| SqliteStoreError::InvalidSchema)?;
        if !valid_bounded_identity(&scope)
            || dispatch_id.is_empty()
            || serde_json::from_str::<MeshRequest>(&payload).is_err()
            || digest != content_digest(payload.as_bytes())
            || payload.len() > MAX_ATOMIC_JSON_BYTES
        {
            return Err(SqliteStoreError::InvalidSchema);
        }
    }
    Ok(())
}

// Kept as one fail-closed validation pass so every cursor is dropped before startup recovery.
#[allow(clippy::too_many_lines)]
fn validate_atomic_records(connection: &Connection) -> Result<(), SqliteStoreError> {
    for expression in [
        "SELECT COALESCE(SUM(length(CAST(tenant_scope AS BLOB)) + length(CAST(task_id AS BLOB)) + length(CAST(event_kind AS BLOB)) + COALESCE(length(CAST(from_state AS BLOB)), 0) + length(CAST(to_state AS BLOB)) + length(CAST(event_json AS BLOB))), 0) FROM task_events",
        "SELECT COALESCE(SUM(length(CAST(tenant_scope AS BLOB)) + length(CAST(message_id AS BLOB)) + length(CAST(request_digest AS BLOB)) + length(CAST(task_id AS BLOB)) + length(CAST(state AS BLOB)) + length(CAST(admission_result_json AS BLOB)) + COALESCE(length(CAST(final_result_json AS BLOB)), 0)), 0) FROM idempotency_records",
        "SELECT COALESCE(SUM(length(CAST(dispatch_id AS BLOB)) + length(CAST(tenant_scope AS BLOB)) + length(CAST(task_id AS BLOB)) + length(CAST(payload_json AS BLOB)) + length(CAST(payload_digest AS BLOB)) + length(CAST(state AS BLOB)) + COALESCE(length(CAST(lease_owner AS BLOB)), 0) + COALESCE(length(CAST(lease_token AS BLOB)), 0) + COALESCE(length(CAST(last_error AS BLOB)), 0)), 0) FROM outbox",
        "SELECT COALESCE(SUM(length(CAST(lease_token AS BLOB)) + COALESCE(length(CAST(outcome AS BLOB)), 0) + COALESCE(length(CAST(error AS BLOB)), 0)), 0) FROM outbox_attempts",
        "SELECT COALESCE(SUM(length(CAST(decision_id AS BLOB)) + length(CAST(tenant_scope AS BLOB)) + length(CAST(actor_account_id AS BLOB)) + length(CAST(policy_id AS BLOB)) + length(CAST(policy_digest AS BLOB)) + length(CAST(operation AS BLOB)) + length(CAST(reason AS BLOB)) + length(CAST(resource_kind AS BLOB)) + length(CAST(resource_digest AS BLOB)) + COALESCE(length(CAST(task_id AS BLOB)), 0)), 0) FROM authorization_decisions",
    ] {
        let bytes: i64 = connection
            .query_row(expression, [], |row| row.get(0))
            .map_err(|_| SqliteStoreError::InvalidSchema)?;
        if usize::try_from(bytes).unwrap_or(usize::MAX) > MAX_STORE_JSON_BYTES {
            return Err(SqliteStoreError::Capacity);
        }
    }

    let mut events = connection
        .prepare(
            "SELECT tenant_scope, task_id, task_revision, event_kind, from_state, to_state, event_json
             FROM task_events",
        )
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    let rows = events
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    for row in rows {
        let (scope, task_id, revision, event_kind, from_state, to_state, event_json) =
            row.map_err(|_| SqliteStoreError::InvalidSchema)?;
        let event_task: Task =
            serde_json::from_str(&event_json).map_err(|_| SqliteStoreError::InvalidSchema)?;
        let from_state = from_state
            .as_deref()
            .map(serde_json::from_str::<a2a::TaskState>)
            .transpose()
            .map_err(|_| SqliteStoreError::InvalidSchema)?;
        if !valid_bounded_identity(&scope)
            || task_id != event_task.id
            || revision <= 0
            || event_kind.is_empty()
            || event_kind.len() > MAX_ATOMIC_TEXT_BYTES
            || event_json.len() > MAX_ATOMIC_JSON_BYTES
            || !state_key(&event_task).is_ok_and(|state| state == to_state)
            || from_state
                .as_ref()
                .is_some_and(|from| !legal_transition(from, &event_task.status.state))
        {
            return Err(SqliteStoreError::InvalidSchema);
        }
    }

    let mut records = connection
        .prepare(
            "SELECT tenant_scope, message_id, request_digest, task_id, state,
                    admission_result_json, final_result_json, digest_version,
                    actor_account_id, causative_request_json, invocation_kind
             FROM idempotency_records",
        )
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    let rows = records
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, Option<String>>(10)?,
            ))
        })
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    for row in rows {
        let (
            scope,
            message_id,
            digest,
            task_id,
            record_state,
            admission,
            final_result,
            digest_version,
            actor_account_id,
            causative_request_json,
            invocation_kind,
        ) = row.map_err(|_| SqliteStoreError::InvalidSchema)?;
        let digest_valid = match digest_version {
            1 => {
                actor_account_id.is_none()
                    && causative_request_json.is_none()
                    && invocation_kind.is_none()
            }
            2 => {
                let actor = actor_account_id
                    .as_deref()
                    .ok_or(SqliteStoreError::InvalidSchema)?;
                let request: SendMessageRequest = serde_json::from_str(
                    causative_request_json
                        .as_deref()
                        .ok_or(SqliteStoreError::InvalidSchema)?,
                )
                .map_err(|_| SqliteStoreError::InvalidSchema)?;
                let streaming = match invocation_kind.as_deref() {
                    Some("unary") => false,
                    Some("streaming") => true,
                    _ => return Err(SqliteStoreError::InvalidSchema),
                };
                canonical_send_message_digest_v2(&scope, actor, &request, streaming)
                    .is_ok_and(|expected| expected == digest)
                    && authorized_message_identity(&scope, actor, &request.message.message_id)
                        == message_id
            }
            _ => false,
        };
        let dispatch_version: i64 = connection
            .query_row(
                "SELECT dispatch_identity_version FROM outbox
                 WHERE tenant_scope=?1 AND message_id=?2 AND task_id=?3",
                params![scope, message_id, task_id],
                |row| row.get(0),
            )
            .map_err(|_| SqliteStoreError::InvalidSchema)?;
        let response_matches = |encoded: &str| {
            serde_json::from_str::<SendMessageResponse>(encoded).is_ok_and(
                |response| match response {
                    SendMessageResponse::Task(task) => task.id == task_id,
                    SendMessageResponse::Message(message) => {
                        message.task_id.as_deref().is_none_or(|id| id == task_id)
                    }
                },
            )
        };
        let valid_final = final_result.as_ref().is_none_or(|result| {
            result.len() <= MAX_ATOMIC_JSON_BYTES
                && final_result_matches_persisted_event(connection, &scope, &task_id, result)
                    .unwrap_or(false)
        });
        if !valid_bounded_identity(&scope)
            || message_id.is_empty()
            || message_id.len() > 4096
            || digest.is_empty()
            || digest.len() > 256
            || !digest_valid
            || dispatch_version != digest_version
            || !matches!(record_state.as_str(), "in_progress" | "completed")
            || (record_state == "completed") != final_result.is_some()
            || admission.len() > MAX_ATOMIC_JSON_BYTES
            || !response_matches(&admission)
            || !valid_final
        {
            return Err(SqliteStoreError::InvalidSchema);
        }
    }

    let mut outbox = connection
        .prepare(
            "SELECT o.tenant_scope, o.task_id, o.dispatch_id, o.message_id,
                    o.causative_revision, o.payload_json, o.payload_digest,
                    o.attempt_count, o.max_attempts, o.last_error, t.context_id, o.lease_owner,
                    t.owner_account_id, o.dispatch_identity_version
             FROM outbox o JOIN tasks t ON t.task_id = o.task_id",
        )
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    let rows = outbox
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, Option<String>>(11)?,
                row.get::<_, String>(12)?,
                row.get::<_, i64>(13)?,
            ))
        })
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    for row in rows {
        let (
            scope,
            task_id,
            dispatch_id,
            message_id,
            causative_revision,
            payload,
            digest,
            attempts,
            max_attempts,
            error,
            context_id,
            lease_owner,
            owner_account_id,
            dispatch_identity_version,
        ) = row.map_err(|_| SqliteStoreError::InvalidSchema)?;
        let request: MeshRequest =
            serde_json::from_str(&payload).map_err(|_| SqliteStoreError::InvalidSchema)?;
        let causative_task_json: String = connection
            .query_row(
                "SELECT event_json FROM task_events
                 WHERE tenant_scope = ?1 AND task_id = ?2 AND task_revision = ?3",
                params![scope, task_id, causative_revision],
                |row| row.get(0),
            )
            .map_err(|_| SqliteStoreError::InvalidSchema)?;
        let causative_task: Task = serde_json::from_str(&causative_task_json)
            .map_err(|_| SqliteStoreError::InvalidSchema)?;
        let causative_message = causative_task
            .history
            .as_ref()
            .and_then(|history| history.last())
            .ok_or(SqliteStoreError::InvalidSchema)?;
        let expected_message_id = if dispatch_identity_version == 2 {
            authorized_message_identity(&scope, &owner_account_id, &causative_message.message_id)
        } else {
            causative_message.message_id.clone()
        };
        let dispatch_identity_matches = if dispatch_identity_version == 2 {
            dispatch_id == content_digest(format!("{scope}\0send-message\0{message_id}").as_bytes())
        } else if dispatch_identity_version == 1 {
            [LEGACY_V4_SENTINEL_SCOPE, TRUSTED_SINGLE_TENANT_SCOPE]
                .into_iter()
                .any(|legacy_scope| {
                    dispatch_id
                        == content_digest(
                            format!("{legacy_scope}\0send-message\0{message_id}").as_bytes(),
                        )
                })
        } else {
            false
        };
        let canonical_request = MeshRequest::from_a2a(
            task_id.clone(),
            context_id.clone(),
            causative_message,
            InputLimits {
                max_text_bytes: usize::MAX,
            },
        )
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
        let identity_matches: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM idempotency_records WHERE tenant_scope = ?1
                 AND message_id = ?2 AND task_id = ?3)",
                params![scope, message_id, task_id],
                |row| row.get(0),
            )
            .map_err(|_| SqliteStoreError::InvalidSchema)?;
        if !valid_bounded_identity(&scope)
            || task_id != request.task_id
            || context_id != request.context_id
            || request != canonical_request
            || message_id != expected_message_id
            || message_id.is_empty()
            || message_id.len() > MAX_ATOMIC_TEXT_BYTES
            || !dispatch_identity_matches
            || !identity_matches
            || dispatch_id.is_empty()
            || digest != content_digest(payload.as_bytes())
            || payload.len() > MAX_ATOMIC_JSON_BYTES
            || attempts < 0
            || max_attempts <= 0
            || max_attempts > i64::from(MAX_OUTBOX_ATTEMPTS)
            || attempts > max_attempts
            || error
                .as_ref()
                .is_some_and(|value| value.len() > MAX_ATOMIC_TEXT_BYTES)
            || lease_owner
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > MAX_ATOMIC_TEXT_BYTES)
        {
            return Err(SqliteStoreError::InvalidSchema);
        }
    }

    let invalid_semantics: bool = connection
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM tasks t
                 WHERE NOT EXISTS (SELECT 1 FROM task_events e WHERE e.task_id = t.task_id)
                    OR (SELECT e.task_revision FROM task_events e WHERE e.task_id = t.task_id
                        ORDER BY e.event_seq DESC LIMIT 1) != t.revision
                    OR (SELECT e.event_json FROM task_events e WHERE e.task_id = t.task_id
                        ORDER BY e.event_seq DESC LIMIT 1) != t.task_json
                 UNION ALL
                 SELECT 1 FROM task_events e
                 WHERE e.event_seq != (
                     SELECT COUNT(*) FROM task_events prior
                     WHERE prior.tenant_scope = e.tenant_scope AND prior.task_id = e.task_id
                       AND prior.event_seq <= e.event_seq)
                    OR e.task_revision <= 0
                    OR (e.event_seq = 1 AND e.from_state IS NOT NULL)
                    OR (e.event_seq > 1 AND e.from_state != (
                        SELECT prior.to_state FROM task_events prior
                        WHERE prior.tenant_scope = e.tenant_scope AND prior.task_id = e.task_id
                          AND prior.event_seq = e.event_seq - 1))
                    OR (e.event_seq > 1 AND e.task_revision != (
                        SELECT prior.task_revision + 1 FROM task_events prior
                        WHERE prior.tenant_scope = e.tenant_scope AND prior.task_id = e.task_id
                          AND prior.event_seq = e.event_seq - 1))
                 UNION ALL
                 SELECT 1 FROM outbox o JOIN tasks t ON t.task_id = o.task_id
                 WHERE o.causative_revision > t.revision
                    OR NOT EXISTS (SELECT 1 FROM task_events e
                        WHERE e.tenant_scope = o.tenant_scope AND e.task_id = o.task_id
                          AND e.task_revision = o.causative_revision)
                    OR o.created_at > o.updated_at
                    OR ((o.state = 'leased') !=
                        (o.lease_owner IS NOT NULL AND o.lease_token IS NOT NULL AND o.lease_until IS NOT NULL))
                    OR (o.state != 'leased' AND
                        (o.lease_owner IS NOT NULL OR o.lease_token IS NOT NULL OR o.lease_until IS NOT NULL))
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    let invalid_attempts: bool = connection
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM outbox_attempts a JOIN outbox o ON o.outbox_id = a.outbox_id
                 WHERE a.attempt_no > o.attempt_count
                    OR a.attempt_no != (SELECT COUNT(*) FROM outbox_attempts prior
                        WHERE prior.outbox_id = a.outbox_id AND prior.attempt_no <= a.attempt_no)
                    OR a.started_at > COALESCE(a.finished_at, a.started_at)
                    OR ((a.finished_at IS NULL) != (a.outcome IS NULL))
                    OR (a.finished_at IS NULL AND
                        (o.state != 'leased' OR a.attempt_no != o.attempt_count
                         OR a.lease_token != o.lease_token))
                    OR length(CAST(COALESCE(a.error, '') AS BLOB)) > 4096
                 UNION ALL
                 SELECT 1 FROM outbox o
                 WHERE o.attempt_count != (SELECT COUNT(*) FROM outbox_attempts a
                     WHERE a.outbox_id = o.outbox_id)
                    OR ((o.state = 'leased') != (SELECT COUNT(*) = 1 FROM outbox_attempts a
                        WHERE a.outbox_id = o.outbox_id AND a.finished_at IS NULL))
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    if invalid_semantics || invalid_attempts {
        return Err(SqliteStoreError::InvalidSchema);
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // One fail-closed pass validates cross-table receiver invariants.
fn validate_receiver_records(connection: &Connection) -> Result<(), SqliteStoreError> {
    let bytes: i64 = connection
        .query_row(
            "SELECT (SELECT COALESCE(SUM(length(CAST(tenant_scope AS BLOB)) +
             length(CAST(dispatch_id AS BLOB)) + length(CAST(payload_digest AS BLOB)) +
             length(CAST(payload_json AS BLOB)) + length(CAST(task_id AS BLOB)) +
             length(CAST(context_id AS BLOB)) + COALESCE(length(CAST(lease_owner AS BLOB)), 0) +
             COALESCE(length(CAST(lease_token AS BLOB)), 0) +
             COALESCE(length(CAST(transcript_digest AS BLOB)), 0) +
             COALESCE(length(CAST(termination_json AS BLOB)), 0)), 0) FROM receiver_inbox) +
         (SELECT COALESCE(SUM(length(CAST(frame_json AS BLOB)) +
             length(CAST(frame_digest AS BLOB))), 0) FROM receiver_frames) +
         (SELECT COALESCE(SUM(length(CAST(tenant_scope AS BLOB)) +
             length(CAST(dispatch_id AS BLOB)) + length(CAST(effect_kind AS BLOB))), 0)
             FROM loopback_effects)",
            [],
            |row| row.get(0),
        )
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    if usize::try_from(bytes).unwrap_or(usize::MAX) > MAX_STORE_JSON_BYTES {
        return Err(SqliteStoreError::Capacity);
    }
    let mut statement = connection
        .prepare(
            "SELECT tenant_scope, dispatch_id, payload_digest, payload_json, task_id, context_id,
                state, lease_epoch, lease_owner, lease_token, lease_until, frame_count,
                transcript_digest, completion_kind, termination_json FROM receiver_inbox",
        )
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, Option<i64>>(10)?,
                row.get::<_, Option<i64>>(11)?,
                row.get::<_, Option<String>>(12)?,
                row.get::<_, Option<String>>(13)?,
                row.get::<_, Option<String>>(14)?,
            ))
        })
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    for row in rows {
        let (
            scope,
            dispatch_id,
            digest,
            payload,
            task_id,
            context_id,
            state,
            epoch,
            owner,
            token,
            lease_until,
            frame_count,
            transcript_digest,
            completion_kind,
            termination_json,
        ) = row.map_err(|_| SqliteStoreError::InvalidSchema)?;
        let request: MeshRequest =
            serde_json::from_str(&payload).map_err(|_| SqliteStoreError::InvalidSchema)?;
        if !valid_bounded_identity(&scope)
            || dispatch_id.is_empty()
            || dispatch_id.len() > 256
            || !receiver_request_is_valid(&request, payload.len())
            || digest != content_digest(payload.as_bytes())
            || request.task_id != task_id
            || request.context_id != context_id
            || epoch <= 0
            || owner
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > MAX_ATOMIC_TEXT_BYTES)
            || token
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 256)
            || (state == "processing")
                != (owner.is_some() && token.is_some() && lease_until.is_some())
        {
            return Err(SqliteStoreError::InvalidSchema);
        }
        if state == "completed" {
            let expected_count = frame_count.ok_or(SqliteStoreError::InvalidSchema)?;
            let expected_digest = transcript_digest
                .as_deref()
                .ok_or(SqliteStoreError::InvalidSchema)?;
            let events = load_receiver_frames(
                connection,
                &scope,
                &dispatch_id,
                expected_count,
                expected_digest,
            )
            .map_err(|_| SqliteStoreError::InvalidSchema)?;
            let termination = decode_receiver_termination(
                completion_kind.as_deref(),
                termination_json.as_deref(),
            )
            .map_err(|_| SqliteStoreError::InvalidSchema)?;
            validate_receiver_outcome(&events, &termination)
                .map_err(|_| SqliteStoreError::InvalidSchema)?;
        } else if completion_kind.is_some() || termination_json.is_some() {
            return Err(SqliteStoreError::InvalidSchema);
        }
    }
    let invalid_effects: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM loopback_effects effect
             LEFT JOIN receiver_inbox inbox
               ON inbox.tenant_scope = effect.tenant_scope
              AND inbox.dispatch_id = effect.dispatch_id
             WHERE effect.effect_kind != 'accepted'
                OR inbox.dispatch_id IS NULL OR inbox.state != 'completed')",
            [],
            |row| row.get(0),
        )
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    if invalid_effects {
        return Err(SqliteStoreError::InvalidSchema);
    }
    Ok(())
}

#[allow(clippy::too_many_lines, clippy::type_complexity)]
fn validate_stream_records(connection: &Connection) -> Result<(), SqliteStoreError> {
    ensure_stream_capacity(connection).map_err(|error| {
        if error.to_string().contains("capacity") {
            SqliteStoreError::Capacity
        } else {
            SqliteStoreError::InvalidSchema
        }
    })?;
    let mut statement = connection
        .prepare(
            "SELECT stream.tenant_scope, stream.message_id, stream.dispatch_id, stream.task_id,
                    stream.transcript_version, stream.state, stream.frame_count,
                    stream.transcript_digest, stream.terminal_seq, stream.interruption_error,
                    identity.state, identity.task_id, outbox.state, outbox.task_id
             FROM stream_transcripts stream
             LEFT JOIN idempotency_records identity
               ON identity.tenant_scope = stream.tenant_scope
              AND identity.message_id = stream.message_id
             LEFT JOIN outbox ON outbox.dispatch_id = stream.dispatch_id",
        )
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<i64>>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, Option<String>>(10)?,
                row.get::<_, Option<String>>(11)?,
                row.get::<_, Option<String>>(12)?,
                row.get::<_, Option<String>>(13)?,
            ))
        })
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    for row in rows {
        let (
            scope,
            message_id,
            dispatch_id,
            task_id,
            version,
            state,
            frame_count,
            digest,
            terminal_seq,
            interruption,
            identity_state,
            identity_task,
            outbox_state,
            outbox_task,
        ) = row.map_err(|_| SqliteStoreError::InvalidSchema)?;
        if !valid_bounded_identity(&scope)
            || message_id.is_empty()
            || message_id.len() > MAX_ATOMIC_TEXT_BYTES
            || dispatch_id.is_empty()
            || dispatch_id.len() > 256
            || task_id.is_empty()
            || version != STREAM_TRANSCRIPT_VERSION
            || identity_task.as_deref() != Some(task_id.as_str())
            || outbox_task.as_deref() != Some(task_id.as_str())
            || (state == "open"
                && (identity_state.as_deref() != Some("in_progress")
                    || !matches!(outbox_state.as_deref(), Some("pending" | "leased"))))
            || (state == "terminal"
                && (identity_state.as_deref() != Some("completed")
                    || !matches!(outbox_state.as_deref(), Some("delivered" | "superseded"))))
            || (state == "interrupted"
                && (identity_state.as_deref() != Some("completed")
                    || !matches!(outbox_state.as_deref(), Some("dead" | "superseded"))))
            || (state == "terminal" && terminal_seq != Some(frame_count))
            || (state != "terminal" && terminal_seq.is_some())
        {
            return Err(SqliteStoreError::InvalidSchema);
        }
        load_public_stream_frames(
            connection,
            &scope,
            &message_id,
            frame_count,
            digest.as_deref(),
            &state,
            interruption.as_deref(),
        )
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    }
    Ok(())
}

fn validate_cancellation_records(connection: &Connection) -> Result<(), SqliteStoreError> {
    let (count, bytes, invalid): (i64, i64, i64) = connection
        .query_row(
            "SELECT COUNT(*),
                    COALESCE(SUM(length(CAST(cancel.tenant_scope AS BLOB))
                       + length(CAST(cancel.dispatch_id AS BLOB))
                       + length(CAST(cancel.task_id AS BLOB))
                       + length(CAST(cancel.state AS BLOB))), 0),
                    COALESCE(SUM(CASE
                      WHEN cancel.tenant_scope != task.tenant_scope OR cancel.task_id != outbox.task_id
                        OR receiver.dispatch_id IS NULL
                        OR (cancel.state = 'requested' AND (
                            receiver.state != 'processing'
                            OR task.state IN ('\"TASK_STATE_COMPLETED\"', '\"TASK_STATE_FAILED\"',
                                              '\"TASK_STATE_CANCELED\"', '\"TASK_STATE_REJECTED\"')
                            OR outbox.state NOT IN ('pending', 'leased')))
                        OR (cancel.state = 'receiver_canceled' AND (
                            receiver.state != 'completed'
                            OR outbox.state NOT IN ('leased', 'delivered'))) THEN 1 ELSE 0 END), 0)
             FROM cancellation_intents cancel
             JOIN outbox ON outbox.dispatch_id = cancel.dispatch_id
             JOIN tasks task ON task.task_id = cancel.task_id
             LEFT JOIN receiver_inbox receiver ON receiver.tenant_scope = cancel.tenant_scope
               AND receiver.dispatch_id = cancel.dispatch_id",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    if count < 0
        || invalid != 0
        || usize::try_from(bytes).unwrap_or(usize::MAX) > MAX_STORE_JSON_BYTES
    {
        return Err(SqliteStoreError::InvalidSchema);
    }
    Ok(())
}

fn validate_tenant_authorization_records(connection: &Connection) -> Result<(), SqliteStoreError> {
    let invalid: bool = connection.query_row(
        "SELECT EXISTS(
          SELECT 1 FROM task_events c JOIN tasks t ON t.task_id=c.task_id WHERE c.tenant_scope!=t.tenant_scope
          UNION ALL SELECT 1 FROM idempotency_records c JOIN tasks t ON t.task_id=c.task_id WHERE c.tenant_scope!=t.tenant_scope
          UNION ALL SELECT 1 FROM outbox c JOIN tasks t ON t.task_id=c.task_id WHERE c.tenant_scope!=t.tenant_scope
          UNION ALL SELECT 1 FROM stream_transcripts c JOIN tasks t ON t.task_id=c.task_id WHERE c.tenant_scope!=t.tenant_scope
          UNION ALL SELECT 1 FROM cancellation_intents c JOIN tasks t ON t.task_id=c.task_id WHERE c.tenant_scope!=t.tenant_scope
          UNION ALL SELECT 1 FROM receiver_inbox c JOIN outbox o ON o.dispatch_id=c.dispatch_id WHERE c.tenant_scope!=o.tenant_scope
          UNION ALL SELECT 1 FROM authorization_decisions a JOIN tasks t ON t.task_id=a.task_id
            WHERE a.task_id IS NOT NULL AND a.tenant_scope!=t.tenant_scope
          UNION ALL SELECT 1 FROM tasks WHERE length(CAST(tenant_scope AS BLOB)) NOT BETWEEN 1 AND 64
            OR length(CAST(owner_account_id AS BLOB)) NOT BETWEEN 1 AND 64)",
        [], |row| row.get(0),
    ).map_err(|_| SqliteStoreError::InvalidSchema)?;
    ensure_authorization_capacity(connection).map_err(|error| {
        if error.message.contains("capacity") {
            SqliteStoreError::Capacity
        } else {
            SqliteStoreError::InvalidSchema
        }
    })?;
    if invalid {
        Err(SqliteStoreError::InvalidSchema)
    } else {
        Ok(())
    }
}

fn initialize_schema(
    connection: &mut Connection,
    binding: &LegacyTenantBinding,
) -> Result<([u8; 32], [u8; 32]), SqliteStoreError> {
    let user_tables: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    if user_tables != 0 {
        return Err(SqliteStoreError::InvalidSchema);
    }
    let cursor_key: [u8; 32] = rand::random();
    let receipt_key: [u8; 32] = rand::random();
    let migration_hash = schema_v6_hash();
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .execute_batch(V2_SCHEMA_SQL)
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .execute_batch(RECEIVER_SCHEMA_SQL)
        .map_err(|_| SqliteStoreError::Initialization)?;
    rebuild_outbox_with_message_ids(&transaction)?;
    transaction
        .execute_batch(OUTBOX_MESSAGE_IMMUTABILITY_SQL)
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .execute_batch(CANCELLATION_SCHEMA_SQL)
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .execute_batch("ALTER TABLE tasks ADD COLUMN tenant_scope TEXT NOT NULL DEFAULT 'smesh-dev-only-tenant';
                        ALTER TABLE tasks ADD COLUMN owner_account_id TEXT NOT NULL DEFAULT 'smesh-dev-only-account';
                        ALTER TABLE idempotency_records ADD COLUMN digest_version INTEGER NOT NULL DEFAULT 2 CHECK(digest_version IN (1,2));
                        ALTER TABLE idempotency_records ADD COLUMN actor_account_id TEXT;
                        ALTER TABLE idempotency_records ADD COLUMN causative_request_json TEXT;
                        ALTER TABLE idempotency_records ADD COLUMN invocation_kind TEXT CHECK(invocation_kind IN ('unary','streaming'));
                        ALTER TABLE outbox ADD COLUMN dispatch_identity_version INTEGER NOT NULL DEFAULT 2 CHECK(dispatch_identity_version IN (1,2));")
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .execute(
            "UPDATE tasks SET tenant_scope = ?1, owner_account_id = ?2",
            params![binding.tenant_scope, binding.owner_account_id],
        )
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .execute_batch(V5_SCHEMA_SQL)
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .execute_batch(V6_SCHEMA_SQL)
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction.execute(
        "INSERT INTO store_identity(singleton, tenant_scope, owner_account_id, policy_id, policy_revision, policy_digest)
         VALUES(1, ?1, ?2, ?3, ?4, ?5)",
        params![binding.tenant_scope, binding.owner_account_id, binding.policy_id, binding.policy_revision, binding.policy_digest],
    ).map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .execute(
            "INSERT INTO store_metadata(
                 singleton, schema_version, migration_hash, cursor_key, receipt_key
             ) VALUES (1, ?1, ?2, ?3, ?4)",
            params![
                SCHEMA_VERSION,
                migration_hash,
                cursor_key.as_slice(),
                receipt_key.as_slice()
            ],
        )
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .pragma_update(None, "user_version", SCHEMA_VERSION)
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .pragma_update(None, "application_id", APPLICATION_ID)
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .commit()
        .map_err(|_| SqliteStoreError::Initialization)?;
    validate_schema(connection)
}

fn normalize_schema_sql(sql: &str) -> String {
    sql.chars()
        .filter(|character| !character.is_whitespace() && *character != ';')
        .flat_map(char::to_lowercase)
        .collect()
}

fn expected_schema_sql(schema: &str, object_name: &str) -> Option<String> {
    let trigger_marker = format!("CREATE TRIGGER {object_name} ");
    if let Some(start) = schema.find(&trigger_marker) {
        let rest = &schema[start..];
        let end = rest.find(" END;")? + " END".len();
        return Some(normalize_schema_sql(&rest[..end]));
    }
    schema.split(';').find_map(|statement| {
        let normalized = normalize_schema_sql(statement);
        let table_prefix = format!("createtable{object_name}(");
        let index_prefix = format!("createindex{object_name}on");
        let unique_index_prefix = format!("createuniqueindex{object_name}on");
        (normalized.starts_with(&table_prefix)
            || normalized.starts_with(&index_prefix)
            || normalized.starts_with(&unique_index_prefix))
        .then_some(normalized)
    })
}

const V1_OBJECTS: &[&str] = &["store_metadata", "tasks", "tasks_context_state_time"];
const V2_OBJECTS: &[&str] = &[
    "store_metadata",
    "tasks",
    "tasks_context_state_time",
    "task_events",
    "task_events_task_revision",
    "idempotency_records",
    "idempotency_records_task",
    "outbox",
    "outbox_due",
    "outbox_task_state",
    "outbox_attempts",
];

const V4_OBJECTS: &[&str] = &[
    "store_metadata",
    "tasks",
    "tasks_context_state_time",
    "task_events",
    "task_events_task_revision",
    "idempotency_records",
    "idempotency_records_task",
    "outbox",
    "outbox_due",
    "outbox_task_state",
    "outbox_message_identity",
    "outbox_message_immutable",
    "outbox_attempts",
    "receiver_inbox",
    "receiver_inbox_reclaim",
    "receiver_frames",
    "loopback_effects",
    "stream_transcripts",
    "stream_transcripts_task",
    "stream_frames",
    "cancellation_intents",
    "cancellation_intents_task",
];
const V5_OBJECTS: &[&str] = &[
    "store_metadata",
    "tasks",
    "tasks_context_state_time",
    "task_events",
    "task_events_task_revision",
    "idempotency_records",
    "idempotency_records_task",
    "outbox",
    "outbox_due",
    "outbox_task_state",
    "outbox_message_identity",
    "outbox_message_immutable",
    "outbox_attempts",
    "receiver_inbox",
    "receiver_inbox_reclaim",
    "receiver_frames",
    "loopback_effects",
    "stream_transcripts",
    "stream_transcripts_task",
    "stream_frames",
    "cancellation_intents",
    "cancellation_intents_task",
    "store_identity",
    "tasks_tenant_owner_time",
    "authorization_decisions",
    "authorization_decisions_tenant_time",
    "authorization_decisions_actor_time",
    "authorization_decisions_resource_time",
    "tasks_ownership_immutable",
    "authorization_decisions_no_update",
    "authorization_decisions_no_delete",
    "authorization_decisions_task_scope",
    "task_events_tenant_match",
    "idempotency_tenant_match",
    "outbox_tenant_match",
    "stream_transcripts_tenant_match",
    "cancellation_tenant_match",
    "task_events_identity_update",
    "idempotency_identity_update",
    "outbox_identity_update",
    "outbox_attempts_identity_update",
    "receiver_inbox_task_match",
    "receiver_inbox_identity_update",
    "receiver_frames_identity_update",
    "loopback_effects_identity_update",
    "stream_transcripts_identity_update",
    "stream_frames_identity_update",
    "cancellation_identity_update",
];
const V6_OBJECTS: &[&str] = &[
    "store_metadata",
    "tasks",
    "tasks_context_state_time",
    "task_events",
    "task_events_task_revision",
    "idempotency_records",
    "idempotency_records_task",
    "outbox",
    "outbox_due",
    "outbox_task_state",
    "outbox_message_identity",
    "outbox_message_immutable",
    "outbox_attempts",
    "receiver_inbox",
    "receiver_inbox_reclaim",
    "receiver_frames",
    "loopback_effects",
    "stream_transcripts",
    "stream_transcripts_task",
    "stream_frames",
    "cancellation_intents",
    "cancellation_intents_task",
    "store_identity",
    "tasks_tenant_owner_time",
    "authorization_decisions",
    "authorization_decisions_tenant_time",
    "authorization_decisions_actor_time",
    "authorization_decisions_resource_time",
    "tasks_ownership_immutable",
    "authorization_decisions_no_update",
    "authorization_decisions_no_delete",
    "authorization_decisions_task_scope",
    "task_events_tenant_match",
    "idempotency_tenant_match",
    "outbox_tenant_match",
    "stream_transcripts_tenant_match",
    "cancellation_tenant_match",
    "task_events_identity_update",
    "idempotency_identity_update",
    "outbox_identity_update",
    "outbox_attempts_identity_update",
    "receiver_inbox_task_match",
    "receiver_inbox_identity_update",
    "receiver_frames_identity_update",
    "loopback_effects_identity_update",
    "stream_transcripts_identity_update",
    "stream_frames_identity_update",
    "cancellation_identity_update",
    "list_snapshots",
    "list_snapshots_expiry",
    "list_snapshot_entries",
    "list_page_tokens",
    "list_page_tokens_snapshot",
    "tasks_tenant_time_v6",
    "tasks_tenant_state_time_v6",
    "tasks_tenant_context_time_v6",
    "tasks_tenant_context_state_time_v6",
    "tasks_tenant_owner_time_v6",
    "tasks_tenant_owner_state_time_v6",
    "tasks_tenant_owner_context_time_v6",
    "tasks_tenant_owner_context_state_time_v6",
];
const V3_OBJECTS: &[&str] = &[
    "store_metadata",
    "tasks",
    "tasks_context_state_time",
    "task_events",
    "task_events_task_revision",
    "idempotency_records",
    "idempotency_records_task",
    "outbox",
    "outbox_due",
    "outbox_task_state",
    "outbox_attempts",
    "receiver_inbox",
    "receiver_inbox_reclaim",
    "receiver_frames",
    "loopback_effects",
    "stream_transcripts",
    "stream_transcripts_task",
    "stream_frames",
];

fn schema_v3_hash() -> String {
    content_digest(
        [V2_SCHEMA_SQL.as_bytes(), RECEIVER_SCHEMA_SQL.as_bytes()]
            .concat()
            .as_slice(),
    )
}

fn schema_v4_hash() -> String {
    content_digest(
        [
            V2_SCHEMA_SQL.as_bytes(),
            RECEIVER_SCHEMA_SQL.as_bytes(),
            V4_OUTBOX_TABLE_SQL.as_bytes(),
            OUTBOX_MESSAGE_BINDING_SQL.as_bytes(),
            OUTBOX_MESSAGE_IMMUTABILITY_SQL.as_bytes(),
            CANCELLATION_SCHEMA_SQL.as_bytes(),
        ]
        .concat()
        .as_slice(),
    )
}

fn schema_v5_hash() -> String {
    content_digest(
        [schema_v4_hash().as_bytes(), V5_SCHEMA_SQL.as_bytes()]
            .concat()
            .as_slice(),
    )
}

fn schema_v6_hash() -> String {
    content_digest(
        [schema_v5_hash().as_bytes(), V6_SCHEMA_SQL.as_bytes()]
            .concat()
            .as_slice(),
    )
}

#[allow(clippy::too_many_lines)]
fn validate_schema_version(
    connection: &Connection,
    version: i64,
    schema: &str,
    objects: &[&str],
) -> Result<([u8; 32], [u8; 32]), SqliteStoreError> {
    let metadata: (i64, String, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT schema_version, migration_hash, cursor_key, receipt_key
             FROM store_metadata WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    for object_name in objects {
        let actual: String = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name = ?1",
                [object_name],
                |row| row.get(0),
            )
            .map_err(|_| SqliteStoreError::InvalidSchema)?;
        let expected = expected_schema_sql(schema, object_name)
            .or_else(|| expected_schema_sql(RECEIVER_SCHEMA_SQL, object_name))
            .or_else(|| expected_schema_sql(OUTBOX_MESSAGE_BINDING_SQL, object_name))
            .or_else(|| expected_schema_sql(CANCELLATION_SCHEMA_SQL, object_name))
            .or_else(|| expected_schema_sql(V5_SCHEMA_SQL, object_name))
            .or_else(|| expected_schema_sql(V6_SCHEMA_SQL, object_name));
        let actual = normalize_schema_sql(&actual);
        let matches_expected = if version >= V5_SCHEMA_VERSION && *object_name == "tasks" {
            let base = expected_schema_sql(V2_SCHEMA_SQL, "tasks").expect("v2 tasks schema");
            let expected_tasks = format!(
                "{},tenant_scopetextnotnulldefault'smesh-dev-only-tenant',owner_account_idtextnotnulldefault'smesh-dev-only-account')",
                base.strip_suffix(')').expect("tasks schema closes")
            );
            actual == expected_tasks
        } else if version >= V5_SCHEMA_VERSION && *object_name == "idempotency_records" {
            let base = expected_schema_sql(V2_SCHEMA_SQL, "idempotency_records")
                .expect("v2 idempotency schema");
            let expected_idempotency = base.replace(
                ",primarykey(tenant_scope,message_id)",
                ",digest_versionintegernotnulldefault2check(digest_versionin(1,2)),actor_account_idtext,causative_request_jsontext,invocation_kindtextcheck(invocation_kindin('unary','streaming')),primarykey(tenant_scope,message_id)",
            );
            actual == expected_idempotency
        } else if version >= V5_SCHEMA_VERSION && *object_name == "outbox" {
            let base = normalize_schema_sql(V4_OUTBOX_TABLE_SQL)
                .replace("outbox_v4", "outbox")
                .replace('"', "");
            let expected_outbox = format!(
                "{},dispatch_identity_versionintegernotnulldefault2check(dispatch_identity_versionin(1,2)))",
                base.strip_suffix(')').expect("outbox schema closes")
            );
            actual.replace('"', "") == expected_outbox
        } else if *object_name == "outbox_message_immutable" {
            actual == normalize_schema_sql(OUTBOX_MESSAGE_IMMUTABILITY_SQL)
        } else if version >= V4_SCHEMA_VERSION && *object_name == "outbox" {
            let expected = normalize_schema_sql(V4_OUTBOX_TABLE_SQL)
                .replace("outbox_v4", "outbox")
                .replace('"', "");
            actual.replace('"', "") == expected
        } else {
            expected
                .as_ref()
                .is_some_and(|expected| actual == *expected)
        };
        if !matches_expected {
            return Err(SqliteStoreError::InvalidSchema);
        }
    }
    let actual_index_columns: String = connection
        .query_row(
            "SELECT group_concat(name, ',') FROM pragma_index_info('tasks_context_state_time')",
            [],
            |row| row.get(0),
        )
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    let actual_task_columns: String = connection
        .query_row(
            "SELECT group_concat(name || ':' || type || ':' || \"notnull\" || ':' || pk, ',') FROM pragma_table_info('tasks')",
            [],
            |row| row.get(0),
        )
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    let object_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    let expected_hash = match version {
        SCHEMA_VERSION => schema_v6_hash(),
        V5_SCHEMA_VERSION => schema_v5_hash(),
        V4_SCHEMA_VERSION => schema_v4_hash(),
        V3_SCHEMA_VERSION => schema_v3_hash(),
        _ => content_digest(schema.as_bytes()),
    };
    if metadata.0 != version
        || metadata.1 != expected_hash
        || metadata.2.len() != 32
        || metadata.3.len() != 32
        || actual_task_columns
            != if version >= V5_SCHEMA_VERSION {
                "created_order:INTEGER:0:1,task_id:TEXT:1:0,context_id:TEXT:1:0,state:TEXT:1:0,status_timestamp:TEXT:0:0,revision:INTEGER:1:0,task_json:TEXT:1:0,tenant_scope:TEXT:1:0,owner_account_id:TEXT:1:0"
            } else {
                "created_order:INTEGER:0:1,task_id:TEXT:1:0,context_id:TEXT:1:0,state:TEXT:1:0,status_timestamp:TEXT:0:0,revision:INTEGER:1:0,task_json:TEXT:1:0"
            }
        || actual_index_columns != "context_id,state,status_timestamp,task_id"
        || object_count
            != i64::try_from(objects.len()).map_err(|_| SqliteStoreError::InvalidSchema)?
    {
        return Err(SqliteStoreError::InvalidSchema);
    }
    let key: [u8; 32] = metadata
        .2
        .try_into()
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    let receipt_key: [u8; 32] = metadata
        .3
        .try_into()
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    Ok((key, receipt_key))
}

fn validate_schema(connection: &Connection) -> Result<([u8; 32], [u8; 32]), SqliteStoreError> {
    validate_schema_version(connection, SCHEMA_VERSION, V2_SCHEMA_SQL, V6_OBJECTS)
}

fn migrate_v1_to_v2(
    connection: &mut Connection,
    max_tasks: usize,
) -> Result<([u8; 32], [u8; 32]), SqliteStoreError> {
    let keys = validate_schema_version(connection, 1, V1_SCHEMA_SQL, V1_OBJECTS)?;
    validate_persisted_records(connection, max_tasks)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .execute_batch(ATOMIC_SCHEMA_SQL)
        .map_err(|_| SqliteStoreError::Initialization)?;
    let now = chrono::Utc::now().timestamp_millis();
    transaction
        .execute(
            "INSERT INTO task_events(
                 tenant_scope, task_id, event_seq, task_revision, event_kind,
                 from_state, to_state, event_json, created_at
             ) SELECT ?1, task_id, 1, revision, 'migration_snapshot', NULL,
                      state, task_json, ?2 FROM tasks",
            params![TRUSTED_SINGLE_TENANT_SCOPE, now],
        )
        .map_err(|_| SqliteStoreError::Initialization)?;
    validate_foreign_keys(&transaction)?;
    validate_persisted_records(&transaction, max_tasks)?;
    validate_pre_v4_atomic_records(&transaction)?;
    transaction
        .execute(
            "UPDATE store_metadata SET schema_version = ?1, migration_hash = ?2
             WHERE singleton = 1",
            params![V2_SCHEMA_VERSION, content_digest(V2_SCHEMA_SQL.as_bytes())],
        )
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .pragma_update(None, "user_version", V2_SCHEMA_VERSION)
        .map_err(|_| SqliteStoreError::Initialization)?;
    validate_persisted_records(&transaction, max_tasks)?;
    let validated =
        validate_schema_version(&transaction, V2_SCHEMA_VERSION, V2_SCHEMA_SQL, V2_OBJECTS)?;
    if validated != keys {
        return Err(SqliteStoreError::InvalidSchema);
    }
    transaction
        .commit()
        .map_err(|_| SqliteStoreError::Initialization)?;
    Ok(validated)
}

fn migrate_v2_to_v3(
    connection: &mut Connection,
    max_tasks: usize,
) -> Result<([u8; 32], [u8; 32]), SqliteStoreError> {
    let keys = validate_schema_version(connection, V2_SCHEMA_VERSION, V2_SCHEMA_SQL, V2_OBJECTS)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| SqliteStoreError::Initialization)?;
    validate_foreign_keys(&transaction)?;
    transaction
        .execute_batch(RECEIVER_SCHEMA_SQL)
        .map_err(|_| SqliteStoreError::Initialization)?;
    validate_persisted_records(&transaction, max_tasks)?;
    validate_pre_v4_atomic_records(&transaction)?;
    transaction.execute(
        "UPDATE store_metadata SET schema_version = ?1, migration_hash = ?2 WHERE singleton = 1",
        params![V3_SCHEMA_VERSION, schema_v3_hash()],
    ).map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .pragma_update(None, "user_version", V3_SCHEMA_VERSION)
        .map_err(|_| SqliteStoreError::Initialization)?;
    let validated =
        validate_schema_version(&transaction, V3_SCHEMA_VERSION, V2_SCHEMA_SQL, V3_OBJECTS)?;
    if validated != keys {
        return Err(SqliteStoreError::InvalidSchema);
    }
    transaction
        .commit()
        .map_err(|_| SqliteStoreError::Initialization)?;
    Ok(validated)
}

fn rebuild_outbox_with_message_ids(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<(), SqliteStoreError> {
    let before: i64 = transaction
        .query_row("SELECT COUNT(*) FROM outbox", [], |row| row.get(0))
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .pragma_update(None, "defer_foreign_keys", true)
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .execute_batch(V4_OUTBOX_TABLE_SQL)
        .map_err(|_| SqliteStoreError::Initialization)?;
    let mut statement = transaction
        .prepare("SELECT outbox_id, tenant_scope, dispatch_id, task_id FROM outbox")
        .map_err(|_| SqliteStoreError::Initialization)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|_| SqliteStoreError::Initialization)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| SqliteStoreError::Initialization)?;
    drop(statement);
    for (outbox_id, scope, dispatch_id, task_id) in rows {
        let mut identities = transaction
            .prepare(
                "SELECT message_id FROM idempotency_records
                 WHERE tenant_scope = ?1 AND task_id = ?2",
            )
            .map_err(|_| SqliteStoreError::Initialization)?;
        let candidates = identities
            .query_map(params![scope, task_id], |row| row.get::<_, String>(0))
            .map_err(|_| SqliteStoreError::Initialization)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| SqliteStoreError::Initialization)?;
        drop(identities);
        let message_id = candidates
            .into_iter()
            .find(|message_id| {
                dispatch_id
                    == content_digest(format!("{scope}\0send-message\0{message_id}").as_bytes())
            })
            .ok_or(SqliteStoreError::InvalidSchema)?;
        transaction
            .execute(
                "INSERT INTO outbox_v4 SELECT outbox_id, dispatch_id, tenant_scope, task_id,
                     ?2, causative_revision, payload_json, payload_digest, state, attempt_count,
                     max_attempts, available_at, lease_owner, lease_token, lease_until,
                     last_error, created_at, updated_at FROM outbox WHERE outbox_id = ?1",
                params![outbox_id, message_id],
            )
            .map_err(|_| SqliteStoreError::Initialization)?;
    }
    let after: i64 = transaction
        .query_row("SELECT COUNT(*) FROM outbox_v4", [], |row| row.get(0))
        .map_err(|_| SqliteStoreError::Initialization)?;
    if after != before {
        return Err(SqliteStoreError::InvalidSchema);
    }
    transaction
        .execute_batch(
            "DROP TABLE outbox;
             ALTER TABLE outbox_v4 RENAME TO outbox;
             CREATE INDEX outbox_due ON outbox(state, available_at, lease_until, outbox_id);
             CREATE INDEX outbox_task_state ON outbox(task_id, state);",
        )
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .execute_batch(OUTBOX_MESSAGE_BINDING_SQL)
        .map_err(|_| SqliteStoreError::Initialization)?;
    Ok(())
}

fn migrate_v3_to_v4(
    connection: &mut Connection,
    max_tasks: usize,
) -> Result<([u8; 32], [u8; 32]), SqliteStoreError> {
    let keys = validate_schema_version(connection, V3_SCHEMA_VERSION, V2_SCHEMA_SQL, V3_OBJECTS)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| SqliteStoreError::Initialization)?;
    rebuild_outbox_with_message_ids(&transaction)?;
    transaction
        .execute_batch(OUTBOX_MESSAGE_IMMUTABILITY_SQL)
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .execute_batch(CANCELLATION_SCHEMA_SQL)
        .map_err(|_| SqliteStoreError::Initialization)?;
    validate_foreign_keys(&transaction)?;
    validate_persisted_records(&transaction, max_tasks)?;
    transaction
        .execute(
            "UPDATE store_metadata SET schema_version = ?1, migration_hash = ?2 WHERE singleton = 1",
            params![V4_SCHEMA_VERSION, schema_v4_hash()],
        )
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .pragma_update(None, "user_version", V4_SCHEMA_VERSION)
        .map_err(|_| SqliteStoreError::Initialization)?;
    let validated =
        validate_schema_version(&transaction, V4_SCHEMA_VERSION, V2_SCHEMA_SQL, V4_OBJECTS)?;
    if validated != keys {
        return Err(SqliteStoreError::InvalidSchema);
    }
    transaction
        .commit()
        .map_err(|_| SqliteStoreError::Initialization)?;
    Ok(validated)
}

#[allow(clippy::too_many_lines)]
fn migrate_v4_to_v5(
    connection: &mut Connection,
    max_tasks: usize,
    binding: &LegacyTenantBinding,
) -> Result<([u8; 32], [u8; 32]), SqliteStoreError> {
    let keys = validate_schema_version(connection, V4_SCHEMA_VERSION, V2_SCHEMA_SQL, V4_OBJECTS)?;
    validate_foreign_keys(connection)?;
    validate_persisted_records(connection, max_tasks)?;
    let invalid_scope: bool = connection
        .query_row(
            "SELECT EXISTS(
           SELECT 1 FROM task_events WHERE tenant_scope NOT IN (?1, ?2)
           UNION ALL SELECT 1 FROM idempotency_records WHERE tenant_scope NOT IN (?1, ?2)
           UNION ALL SELECT 1 FROM outbox WHERE tenant_scope NOT IN (?1, ?2)
           UNION ALL SELECT 1 FROM receiver_inbox WHERE tenant_scope NOT IN (?1, ?2)
           UNION ALL SELECT 1 FROM stream_transcripts WHERE tenant_scope NOT IN (?1, ?2)
           UNION ALL SELECT 1 FROM cancellation_intents WHERE tenant_scope NOT IN (?1, ?2))",
            params![LEGACY_V4_SENTINEL_SCOPE, TRUSTED_SINGLE_TENANT_SCOPE],
            |row| row.get(0),
        )
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    if invalid_scope {
        return Err(SqliteStoreError::InvalidSchema);
    }

    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .pragma_update(None, "defer_foreign_keys", true)
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction.execute_batch(
        "ALTER TABLE tasks ADD COLUMN tenant_scope TEXT NOT NULL DEFAULT 'smesh-dev-only-tenant';
         ALTER TABLE tasks ADD COLUMN owner_account_id TEXT NOT NULL DEFAULT 'smesh-dev-only-account';
         ALTER TABLE idempotency_records ADD COLUMN digest_version INTEGER NOT NULL DEFAULT 2 CHECK(digest_version IN (1,2));
                        ALTER TABLE idempotency_records ADD COLUMN actor_account_id TEXT;
                        ALTER TABLE idempotency_records ADD COLUMN causative_request_json TEXT;
                        ALTER TABLE idempotency_records ADD COLUMN invocation_kind TEXT CHECK(invocation_kind IN ('unary','streaming'));
         ALTER TABLE outbox ADD COLUMN dispatch_identity_version INTEGER NOT NULL DEFAULT 2 CHECK(dispatch_identity_version IN (1,2));"
    ).map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .execute_batch(
            "UPDATE idempotency_records SET digest_version=1;
                        UPDATE outbox SET dispatch_identity_version=1;",
        )
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .execute(
            "UPDATE tasks SET tenant_scope=?1, owner_account_id=?2",
            params![binding.tenant_scope, binding.owner_account_id],
        )
        .map_err(|_| SqliteStoreError::Initialization)?;
    for table in [
        "task_events",
        "idempotency_records",
        "outbox",
        "receiver_inbox",
        "receiver_frames",
        "loopback_effects",
        "stream_transcripts",
        "stream_frames",
        "cancellation_intents",
    ] {
        transaction
            .execute(
                &format!("UPDATE {table} SET tenant_scope=?1"),
                [&binding.tenant_scope],
            )
            .map_err(|_| SqliteStoreError::Initialization)?;
    }
    transaction
        .execute_batch(V5_SCHEMA_SQL)
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction.execute(
        "INSERT INTO store_identity(singleton, tenant_scope, owner_account_id, policy_id, policy_revision, policy_digest)
         VALUES(1,?1,?2,?3,?4,?5)",
        params![binding.tenant_scope, binding.owner_account_id, binding.policy_id, binding.policy_revision, binding.policy_digest],
    ).map_err(|_| SqliteStoreError::Initialization)?;
    let migration_digest = content_digest(
        format!(
            "v4-to-v5\0{}\0{}\0{}\0{}",
            binding.tenant_scope,
            binding.owner_account_id,
            binding.policy_id,
            binding.policy_revision
        )
        .as_bytes(),
    );
    transaction.execute(
        "INSERT INTO authorization_decisions(decision_id, tenant_scope, actor_account_id, policy_id,
          policy_revision, policy_digest, operation, effect, reason, resource_kind, resource_digest, task_id, decided_at)
         VALUES(?1,?2,?3,?4,?5,?6,'legacyMigration','allow','explicit_legacy_binding','store',?7,NULL,?8)",
        params![format!("migration-{}", &migration_digest[..32]), binding.tenant_scope, binding.owner_account_id,
                binding.policy_id, binding.policy_revision, binding.policy_digest, migration_digest,
                chrono::Utc::now().timestamp_millis()],
    ).map_err(|_| SqliteStoreError::Initialization)?;
    validate_foreign_keys(&transaction)?;
    validate_persisted_records(&transaction, max_tasks)?;
    transaction
        .execute(
            "UPDATE store_metadata SET schema_version=?1, migration_hash=?2 WHERE singleton=1",
            params![V5_SCHEMA_VERSION, schema_v5_hash()],
        )
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .pragma_update(None, "user_version", V5_SCHEMA_VERSION)
        .map_err(|_| SqliteStoreError::Initialization)?;
    let validated =
        validate_schema_version(&transaction, V5_SCHEMA_VERSION, V2_SCHEMA_SQL, V5_OBJECTS)?;
    if validated != keys {
        return Err(SqliteStoreError::InvalidSchema);
    }
    // Every semantic validator must run before commit. A schema-valid but corrupt
    // legacy row must leave the original v4 database retryable byte-for-byte.
    validate_foreign_keys(&transaction)?;
    validate_persisted_records(&transaction, max_tasks)?;
    validate_atomic_records(&transaction)?;
    validate_receiver_records(&transaction)?;
    validate_stream_records(&transaction)?;
    validate_cancellation_records(&transaction)?;
    validate_tenant_authorization_records(&transaction)?;
    transaction
        .commit()
        .map_err(|_| SqliteStoreError::Initialization)?;
    Ok(validated)
}

fn migrate_v5_to_v6(connection: &mut Connection) -> Result<([u8; 32], [u8; 32]), SqliteStoreError> {
    let keys = validate_schema_version(connection, V5_SCHEMA_VERSION, V2_SCHEMA_SQL, V5_OBJECTS)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .execute_batch(V6_SCHEMA_SQL)
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .execute(
            "UPDATE store_metadata SET schema_version=?1,migration_hash=?2 WHERE singleton=1",
            params![SCHEMA_VERSION, schema_v6_hash()],
        )
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .pragma_update(None, "user_version", SCHEMA_VERSION)
        .map_err(|_| SqliteStoreError::Initialization)?;
    validate_foreign_keys(&transaction)?;
    let validated =
        validate_schema_version(&transaction, SCHEMA_VERSION, V2_SCHEMA_SQL, V6_OBJECTS)?;
    if validated != keys {
        return Err(SqliteStoreError::InvalidSchema);
    }
    transaction
        .commit()
        .map_err(|_| SqliteStoreError::Initialization)?;
    Ok(validated)
}

// One transaction intentionally keeps lease reclamation and orphan arbitration indivisible.
#[allow(clippy::too_many_lines)]
fn recover_orphaned_tasks(connection: &mut Connection) -> Result<(), SqliteStoreError> {
    let nonterminal = [
        "\"TASK_STATE_UNSPECIFIED\"",
        "\"TASK_STATE_SUBMITTED\"",
        "\"TASK_STATE_WORKING\"",
        "\"TASK_STATE_INPUT_REQUIRED\"",
        "\"TASK_STATE_AUTH_REQUIRED\"",
    ];
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| SqliteStoreError::Initialization)?;
    // Ownership lock proves the prior process is gone. Reclaim its leases without
    // failing tasks that still have a durable dispatch intent.
    let recovery_now = chrono::Utc::now().timestamp_millis();
    transaction
        .execute(
            "UPDATE receiver_inbox SET lease_until = 0, updated_at = ?1 WHERE state = 'processing'",
            [recovery_now],
        )
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .execute(
            "UPDATE outbox SET lease_until = 0, updated_at = ?1
             WHERE state = 'leased'
               AND EXISTS (
                   SELECT 1 FROM receiver_inbox receiver
                   WHERE receiver.tenant_scope = outbox.tenant_scope
                     AND receiver.dispatch_id = outbox.dispatch_id
                     AND receiver.payload_digest = outbox.payload_digest
                     AND receiver.state IN ('processing', 'completed')
               )",
            [recovery_now],
        )
        .map_err(|_| SqliteStoreError::Initialization)?;
    loop {
        let expired_final: Option<(i64, String, String)> = transaction
            .query_row(
                "SELECT outbox_id, task_id, dispatch_id FROM outbox
                 WHERE state = 'leased' AND attempt_count >= max_attempts
                   AND NOT EXISTS (
                       SELECT 1 FROM receiver_inbox receiver
                       WHERE receiver.tenant_scope = outbox.tenant_scope
                         AND receiver.dispatch_id = outbox.dispatch_id
                         AND receiver.payload_digest = outbox.payload_digest
                         AND receiver.state IN ('processing', 'completed')
                   )
                 ORDER BY outbox_id LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| SqliteStoreError::Initialization)?;
        let Some((outbox_id, task_id, dispatch_id)) = expired_final else {
            break;
        };
        let error = "final outbox attempt was abandoned by the prior process";
        transaction
            .execute(
                "UPDATE outbox_attempts SET finished_at = ?2, outcome = 'dead', error = ?3
                 WHERE outbox_id = ?1 AND finished_at IS NULL",
                params![outbox_id, recovery_now, error],
            )
            .map_err(|_| SqliteStoreError::Initialization)?;
        let was_terminal: bool = transaction
            .query_row(
                "SELECT state IN ('\"TASK_STATE_COMPLETED\"', '\"TASK_STATE_FAILED\"',
                                  '\"TASK_STATE_CANCELED\"', '\"TASK_STATE_REJECTED\"')
                 FROM tasks WHERE task_id = ?1",
                [&task_id],
                |row| row.get(0),
            )
            .map_err(|_| SqliteStoreError::Initialization)?;
        dead_letter_task(&transaction, &task_id, &dispatch_id, error, recovery_now)
            .map_err(|_| SqliteStoreError::Initialization)?;
        transaction
            .execute(
                "UPDATE outbox SET state = ?2, lease_owner = NULL, lease_token = NULL,
                     lease_until = NULL, last_error = ?3, updated_at = ?4
                 WHERE outbox_id = ?1",
                params![
                    outbox_id,
                    if was_terminal { "superseded" } else { "dead" },
                    error,
                    recovery_now
                ],
            )
            .map_err(|_| SqliteStoreError::Initialization)?;
    }
    loop {
        let delivered_nonterminal: Option<(String, String)> = transaction
            .query_row(
                "SELECT o.task_id, o.dispatch_id
                 FROM outbox o JOIN tasks t ON t.task_id = o.task_id
                 WHERE o.state = 'delivered' AND o.causative_revision = t.revision
                   AND t.state NOT IN ('\"TASK_STATE_COMPLETED\"', '\"TASK_STATE_FAILED\"',
                                       '\"TASK_STATE_CANCELED\"', '\"TASK_STATE_REJECTED\"')
                 ORDER BY o.outbox_id LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| SqliteStoreError::Initialization)?;
        let Some((task_id, dispatch_id)) = delivered_nonterminal else {
            break;
        };
        let error = "delivered outbox intent lacked a terminal transition at restart; downstream effect outcome is unknown";
        dead_letter_task(&transaction, &task_id, &dispatch_id, error, recovery_now)
            .map_err(|_| SqliteStoreError::Initialization)?;
        transaction
            .execute(
                "UPDATE outbox SET state = 'superseded', last_error = ?2, updated_at = ?3
                 WHERE task_id = ?1 AND state = 'delivered'",
                params![task_id, error, recovery_now],
            )
            .map_err(|_| SqliteStoreError::Initialization)?;
    }
    transaction
        .execute(
            "UPDATE outbox_attempts SET finished_at = ?1, outcome = 'abandoned'
             WHERE finished_at IS NULL AND outbox_id IN
                 (SELECT outbox_id FROM outbox
                  WHERE state = 'leased' AND NOT EXISTS (
                      SELECT 1 FROM receiver_inbox receiver
                      WHERE receiver.tenant_scope = outbox.tenant_scope
                        AND receiver.dispatch_id = outbox.dispatch_id
                        AND receiver.payload_digest = outbox.payload_digest
                        AND receiver.state IN ('processing', 'completed')
                  ))",
            [recovery_now],
        )
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .execute(
            "UPDATE outbox SET state = 'pending', available_at = MIN(available_at, ?1),
                 lease_owner = NULL, lease_token = NULL, lease_until = NULL, updated_at = ?1
             WHERE state = 'leased' AND NOT EXISTS (
                 SELECT 1 FROM receiver_inbox receiver
                 WHERE receiver.tenant_scope = outbox.tenant_scope
                   AND receiver.dispatch_id = outbox.dispatch_id
                   AND receiver.payload_digest = outbox.payload_digest
                   AND receiver.state IN ('processing', 'completed')
             )",
            [recovery_now],
        )
        .map_err(|_| SqliteStoreError::Initialization)?;
    let aggregate_bytes: i64 = transaction
        .query_row(
            "SELECT COALESCE(SUM(length(CAST(task_json AS BLOB))), 0) FROM tasks",
            [],
            |row| row.get(0),
        )
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    let mut aggregate_bytes =
        usize::try_from(aggregate_bytes).map_err(|_| SqliteStoreError::Capacity)?;
    loop {
        let record: Option<(String, u64, String, String)> = transaction
            .query_row(
                "SELECT task_json, revision, state, tenant_scope FROM tasks
                 WHERE state IN (?1, ?2, ?3, ?4, ?5)
                   AND NOT EXISTS (
                       SELECT 1 FROM outbox
                       WHERE outbox.task_id = tasks.task_id
                         AND outbox.state IN ('pending', 'leased', 'delivered')
                   )
                 ORDER BY created_order ASC LIMIT 1",
                params![
                    nonterminal[0],
                    nonterminal[1],
                    nonterminal[2],
                    nonterminal[3],
                    nonterminal[4]
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|_| SqliteStoreError::InvalidSchema)?;
        let Some((encoded, revision, previous_state, tenant_scope)) = record else {
            break;
        };
        let mut task: Task =
            serde_json::from_str(&encoded).map_err(|_| SqliteStoreError::InvalidSchema)?;
        if !legal_transition(&task.status.state, &a2a::TaskState::Failed) {
            return Err(SqliteStoreError::InvalidSchema);
        }
        task.status.state = a2a::TaskState::Failed;
        task.status.timestamp = Some(chrono::Utc::now());
        let mut recovery_message = Message::new(
            Role::Agent,
            vec![Part::text(
                "Task failed during restart recovery because its prior execution was orphaned",
            )],
        );
        recovery_message.task_id = Some(task.id.clone());
        recovery_message.context_id = Some(task.context_id.clone());
        task.status.message = Some(recovery_message);
        let state = state_key(&task).map_err(|_| SqliteStoreError::Initialization)?;
        let timestamp = task.status.timestamp.map(|value| value.to_rfc3339());
        let recovered = encode_task(&task).map_err(|_| SqliteStoreError::Capacity)?;
        aggregate_bytes = aggregate_bytes
            .saturating_sub(encoded.len())
            .saturating_add(recovered.len());
        if aggregate_bytes > MAX_STORE_JSON_BYTES {
            return Err(SqliteStoreError::Capacity);
        }
        let next_revision = revision.checked_add(1).ok_or(SqliteStoreError::Capacity)?;
        let next_revision = i64::try_from(next_revision).map_err(|_| SqliteStoreError::Capacity)?;
        transaction
            .execute(
                "UPDATE tasks SET state = ?2, status_timestamp = ?3, revision = ?4, task_json = ?5 WHERE task_id = ?1",
                params![task.id, state, timestamp, next_revision, recovered],
            )
            .map_err(|_| SqliteStoreError::Initialization)?;
        let event_seq: i64 = transaction
            .query_row(
                "SELECT COALESCE(MAX(event_seq), 0) + 1 FROM task_events
                 WHERE tenant_scope = ?1 AND task_id = ?2",
                params![tenant_scope, task.id],
                |row| row.get(0),
            )
            .map_err(|_| SqliteStoreError::Initialization)?;
        transaction
            .execute(
                "INSERT INTO task_events(tenant_scope, task_id, event_seq, task_revision,
                     event_kind, from_state, to_state, event_json, created_at)
                 VALUES (?1, ?2, ?3, ?4, 'restart_orphan_failed', ?5, ?6, ?7, ?8)",
                params![
                    tenant_scope,
                    task.id,
                    event_seq,
                    next_revision,
                    previous_state,
                    state,
                    recovered,
                    recovery_now
                ],
            )
            .map_err(|_| SqliteStoreError::Initialization)?;
    }
    ensure_atomic_capacity(&transaction).map_err(|_| SqliteStoreError::Capacity)?;
    transaction
        .commit()
        .map_err(|_| SqliteStoreError::Initialization)
}

#[cfg(unix)]
fn prepare_secure_path(path: &Path) -> Result<(), SqliteStoreError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    if !path.is_absolute() {
        return Err(SqliteStoreError::Initialization);
    }
    let parent = path.parent().ok_or(SqliteStoreError::Initialization)?;
    let canonical_parent = parent
        .canonicalize()
        .map_err(|_| SqliteStoreError::Initialization)?;
    if canonical_parent != parent
        || std::fs::symlink_metadata(parent)
            .map_err(|_| SqliteStoreError::Initialization)?
            .file_type()
            .is_symlink()
    {
        return Err(SqliteStoreError::SymbolicLink);
    }
    let metadata = std::fs::metadata(parent).map_err(|_| SqliteStoreError::Initialization)?;
    let current_uid = rustix::process::getuid().as_raw();
    if !metadata.is_dir()
        || metadata.uid() != current_uid
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(SqliteStoreError::Initialization);
    }
    if path.exists() {
        let metadata =
            std::fs::symlink_metadata(path).map_err(|_| SqliteStoreError::Initialization)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.uid() != current_uid
        {
            return Err(SqliteStoreError::SymbolicLink);
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| SqliteStoreError::Initialization)?;
    } else {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| SqliteStoreError::Initialization)?;
    }
    Ok(())
}

#[cfg(unix)]
fn acquire_ownership_lock(path: &Path) -> Result<File, SqliteStoreError> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|_| SqliteStoreError::Initialization)?;
    fs2::FileExt::try_lock_exclusive(&file).map_err(|_| SqliteStoreError::AlreadyOpen)?;
    Ok(file)
}

#[cfg(unix)]
fn secure_permissions(connection: &Connection) -> Result<(), SqliteStoreError> {
    use std::os::unix::fs::PermissionsExt;
    let path = connection.path().ok_or(SqliteStoreError::Initialization)?;
    for candidate in [
        path.to_owned(),
        format!("{path}-wal"),
        format!("{path}-shm"),
    ] {
        let candidate = Path::new(&candidate);
        if !candidate.exists() {
            continue;
        }
        let mut permissions = std::fs::metadata(candidate)
            .map_err(|_| SqliteStoreError::Initialization)?
            .permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(candidate, permissions)
            .map_err(|_| SqliteStoreError::Initialization)?;
    }
    Ok(())
}

fn encode_task(task: &Task) -> Result<String, A2AError> {
    let encoded = serde_json::to_string(task)
        .map_err(|_| A2AError::internal("failed to encode persistent task"))?;
    if encoded.len() > MAX_TASK_JSON_BYTES {
        return Err(A2AError::invalid_params(
            "task exceeds persistent storage limit",
        ));
    }
    Ok(encoded)
}

fn insert_authorization_audit(
    transaction: &rusqlite::Transaction<'_>,
    audit: &AuthorizationAuditInput,
) -> Result<(), A2AError> {
    transaction.execute(
        "INSERT INTO authorization_decisions(decision_id,tenant_scope,actor_account_id,policy_id,
         policy_revision,policy_digest,operation,effect,reason,resource_kind,resource_digest,task_id,decided_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        params![audit.decision_id, audit.tenant_scope, audit.actor_account_id, audit.policy_id,
            audit.policy_revision, audit.policy_digest, audit.operation,
            match audit.effect { AuthorizationDecisionEffect::Allow => "allow", AuthorizationDecisionEffect::Deny => "deny" },
            audit.reason, audit.resource_kind, audit.resource_digest, audit.task_id, audit.decided_at],
    ).map_err(|_| A2AError::internal("authorization audit append failed"))?;
    Ok(())
}

fn ensure_authorization_capacity(connection: &Connection) -> Result<(), A2AError> {
    let (count, bytes): (i64, i64) = connection.query_row(
        "SELECT COUNT(*), COALESCE(SUM(length(CAST(decision_id AS BLOB))+length(CAST(tenant_scope AS BLOB))+
         length(CAST(actor_account_id AS BLOB))+length(CAST(policy_id AS BLOB))+length(CAST(policy_digest AS BLOB))+
         length(CAST(operation AS BLOB))+length(CAST(reason AS BLOB))+length(CAST(resource_kind AS BLOB))+
         length(CAST(resource_digest AS BLOB))+COALESCE(length(CAST(task_id AS BLOB)),0)),0)
         FROM authorization_decisions", [], |row| Ok((row.get(0)?, row.get(1)?)),
    ).map_err(|_| A2AError::internal("authorization audit capacity check failed"))?;
    if usize::try_from(count).unwrap_or(usize::MAX) > MAX_AUTHORIZATION_DECISIONS
        || usize::try_from(bytes).unwrap_or(usize::MAX) > MAX_STORE_JSON_BYTES
    {
        return Err(A2AError::internal("authorization audit capacity reached"));
    }
    Ok(())
}

fn decode_task(encoded: &str) -> Result<Task, A2AError> {
    if encoded.len() > MAX_TASK_JSON_BYTES {
        return Err(A2AError::internal(
            "persistent task record exceeds storage limit",
        ));
    }
    serde_json::from_str(encoded)
        .map_err(|_| A2AError::internal("persistent task record is corrupt"))
}

fn state_key(task: &Task) -> Result<String, A2AError> {
    serde_json::to_string(&task.status.state)
        .map_err(|_| A2AError::internal("failed to encode persistent task state"))
}

fn normalized_list_digest(request: &ListTasksRequest, page_size: i32) -> Result<String, A2AError> {
    serde_json::to_vec(&serde_json::json!({
        "contextId": request.context_id,
        "status": request.status,
        "pageSize": page_size,
        "historyLength": request.history_length,
        "statusTimestampAfter": request.status_timestamp_after,
        "includeArtifacts": request.include_artifacts.unwrap_or(false),
        "projectionVersion": 1,
    }))
    .map(|encoded| content_digest(&encoded))
    .map_err(|_| A2AError::internal("failed to normalize task-list request"))
}

fn validate_snapshot_request(request: &ListTasksRequest) -> Result<(i32, String), A2AError> {
    if request
        .history_length
        .is_some_and(|length| !(0..=100).contains(&length))
    {
        return Err(A2AError::invalid_params(
            "historyLength must be between 0 and 100",
        ));
    }
    let page_size = request.page_size.unwrap_or(50);
    if !(1..=100).contains(&page_size) {
        return Err(A2AError::invalid_params(
            "pageSize must be between 1 and 100",
        ));
    }
    normalized_list_digest(request, page_size).map(|digest| (page_size, digest))
}

fn project_snapshot_task(mut task: Task, request: &ListTasksRequest) -> Task {
    if !request.include_artifacts.unwrap_or(false) {
        task.artifacts = None;
    }
    let history_length = request
        .history_length
        .and_then(|value| usize::try_from(value).ok());
    if history_length == Some(0) {
        task.history = None;
    } else if let (Some(limit), Some(history)) = (history_length, task.history.as_mut())
        && history.len() > limit
    {
        history.drain(..history.len() - limit);
    }
    task
}

fn mac_field(mac: &mut Hmac<Sha256>, bytes: &[u8]) {
    mac.update(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    mac.update(bytes);
}

#[allow(clippy::too_many_arguments)]
fn snapshot_metadata_digest(
    key: &[u8; 32],
    snapshot_id: &[u8],
    scope_digest: &str,
    query_digest: &str,
    total_size: i64,
    page_size: i64,
    issued_at: i64,
    expires_at: i64,
    projection_version: i64,
    frozen_bytes: i64,
    entries: &[(i64, String, i64, String)],
) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts a 32-byte key");
    mac.update(b"smesh-list-snapshot-metadata-v1\0");
    mac_field(&mut mac, snapshot_id);
    mac_field(&mut mac, scope_digest.as_bytes());
    mac_field(&mut mac, query_digest.as_bytes());
    for value in [
        total_size,
        page_size,
        issued_at,
        expires_at,
        projection_version,
        frozen_bytes,
        PAGE_TOKEN_VERSION,
        PAGE_TOKEN_KEY_GENERATION,
    ] {
        mac.update(&value.to_be_bytes());
    }
    for (ordinal, task_id, revision, task_digest) in entries {
        mac.update(&ordinal.to_be_bytes());
        mac_field(&mut mac, task_id.as_bytes());
        mac.update(&revision.to_be_bytes());
        mac_field(&mut mac, task_digest.as_bytes());
    }
    mac.finalize().into_bytes().into()
}

fn derive_page_token(
    key: &[u8; 32],
    snapshot_id: &[u8],
    position: i64,
    metadata_digest: &[u8; 32],
) -> Result<(String, [u8; 32]), A2AError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| A2AError::internal("page-token derivation failed"))?;
    mac.update(b"smesh-list-tasks-page-v1\0");
    mac.update(&PAGE_TOKEN_VERSION.to_be_bytes());
    mac.update(&PAGE_TOKEN_KEY_GENERATION.to_be_bytes());
    mac_field(&mut mac, snapshot_id);
    mac.update(&position.to_be_bytes());
    mac.update(metadata_digest);
    let raw: [u8; 32] = mac.finalize().into_bytes().into();
    let hash: [u8; 32] = Sha256::digest(raw).into();
    Ok((URL_SAFE_NO_PAD.encode(raw), hash))
}

fn decode_page_token_hash(token: &str) -> Result<[u8; 32], A2AError> {
    if token.len() > MAX_PAGE_TOKEN_BYTES {
        return Err(A2AError::invalid_params("invalid pageToken"));
    }
    let raw = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| A2AError::invalid_params("invalid pageToken"))?;
    if raw.len() != 32 {
        return Err(A2AError::invalid_params("invalid pageToken"));
    }
    Ok(Sha256::digest(raw).into())
}

#[allow(clippy::too_many_arguments)]
fn insert_page_token(
    tx: &rusqlite::Transaction<'_>,
    key: &[u8; 32],
    snapshot_id: &[u8],
    position: i64,
    metadata_digest: &[u8; 32],
    scope_digest: &str,
    query_digest: &str,
    issued_at: i64,
    expires_at: i64,
) -> Result<String, A2AError> {
    let (token, hash) = derive_page_token(key, snapshot_id, position, metadata_digest)?;
    tx.execute(
        "INSERT OR IGNORE INTO list_page_tokens(token_hash,snapshot_id,next_position,scope_digest,
         query_digest,token_version,key_generation,issued_at,expires_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![
            hash.as_slice(),
            snapshot_id,
            position,
            scope_digest,
            query_digest,
            PAGE_TOKEN_VERSION,
            PAGE_TOKEN_KEY_GENERATION,
            issued_at,
            expires_at
        ],
    )
    .map_err(|_| A2AError::internal("page-token persistence failed"))?;
    Ok(token)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn frozen_list_transaction(
    connection: &mut Connection,
    tenant: &str,
    owner: &str,
    own_only: bool,
    request: &ListTasksRequest,
    scope_digest: &str,
    cursor_key: &[u8; 32],
    now: i64,
    audit: Option<&AuthorizationAuditInput>,
) -> Result<ListTasksResponse, A2AError> {
    let (page_size, query_digest) = validate_snapshot_request(request)?;
    // Expiry reclamation commits independently so an oversized admission cannot roll it back.
    {
        let gc = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| A2AError::internal("task snapshot cleanup failed"))?;
        gc.execute("DELETE FROM list_snapshots WHERE expires_at<=?1", [now])
            .map_err(|_| A2AError::internal("task snapshot cleanup failed"))?;
        gc.commit()
            .map_err(|_| A2AError::internal("task snapshot cleanup failed"))?;
    }
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| A2AError::internal("task snapshot transaction failed"))?;

    let response = if let Some(token) = request
        .page_token
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        let hash = decode_page_token_hash(token)?;
        let record: Option<PageTokenRow> = tx
            .query_row(
                "SELECT t.snapshot_id,t.next_position,t.scope_digest,t.query_digest,t.token_version,
                        t.key_generation,t.issued_at,t.expires_at,s.total_size
                 FROM list_page_tokens t JOIN list_snapshots s ON s.snapshot_id=t.snapshot_id
                 WHERE t.token_hash=?1",
                [hash.as_slice()],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,
                           row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?)),
            )
            .optional()
            .map_err(|_| A2AError::internal("page-token lookup failed"))?;
        let Some((
            snapshot_id,
            position,
            stored_scope,
            stored_query,
            version,
            generation,
            issued_at,
            expires_at,
            total_size,
        )) = record
        else {
            return Err(A2AError::invalid_params("invalid pageToken"));
        };
        validate_snapshot_chains(&tx, Some(&snapshot_id))
            .map_err(|_| A2AError::invalid_params("invalid pageToken"))?;
        if stored_scope != scope_digest
            || stored_query != query_digest
            || version != PAGE_TOKEN_VERSION
            || generation != PAGE_TOKEN_KEY_GENERATION
            || issued_at < 0
            || issued_at > now
            || issued_at.checked_add(SNAPSHOT_TTL_MILLIS) != Some(expires_at)
            || expires_at <= now
            || position <= 0
            || position >= total_size
            || position % i64::from(page_size) != 0
        {
            return Err(A2AError::invalid_params("invalid pageToken"));
        }
        let snapshot_meta: (String, String, i64, i64, i64, i64, i64, Vec<u8>) = tx
            .query_row(
                "SELECT scope_digest,query_digest,page_size,issued_at,expires_at,projection_version,frozen_bytes,metadata_digest
                 FROM list_snapshots WHERE snapshot_id=?1",
                [&snapshot_id],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?)),
            )
            .map_err(|_| A2AError::invalid_params("invalid pageToken"))?;
        if snapshot_meta.0 != stored_scope
            || snapshot_meta.1 != stored_query
            || snapshot_meta.2 != i64::from(page_size)
            || snapshot_meta.3 != issued_at
            || snapshot_meta.4 != expires_at
            || snapshot_meta.5 != 1
            || snapshot_meta.6 < 0
            || snapshot_meta.7.len() != 32
            || total_size <= i64::from(page_size)
        {
            return Err(A2AError::invalid_params("invalid pageToken"));
        }
        let entries = {
            let mut statement = tx
                .prepare(
                    "SELECT ordinal,task_id,task_digest,task_json FROM list_snapshot_entries WHERE snapshot_id=?1
                          AND ordinal>=?2 ORDER BY ordinal LIMIT ?3",
                )
                .map_err(|_| A2AError::internal("task snapshot page failed"))?;
            statement
                .query_map(params![snapshot_id, position, page_size], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })
                .map_err(|_| A2AError::internal("task snapshot page failed"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| A2AError::internal("task snapshot page failed"))?
        };
        let expected_len = (total_size - position).min(i64::from(page_size));
        if i64::try_from(entries.len()).unwrap_or(i64::MAX) != expected_len {
            return Err(A2AError::invalid_params("invalid pageToken"));
        }
        let mut tasks = Vec::with_capacity(entries.len());
        for (offset, (ordinal, task_id, digest, encoded)) in entries.iter().enumerate() {
            if *ordinal != position.saturating_add(i64::try_from(offset).unwrap_or(i64::MAX)) {
                return Err(A2AError::invalid_params("invalid pageToken"));
            }
            let task = decode_task(encoded)?;
            if task.id != *task_id || *digest != content_digest(encoded.as_bytes()) {
                return Err(A2AError::internal("persistent task snapshot is corrupt"));
            }
            tasks.push(task);
        }
        let end = position.saturating_add(i64::try_from(tasks.len()).unwrap_or(i64::MAX));
        let next_page_token = if end < total_size {
            let metadata_digest: [u8; 32] = snapshot_meta
                .7
                .as_slice()
                .try_into()
                .map_err(|_| A2AError::invalid_params("invalid pageToken"))?;
            derive_page_token(cursor_key, &snapshot_id, end, &metadata_digest)?.0
        } else {
            String::new()
        };
        ListTasksResponse {
            tasks,
            next_page_token,
            page_size,
            total_size: i32::try_from(total_size).unwrap_or(i32::MAX),
        }
    } else {
        let index = match (
            own_only,
            request.context_id.is_some(),
            request.status.is_some(),
        ) {
            (false, false, false) => "tasks_tenant_time_v6",
            (false, false, true) => "tasks_tenant_state_time_v6",
            (false, true, false) => "tasks_tenant_context_time_v6",
            (false, true, true) => "tasks_tenant_context_state_time_v6",
            (true, false, false) => "tasks_tenant_owner_time_v6",
            (true, false, true) => "tasks_tenant_owner_state_time_v6",
            (true, true, false) => "tasks_tenant_owner_context_time_v6",
            (true, true, true) => "tasks_tenant_owner_context_state_time_v6",
        };
        let mut sql = format!(
            "SELECT task_id,context_id,state,status_timestamp,revision,task_json FROM tasks INDEXED BY {index} WHERE tenant_scope=?1"
        );
        let mut values = vec![rusqlite::types::Value::Text(tenant.to_owned())];
        if own_only {
            write!(&mut sql, " AND owner_account_id=?{}", values.len() + 1)
                .expect("writing to String cannot fail");
            values.push(rusqlite::types::Value::Text(owner.to_owned()));
        }
        if let Some(context) = &request.context_id {
            write!(&mut sql, " AND context_id=?{}", values.len() + 1)
                .expect("writing to String cannot fail");
            values.push(rusqlite::types::Value::Text(context.clone()));
        }
        if let Some(status) = &request.status {
            write!(&mut sql, " AND state=?{}", values.len() + 1)
                .expect("writing to String cannot fail");
            values.push(rusqlite::types::Value::Text(
                serde_json::to_string(status)
                    .map_err(|_| A2AError::internal("task status encoding failed"))?,
            ));
        }
        if let Some(after) = request.status_timestamp_after {
            write!(&mut sql, " AND status_timestamp>=?{}", values.len() + 1)
                .expect("writing to String cannot fail");
            values.push(rusqlite::types::Value::Text(after.to_rfc3339()));
        }
        sql.push_str(" ORDER BY status_timestamp DESC,task_id ASC");
        let rows = {
            let mut statement = tx
                .prepare(&sql)
                .map_err(|_| A2AError::internal("indexed task snapshot query failed"))?;
            statement
                .query_map(rusqlite::params_from_iter(values), |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                })
                .map_err(|_| A2AError::internal("indexed task snapshot query failed"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| A2AError::internal("indexed task snapshot query failed"))?
        };
        let mut frozen = Vec::with_capacity(rows.len());
        let mut frozen_bytes = 0_i64;
        for (task_id, context_id, state, timestamp, revision, encoded) in rows {
            if !persisted_task_matches(
                &task_id,
                &context_id,
                &state,
                timestamp.as_deref(),
                &encoded,
            ) {
                return Err(A2AError::internal("persistent task record is corrupt"));
            }
            let task = project_snapshot_task(decode_task(&encoded)?, request);
            let projected = encode_task(&task)?;
            frozen_bytes = frozen_bytes
                .checked_add(
                    i64::try_from(projected.len())
                        .map_err(|_| A2AError::internal("task snapshot capacity reached"))?,
                )
                .ok_or_else(|| A2AError::internal("task snapshot capacity reached"))?;
            frozen.push((task_id, revision, projected, task));
        }
        let total_size = i64::try_from(frozen.len()).unwrap_or(i64::MAX);
        let first_len = usize::try_from(page_size)
            .expect("validated page size")
            .min(frozen.len());
        let first_tasks = frozen[..first_len]
            .iter()
            .map(|entry| entry.3.clone())
            .collect();
        if total_size <= i64::from(page_size) {
            ListTasksResponse {
                tasks: first_tasks,
                next_page_token: String::new(),
                page_size,
                total_size: i32::try_from(total_size).unwrap_or(i32::MAX),
            }
        } else {
            let (active, bytes): (i64, i64) = tx
                .query_row(
                    "SELECT COUNT(*),COALESCE(SUM(frozen_bytes),0) FROM list_snapshots",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|_| A2AError::internal("task snapshot capacity check failed"))?;
            if active >= MAX_ACTIVE_SNAPSHOTS
                || bytes.saturating_add(frozen_bytes) > MAX_SNAPSHOT_BYTES
            {
                return Err(A2AError::internal("task snapshot capacity reached"));
            }
            let snapshot_id = rand::random::<[u8; 32]>();
            let expires_at = now
                .checked_add(SNAPSHOT_TTL_MILLIS)
                .ok_or_else(|| A2AError::internal("task snapshot clock exhausted"))?;
            let seals = frozen
                .iter()
                .enumerate()
                .map(|(ordinal, (task_id, revision, encoded, _))| {
                    (
                        i64::try_from(ordinal).unwrap_or(i64::MAX),
                        task_id.clone(),
                        *revision,
                        content_digest(encoded.as_bytes()),
                    )
                })
                .collect::<Vec<_>>();
            let metadata_digest = snapshot_metadata_digest(
                cursor_key,
                &snapshot_id,
                scope_digest,
                &query_digest,
                total_size,
                i64::from(page_size),
                now,
                expires_at,
                1,
                frozen_bytes,
                &seals,
            );
            tx.execute(
                "INSERT INTO list_snapshots(snapshot_id,scope_digest,query_digest,total_size,page_size,
                 issued_at,expires_at,projection_version,frozen_bytes,metadata_digest)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,1,?8,?9)",
                params![snapshot_id.as_slice(),scope_digest,query_digest,total_size,page_size,now,expires_at,frozen_bytes,metadata_digest.as_slice()],
            )
            .map_err(|_| A2AError::internal("task snapshot persistence failed"))?;
            for (ordinal, (task_id, revision, encoded, _)) in frozen.iter().enumerate() {
                tx.execute(
                    "INSERT INTO list_snapshot_entries(snapshot_id,ordinal,task_id,task_revision,task_digest,task_json)
                     VALUES(?1,?2,?3,?4,?5,?6)",
                    params![snapshot_id.as_slice(),i64::try_from(ordinal).unwrap_or(i64::MAX),task_id,revision,content_digest(encoded.as_bytes()),encoded],
                )
                .map_err(|_| A2AError::internal("task snapshot entry persistence failed"))?;
            }
            let mut next_page_token = String::new();
            let step = i64::from(page_size);
            let mut position = step;
            while position < total_size {
                let token = insert_page_token(
                    &tx,
                    cursor_key,
                    &snapshot_id,
                    position,
                    &metadata_digest,
                    scope_digest,
                    &query_digest,
                    now,
                    expires_at,
                )?;
                if position == step {
                    next_page_token = token;
                }
                position = position
                    .checked_add(step)
                    .ok_or_else(|| A2AError::internal("task snapshot position exhausted"))?;
            }
            ListTasksResponse {
                tasks: first_tasks,
                next_page_token,
                page_size,
                total_size: i32::try_from(total_size).unwrap_or(i32::MAX),
            }
        }
    };
    if let Some(audit) = audit {
        insert_authorization_audit(&tx, audit)?;
        ensure_authorization_capacity(&tx)?;
    }
    tx.commit()
        .map_err(|_| A2AError::internal("task snapshot commit failed"))?;
    Ok(response)
}

fn persisted_task_matches(
    task_id: &str,
    context_id: &str,
    state: &str,
    timestamp: Option<&str>,
    encoded: &str,
) -> bool {
    if encoded.len() > MAX_TASK_JSON_BYTES {
        return false;
    }
    let Ok(task) = serde_json::from_str::<Task>(encoded) else {
        return false;
    };
    task.id == task_id
        && task.context_id == context_id
        && state_key(&task).is_ok_and(|value| value == state)
        && task
            .status
            .timestamp
            .map(|value| value.to_rfc3339())
            .as_deref()
            == timestamp
}

impl crate::IntoDurableAuthority for SqliteTaskStore {
    fn into_durable_authority(self) -> Arc<dyn crate::DurableAuthority> {
        Arc::new(self)
    }

    fn into_durable_authority_parts(self) -> crate::durable_authority::DurableAuthorityParts {
        let store = Arc::new(self);
        crate::durable_authority::DurableAuthorityParts::local(store.clone(), store)
    }
}

impl crate::QuotaLeaseAuthority for SqliteTaskStore {}

impl crate::AuthorityIdentity for SqliteTaskStore {
    fn capabilities(&self) -> crate::AuthorityCapabilities {
        crate::AuthorityCapabilities {
            lease_renewal: false,
            quota_reservations: false,
        }
    }

    fn completion_receipt_key(&self) -> Option<[u8; 32]> {
        Some(SqliteTaskStore::completion_receipt_key(self))
    }

    fn authorization_resource_digest(&self, resource: &str) -> Result<String, A2AError> {
        SqliteTaskStore::authorization_resource_digest(self, resource)
    }
}

impl crate::ChangeObserver for SqliteTaskStore {
    fn change_observation(&self) -> crate::ChangeObservation {
        crate::ChangeObservation::default()
    }
}

#[async_trait]
impl crate::AuthorizationAuditSink for SqliteTaskStore {
    async fn append_denied_authorization_decision(
        &self,
        audit: AuthorizationAuditInput,
    ) -> Result<(), A2AError> {
        SqliteTaskStore::append_denied_authorization_decision(self, audit).await
    }

    async fn append_authorization_decision(
        &self,
        audit: AuthorizationAuditInput,
    ) -> Result<(), A2AError> {
        SqliteTaskStore::append_authorization_decision(self, audit).await
    }
}

#[async_trait]
impl crate::AuthorizedTaskRead for SqliteTaskStore {
    async fn get_authorized(
        &self,
        scope: &OwnedTaskScope,
        task_id: &str,
        audit: AuthorizationAuditInput,
    ) -> Result<Option<Task>, A2AError> {
        SqliteTaskStore::get_authorized(self, scope, task_id, audit).await
    }

    async fn list_authorized(
        &self,
        scope: &OwnedTaskScope,
        request: &ListTasksRequest,
        audit: AuthorizationAuditInput,
        cursor_scope_digest: &str,
    ) -> Result<ListTasksResponse, A2AError> {
        SqliteTaskStore::list_authorized(self, scope, request, audit, cursor_scope_digest).await
    }
}

#[async_trait]
impl crate::TaskAdmission for SqliteTaskStore {
    async fn replay_authorized(
        &self,
        scope: &OwnedTaskScope,
        actor_account_id: &str,
        request: &SendMessageRequest,
        streaming: bool,
        audit: AuthorizationAuditInput,
    ) -> Result<Option<SendMessageResponse>, A2AError> {
        SqliteTaskStore::replay_authorized(self, scope, actor_account_id, request, streaming, audit)
            .await
    }

    async fn authorize_and_admit(
        &self,
        scope: &OwnedTaskScope,
        command: SendMessageAdmission,
        audit: AuthorizationAuditInput,
    ) -> Result<AdmissionOutcome, A2AError> {
        SqliteTaskStore::authorize_and_admit(self, scope, command, audit).await
    }

    async fn authorize_and_continue(
        &self,
        scope: &OwnedTaskScope,
        command: SendMessageAdmission,
        audit: AuthorizationAuditInput,
    ) -> Result<AdmissionOutcome, A2AError> {
        SqliteTaskStore::authorize_and_continue(self, scope, command, audit).await
    }

    async fn authorize_and_admit_mutation(
        &self,
        scope: &OwnedTaskScope,
        mutation: crate::AuthorizedMutation<SendMessageAdmission>,
        audit: AuthorizationAuditInput,
    ) -> Result<AdmissionOutcome, A2AError> {
        let (command, quota, intent) = mutation.into_authority_parts();
        if quota.is_some() || intent.is_some() {
            return Err(A2AError::unsupported_operation(
                "quota reservations are unsupported by SQLite",
            ));
        }
        SqliteTaskStore::authorize_and_admit(self, scope, command, audit).await
    }

    async fn authorize_and_continue_mutation(
        &self,
        scope: &OwnedTaskScope,
        mutation: crate::AuthorizedMutation<SendMessageAdmission>,
        audit: AuthorizationAuditInput,
    ) -> Result<AdmissionOutcome, A2AError> {
        let (command, quota, intent) = mutation.into_authority_parts();
        if quota.is_some() || intent.is_some() {
            return Err(A2AError::unsupported_operation(
                "quota reservations are unsupported by SQLite",
            ));
        }
        SqliteTaskStore::authorize_and_continue(self, scope, command, audit).await
    }
}

#[async_trait]
impl crate::TaskLifecycle for SqliteTaskStore {
    async fn final_result_scoped(
        &self,
        tenant_scope: &str,
        message_id: &str,
    ) -> Result<Option<SendMessageResponse>, A2AError> {
        SqliteTaskStore::final_result_for_message_scoped(self, tenant_scope, message_id).await
    }
}

#[async_trait]
impl crate::CancellationAuthority for SqliteTaskStore {
    async fn cancel_authorized(
        &self,
        scope: &OwnedTaskScope,
        task_id: &str,
        now: i64,
        audit: AuthorizationAuditInput,
    ) -> Result<CancellationOutcome, A2AError> {
        SqliteTaskStore::cancel_authorized(self, scope, task_id, now, audit).await
    }

    async fn cancel_authorized_with_quota(
        &self,
        scope: &OwnedTaskScope,
        task_id: &str,
        now: i64,
        audit: AuthorizationAuditInput,
        quota: Option<&crate::QuotaReservationInput>,
        quota_intent: Option<&crate::QuotaIntent>,
    ) -> Result<CancellationOutcome, A2AError> {
        if quota.is_some() || quota_intent.is_some() {
            return Err(A2AError::unsupported_operation(
                "quota reservations are unsupported by SQLite",
            ));
        }
        SqliteTaskStore::cancel_authorized(self, scope, task_id, now, audit).await
    }
}

#[async_trait]
impl crate::OutboxAuthority for SqliteTaskStore {
    async fn claim_outbox(
        &self,
        lease_owner: &str,
        now: i64,
        lease_duration: i64,
    ) -> Result<Option<OutboxLease>, A2AError> {
        SqliteTaskStore::claim_outbox(self, lease_owner.to_owned(), now, lease_duration).await
    }

    async fn renew_outbox_lease(
        &self,
        _: &OutboxLease,
        _: i64,
    ) -> Result<crate::LeaseRenewalOutcome, A2AError> {
        Ok(crate::LeaseRenewalOutcome::Unsupported)
    }

    async fn task_for_outbox(&self, lease: &OutboxLease) -> Result<Option<Task>, A2AError> {
        let scope = OwnedTaskScope::new(
            &lease.tenant_scope,
            "durable-outbox-driver",
            VisibilityScope::Tenant,
        )?;
        SqliteTaskStore::get_scoped(self, &scope, &lease.task_id).await
    }

    async fn finish_outbox_attempt(
        &self,
        lease: &OutboxLease,
        disposition: AttemptDisposition,
        now: i64,
    ) -> Result<TransitionOutcome, A2AError> {
        SqliteTaskStore::finish_outbox_attempt(self, lease, disposition, now).await
    }

    async fn append_stream_progress(
        &self,
        tenant_scope: &str,
        dispatch_id: &str,
        frame: StreamResponse,
        now: i64,
    ) -> Result<Option<StreamResponse>, A2AError> {
        SqliteTaskStore::append_stream_progress(self, tenant_scope, dispatch_id, frame, now).await
    }

    async fn commit_delivery(
        &self,
        lease: &OutboxLease,
        task: Task,
        result: SendMessageResponse,
        public_transcript: &[StreamResponse],
        now: i64,
    ) -> Result<TransitionOutcome, A2AError> {
        SqliteTaskStore::commit_delivery(self, lease, task, result, public_transcript, now).await
    }
}

#[async_trait]
impl crate::ReceiverAuthority for SqliteTaskStore {
    async fn begin_receive(
        &self,
        envelope: DurableDispatchEnvelope,
        lease_owner: &str,
        now: i64,
        lease_duration: i64,
    ) -> Result<ReceiverAdmission, A2AError> {
        SqliteTaskStore::begin_receive(self, envelope, lease_owner, now, lease_duration).await
    }

    async fn renew_receiver_lease(
        &self,
        _: &ReceiverLease,
        _: i64,
    ) -> Result<crate::LeaseRenewalOutcome, A2AError> {
        Ok(crate::LeaseRenewalOutcome::Unsupported)
    }

    async fn complete_loopback_receive(
        &self,
        lease: &ReceiverLease,
        events: &[MeshEvent],
        now: i64,
    ) -> Result<(), A2AError> {
        SqliteTaskStore::complete_loopback_receive(self, lease, events, now).await
    }

    async fn complete_loopback_outcome(
        &self,
        lease: &ReceiverLease,
        outcome: &DurableReceiverResult,
        now: i64,
    ) -> Result<(), A2AError> {
        SqliteTaskStore::complete_loopback_outcome(self, lease, outcome, now).await
    }

    async fn complete_canceled_receive(
        &self,
        lease: &ReceiverLease,
        events: &[MeshEvent],
        now: i64,
    ) -> Result<(), A2AError> {
        SqliteTaskStore::complete_canceled_receive(self, lease, events, now).await
    }

    async fn cancellation_requested(&self, dispatch_id: &str) -> Result<bool, A2AError> {
        SqliteTaskStore::cancellation_requested(self, dispatch_id).await
    }
}

#[async_trait]
impl crate::TranscriptAuthority for SqliteTaskStore {
    async fn stream_frames_after_scoped(
        &self,
        tenant_scope: &str,
        message_id: &str,
        last_sequence: usize,
    ) -> Result<StreamTranscriptBatch, A2AError> {
        SqliteTaskStore::stream_frames_after_scoped(self, tenant_scope, message_id, last_sequence)
            .await
    }

    async fn subscription_snapshot_authorized(
        &self,
        scope: &OwnedTaskScope,
        task_id: &str,
    ) -> Result<Option<(Task, SubscriptionCursor)>, A2AError> {
        SqliteTaskStore::subscription_snapshot_authorized(self, scope, task_id).await
    }

    async fn task_events_after_scoped(
        &self,
        scope: &OwnedTaskScope,
        task_id: &str,
        last_revision: u64,
    ) -> Result<TaskEventBatch, A2AError> {
        SqliteTaskStore::task_events_after_scoped(self, scope, task_id, last_revision).await
    }
}

#[async_trait]
impl crate::AuthorityDiagnostics for SqliteTaskStore {
    async fn authorization_decision_count(&self) -> Result<u64, A2AError> {
        SqliteTaskStore::authorization_decision_count(self).await
    }

    async fn atomic_record_counts(&self) -> Result<AtomicRecordCounts, A2AError> {
        SqliteTaskStore::atomic_record_counts(self).await
    }

    async fn durable_effect_count(&self) -> Result<u64, A2AError> {
        SqliteTaskStore::durable_effect_count(self).await
    }
}

#[async_trait]
impl crate::AuthorityShutdown for SqliteTaskStore {
    async fn shutdown(&self) -> Result<(), A2AError> {
        SqliteTaskStore::shutdown_shared(self).await
    }

    fn close_owned_sync(&self) {
        SqliteTaskStore::close_shared_sync(self);
    }
}

#[async_trait]
impl crate::durable_authority::LocalDevelopmentCompatibility for SqliteTaskStore {
    async fn get(&self, task_id: &str) -> Result<Option<Task>, A2AError> {
        TaskStore::get(self, task_id).await
    }

    async fn list(&self, request: &ListTasksRequest) -> Result<ListTasksResponse, A2AError> {
        TaskStore::list(self, request).await
    }

    async fn replay(
        &self,
        request: &SendMessageRequest,
        streaming: bool,
    ) -> Result<Option<SendMessageResponse>, A2AError> {
        SqliteTaskStore::replay_send_message(self, request, streaming).await
    }

    async fn admit(&self, command: SendMessageAdmission) -> Result<AdmissionOutcome, A2AError> {
        SqliteTaskStore::admit_send_message(self, command).await
    }

    async fn continue_task(
        &self,
        command: SendMessageAdmission,
    ) -> Result<AdmissionOutcome, A2AError> {
        SqliteTaskStore::admit_continuation(self, command).await
    }

    async fn final_result(
        &self,
        message_id: &str,
    ) -> Result<Option<SendMessageResponse>, A2AError> {
        SqliteTaskStore::final_result_for_message(self, message_id).await
    }

    async fn cancel(&self, task_id: &str, now: i64) -> Result<CancellationOutcome, A2AError> {
        SqliteTaskStore::request_cancellation(self, task_id, now).await
    }

    async fn stream_frames_after(
        &self,
        message_id: &str,
        last_sequence: usize,
    ) -> Result<StreamTranscriptBatch, A2AError> {
        SqliteTaskStore::stream_frames_after(self, message_id, last_sequence).await
    }

    async fn subscription_snapshot(
        &self,
        task_id: &str,
    ) -> Result<Option<(Task, SubscriptionCursor)>, A2AError> {
        SqliteTaskStore::subscription_snapshot(self, task_id).await
    }

    async fn task_events_after(
        &self,
        task_id: &str,
        last_revision: u64,
    ) -> Result<TaskEventBatch, A2AError> {
        SqliteTaskStore::task_events_after(self, task_id, last_revision).await
    }
}

#[async_trait]
impl TaskStore for SqliteTaskStore {
    async fn create(&self, task: Task) -> Result<u64, A2AError> {
        let max_tasks = self.max_tasks;
        let tenant_scope = self.default_scope.to_string();
        let owner_account_id = self.default_account.to_string();
        let encoded = encode_task(&task)?;
        let state = state_key(&task)?;
        let timestamp = task.status.timestamp.map(|value| value.to_rfc3339());
        self.run(move |connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| A2AError::internal("persistent task transaction failed"))?;
            let exists: bool = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM tasks WHERE task_id = ?1)",
                    [&task.id],
                    |row| row.get(0),
                )
                .map_err(|_| A2AError::internal("persistent task query failed"))?;
            if exists {
                return Err(A2AError::invalid_request("task already exists"));
            }
            let count: i64 = transaction
                .query_row("SELECT COUNT(*) FROM tasks", [], |row| row.get(0))
                .map_err(|_| A2AError::internal("persistent task count failed"))?;
            if usize::try_from(count).unwrap_or(usize::MAX) >= max_tasks {
                return Err(A2AError::internal("task store capacity reached"));
            }
            let aggregate_bytes: i64 = transaction
                .query_row("SELECT COALESCE(SUM(length(CAST(task_json AS BLOB))), 0) FROM tasks", [], |row| row.get(0))
                .map_err(|_| A2AError::internal("persistent task size query failed"))?;
            if usize::try_from(aggregate_bytes).unwrap_or(usize::MAX).saturating_add(encoded.len()) > MAX_STORE_JSON_BYTES {
                return Err(A2AError::internal("task store byte capacity reached"));
            }
            transaction
                .execute(
                    "INSERT INTO tasks(task_id, context_id, state, status_timestamp, revision, task_json, tenant_scope, owner_account_id)
                     VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7)",
                    params![task.id, task.context_id, state, timestamp, encoded, tenant_scope, owner_account_id],
                )
                .map_err(|_| A2AError::internal("persistent task insert failed"))?;
            transaction
                .execute(
                    "INSERT INTO task_events(tenant_scope, task_id, event_seq, task_revision,
                         event_kind, from_state, to_state, event_json, created_at)
                     VALUES (?1, ?2, 1, 1, 'sdk_create', NULL, ?3, ?4, ?5)",
                    params![
                        tenant_scope,
                        task.id,
                        state,
                        encoded,
                        chrono::Utc::now().timestamp_millis()
                    ],
                )
                .map_err(|_| A2AError::internal("persistent task event append failed"))?;
            ensure_atomic_capacity(&transaction)?;
            transaction
                .commit()
                .map_err(|_| A2AError::internal("persistent task commit failed"))?;
            Ok(1)
        })
        .await
    }

    async fn update(&self, task: Task) -> Result<u64, A2AError> {
        let encoded = encode_task(&task)?;
        let state = state_key(&task)?;
        let timestamp = task.status.timestamp.map(|value| value.to_rfc3339());
        self.run(move |connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| A2AError::internal("persistent task transaction failed"))?;
            let current: Option<(String, u64)> = transaction
                .query_row(
                    "SELECT task_json, revision FROM tasks WHERE task_id = ?1",
                    [&task.id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|_| A2AError::internal("persistent task query failed"))?;
            let Some((current_json, revision)) = current else {
                return Err(A2AError::task_not_found(&task.id));
            };
            let aggregate_bytes: i64 = transaction
                .query_row(
                    "SELECT COALESCE(SUM(length(CAST(task_json AS BLOB))), 0) FROM tasks",
                    [],
                    |row| row.get(0),
                )
                .map_err(|_| A2AError::internal("persistent task size query failed"))?;
            let projected = usize::try_from(aggregate_bytes)
                .unwrap_or(usize::MAX)
                .saturating_sub(current_json.len())
                .saturating_add(encoded.len());
            if projected > MAX_STORE_JSON_BYTES {
                return Err(A2AError::internal("task store byte capacity reached"));
            }
            let current_task = decode_task(&current_json)?;
            // The upstream SDK may persist a snapshot already committed by the
            // repository-owned lifecycle driver. Exact duplicates are true no-ops.
            if current_task == task {
                return Ok(revision);
            }
            if current_task.status.state.is_terminal() {
                return Err(A2AError::unsupported_operation(
                    "terminal task state cannot be changed",
                ));
            }
            if !legal_transition(&current_task.status.state, &task.status.state) {
                return Err(A2AError::unsupported_operation(
                    "task lifecycle transition is not allowed",
                ));
            }
            let previous_state = state_key(&current_task)?;
            let next_revision = revision
                .checked_add(1)
                .ok_or_else(|| A2AError::internal("persistent task revision exhausted"))?;
            transaction
                .execute(
                    "UPDATE tasks
                     SET context_id = ?2, state = ?3, status_timestamp = ?4,
                         revision = ?5, task_json = ?6
                     WHERE task_id = ?1",
                    params![
                        task.id,
                        task.context_id,
                        state,
                        timestamp,
                        next_revision,
                        encoded
                    ],
                )
                .map_err(|_| A2AError::internal("persistent task update failed"))?;
            let event_seq: i64 = transaction
                .query_row(
                    "SELECT COALESCE(MAX(event_seq), 0) + 1 FROM task_events
                     WHERE tenant_scope = ?1 AND task_id = ?2",
                    params![TRUSTED_SINGLE_TENANT_SCOPE, task.id],
                    |row| row.get(0),
                )
                .map_err(|_| A2AError::internal("persistent task event sequence failed"))?;
            transaction
                .execute(
                    "INSERT INTO task_events(tenant_scope, task_id, event_seq, task_revision,
                         event_kind, from_state, to_state, event_json, created_at)
                     VALUES (?1, ?2, ?3, ?4, 'sdk_update', ?5, ?6, ?7, ?8)",
                    params![
                        TRUSTED_SINGLE_TENANT_SCOPE,
                        task.id,
                        event_seq,
                        next_revision,
                        previous_state,
                        state,
                        encoded,
                        chrono::Utc::now().timestamp_millis()
                    ],
                )
                .map_err(|_| A2AError::internal("persistent task event append failed"))?;
            ensure_atomic_capacity(&transaction)?;
            transaction
                .commit()
                .map_err(|_| A2AError::internal("persistent task commit failed"))?;
            Ok(next_revision)
        })
        .await
    }

    async fn get(&self, task_id: &str) -> Result<Option<Task>, A2AError> {
        let task_id = task_id.to_owned();
        self.run(move |connection| {
            let record: Option<(String, String, String, Option<String>, String)> = connection
                .query_row(
                    "SELECT task_id, context_id, state, status_timestamp, task_json
                     FROM tasks WHERE task_id = ?1",
                    [&task_id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .optional()
                .map_err(|_| A2AError::internal("persistent task query failed"))?;
            let Some((stored_id, context_id, state, timestamp, encoded)) = record else {
                return Ok(None);
            };
            if !persisted_task_matches(
                &stored_id,
                &context_id,
                &state,
                timestamp.as_deref(),
                &encoded,
            ) {
                return Err(A2AError::internal("persistent task record is corrupt"));
            }
            decode_task(&encoded).map(Some)
        })
        .await
    }

    async fn list(&self, request: &ListTasksRequest) -> Result<ListTasksResponse, A2AError> {
        let request = request.clone();
        let cursor_key = *self.cursor_key;
        let tenant = self.default_scope.to_string();
        let owner = self.default_account.to_string();
        let scope_digest =
            content_digest(format!("development-list-v1\0{tenant}\0{owner}").as_bytes());
        let now = chrono::Utc::now().timestamp_millis();
        self.run(move |connection| {
            frozen_list_transaction(
                connection,
                &tenant,
                &owner,
                false,
                &request,
                &scope_digest,
                &cursor_key,
                now,
                None,
            )
        })
        .await
    }
}

crate::impl_unsupported_artifact_authority!(SqliteTaskStore);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_schema_lookup_does_not_confuse_table_with_prefixed_index() {
        let reordered =
            "CREATE INDEX outbox_due ON outbox(state); CREATE TABLE outbox (state TEXT);";
        assert_eq!(
            expected_schema_sql(reordered, "outbox"),
            Some("createtableoutbox(statetext)".to_owned())
        );
        assert_eq!(
            expected_schema_sql(reordered, "outbox_due"),
            Some("createindexoutbox_dueonoutbox(state)".to_owned())
        );
    }

    #[test]
    fn list_query_families_use_exact_ordering_indexes_without_temp_sort() {
        let mut connection = Connection::open_in_memory().unwrap();
        initialize_schema(&mut connection, &LegacyTenantBinding::development()).unwrap();
        let families = [
            ("tasks_tenant_time_v6", "tenant_scope=?1"),
            ("tasks_tenant_state_time_v6", "tenant_scope=?1 AND state=?2"),
            (
                "tasks_tenant_context_time_v6",
                "tenant_scope=?1 AND context_id=?2",
            ),
            (
                "tasks_tenant_context_state_time_v6",
                "tenant_scope=?1 AND context_id=?2 AND state=?3",
            ),
            (
                "tasks_tenant_owner_time_v6",
                "tenant_scope=?1 AND owner_account_id=?2",
            ),
            (
                "tasks_tenant_owner_state_time_v6",
                "tenant_scope=?1 AND owner_account_id=?2 AND state=?3",
            ),
            (
                "tasks_tenant_owner_context_time_v6",
                "tenant_scope=?1 AND owner_account_id=?2 AND context_id=?3",
            ),
            (
                "tasks_tenant_owner_context_state_time_v6",
                "tenant_scope=?1 AND owner_account_id=?2 AND context_id=?3 AND state=?4",
            ),
        ];
        for (index, predicate) in families {
            let sql = format!(
                "EXPLAIN QUERY PLAN SELECT task_id,revision,task_json FROM tasks
                 INDEXED BY {index} WHERE {predicate}
                 ORDER BY status_timestamp DESC,task_id ASC LIMIT 11"
            );
            let mut statement = connection.prepare(&sql).unwrap();
            let parameter_count = statement.parameter_count();
            let values =
                (0..parameter_count).map(|_| rusqlite::types::Value::Text("fixture".to_owned()));
            let details = statement
                .query_map(rusqlite::params_from_iter(values), |row| {
                    row.get::<_, String>(3)
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .join(" ");
            assert!(details.contains(index), "{sql}: {details}");
            assert!(!details.contains("SCAN tasks"), "{sql}: {details}");
            assert!(!details.contains("TEMP B-TREE"), "{sql}: {details}");
        }
    }

    fn task(id: &str, state: a2a::TaskState) -> Task {
        Task {
            id: id.to_owned(),
            context_id: "recovery-transaction".to_owned(),
            status: a2a::TaskStatus {
                state,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        }
    }

    #[test]
    fn recovery_failure_rolls_back_every_orphan_transition() {
        let mut connection = Connection::open_in_memory().unwrap();
        initialize_schema(&mut connection, &LegacyTenantBinding::development()).unwrap();
        for value in [
            task("recover-a", a2a::TaskState::Working),
            task("recover-b", a2a::TaskState::Submitted),
        ] {
            let encoded = encode_task(&value).unwrap();
            let state = state_key(&value).unwrap();
            connection
                .execute(
                    "INSERT INTO tasks(
                         task_id, context_id, state, status_timestamp, revision, task_json
                     ) VALUES (?1, ?2, ?3, NULL, 1, ?4)",
                    params![value.id, value.context_id, state, encoded],
                )
                .unwrap();
        }
        connection
            .execute_batch(
                "CREATE TRIGGER reject_second_recovery
                 BEFORE UPDATE ON tasks
                 WHEN OLD.task_id = 'recover-b'
                 BEGIN
                     SELECT RAISE(ABORT, 'injected recovery failure');
                 END;",
            )
            .unwrap();

        assert!(recover_orphaned_tasks(&mut connection).is_err());
        let states = ["recover-a", "recover-b"].map(|id| {
            connection
                .query_row("SELECT state FROM tasks WHERE task_id = ?1", [id], |row| {
                    row.get::<_, String>(0)
                })
                .unwrap()
        });
        assert_eq!(
            states,
            [
                "\"TASK_STATE_WORKING\"".to_owned(),
                "\"TASK_STATE_SUBMITTED\"".to_owned(),
            ]
        );
    }

    #[test]
    fn migration_transaction_fault_rolls_back_schema_and_version() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(V1_SCHEMA_SQL).unwrap();
        connection
            .execute(
                "INSERT INTO store_metadata(
                     singleton, schema_version, migration_hash, cursor_key, receipt_key
                 ) VALUES (1, 1, ?1, ?2, ?3)",
                params![
                    content_digest(V1_SCHEMA_SQL.as_bytes()),
                    [3_u8; 32],
                    [4_u8; 32]
                ],
            )
            .unwrap();
        connection
            .pragma_update(None, "application_id", APPLICATION_ID)
            .unwrap();
        connection.pragma_update(None, "user_version", 1).unwrap();
        connection
            .execute_batch(
                "CREATE TEMP TRIGGER reject_migration_metadata
                 BEFORE UPDATE ON store_metadata
                 BEGIN SELECT RAISE(ABORT, 'injected migration failure'); END;",
            )
            .unwrap();

        assert!(migrate_v1_to_v2(&mut connection, 8).is_err());
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let atomic_tables: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name IN
                     ('task_events', 'idempotency_records', 'outbox', 'outbox_attempts')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!((version, atomic_tables), (1, 0));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn active_v4_outbox_migrates_with_preserved_legacy_dispatch_identity() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(V1_SCHEMA_SQL).unwrap();
        connection
            .execute(
                "INSERT INTO store_metadata(
                     singleton, schema_version, migration_hash, cursor_key, receipt_key
                 ) VALUES (1, 1, ?1, ?2, ?3)",
                params![
                    content_digest(V1_SCHEMA_SQL.as_bytes()),
                    [3_u8; 32],
                    [4_u8; 32]
                ],
            )
            .unwrap();
        connection
            .pragma_update(None, "application_id", APPLICATION_ID)
            .unwrap();
        connection.pragma_update(None, "user_version", 1).unwrap();
        migrate_v1_to_v2(&mut connection, 8).unwrap();

        let mut message = a2a::Message::new(a2a::Role::User, vec![a2a::Part::text("migrate")]);
        message.message_id = "legacy-active-message".to_owned();
        let task = Task {
            id: "legacy-active-task".to_owned(),
            context_id: "legacy-active-context".to_owned(),
            status: a2a::TaskStatus {
                state: a2a::TaskState::Submitted,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: Some(vec![message.clone()]),
            metadata: None,
        };
        let request = a2a::SendMessageRequest {
            message,
            configuration: None,
            metadata: None,
            tenant: None,
        };
        let mesh = MeshRequest::from_a2a(
            task.id.clone(),
            task.context_id.clone(),
            &request.message,
            InputLimits::default(),
        )
        .unwrap();
        let task_json = encode_task(&task).unwrap();
        let state = state_key(&task).unwrap();
        let admission = serde_json::to_string(&SendMessageResponse::Task(task.clone())).unwrap();
        let payload = serde_json::to_string(&mesh).unwrap();
        let dispatch_id = content_digest(
            format!(
                "{}\0send-message\0{}",
                LEGACY_V4_SENTINEL_SCOPE, request.message.message_id
            )
            .as_bytes(),
        );
        connection
            .execute(
                "INSERT INTO tasks(task_id, context_id, state, revision, task_json)
                 VALUES(?1, ?2, ?3, 1, ?4)",
                params![task.id, task.context_id, state, task_json],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO task_events(tenant_scope, task_id, event_seq, task_revision,
                     event_kind, from_state, to_state, event_json, created_at)
                 VALUES(?1, ?2, 1, 1, 'admission', NULL, ?3, ?4, 100)",
                params![LEGACY_V4_SENTINEL_SCOPE, task.id, state, task_json],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO idempotency_records(tenant_scope, message_id, request_digest,
                     task_id, state, admission_result_json, created_at, updated_at)
                 VALUES(?1, ?2, ?3, ?4, 'in_progress', ?5, 100, 100)",
                params![
                    LEGACY_V4_SENTINEL_SCOPE,
                    request.message.message_id,
                    canonical_send_message_digest(&request, false).unwrap(),
                    task.id,
                    admission
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO outbox(dispatch_id, tenant_scope, task_id, causative_revision,
                     payload_json, payload_digest, state, attempt_count, max_attempts,
                     available_at, created_at, updated_at)
                 VALUES(?1, ?2, ?3, 1, ?4, ?5, 'pending', 0, 8, 100, 100, 100)",
                params![
                    dispatch_id,
                    LEGACY_V4_SENTINEL_SCOPE,
                    task.id,
                    payload,
                    content_digest(payload.as_bytes())
                ],
            )
            .unwrap();

        migrate_v2_to_v3(&mut connection, 8).unwrap();
        migrate_v3_to_v4(&mut connection, 8).unwrap();
        let binding = LegacyTenantBinding::new(
            "tenant-a",
            "owner-a",
            "policy-a",
            1,
            content_digest(b"policy-a"),
        )
        .unwrap();
        connection
            .execute("UPDATE outbox SET dispatch_id='corrupt-dispatch'", [])
            .unwrap();
        assert!(migrate_v4_to_v5(&mut connection, 8, &binding).is_err());
        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            4
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE name='store_identity'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        connection
            .execute("UPDATE outbox SET dispatch_id=?1", [&dispatch_id])
            .unwrap();
        migrate_v4_to_v5(&mut connection, 8, &binding).unwrap();

        let migrated: (String, String, i64) = connection
            .query_row(
                "SELECT tenant_scope, dispatch_id, dispatch_identity_version FROM outbox",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(migrated, ("tenant-a".to_owned(), dispatch_id, 1));
        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            5
        );
        validate_persisted_records(&connection, 8).unwrap();
    }
}
