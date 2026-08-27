#![cfg_attr(not(unix), allow(dead_code))]

use std::fs::File;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use a2a::{
    A2AError, ListTasksRequest, ListTasksResponse, Message, Part, Role, SendMessageRequest,
    SendMessageResponse, Task,
};
use a2a_server::TaskStore;
use async_trait::async_trait;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;

use crate::{InputLimits, MeshRequest, content_digest, store::list_tasks_response};

const SCHEMA_VERSION: i64 = 2;
const APPLICATION_ID: i64 = 0x534D_4132;
const MAX_TASK_JSON_BYTES: usize = 1024 * 1024;
const MAX_STORE_JSON_BYTES: usize = 64 * 1024 * 1024;
const MAX_ATOMIC_JSON_BYTES: usize = 1024 * 1024;
const MAX_ATOMIC_TEXT_BYTES: usize = 4096;
const MAX_OUTBOX_ATTEMPTS: u32 = 1_000;
/// Authority is deliberately not caller controlled. Authenticated multi-tenant scoping is #13.
pub const TRUSTED_SINGLE_TENANT_SCOPE: &str = "smesh:trusted-single-tenant:v1";

/// Canonical semantic identity for `SendMessage` admission. Transport IDs/bindings
/// and caller-controlled tenant/header values are deliberately excluded.
///
/// # Errors
///
/// Returns an internal error if the semantic request cannot be encoded.
pub fn canonical_send_message_digest(
    request: &SendMessageRequest,
    streaming: bool,
) -> Result<String, A2AError> {
    let semantic = serde_json::json!({
        "configuration": request.configuration,
        "invocation": if streaming { "streaming" } else { "unary" },
        "message": request.message,
        "metadata": request.metadata,
        "operation": "sendMessage",
        "trustedScope": TRUSTED_SINGLE_TENANT_SCOPE,
    });
    let encoded = serde_json::to_vec(&semantic)
        .map_err(|_| A2AError::internal("failed to canonicalize send-message request"))?;
    Ok(content_digest(&encoded))
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
const SCHEMA_SQL: &str = "CREATE TABLE store_metadata (
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

#[derive(Debug, Clone, PartialEq)]
pub struct SendMessageAdmission {
    pub request: SendMessageRequest,
    pub streaming: bool,
    pub task: Task,
    pub original_result: SendMessageResponse,
    pub input_limits: InputLimits,
    pub now: i64,
    pub max_attempts: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionRecord {
    pub task_id: String,
    pub revision: u64,
    pub dispatch_id: String,
}

// Keeping the typed replay inline makes the public API exact and allocation-free
// for its dominant admitted case; response payload size is durably bounded.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum AdmissionOutcome {
    Admitted(AdmissionRecord),
    Replay(SendMessageResponse),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxLease {
    pub outbox_id: i64,
    pub dispatch_id: String,
    pub task_id: String,
    pub attempt_no: u32,
    pub max_attempts: u32,
    pub lease_owner: String,
    pub lease_token: String,
    pub lease_until: i64,
    pub request: MeshRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptDisposition {
    Retry { available_at: i64, error: String },
    Permanent { error: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionOutcome {
    Applied,
    Idempotent,
    Stale,
    DeadLettered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtomicRecordCounts {
    pub tasks: u64,
    pub events: u64,
    pub idempotency_records: u64,
    pub outbox: u64,
}

#[derive(Clone)]
pub struct SqliteTaskStore {
    connection: Arc<Mutex<Connection>>,
    _ownership_lock: Arc<File>,
    admission: Arc<tokio::sync::Semaphore>,
    cursor_key: Arc<[u8; 32]>,
    receipt_key: Arc<[u8; 32]>,
    max_tasks: usize,
}

impl SqliteTaskStore {
    /// Open or create a versioned SQLite task store.
    ///
    /// # Errors
    ///
    /// Returns an error for symbolic-link paths, unknown/corrupt schemas, or initialization failure.
    pub async fn open(path: impl AsRef<Path>, max_tasks: usize) -> Result<Self, SqliteStoreError> {
        #[cfg(not(unix))]
        {
            let _ = (path, max_tasks);
            Err(SqliteStoreError::UnsupportedPlatform)
        }

        #[cfg(unix)]
        {
            let path = path.as_ref().to_path_buf();
            prepare_secure_path(&path)?;
            let ownership_lock = acquire_ownership_lock(&path)?;
            let capacity = max_tasks.max(1);
            let (connection, cursor_key, receipt_key) =
                tokio::task::spawn_blocking(move || open_database(&path, capacity))
                    .await
                    .map_err(|_| SqliteStoreError::Initialization)??;
            secure_permissions(&connection)?;
            Ok(Self {
                connection: Arc::new(Mutex::new(connection)),
                _ownership_lock: Arc::new(ownership_lock),
                admission: Arc::new(tokio::sync::Semaphore::new(1)),
                cursor_key: Arc::new(cursor_key),
                receipt_key: Arc::new(receipt_key),
                max_tasks: capacity,
            })
        }
    }

    #[must_use]
    pub fn completion_receipt_key(&self) -> [u8; 32] {
        *self.receipt_key
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
        let digest = canonical_send_message_digest(&command.request, command.streaming)?;
        let dispatch = MeshRequest::from_a2a(
            command.task.id.clone(),
            command.task.context_id.clone(),
            &command.request.message,
            command.input_limits,
        )
        .map_err(|error| A2AError::invalid_params(error.to_string()))?;
        self.admit_message(
            command.task,
            digest,
            command.original_result,
            dispatch,
            command.now,
            command.max_attempts,
        )
        .await
    }

    /// Atomically reserve message identity, create the task/event, and enqueue dispatch.
    ///
    /// # Errors
    ///
    /// Returns an A2A error for invalid identity/payload bounds, conflicts, capacity,
    /// serialization failures, or any transactional storage failure.
    #[allow(clippy::too_many_lines)]
    async fn admit_message(
        &self,
        task: Task,
        request_digest: impl Into<String>,
        original_result: SendMessageResponse,
        request: MeshRequest,
        now: i64,
        max_attempts: u32,
    ) -> Result<AdmissionOutcome, A2AError> {
        let request_digest = request_digest.into();
        let message_id = task
            .history
            .as_ref()
            .and_then(|history| history.last())
            .map(|message| message.message_id.clone())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                A2AError::invalid_params("messageId is required for durable admission")
            })?;
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
        let dispatch_id = content_digest(
            format!("{TRUSTED_SINGLE_TENANT_SCOPE}\0send-message\0{message_id}").as_bytes(),
        );
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
                    params![TRUSTED_SINGLE_TENANT_SCOPE, message_id],
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
                    "INSERT INTO tasks(task_id, context_id, state, status_timestamp, revision, task_json)
                     VALUES (?1, ?2, ?3, ?4, 1, ?5)",
                    params![task.id, task.context_id, state, timestamp, encoded_task],
                )
                .map_err(|_| A2AError::invalid_request("task already exists"))?;
            transaction
                .execute(
                    "INSERT INTO task_events(
                         tenant_scope, task_id, event_seq, task_revision, event_kind,
                         from_state, to_state, event_json, created_at
                     ) VALUES (?1, ?2, 1, 1, 'admitted', NULL, ?3, ?4, ?5)",
                    params![TRUSTED_SINGLE_TENANT_SCOPE, task.id, state, encoded_task, now],
                )
                .map_err(|_| A2AError::internal("atomic event append failed"))?;
            transaction
                .execute(
                    "INSERT INTO idempotency_records(
                         tenant_scope, message_id, request_digest, task_id, state,
                         admission_result_json, final_result_json, created_at, updated_at
                     ) VALUES (?1, ?2, ?3, ?4, 'in_progress', ?5, NULL, ?6, ?6)",
                    params![
                        TRUSTED_SINGLE_TENANT_SCOPE,
                        message_id,
                        request_digest,
                        task.id,
                        result_json,
                        now
                    ],
                )
                .map_err(|_| A2AError::internal("idempotency reservation failed"))?;
            transaction
                .execute(
                    "INSERT INTO outbox(
                         dispatch_id, tenant_scope, task_id, causative_revision,
                         payload_json, payload_digest, state, attempt_count,
                         max_attempts, available_at, created_at, updated_at
                     ) VALUES (?1, ?2, ?3, 1, ?4, ?5, 'pending', 0, ?6, ?7, ?7, ?7)",
                    params![
                        dispatch_id,
                        TRUSTED_SINGLE_TENANT_SCOPE,
                        task.id,
                        payload_json,
                        payload_digest,
                        max_attempts,
                        now
                    ],
                )
                .map_err(|_| A2AError::internal("atomic outbox enqueue failed"))?;
            ensure_atomic_capacity(&transaction)?;
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
        let digest = canonical_send_message_digest(&command.request, command.streaming)?;
        if !matches!(
            command.task.status.state,
            a2a::TaskState::InputRequired | a2a::TaskState::AuthRequired
        ) {
            return Err(A2AError::unsupported_operation(
                "only interrupted tasks accept durable continuation",
            ));
        }
        let result_json = serde_json::to_string(&command.original_result)
            .map_err(|_| A2AError::internal("failed to encode continuation result"))?;
        let dispatch_id = content_digest(
            format!("{TRUSTED_SINGLE_TENANT_SCOPE}\0send-message\0{message_id}").as_bytes(),
        );
        let now = command.now;
        let max_attempts = command.max_attempts;
        let expected_task = command.task;
        let request = command.request;
        let input_limits = command.input_limits;
        self.run(move |connection| {
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| A2AError::internal("continuation transaction failed"))?;
            let existing: Option<(String, String, Option<String>)> = tx
                .query_row(
                    "SELECT request_digest, admission_result_json, final_result_json
                     FROM idempotency_records WHERE tenant_scope = ?1 AND message_id = ?2",
                    params![TRUSTED_SINGLE_TENANT_SCOPE, message_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(|_| A2AError::internal("continuation idempotency lookup failed"))?;
            if let Some((stored_digest, admission, final_result)) = existing {
                if stored_digest != digest || admission != result_json {
                    return Err(A2AError::invalid_request(
                        "idempotency key is already bound to different request or continuation semantics",
                    ));
                }
                return serde_json::from_str(final_result.as_deref().unwrap_or(&admission))
                    .map(AdmissionOutcome::Replay)
                    .map_err(|_| A2AError::internal("stored continuation result is corrupt"));
            }
            let (durable_json, state, revision, durable_context): (String, String, u64, String) = tx
                .query_row(
                    "SELECT task_json, state, revision, context_id FROM tasks WHERE task_id = ?1",
                    [&expected_task.id],
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
            task.status.timestamp = chrono::DateTime::from_timestamp_millis(now);
            let task_json = encode_task(&task)?;
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
                 WHERE task_id = ?1 AND revision = ?6 AND state = ?7",
                params![task.id, working_state,
                    task.status.timestamp.map(|value| value.to_rfc3339()), next_revision,
                    task_json, revision, state],
            ).map_err(|_| A2AError::internal("continuation task update failed"))?;
            let event_seq: i64 = tx.query_row(
                "SELECT COALESCE(MAX(event_seq), 0) + 1 FROM task_events
                 WHERE tenant_scope = ?1 AND task_id = ?2",
                params![TRUSTED_SINGLE_TENANT_SCOPE, task.id], |row| row.get(0),
            ).map_err(|_| A2AError::internal("continuation event sequence failed"))?;
            tx.execute(
                "INSERT INTO task_events(tenant_scope, task_id, event_seq, task_revision,
                     event_kind, from_state, to_state, event_json, created_at)
                 VALUES (?1, ?2, ?3, ?4, 'continued', ?5, ?6, ?7, ?8)",
                params![TRUSTED_SINGLE_TENANT_SCOPE, task.id, event_seq, next_revision, state,
                    working_state, task_json, now],
            ).map_err(|_| A2AError::internal("continuation event append failed"))?;
            tx.execute(
                "INSERT INTO idempotency_records(tenant_scope, message_id, request_digest, task_id,
                     state, admission_result_json, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, 'in_progress', ?5, ?6, ?6)",
                params![TRUSTED_SINGLE_TENANT_SCOPE, message_id, digest, task.id, result_json, now],
            ).map_err(|_| A2AError::internal("continuation idempotency reservation failed"))?;
            tx.execute(
                "INSERT INTO outbox(dispatch_id, tenant_scope, task_id, causative_revision,
                     payload_json, payload_digest, state, max_attempts, available_at, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7, ?8, ?8, ?8)",
                params![dispatch_id, TRUSTED_SINGLE_TENANT_SCOPE, task.id, next_revision,
                    payload_json, payload_digest, max_attempts, now],
            ).map_err(|_| A2AError::internal("continuation outbox enqueue failed"))?;
            ensure_atomic_capacity(&tx)?;
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
    #[allow(clippy::too_many_lines)] // Claim also atomically reaps an expired final attempt.
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
            let expired_final: Option<(i64, String)> = transaction
                .query_row(
                    "SELECT outbox_id, task_id FROM outbox
                     WHERE state = 'leased' AND lease_until <= ?1
                       AND attempt_count >= max_attempts
                     ORDER BY lease_until, outbox_id LIMIT 1",
                    [now],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|_| A2AError::internal("expired final attempt lookup failed"))?;
            if let Some((outbox_id, task_id)) = expired_final {
                let error = "final outbox attempt lease expired before acknowledgement";
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
                dead_letter_task(&transaction, &task_id, error, now)?;
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
            let row: Option<(i64, String, String, i64, i64, String)> = transaction
                .query_row(
                    "SELECT outbox_id, dispatch_id, task_id, attempt_count, max_attempts, payload_json
                     FROM outbox
                     WHERE ((state = 'pending' AND available_at <= ?1)
                         OR (state = 'leased' AND lease_until <= ?1))
                       AND attempt_count < max_attempts
                     ORDER BY available_at, outbox_id LIMIT 1",
                    [now],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
                )
                .optional()
                .map_err(|_| A2AError::internal("outbox claim lookup failed"))?;
            let Some((outbox_id, dispatch_id, task_id, attempts, max_attempts, payload)) = row else {
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
                       AND lease_until = ?7 AND lease_until > ?3 AND task_id = ?8",
                    params![
                        lease.outbox_id,
                        lease.lease_token,
                        now,
                        lease.lease_owner,
                        lease.attempt_no,
                        lease.max_attempts,
                        lease.lease_until,
                        lease.task_id
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
            let durable: Option<(i64, i64, String, i64, String)> = transaction
                .query_row(
                    "SELECT attempt_count, max_attempts, lease_owner, lease_until, task_id FROM outbox
                     WHERE outbox_id = ?1 AND state = 'leased' AND lease_token = ?2",
                    params![lease.outbox_id, lease.lease_token],
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
                .map_err(|_| A2AError::internal("outbox fence lookup failed"))?;
            let Some((attempt_no, max_attempts, owner, lease_until, task_id)) = durable else {
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
            let exhausted = attempt_no >= max_attempts;
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
            dead_letter_task(&transaction, &lease.task_id, &error, now)?;
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
            let mut connection = connection
                .lock()
                .map_err(|_| A2AError::internal("persistent task store lock failed"))?;
            operation(&mut connection)
        })
        .await
        .map_err(|_| A2AError::internal("persistent task store worker failed"))?
    }
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

fn ensure_atomic_capacity(connection: &Connection) -> Result<(), A2AError> {
    for expression in [
        "SELECT COALESCE(SUM(length(CAST(task_id AS BLOB)) + length(CAST(context_id AS BLOB)) + length(CAST(state AS BLOB)) + COALESCE(length(CAST(status_timestamp AS BLOB)), 0) + length(CAST(task_json AS BLOB))), 0) FROM tasks",
        "SELECT COALESCE(SUM(length(CAST(tenant_scope AS BLOB)) + length(CAST(task_id AS BLOB)) + length(CAST(event_kind AS BLOB)) + COALESCE(length(CAST(from_state AS BLOB)), 0) + length(CAST(to_state AS BLOB)) + length(CAST(event_json AS BLOB))), 0) FROM task_events",
        "SELECT COALESCE(SUM(length(CAST(tenant_scope AS BLOB)) + length(CAST(message_id AS BLOB)) + length(CAST(request_digest AS BLOB)) + length(CAST(task_id AS BLOB)) + length(CAST(state AS BLOB)) + length(CAST(admission_result_json AS BLOB)) + COALESCE(length(CAST(final_result_json AS BLOB)), 0)), 0) FROM idempotency_records",
        "SELECT COALESCE(SUM(length(CAST(dispatch_id AS BLOB)) + length(CAST(tenant_scope AS BLOB)) + length(CAST(task_id AS BLOB)) + length(CAST(payload_json AS BLOB)) + length(CAST(payload_digest AS BLOB)) + length(CAST(state AS BLOB)) + COALESCE(length(CAST(lease_owner AS BLOB)), 0) + COALESCE(length(CAST(lease_token AS BLOB)), 0) + COALESCE(length(CAST(last_error AS BLOB)), 0)), 0) FROM outbox",
        "SELECT COALESCE(SUM(length(CAST(lease_token AS BLOB)) + COALESCE(length(CAST(outcome AS BLOB)), 0) + COALESCE(length(CAST(error AS BLOB)), 0)), 0) FROM outbox_attempts",
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

fn dead_letter_task(
    transaction: &rusqlite::Transaction<'_>,
    task_id: &str,
    error: &str,
    now: i64,
) -> Result<(), A2AError> {
    let current: Option<(String, String, u64)> = transaction
        .query_row(
            "SELECT task_json, state, revision FROM tasks WHERE task_id = ?1",
            [task_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| A2AError::internal("dead-letter task lookup failed"))?;
    let Some((encoded, from_state, revision)) = current else {
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
            params![TRUSTED_SINGLE_TENANT_SCOPE, task_id],
            |row| row.get(0),
        )
        .map_err(|_| A2AError::internal("dead-letter event sequence failed"))?;
    transaction
        .execute(
            "INSERT INTO task_events(tenant_scope, task_id, event_seq, task_revision,
                 event_kind, from_state, to_state, event_json, created_at)
             VALUES (?1, ?2, ?3, ?4, 'dead_lettered', ?5, ?6, ?7, ?8)",
            params![
                TRUSTED_SINGLE_TENANT_SCOPE,
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
             WHERE tenant_scope = ?1 AND task_id = ?4 AND state = 'in_progress'",
            params![TRUSTED_SINGLE_TENANT_SCOPE, final_json, now, task_id],
        )
        .map_err(|_| A2AError::internal("dead-letter idempotency completion failed"))?;
    Ok(())
}

fn open_database(
    path: &Path,
    max_tasks: usize,
) -> Result<(Connection, [u8; 32], [u8; 32]), SqliteStoreError> {
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
    if !matches!(version, 0 | 1 | SCHEMA_VERSION) {
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
    let (cursor_key, receipt_key) = match version {
        0 => initialize_schema(&mut connection),
        1 => migrate_v1_to_v2(&mut connection, max_tasks),
        SCHEMA_VERSION => validate_schema(&connection),
        _ => Err(SqliteStoreError::InvalidSchema),
    }?;
    validate_persisted_records(&connection, max_tasks)?;
    validate_atomic_records(&connection)?;
    recover_orphaned_tasks(&mut connection)?;
    Ok((connection, cursor_key, receipt_key))
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

// Kept as one fail-closed validation pass so every cursor is dropped before startup recovery.
#[allow(clippy::too_many_lines)]
fn validate_atomic_records(connection: &Connection) -> Result<(), SqliteStoreError> {
    for expression in [
        "SELECT COALESCE(SUM(length(CAST(tenant_scope AS BLOB)) + length(CAST(task_id AS BLOB)) + length(CAST(event_kind AS BLOB)) + COALESCE(length(CAST(from_state AS BLOB)), 0) + length(CAST(to_state AS BLOB)) + length(CAST(event_json AS BLOB))), 0) FROM task_events",
        "SELECT COALESCE(SUM(length(CAST(tenant_scope AS BLOB)) + length(CAST(message_id AS BLOB)) + length(CAST(request_digest AS BLOB)) + length(CAST(task_id AS BLOB)) + length(CAST(state AS BLOB)) + length(CAST(admission_result_json AS BLOB)) + COALESCE(length(CAST(final_result_json AS BLOB)), 0)), 0) FROM idempotency_records",
        "SELECT COALESCE(SUM(length(CAST(dispatch_id AS BLOB)) + length(CAST(tenant_scope AS BLOB)) + length(CAST(task_id AS BLOB)) + length(CAST(payload_json AS BLOB)) + length(CAST(payload_digest AS BLOB)) + length(CAST(state AS BLOB)) + COALESCE(length(CAST(lease_owner AS BLOB)), 0) + COALESCE(length(CAST(lease_token AS BLOB)), 0) + COALESCE(length(CAST(last_error AS BLOB)), 0)), 0) FROM outbox",
        "SELECT COALESCE(SUM(length(CAST(lease_token AS BLOB)) + COALESCE(length(CAST(outcome AS BLOB)), 0) + COALESCE(length(CAST(error AS BLOB)), 0)), 0) FROM outbox_attempts",
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
        if scope != TRUSTED_SINGLE_TENANT_SCOPE
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
                    admission_result_json, final_result_json FROM idempotency_records",
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
            ))
        })
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    for row in rows {
        let (scope, message_id, digest, task_id, record_state, admission, final_result) =
            row.map_err(|_| SqliteStoreError::InvalidSchema)?;
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
        if scope != TRUSTED_SINGLE_TENANT_SCOPE
            || message_id.is_empty()
            || message_id.len() > 4096
            || digest.is_empty()
            || digest.len() > 256
            || !matches!(record_state.as_str(), "in_progress" | "completed")
            || (record_state == "completed") != final_result.is_some()
            || admission.len() > MAX_ATOMIC_JSON_BYTES
            || !response_matches(&admission)
            || final_result.as_ref().is_some_and(|result| {
                result.len() > MAX_ATOMIC_JSON_BYTES || !response_matches(result)
            })
        {
            return Err(SqliteStoreError::InvalidSchema);
        }
    }

    let mut outbox = connection
        .prepare(
            "SELECT o.tenant_scope, o.task_id, o.dispatch_id, o.payload_json, o.payload_digest,
                    o.attempt_count, o.max_attempts, o.last_error, t.context_id, o.lease_owner
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
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, Option<String>>(9)?,
            ))
        })
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    for row in rows {
        let (
            scope,
            task_id,
            dispatch_id,
            payload,
            digest,
            attempts,
            max_attempts,
            error,
            context_id,
            lease_owner,
        ) = row.map_err(|_| SqliteStoreError::InvalidSchema)?;
        let request: MeshRequest =
            serde_json::from_str(&payload).map_err(|_| SqliteStoreError::InvalidSchema)?;
        if scope != TRUSTED_SINGLE_TENANT_SCOPE
            || task_id != request.task_id
            || context_id != request.context_id
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

fn initialize_schema(
    connection: &mut Connection,
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
    let migration_hash = content_digest(SCHEMA_SQL.as_bytes());
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .execute_batch(SCHEMA_SQL)
        .map_err(|_| SqliteStoreError::Initialization)?;
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
    schema.split(';').find_map(|statement| {
        let normalized = normalize_schema_sql(statement);
        let table_prefix = format!("createtable{object_name}(");
        let index_prefix = format!("createindex{object_name}on");
        (normalized.starts_with(&table_prefix) || normalized.starts_with(&index_prefix))
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
        if Some(normalize_schema_sql(&actual)) != expected_schema_sql(schema, object_name) {
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
    if metadata.0 != version
        || metadata.1 != content_digest(schema.as_bytes())
        || metadata.2.len() != 32
        || metadata.3.len() != 32
        || actual_task_columns
            != "created_order:INTEGER:0:1,task_id:TEXT:1:0,context_id:TEXT:1:0,state:TEXT:1:0,status_timestamp:TEXT:0:0,revision:INTEGER:1:0,task_json:TEXT:1:0"
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
    validate_schema_version(connection, SCHEMA_VERSION, SCHEMA_SQL, V2_OBJECTS)
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
    transaction
        .execute(
            "UPDATE store_metadata SET schema_version = ?1, migration_hash = ?2
             WHERE singleton = 1",
            params![SCHEMA_VERSION, content_digest(SCHEMA_SQL.as_bytes())],
        )
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .pragma_update(None, "user_version", SCHEMA_VERSION)
        .map_err(|_| SqliteStoreError::Initialization)?;
    validate_persisted_records(&transaction, max_tasks)?;
    validate_atomic_records(&transaction)?;
    let validated = validate_schema(&transaction)?;
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
    loop {
        let expired_final: Option<(i64, String)> = transaction
            .query_row(
                "SELECT outbox_id, task_id FROM outbox
                 WHERE state = 'leased' AND attempt_count >= max_attempts
                 ORDER BY outbox_id LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| SqliteStoreError::Initialization)?;
        let Some((outbox_id, task_id)) = expired_final else {
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
        dead_letter_task(&transaction, &task_id, error, recovery_now)
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
        let delivered_nonterminal: Option<String> = transaction
            .query_row(
                "SELECT o.task_id
                 FROM outbox o JOIN tasks t ON t.task_id = o.task_id
                 WHERE o.state = 'delivered'
                   AND t.state NOT IN ('\"TASK_STATE_COMPLETED\"', '\"TASK_STATE_FAILED\"',
                                       '\"TASK_STATE_CANCELED\"', '\"TASK_STATE_REJECTED\"')
                 ORDER BY o.outbox_id LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| SqliteStoreError::Initialization)?;
        let Some(task_id) = delivered_nonterminal else {
            break;
        };
        let error = "delivered outbox intent lacked a terminal transition at restart; downstream effect outcome is unknown";
        dead_letter_task(&transaction, &task_id, error, recovery_now)
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
                 (SELECT outbox_id FROM outbox WHERE state = 'leased')",
            [recovery_now],
        )
        .map_err(|_| SqliteStoreError::Initialization)?;
    transaction
        .execute(
            "UPDATE outbox SET state = 'pending', available_at = MIN(available_at, ?1),
                 lease_owner = NULL, lease_token = NULL, lease_until = NULL, updated_at = ?1
             WHERE state = 'leased'",
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
        let record: Option<(String, u64, String)> = transaction
            .query_row(
                "SELECT task_json, revision, state FROM tasks
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
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| SqliteStoreError::InvalidSchema)?;
        let Some((encoded, revision, previous_state)) = record else {
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
                params![TRUSTED_SINGLE_TENANT_SCOPE, task.id],
                |row| row.get(0),
            )
            .map_err(|_| SqliteStoreError::Initialization)?;
        transaction
            .execute(
                "INSERT INTO task_events(tenant_scope, task_id, event_seq, task_revision,
                     event_kind, from_state, to_state, event_json, created_at)
                 VALUES (?1, ?2, ?3, ?4, 'restart_orphan_failed', ?5, ?6, ?7, ?8)",
                params![
                    TRUSTED_SINGLE_TENANT_SCOPE,
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

#[async_trait]
impl TaskStore for SqliteTaskStore {
    async fn create(&self, task: Task) -> Result<u64, A2AError> {
        let max_tasks = self.max_tasks;
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
                    "INSERT INTO tasks(task_id, context_id, state, status_timestamp, revision, task_json)
                     VALUES (?1, ?2, ?3, ?4, 1, ?5)",
                    params![task.id, task.context_id, state, timestamp, encoded],
                )
                .map_err(|_| A2AError::internal("persistent task insert failed"))?;
            transaction
                .execute(
                    "INSERT INTO task_events(tenant_scope, task_id, event_seq, task_revision,
                         event_kind, from_state, to_state, event_json, created_at)
                     VALUES (?1, ?2, 1, 1, 'sdk_create', NULL, ?3, ?4, ?5)",
                    params![
                        TRUSTED_SINGLE_TENANT_SCOPE,
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
        self.run(move |connection| {
            let mut statement = connection
                .prepare(
                    "SELECT task_id, context_id, state, status_timestamp, task_json
                     FROM tasks ORDER BY created_order ASC",
                )
                .map_err(|_| A2AError::internal("persistent task query failed"))?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                })
                .map_err(|_| A2AError::internal("persistent task query failed"))?;
            let mut tasks = Vec::new();
            for row in rows {
                let (task_id, context_id, state, timestamp, encoded) =
                    row.map_err(|_| A2AError::internal("persistent task query failed"))?;
                if !persisted_task_matches(
                    &task_id,
                    &context_id,
                    &state,
                    timestamp.as_deref(),
                    &encoded,
                ) {
                    return Err(A2AError::internal("persistent task record is corrupt"));
                }
                tasks.push(decode_task(&encoded)?);
            }
            list_tasks_response(tasks, &request, &cursor_key)
        })
        .await
    }
}

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
        initialize_schema(&mut connection).unwrap();
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
}
