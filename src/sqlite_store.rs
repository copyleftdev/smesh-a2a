#![cfg_attr(not(unix), allow(dead_code))]

use std::fs::File;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use a2a::{A2AError, ListTasksRequest, ListTasksResponse, Message, Part, Role, Task};
use a2a_server::TaskStore;
use async_trait::async_trait;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;

use crate::{content_digest, store::list_tasks_response};

const SCHEMA_VERSION: i64 = 1;
const APPLICATION_ID: i64 = 0x534D_4132;
const MAX_TASK_JSON_BYTES: usize = 1024 * 1024;
const MAX_STORE_JSON_BYTES: usize = 64 * 1024 * 1024;
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
     ON tasks(context_id, state, status_timestamp, task_id);";

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
    if !matches!(version, 0 | SCHEMA_VERSION) {
        return Err(SqliteStoreError::InvalidSchema);
    }
    let application_id: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    if version == SCHEMA_VERSION && application_id != APPLICATION_ID {
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
        SCHEMA_VERSION => validate_schema(&connection),
        _ => Err(SqliteStoreError::InvalidSchema),
    }?;
    validate_persisted_records(&connection, max_tasks)?;
    recover_orphaned_tasks(&mut connection)?;
    Ok((connection, cursor_key, receipt_key))
}

fn validate_persisted_records(
    connection: &Connection,
    max_tasks: usize,
) -> Result<(), SqliteStoreError> {
    let (count, aggregate_bytes): (i64, i64) = connection
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(length(CAST(task_json AS BLOB))), 0) FROM tasks",
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
        .prepare("SELECT task_id, context_id, state, status_timestamp, task_json FROM tasks")
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
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
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    for row in rows {
        let (task_id, context_id, state, timestamp, encoded) =
            row.map_err(|_| SqliteStoreError::InvalidSchema)?;
        if !persisted_task_matches(
            &task_id,
            &context_id,
            &state,
            timestamp.as_deref(),
            &encoded,
        ) {
            return Err(SqliteStoreError::InvalidSchema);
        }
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

fn expected_schema_sql(object_name: &str) -> Option<String> {
    SCHEMA_SQL.split(';').find_map(|statement| {
        let normalized = normalize_schema_sql(statement);
        let matches = match object_name {
            "store_metadata" => normalized.starts_with("createtablestore_metadata("),
            "tasks" => normalized.starts_with("createtabletasks("),
            "tasks_context_state_time" => {
                normalized.starts_with("createindextasks_context_state_time")
            }
            _ => false,
        };
        matches.then_some(normalized)
    })
}

fn validate_schema(connection: &Connection) -> Result<([u8; 32], [u8; 32]), SqliteStoreError> {
    let metadata: (i64, String, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT schema_version, migration_hash, cursor_key, receipt_key
             FROM store_metadata WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| SqliteStoreError::InvalidSchema)?;
    for object_name in ["store_metadata", "tasks", "tasks_context_state_time"] {
        let actual: String = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name = ?1",
                [object_name],
                |row| row.get(0),
            )
            .map_err(|_| SqliteStoreError::InvalidSchema)?;
        if Some(normalize_schema_sql(&actual)) != expected_schema_sql(object_name) {
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
    if metadata.0 != SCHEMA_VERSION
        || metadata.1 != content_digest(SCHEMA_SQL.as_bytes())
        || metadata.2.len() != 32
        || metadata.3.len() != 32
        || actual_task_columns
            != "created_order:INTEGER:0:1,task_id:TEXT:1:0,context_id:TEXT:1:0,state:TEXT:1:0,status_timestamp:TEXT:0:0,revision:INTEGER:1:0,task_json:TEXT:1:0"
        || actual_index_columns != "context_id,state,status_timestamp,task_id"
        || object_count != 3
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
        let record: Option<String> = transaction
            .query_row(
                "SELECT task_json FROM tasks
                 WHERE state IN (?1, ?2, ?3, ?4, ?5)
                 ORDER BY created_order ASC LIMIT 1",
                params![
                    nonterminal[0],
                    nonterminal[1],
                    nonterminal[2],
                    nonterminal[3],
                    nonterminal[4]
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| SqliteStoreError::InvalidSchema)?;
        let Some(encoded) = record else { break };
        let mut task: Task =
            serde_json::from_str(&encoded).map_err(|_| SqliteStoreError::InvalidSchema)?;
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
        transaction
            .execute(
                "UPDATE tasks SET state = ?2, status_timestamp = ?3, revision = revision + 1, task_json = ?4 WHERE task_id = ?1",
                params![task.id, state, timestamp, recovered],
            )
            .map_err(|_| SqliteStoreError::Initialization)?;
    }
    transaction
        .commit()
        .map_err(|_| SqliteStoreError::Initialization)
}

#[cfg(unix)]
fn prepare_secure_path(path: &Path) -> Result<(), SqliteStoreError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
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
            if current_task.status.state.is_terminal() {
                if current_task == task {
                    return Ok(revision);
                }
                return Err(A2AError::unsupported_operation(
                    "terminal task state cannot be changed",
                ));
            }
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
}
