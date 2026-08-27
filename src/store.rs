use std::collections::HashMap;
use std::sync::Arc;

use a2a::{A2AError, ListTasksRequest, ListTasksResponse, Task, TaskId, TaskState};
use a2a_server::TaskStore;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::RwLock;

const CURSOR_VERSION: u8 = 1;
const MAX_PAGE_TOKEN_BYTES: usize = 4096;
const CURSOR_TAG_BYTES: usize = 32;
type CursorMac = Hmac<Sha256>;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TaskCursor {
    version: u8,
    status_timestamp: Option<DateTime<Utc>>,
    task_id: TaskId,
    scope: CursorScope,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CursorScope {
    context_id: Option<String>,
    status: Option<TaskState>,
    page_size: i32,
    history_length: Option<i32>,
    status_timestamp_after: Option<DateTime<Utc>>,
    include_artifacts: bool,
    tenant: Option<String>,
}

impl CursorScope {
    fn from_request(request: &ListTasksRequest, page_size: i32) -> Self {
        Self {
            context_id: request.context_id.clone(),
            status: request.status.clone(),
            page_size,
            history_length: request.history_length,
            status_timestamp_after: request.status_timestamp_after,
            include_artifacts: request.include_artifacts.unwrap_or(false),
            tenant: request.tenant.clone(),
        }
    }
}

fn encode_cursor(task: &Task, scope: CursorScope, key: &[u8; 32]) -> Result<String, A2AError> {
    let cursor = TaskCursor {
        version: CURSOR_VERSION,
        status_timestamp: task.status.timestamp,
        task_id: task.id.clone(),
        scope,
    };
    let mut bytes = serde_json::to_vec(&cursor)
        .map_err(|error| A2AError::internal(format!("failed to encode page cursor: {error}")))?;
    let mut mac = CursorMac::new_from_slice(key)
        .map_err(|_| A2AError::internal("failed to initialize page cursor signer"))?;
    mac.update(&bytes);
    bytes.extend_from_slice(&mac.finalize().into_bytes());
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn decode_cursor(
    token: &str,
    expected_scope: &CursorScope,
    key: &[u8; 32],
) -> Result<TaskCursor, A2AError> {
    if token.len() > MAX_PAGE_TOKEN_BYTES {
        return Err(A2AError::invalid_params("pageToken is too large"));
    }
    let mut bytes = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| A2AError::invalid_params("invalid pageToken"))?;
    if bytes.len() <= CURSOR_TAG_BYTES {
        return Err(A2AError::invalid_params("invalid pageToken"));
    }
    let tag = bytes.split_off(bytes.len() - CURSOR_TAG_BYTES);
    let mut mac = CursorMac::new_from_slice(key)
        .map_err(|_| A2AError::internal("failed to initialize page cursor verifier"))?;
    mac.update(&bytes);
    mac.verify_slice(&tag)
        .map_err(|_| A2AError::invalid_params("invalid pageToken signature"))?;
    let cursor: TaskCursor = serde_json::from_slice(&bytes)
        .map_err(|_| A2AError::invalid_params("invalid pageToken"))?;
    if cursor.version != CURSOR_VERSION {
        return Err(A2AError::invalid_params("unsupported pageToken version"));
    }
    if &cursor.scope != expected_scope {
        return Err(A2AError::invalid_params(
            "pageToken does not match the list query",
        ));
    }
    Ok(cursor)
}

fn build_list_response(
    mut tasks: Vec<Task>,
    req: &ListTasksRequest,
    cursor_key: &[u8; 32],
) -> Result<ListTasksResponse, A2AError> {
    if req.history_length.is_some_and(|length| length < 0) {
        return Err(A2AError::invalid_params(
            "historyLength must be a non-negative integer",
        ));
    }
    tasks.retain(|task| {
        req.context_id
            .as_ref()
            .is_none_or(|context| task.context_id == *context)
            && req
                .status
                .as_ref()
                .is_none_or(|status| task.status.state == *status)
            && req.status_timestamp_after.is_none_or(|after| {
                task.status
                    .timestamp
                    .is_some_and(|timestamp| timestamp >= after)
            })
    });
    tasks.sort_by(|left, right| {
        right
            .status
            .timestamp
            .cmp(&left.status.timestamp)
            .then_with(|| left.id.cmp(&right.id))
    });

    let page_size = req.page_size.unwrap_or(50);
    if !(1..=100).contains(&page_size) {
        return Err(A2AError::invalid_params(
            "pageSize must be between 1 and 100",
        ));
    }
    let cursor_scope = CursorScope::from_request(req, page_size);
    let start = match req.page_token.as_deref() {
        None | Some("") => 0,
        Some(token) => {
            let cursor = decode_cursor(token, &cursor_scope, cursor_key)?;
            tasks
                .iter()
                .position(|task| {
                    task.id == cursor.task_id && task.status.timestamp == cursor.status_timestamp
                })
                .map(|position| position + 1)
                .ok_or_else(|| A2AError::invalid_params("pageToken is stale or invalid"))?
        }
    };
    let page_size_usize = usize::try_from(page_size)
        .map_err(|_| A2AError::invalid_params("pageSize is out of range"))?;
    let end = start.saturating_add(page_size_usize).min(tasks.len());
    let total_size = i32::try_from(tasks.len()).unwrap_or(i32::MAX);
    let next_page_token = if end < tasks.len() {
        encode_cursor(&tasks[end - 1], cursor_scope, cursor_key)?
    } else {
        String::new()
    };
    let include_artifacts = req.include_artifacts.unwrap_or(false);
    let history_length = req
        .history_length
        .and_then(|length| usize::try_from(length).ok());
    let mut page = tasks[start..end].to_vec();
    for task in &mut page {
        if !include_artifacts {
            task.artifacts = None;
        }
        if history_length == Some(0) {
            task.history = None;
        } else if let (Some(limit), Some(history)) = (history_length, task.history.as_mut())
            && history.len() > limit
        {
            history.drain(..history.len() - limit);
        }
    }

    Ok(ListTasksResponse {
        tasks: page,
        next_page_token,
        page_size,
        total_size,
    })
}

pub(crate) fn list_tasks_response(
    tasks: Vec<Task>,
    req: &ListTasksRequest,
    cursor_key: &[u8; 32],
) -> Result<ListTasksResponse, A2AError> {
    build_list_response(tasks, req, cursor_key)
}

#[derive(Default)]
struct StoreState {
    tasks: HashMap<TaskId, Task>,
}

/// Single-process task store with a hard task-count ceiling.
#[derive(Clone)]
pub struct BoundedTaskStore {
    state: Arc<RwLock<StoreState>>,
    max_tasks: usize,
    cursor_key: Arc<[u8; 32]>,
}

impl BoundedTaskStore {
    #[must_use]
    pub fn new(max_tasks: usize) -> Self {
        Self {
            state: Arc::new(RwLock::new(StoreState::default())),
            max_tasks: max_tasks.max(1),
            cursor_key: Arc::new(rand::random()),
        }
    }
}

#[async_trait]
impl TaskStore for BoundedTaskStore {
    async fn create(&self, task: Task) -> Result<u64, A2AError> {
        let mut state = self.state.write().await;
        if state.tasks.contains_key(&task.id) {
            return Err(A2AError::invalid_request("task already exists"));
        }
        if state.tasks.len() >= self.max_tasks {
            return Err(A2AError::internal("task store capacity reached"));
        }
        state.tasks.insert(task.id.clone(), task);
        Ok(1)
    }

    async fn update(&self, task: Task) -> Result<u64, A2AError> {
        let mut state = self.state.write().await;
        let stored = state
            .tasks
            .get_mut(&task.id)
            .ok_or_else(|| A2AError::task_not_found(&task.id))?;
        if *stored == task {
            return Ok(1);
        }
        if stored.status.state.is_terminal() {
            return Err(A2AError::unsupported_operation(
                "terminal task state cannot be changed",
            ));
        }
        *stored = task;
        Ok(1)
    }

    async fn get(&self, task_id: &str) -> Result<Option<Task>, A2AError> {
        Ok(self.state.read().await.tasks.get(task_id).cloned())
    }

    async fn list(&self, req: &ListTasksRequest) -> Result<ListTasksResponse, A2AError> {
        let tasks = self.state.read().await.tasks.values().cloned().collect();
        list_tasks_response(tasks, req, &self.cursor_key)
    }
}
