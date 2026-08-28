use std::collections::HashMap;
use std::mem::size_of;
use std::sync::Arc;
use std::time::Instant;

use a2a::{A2AError, ListTasksRequest, ListTasksResponse, Task, TaskId, TaskState};
use a2a_server::TaskStore;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use tokio::sync::RwLock;

const MAX_PAGE_TOKEN_BYTES: usize = 4096;
const SNAPSHOT_TTL_MILLIS: u64 = 5 * 60 * 1_000;
const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
const MAX_ACTIVE_SNAPSHOTS: usize = 128;
const ALLOCATION_OVERHEAD_BYTES: usize = 3 * size_of::<usize>();
#[derive(Debug, Clone, PartialEq)]
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

struct StoreState {
    tasks: HashMap<TaskId, Task>,
    snapshots: Vec<([u8; 16], MemorySnapshot)>,
    snapshot_bytes: usize,
    observed_now: u64,
}

impl Default for StoreState {
    fn default() -> Self {
        let snapshots = Vec::with_capacity(MAX_ACTIVE_SNAPSHOTS);
        let snapshot_bytes = snapshots
            .capacity()
            .checked_mul(size_of::<([u8; 16], MemorySnapshot)>())
            .and_then(|value| value.checked_add(ALLOCATION_OVERHEAD_BYTES))
            .expect("fixed snapshot registry capacity fits usize");
        Self {
            tasks: HashMap::new(),
            snapshots,
            snapshot_bytes,
            observed_now: 0,
        }
    }
}

struct MemorySnapshot {
    tasks: Vec<Vec<u8>>,
    page_size: i32,
    scope: CursorScope,
    expires_at: u64,
    bytes: usize,
    tokens: Vec<(usize, String)>,
}

fn random_page_token() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

fn validate_list_request(request: &ListTasksRequest) -> Result<(i32, CursorScope), A2AError> {
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
    Ok((page_size, CursorScope::from_request(request, page_size)))
}

fn freeze_projection(mut tasks: Vec<Task>, request: &ListTasksRequest) -> Vec<Task> {
    tasks.retain(|task| {
        request
            .context_id
            .as_ref()
            .is_none_or(|context| task.context_id == *context)
            && request
                .status
                .as_ref()
                .is_none_or(|status| task.status.state == *status)
            && request.status_timestamp_after.is_none_or(|after| {
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
    let include_artifacts = request.include_artifacts.unwrap_or(false);
    let history_length = request
        .history_length
        .and_then(|length| usize::try_from(length).ok());
    for task in &mut tasks {
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
    tasks
}

fn memory_page(snapshot: &MemorySnapshot, position: usize) -> Result<ListTasksResponse, A2AError> {
    let page_size = usize::try_from(snapshot.page_size).expect("validated page size");
    let end = position.saturating_add(page_size).min(snapshot.tasks.len());
    let tasks = snapshot.tasks[position..end]
        .iter()
        .map(|encoded| {
            serde_json::from_slice(encoded)
                .map_err(|_| A2AError::internal("frozen task snapshot is corrupt"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ListTasksResponse {
        tasks,
        next_page_token: snapshot
            .tokens
            .iter()
            .find_map(|(token_position, token)| (*token_position == end).then(|| token.clone()))
            .unwrap_or_default(),
        page_size: snapshot.page_size,
        total_size: i32::try_from(snapshot.tasks.len()).unwrap_or(i32::MAX),
    })
}

fn gc_memory_snapshots(state: &mut StoreState, now: u64) {
    state.snapshots.retain(|(_, snapshot)| {
        if snapshot.expires_at <= now {
            state.snapshot_bytes = state.snapshot_bytes.saturating_sub(snapshot.bytes);
            false
        } else {
            true
        }
    });
}

fn reusable_snapshot<'a>(
    state: &'a StoreState,
    scope: &CursorScope,
    now: u64,
) -> Option<&'a MemorySnapshot> {
    state
        .snapshots
        .iter()
        .map(|(_, snapshot)| snapshot)
        .find(|snapshot| snapshot.expires_at > now && snapshot.scope == *scope)
}

fn conservative_snapshot_bytes(
    tasks: &[Vec<u8>],
    task_capacity: usize,
    scope: &CursorScope,
    tokens: &[(usize, String)],
    token_capacity: usize,
) -> Result<usize, A2AError> {
    let capacity = || A2AError::internal("task snapshot capacity reached");
    let mut bytes = size_of::<([u8; 16], MemorySnapshot)>()
        .checked_add(ALLOCATION_OVERHEAD_BYTES)
        .and_then(|value| value.checked_add(ALLOCATION_OVERHEAD_BYTES))
        .ok_or_else(capacity)?
        .checked_add(
            task_capacity
                .checked_mul(size_of::<Vec<u8>>())
                .ok_or_else(capacity)?,
        )
        .ok_or_else(capacity)?;
    for encoded in tasks {
        bytes = bytes
            .checked_add(encoded.capacity())
            .and_then(|value| value.checked_add(ALLOCATION_OVERHEAD_BYTES))
            .ok_or_else(capacity)?;
    }
    bytes = bytes
        .checked_add(scope.context_id.as_ref().map_or(0, String::capacity))
        .and_then(|value| {
            value.checked_add(
                scope
                    .context_id
                    .as_ref()
                    .map_or(0, |_| ALLOCATION_OVERHEAD_BYTES),
            )
        })
        .and_then(|value| value.checked_add(scope.tenant.as_ref().map_or(0, String::capacity)))
        .and_then(|value| {
            value.checked_add(
                scope
                    .tenant
                    .as_ref()
                    .map_or(0, |_| ALLOCATION_OVERHEAD_BYTES),
            )
        })
        .and_then(|value| {
            token_capacity
                .checked_mul(size_of::<(usize, String)>())
                .and_then(|token_slots| value.checked_add(token_slots))
        })
        .ok_or_else(capacity)?;
    for (_, token) in tokens {
        bytes = bytes
            .checked_add(token.capacity())
            .and_then(|value| value.checked_add(ALLOCATION_OVERHEAD_BYTES))
            .ok_or_else(capacity)?;
    }
    Ok(bytes)
}

/// Single-process task store with a hard task-count ceiling.
#[derive(Clone)]
pub struct BoundedTaskStore {
    state: Arc<RwLock<StoreState>>,
    max_tasks: usize,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl BoundedTaskStore {
    #[must_use]
    pub fn new(max_tasks: usize) -> Self {
        let baseline = Instant::now();
        Self::new_with_clock(
            max_tasks,
            Arc::new(move || {
                baseline
                    .elapsed()
                    .as_millis()
                    .try_into()
                    .unwrap_or(u64::MAX)
            }),
        )
    }

    /// Construct a store with an injected monotonic millisecond source.
    ///
    /// Callers must supply a monotonic source. The ordinary constructor uses [`Instant`].
    #[must_use]
    pub fn new_with_clock(max_tasks: usize, clock: Arc<dyn Fn() -> u64 + Send + Sync>) -> Self {
        Self {
            state: Arc::new(RwLock::new(StoreState::default())),
            max_tasks: max_tasks.max(1),
            clock,
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
        let (page_size, scope) = validate_list_request(req)?;
        let mut state = self.state.write().await;
        let now = (self.clock)().max(state.observed_now);
        state.observed_now = now;
        gc_memory_snapshots(&mut state, now);
        if let Some(token) = req.page_token.as_deref().filter(|token| !token.is_empty()) {
            if token.len() > MAX_PAGE_TOKEN_BYTES {
                return Err(A2AError::invalid_params("invalid pageToken"));
            }
            let (snapshot, position) = state
                .snapshots
                .iter()
                .find_map(|(_, snapshot)| {
                    snapshot.tokens.iter().find_map(|(position, candidate)| {
                        (candidate == token).then_some((snapshot, *position))
                    })
                })
                .filter(|(snapshot, _)| snapshot.expires_at > now && snapshot.scope == scope)
                .ok_or_else(|| A2AError::invalid_params("invalid pageToken"))?;
            let step = usize::try_from(snapshot.page_size).expect("validated page size");
            if position == 0 || position > snapshot.tasks.len() || position % step != 0 {
                return Err(A2AError::invalid_params("invalid pageToken"));
            }
            return memory_page(snapshot, position);
        }

        // A retry of the same first-page request reuses its live frozen view instead
        // of allocating another five-minute capability chain. This bounds anonymous
        // retry pressure without evicting snapshots whose tokens remain in use.
        if let Some(snapshot) = reusable_snapshot(&state, &scope, now) {
            return memory_page(snapshot, 0);
        }

        let tasks = freeze_projection(state.tasks.values().cloned().collect(), req);
        if tasks.len() <= usize::try_from(page_size).expect("validated page size") {
            return Ok(ListTasksResponse {
                total_size: i32::try_from(tasks.len()).unwrap_or(i32::MAX),
                tasks,
                next_page_token: String::new(),
                page_size,
            });
        }
        let step = usize::try_from(page_size).expect("validated page size");
        let mut frozen = tasks
            .iter()
            .map(|task| {
                serde_json::to_vec(task)
                    .map_err(|_| A2AError::internal("failed to freeze task snapshot"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        frozen.shrink_to_fit();
        for encoded in &mut frozen {
            encoded.shrink_to_fit();
        }
        let mut tokens = Vec::with_capacity((tasks.len() - 1) / step);
        for position in (step..tasks.len()).step_by(step) {
            let mut token = random_page_token();
            token.shrink_to_fit();
            tokens.push((position, token));
        }
        let bytes = conservative_snapshot_bytes(
            &frozen,
            frozen.capacity(),
            &scope,
            &tokens,
            tokens.capacity(),
        )?;
        if state.snapshots.len() >= MAX_ACTIVE_SNAPSHOTS
            || state
                .snapshot_bytes
                .checked_add(bytes)
                .is_none_or(|total| total > MAX_SNAPSHOT_BYTES)
        {
            return Err(A2AError::internal("task snapshot capacity reached"));
        }
        let snapshot_id = rand::random::<[u8; 16]>();
        let expires_at = now
            .checked_add(SNAPSHOT_TTL_MILLIS)
            .ok_or_else(|| A2AError::internal("task snapshot clock exhausted"))?;
        state.snapshots.push((
            snapshot_id,
            MemorySnapshot {
                tasks: frozen,
                page_size,
                scope,
                expires_at,
                bytes,
                tokens,
            },
        ));
        state.snapshot_bytes = state
            .snapshot_bytes
            .checked_add(bytes)
            .expect("capacity checked before snapshot insertion");
        memory_page(
            state
                .snapshots
                .iter()
                .find_map(|(id, snapshot)| (*id == snapshot_id).then_some(snapshot))
                .expect("snapshot inserted"),
            0,
        )
    }
}
