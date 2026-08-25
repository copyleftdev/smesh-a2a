use std::collections::HashMap;
use std::sync::Arc;

use a2a::{A2AError, ListTasksRequest, ListTasksResponse, Task, TaskId};
use a2a_server::TaskStore;
use async_trait::async_trait;
use tokio::sync::RwLock;

#[derive(Default)]
struct StoreState {
    tasks: HashMap<TaskId, Task>,
}

/// Single-process task store with a hard task-count ceiling.
#[derive(Clone)]
pub struct BoundedTaskStore {
    state: Arc<RwLock<StoreState>>,
    max_tasks: usize,
}

impl BoundedTaskStore {
    #[must_use]
    pub fn new(max_tasks: usize) -> Self {
        Self {
            state: Arc::new(RwLock::new(StoreState::default())),
            max_tasks: max_tasks.max(1),
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
        if stored.status.state.is_terminal() {
            if stored.status.state == task.status.state {
                return Ok(1);
            }
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
        let state = self.state.read().await;
        let mut tasks: Vec<Task> = state
            .tasks
            .values()
            .filter(|task| {
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
            })
            .cloned()
            .collect();
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
        let start = match req.page_token.as_deref() {
            None | Some("") => 0,
            Some(token) => token
                .parse::<usize>()
                .map_err(|_| A2AError::invalid_params("invalid pageToken"))?,
        };
        if start > tasks.len() {
            return Err(A2AError::invalid_params("pageToken is out of range"));
        }
        let page_size_usize = usize::try_from(page_size)
            .map_err(|_| A2AError::invalid_params("pageSize is out of range"))?;
        let end = start.saturating_add(page_size_usize).min(tasks.len());
        let total_size = i32::try_from(tasks.len()).unwrap_or(i32::MAX);
        let include_artifacts = req.include_artifacts.unwrap_or(false);
        let history_length = req
            .history_length
            .and_then(|length| usize::try_from(length.max(0)).ok());
        let mut page = tasks[start..end].to_vec();
        for task in &mut page {
            if !include_artifacts {
                task.artifacts = None;
            }
            if let (Some(limit), Some(history)) = (history_length, task.history.as_mut()) {
                if history.len() > limit {
                    history.drain(..history.len() - limit);
                }
            }
        }

        Ok(ListTasksResponse {
            tasks: page,
            next_page_token: if end < tasks.len() {
                end.to_string()
            } else {
                String::new()
            },
            page_size,
            total_size,
        })
    }
}
