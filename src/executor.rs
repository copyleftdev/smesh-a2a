use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use a2a::{
    A2AError, Artifact, Message, Part, Role, StreamResponse, Task, TaskArtifactUpdateEvent,
    TaskState, TaskStatus, TaskStatusUpdateEvent, new_artifact_id, new_message_id,
};
use a2a_server::{AgentExecutor, ExecutorContext};
use futures::StreamExt;
use futures::stream::{self, BoxStream};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

use crate::{InputLimits, MeshDispatcher, MeshEvent, MeshRequest};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionLimits {
    pub max_concurrent_tasks: usize,
    pub worker_idle_timeout: Duration,
    pub task_timeout: Duration,
    pub cancel_timeout: Duration,
    pub max_events: usize,
    pub max_artifacts: usize,
    pub max_output_bytes: usize,
}

impl Default for ExecutionLimits {
    fn default() -> Self {
        Self {
            max_concurrent_tasks: 64,
            worker_idle_timeout: Duration::from_secs(30),
            task_timeout: Duration::from_secs(5 * 60),
            cancel_timeout: Duration::from_secs(5),
            max_events: 16,
            max_artifacts: 16,
            max_output_bytes: 1024 * 1024,
        }
    }
}

#[derive(Default)]
struct EventBudget {
    events: usize,
    artifacts: usize,
    output_bytes: usize,
}

impl EventBudget {
    fn observe(
        &mut self,
        event: &MeshEvent,
        limits: ExecutionLimits,
    ) -> Result<(), crate::DispatchError> {
        self.events = self.events.saturating_add(1);
        if self.events > limits.max_events {
            return Err(crate::DispatchError::Message(
                "SMESH worker exceeded event budget".to_owned(),
            ));
        }

        let bytes = match event {
            MeshEvent::Progress(text) | MeshEvent::Completed { summary: text } => text.len(),
            MeshEvent::Artifact {
                name,
                media_type,
                content,
            } => {
                self.artifacts = self.artifacts.saturating_add(1);
                if self.artifacts > limits.max_artifacts {
                    return Err(crate::DispatchError::Message(
                        "SMESH worker exceeded artifact budget".to_owned(),
                    ));
                }
                name.len()
                    .saturating_add(media_type.len())
                    .saturating_add(content.len())
            }
        };
        self.output_bytes = self.output_bytes.saturating_add(bytes);
        if self.output_bytes > limits.max_output_bytes {
            return Err(crate::DispatchError::Message(
                "SMESH worker exceeded output byte budget".to_owned(),
            ));
        }
        Ok(())
    }
}

/// A2A executor that delegates accepted work to a SMESH dispatcher.
pub struct SmeshExecutor<D> {
    dispatcher: Arc<D>,
    limits: InputLimits,
    gateway_node_id: String,
    cancellations: Arc<Mutex<HashMap<String, CancellationToken>>>,
    execution_limits: ExecutionLimits,
    permits: Arc<tokio::sync::Semaphore>,
}

impl<D> SmeshExecutor<D>
where
    D: MeshDispatcher,
{
    #[must_use]
    pub fn new(dispatcher: D, limits: InputLimits, gateway_node_id: impl Into<String>) -> Self {
        Self {
            dispatcher: Arc::new(dispatcher),
            limits,
            gateway_node_id: gateway_node_id.into(),
            cancellations: Arc::new(Mutex::new(HashMap::new())),
            execution_limits: ExecutionLimits::default(),
            permits: Arc::new(tokio::sync::Semaphore::new(
                ExecutionLimits::default().max_concurrent_tasks,
            )),
        }
    }

    #[must_use]
    pub fn with_execution_limits(mut self, mut limits: ExecutionLimits) -> Self {
        // The upstream A2A handler uses a 32-event broadcast buffer. Keep the
        // producer budget below that ceiling so a burst cannot outrun a newly
        // attached subscriber before backpressure begins.
        limits.max_events = limits.max_events.clamp(1, 16);
        self.permits = Arc::new(tokio::sync::Semaphore::new(
            limits.max_concurrent_tasks.max(1),
        ));
        self.execution_limits = limits;
        self
    }
}

impl<D> AgentExecutor for SmeshExecutor<D>
where
    D: MeshDispatcher,
{
    // Keeping the translation loop linear makes protocol ordering auditable.
    #[allow(clippy::too_many_lines)]
    fn execute(
        &self,
        ctx: ExecutorContext,
    ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
        if ctx
            .stored_task
            .as_ref()
            .is_some_and(|task| task.status.state.is_terminal())
        {
            return Box::pin(stream::once(async {
                Err(A2AError::unsupported_operation(
                    "terminal tasks cannot accept additional messages",
                ))
            }));
        }

        let Some(message) = ctx.message.as_ref() else {
            return Box::pin(stream::once(async {
                Err(A2AError::invalid_params("message is required"))
            }));
        };

        let mut history = ctx
            .stored_task
            .as_ref()
            .and_then(|task| task.history.clone())
            .unwrap_or_default();
        if history.last().map(|item| &item.message_id) != Some(&message.message_id) {
            history.push(message.clone());
        }

        let request = match MeshRequest::from_a2a(
            ctx.task_id.clone(),
            ctx.context_id.clone(),
            message,
            self.limits,
        ) {
            Ok(request) => request,
            Err(error) => {
                let task_id = ctx.task_id.clone();
                let context_id = ctx.context_id.clone();
                return Box::pin(stream::once(async move {
                    Ok(StreamResponse::Task(Task {
                        id: task_id.clone(),
                        context_id: context_id.clone(),
                        status: TaskStatus {
                            state: TaskState::Rejected,
                            message: Some(agent_message(&task_id, &context_id, error.to_string())),
                            timestamp: Some(chrono::Utc::now()),
                        },
                        artifacts: None,
                        history: Some(history),
                        metadata: None,
                    }))
                }));
            }
        };

        let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() else {
            let task_id = ctx.task_id.clone();
            let context_id = ctx.context_id.clone();
            return Box::pin(stream::once(async move {
                Ok(StreamResponse::Task(Task {
                    id: task_id.clone(),
                    context_id: context_id.clone(),
                    status: TaskStatus {
                        state: TaskState::Rejected,
                        message: Some(agent_message(
                            &task_id,
                            &context_id,
                            "gateway concurrency capacity reached".to_owned(),
                        )),
                        timestamp: Some(chrono::Utc::now()),
                    },
                    artifacts: None,
                    history: Some(history),
                    metadata: None,
                }))
            }));
        };

        // Constructing the signal here proves the gateway-to-SMESH translation
        // before the request crosses the dispatcher boundary. Dispatchers may
        // reconstruct or forward it according to their transport policy.
        let _signal = request.to_signal(&self.gateway_node_id);
        let mut mesh_stream = self.dispatcher.dispatch(request);
        let task_id = ctx.task_id;
        let context_id = ctx.context_id;
        let cancellation = CancellationToken::new();
        self.cancellations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(task_id.clone(), cancellation.clone());
        let cancellations = Arc::clone(&self.cancellations);
        let execution_limits = self.execution_limits;
        let (tx, rx) = tokio::sync::mpsc::channel(16);

        tokio::spawn(async move {
            let _permit = permit;
            let mut artifacts = Vec::new();
            let mut budget = EventBudget::default();
            let mut terminal_emitted = false;
            let task_deadline = tokio::time::sleep(execution_limits.task_timeout);
            tokio::pin!(task_deadline);
            if tx
                .send(Ok(StreamResponse::Task(Task {
                    id: task_id.clone(),
                    context_id: context_id.clone(),
                    status: TaskStatus {
                        state: TaskState::Working,
                        message: None,
                        timestamp: Some(chrono::Utc::now()),
                    },
                    artifacts: None,
                    history: Some(history.clone()),
                    metadata: None,
                })))
                .await
                .is_err()
            {
                cancellations
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&task_id);
                return;
            }

            loop {
                let next = tokio::select! {
                    biased;
                    () = cancellation.cancelled() => {
                        terminal_emitted = true;
                        break;
                    }
                    () = &mut task_deadline => Some(Err(crate::DispatchError::Message(
                        "SMESH task deadline exceeded".to_owned(),
                    ))),
                    next = tokio::time::timeout(
                        execution_limits.worker_idle_timeout,
                        mesh_stream.next(),
                    ) => match next {
                        Ok(next) => next,
                        Err(_) => Some(Err(crate::DispatchError::Message(
                            "SMESH worker inactivity timeout".to_owned(),
                        ))),
                    },
                };
                let Some(event) = next else {
                    break;
                };
                let event = match event {
                    Ok(event) => match budget.observe(&event, execution_limits) {
                        Ok(()) => Ok(event),
                        Err(error) => Err(error),
                    },
                    Err(error) => Err(error),
                };
                let response = match event {
                    Ok(MeshEvent::Progress(progress)) => Ok(status_update(
                        &task_id,
                        &context_id,
                        TaskState::Working,
                        Some(progress),
                    )),
                    Ok(MeshEvent::Artifact {
                        name,
                        media_type,
                        content,
                    }) => {
                        let artifact = Artifact {
                            artifact_id: new_artifact_id(),
                            name: Some(name),
                            description: Some("Accepted SMESH output".to_owned()),
                            parts: vec![Part::text(content).with_media_type(media_type)],
                            metadata: None,
                            extensions: None,
                        };
                        artifacts.push(artifact.clone());
                        Ok(StreamResponse::ArtifactUpdate(TaskArtifactUpdateEvent {
                            task_id: task_id.clone(),
                            context_id: context_id.clone(),
                            artifact,
                            append: Some(false),
                            last_chunk: Some(true),
                            metadata: None,
                        }))
                    }
                    Ok(MeshEvent::Completed { summary }) => Ok(StreamResponse::Task(Task {
                        id: task_id.clone(),
                        context_id: context_id.clone(),
                        status: TaskStatus {
                            state: TaskState::Completed,
                            message: Some(agent_message(&task_id, &context_id, summary)),
                            timestamp: Some(chrono::Utc::now()),
                        },
                        artifacts: (!artifacts.is_empty()).then(|| artifacts.clone()),
                        history: Some(history.clone()),
                        metadata: None,
                    })),
                    Err(error) => Ok(StreamResponse::Task(Task {
                        id: task_id.clone(),
                        context_id: context_id.clone(),
                        status: TaskStatus {
                            state: TaskState::Failed,
                            message: Some(agent_message(&task_id, &context_id, error.to_string())),
                            timestamp: Some(chrono::Utc::now()),
                        },
                        artifacts: None,
                        history: Some(history.clone()),
                        metadata: None,
                    })),
                };

                let terminal = matches!(
                    &response,
                    Ok(StreamResponse::Task(task)) if task.status.state.is_terminal()
                );
                if tx.send(response).await.is_err() {
                    terminal_emitted = true;
                    break;
                }
                if terminal {
                    terminal_emitted = true;
                    break;
                }
            }

            if !terminal_emitted {
                let _ = tx
                    .send(Ok(StreamResponse::Task(Task {
                        id: task_id.clone(),
                        context_id: context_id.clone(),
                        status: TaskStatus {
                            state: TaskState::Failed,
                            message: Some(agent_message(
                                &task_id,
                                &context_id,
                                "SMESH worker stream ended without a terminal event".to_owned(),
                            )),
                            timestamp: Some(chrono::Utc::now()),
                        },
                        artifacts: (!artifacts.is_empty()).then_some(artifacts),
                        history: Some(history.clone()),
                        metadata: None,
                    })))
                    .await;
            }
            cancellations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&task_id);
        });

        Box::pin(ReceiverStream::new(rx))
    }

    fn cancel(&self, ctx: ExecutorContext) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
        let dispatcher = Arc::clone(&self.dispatcher);
        let cancellations = Arc::clone(&self.cancellations);
        let cancel_timeout = self.execution_limits.cancel_timeout;
        let task_id = ctx.task_id;
        let context_id = ctx.context_id;

        Box::pin(stream::once(async move {
            let token = cancellations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&task_id)
                .cloned();
            tokio::time::timeout(cancel_timeout, dispatcher.cancel(&task_id))
                .await
                .map_err(|_| A2AError::internal("SMESH cancellation timed out"))?
                .map_err(|error| A2AError::internal(error.to_string()))?;
            if let Some(token) = token {
                token.cancel();
            }
            Ok(status_update(
                &task_id,
                &context_id,
                TaskState::Canceled,
                None,
            ))
        }))
    }
}

fn status_update(
    task_id: &str,
    context_id: &str,
    state: TaskState,
    text: Option<String>,
) -> StreamResponse {
    StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
        task_id: task_id.to_owned(),
        context_id: context_id.to_owned(),
        status: TaskStatus {
            state,
            message: text.map(|message| agent_message(task_id, context_id, message)),
            timestamp: Some(chrono::Utc::now()),
        },
        metadata: None,
    })
}

fn agent_message(task_id: &str, context_id: &str, text: String) -> Message {
    Message {
        message_id: new_message_id(),
        context_id: Some(context_id.to_owned()),
        task_id: Some(task_id.to_owned()),
        role: Role::Agent,
        parts: vec![Part::text(text)],
        metadata: None,
        extensions: None,
        reference_task_ids: None,
    }
}
