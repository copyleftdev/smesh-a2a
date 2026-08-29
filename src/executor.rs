use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use a2a::{
    A2AError, Artifact, Message, Part, Role, StreamResponse, Task, TaskState, TaskStatus,
    TaskStatusUpdateEvent, new_artifact_id, new_message_id,
};
use a2a_server::{AgentExecutor, ExecutorContext};
use futures::StreamExt;
use futures::stream::{self, BoxStream};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

use crate::{
    ArtifactManifest, CompletionEvidence, CompletionSnapshot, InputLimits, MeshDispatcher,
    MeshEvent, MeshRequest, PolicyCheckpoint, PolicyDecision, RuntimeCancellationOutcome,
    RuntimeEventCapture, RuntimeTerminalState, VersionedCompletionPolicy, content_digest,
};

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

        if matches!(event, MeshEvent::Artifact { .. }) {
            self.artifacts = self.artifacts.saturating_add(1);
            if self.artifacts > limits.max_artifacts {
                return Err(crate::DispatchError::Message(
                    "SMESH worker exceeded artifact budget".to_owned(),
                ));
            }
        }
        let bytes = serde_json::to_vec(event)
            .map_err(|error| {
                crate::DispatchError::Message(format!("SMESH event serialization failed: {error}"))
            })?
            .len();
        self.output_bytes = self.output_bytes.saturating_add(bytes);
        if self.output_bytes > limits.max_output_bytes {
            return Err(crate::DispatchError::Message(
                "SMESH worker exceeded output byte budget".to_owned(),
            ));
        }
        Ok(())
    }
}

const TERMINAL_OPEN: u8 = 0;
const TERMINAL_CANCEL: u8 = 1;
const TERMINAL_EXECUTION: u8 = 2;
const CANCEL_OUTCOME_PENDING: u8 = 0;
const CANCEL_OUTCOME_CANCELED: u8 = 1;
const CANCEL_OUTCOME_FAILED: u8 = 2;
const CANCEL_OUTCOME_FORCED_ABORT: u8 = 3;

struct ExecutionControl {
    cancellation: CancellationToken,
    terminal: AtomicU8,
    cancel_outcome: AtomicU8,
    cancel_done: tokio::sync::Notify,
    terminal_published: tokio::sync::Notify,
    emission: tokio::sync::Mutex<()>,
}

impl ExecutionControl {
    fn new() -> Self {
        Self {
            cancellation: CancellationToken::new(),
            terminal: AtomicU8::new(TERMINAL_OPEN),
            cancel_outcome: AtomicU8::new(CANCEL_OUTCOME_PENDING),
            cancel_done: tokio::sync::Notify::new(),
            terminal_published: tokio::sync::Notify::new(),
            emission: tokio::sync::Mutex::new(()),
        }
    }

    fn claim_execution(&self) -> bool {
        self.terminal
            .compare_exchange(
                TERMINAL_OPEN,
                TERMINAL_EXECUTION,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
    }

    fn claim_cancel(&self) -> bool {
        self.terminal
            .compare_exchange(
                TERMINAL_OPEN,
                TERMINAL_CANCEL,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
    }
}

fn cancellation_terminal(outcome: u8) -> (TaskState, RuntimeCancellationOutcome, &'static str) {
    match outcome {
        CANCEL_OUTCOME_CANCELED => (
            TaskState::Canceled,
            RuntimeCancellationOutcome::CooperativeStop,
            "SMESH task canceled",
        ),
        CANCEL_OUTCOME_FORCED_ABORT => (
            TaskState::Failed,
            RuntimeCancellationOutcome::ForcedAbort,
            "SMESH dispatcher reported a forced abort; external effect containment is unknown",
        ),
        _ => (
            TaskState::Failed,
            RuntimeCancellationOutcome::Failed,
            "SMESH cancellation failed",
        ),
    }
}

/// A2A executor that delegates accepted work to a SMESH dispatcher.
pub struct SmeshExecutor<D> {
    dispatcher: Arc<D>,
    limits: InputLimits,
    gateway_node_id: String,
    cancellations: Arc<Mutex<HashMap<String, Arc<ExecutionControl>>>>,
    execution_limits: ExecutionLimits,
    permits: Arc<tokio::sync::Semaphore>,
    completion_policy: Arc<VersionedCompletionPolicy>,
    runtime_trace: Option<Arc<RuntimeEventCapture>>,
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
            completion_policy: Arc::new(VersionedCompletionPolicy::default()),
            runtime_trace: None,
        }
    }

    #[must_use]
    pub fn with_execution_limits(mut self, mut limits: ExecutionLimits) -> Self {
        // The upstream A2A handler uses a 32-event broadcast buffer. Keep the
        // producer budget below that ceiling so a burst cannot outrun a newly
        // attached subscriber before backpressure begins.
        if limits.max_events > 16 {
            limits.max_events = 16;
        }
        self.permits = Arc::new(tokio::sync::Semaphore::new(
            limits.max_concurrent_tasks.max(1),
        ));
        self.execution_limits = limits;
        self
    }

    #[must_use]
    pub fn with_completion_policy(mut self, policy: VersionedCompletionPolicy) -> Self {
        self.completion_policy = Arc::new(policy);
        self
    }

    #[must_use]
    pub fn with_runtime_trace(mut self, trace: Arc<RuntimeEventCapture>) -> Self {
        self.runtime_trace = Some(trace);
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
                let runtime_trace = self.runtime_trace.clone();
                return Box::pin(stream::once(async move {
                    if !record_terminal_trace(
                        runtime_trace.as_deref(),
                        &task_id,
                        &context_id,
                        TaskState::Rejected,
                        Vec::new(),
                    )
                    .await
                    {
                        return Err(A2AError::internal("required runtime trace capture failed"));
                    }
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
        let current_request_digest = match serde_json::to_vec(&request) {
            Ok(bytes) => content_digest(&bytes),
            Err(error) => {
                return Box::pin(stream::once(async move {
                    Err(A2AError::internal(format!(
                        "failed to encode completion request binding: {error}"
                    )))
                }));
            }
        };
        let request_digest = match pending_ratification_request_digest(
            ctx.stored_task.as_ref(),
            &ctx.task_id,
            &ctx.context_id,
            &self.completion_policy,
        ) {
            Ok(Some(digest)) => digest,
            Ok(None) => current_request_digest,
            Err(error) => return Box::pin(stream::once(async move { Err(error) })),
        };

        let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() else {
            let task_id = ctx.task_id.clone();
            let context_id = ctx.context_id.clone();
            let runtime_trace = self.runtime_trace.clone();
            return Box::pin(stream::once(async move {
                if !record_terminal_trace(
                    runtime_trace.as_deref(),
                    &task_id,
                    &context_id,
                    TaskState::Rejected,
                    Vec::new(),
                )
                .await
                {
                    return Err(A2AError::internal("required runtime trace capture failed"));
                }
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
        let task_id = ctx.task_id;
        let context_id = ctx.context_id;
        let Ok(execution_budget) = crate::ExecutionBudget::new(
            u64::try_from(self.execution_limits.max_output_bytes).unwrap_or(u64::MAX),
            u64::try_from(self.execution_limits.max_events.clamp(1, 16)).unwrap_or(16),
        ) else {
            return Box::pin(stream::once(async {
                Err(A2AError::internal("invalid trusted execution budget"))
            }));
        };
        let control = Arc::new(ExecutionControl::new());
        let cancellation = control.cancellation.clone();
        self.cancellations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(task_id.clone(), Arc::clone(&control));
        let mut mesh_stream = self.dispatcher.dispatch_bounded(request, execution_budget);
        let cancellations = Arc::clone(&self.cancellations);
        let execution_limits = self.execution_limits;
        let completion_policy = Arc::clone(&self.completion_policy);
        let runtime_trace = self.runtime_trace.clone();
        let dispatcher: Arc<dyn MeshDispatcher> = self.dispatcher.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(16);

        tokio::spawn(async move {
            let _permit = permit;
            let mut artifacts = Vec::new();
            let mut artifact_manifests = Vec::new();
            let mut evidence = Vec::<CompletionEvidence>::new();
            let mut completion_proposed = false;
            let mut budget = EventBudget::default();
            let mut terminal_emitted = false;
            let task_deadline = tokio::time::sleep(execution_limits.task_timeout);
            tokio::pin!(task_deadline);
            if !send_work_event(
                &control,
                &tx,
                StreamResponse::Task(Task {
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
                }),
            )
            .await
            {
                request_dispatcher_cancel(&dispatcher, &task_id, execution_limits.cancel_timeout)
                    .await;
                cancellations
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&task_id);
                return;
            }

            loop {
                let next = tokio::select! {
                    biased;
                    () = tx.closed() => {
                        request_dispatcher_cancel(
                            &dispatcher,
                            &task_id,
                            execution_limits.cancel_timeout,
                        ).await;
                        terminal_emitted = true;
                        break;
                    }
                    () = cancellation.cancelled() => {
                        publish_cancellation_terminal(
                            control.as_ref(),
                            &tx,
                            runtime_trace.as_deref(),
                            &task_id,
                            &context_id,
                            &history,
                        )
                        .await;
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
                match event {
                    Ok(MeshEvent::Progress(_progress)) => {
                        if !send_work_event(
                            &control,
                            &tx,
                            status_update(
                                &task_id,
                                &context_id,
                                TaskState::Working,
                                Some("SMESH worker reported progress".to_owned()),
                            ),
                        )
                        .await
                        {
                            request_dispatcher_cancel(
                                &dispatcher,
                                &task_id,
                                execution_limits.cancel_timeout,
                            )
                            .await;
                            terminal_emitted = true;
                            break;
                        }
                    }
                    Ok(MeshEvent::Evidence(record)) => {
                        if let Some(trace) = &runtime_trace
                            && trace
                                .record_evidence(&task_id, &context_id, &record)
                                .await
                                .is_err()
                        {
                            let _ = control.claim_execution();
                            request_dispatcher_cancel(
                                &dispatcher,
                                &task_id,
                                execution_limits.cancel_timeout,
                            )
                            .await;
                            terminal_emitted = true;
                            break;
                        }
                        evidence.push(record);
                    }
                    Ok(MeshEvent::Artifact {
                        name,
                        media_type,
                        content,
                    }) => {
                        artifact_manifests.push(ArtifactManifest {
                            name: name.clone(),
                            media_type: media_type.clone(),
                            digest: content_digest(content.as_bytes()),
                        });
                        artifacts.push(Artifact {
                            artifact_id: new_artifact_id(),
                            name: Some(name),
                            description: Some("Unpublished SMESH candidate output".to_owned()),
                            parts: vec![Part::text(content).with_media_type(media_type)],
                            metadata: None,
                            extensions: None,
                        });
                    }
                    Ok(MeshEvent::Completed { summary: _summary }) => {
                        if completion_proposed {
                            if control.claim_execution()
                                && record_terminal_trace(
                                    runtime_trace.as_deref(),
                                    &task_id,
                                    &context_id,
                                    TaskState::Failed,
                                    Vec::new(),
                                )
                                .await
                            {
                                let _ = tx
                                    .send(Ok(task_response(
                                        &task_id,
                                        &context_id,
                                        TaskState::Failed,
                                        "worker emitted more than one completion proposal"
                                            .to_owned(),
                                        None,
                                        history.clone(),
                                        None,
                                    )))
                                    .await;
                            }
                            request_dispatcher_cancel(
                                &dispatcher,
                                &task_id,
                                execution_limits.cancel_timeout,
                            )
                            .await;
                            terminal_emitted = true;
                            break;
                        }
                        completion_proposed = true;
                    }
                    Err(_error) => {
                        if control.claim_execution()
                            && record_terminal_trace(
                                runtime_trace.as_deref(),
                                &task_id,
                                &context_id,
                                TaskState::Failed,
                                Vec::new(),
                            )
                            .await
                        {
                            let _ = tx
                                .send(Ok(task_response(
                                    &task_id,
                                    &context_id,
                                    TaskState::Failed,
                                    "SMESH worker failed".to_owned(),
                                    None,
                                    history.clone(),
                                    None,
                                )))
                                .await;
                        }
                        request_dispatcher_cancel(
                            &dispatcher,
                            &task_id,
                            execution_limits.cancel_timeout,
                        )
                        .await;
                        terminal_emitted = true;
                        break;
                    }
                }
            }

            if !terminal_emitted {
                if completion_proposed {
                    let completion = finalize_completion(
                        &tx,
                        completion_policy.as_ref(),
                        control.as_ref(),
                        runtime_trace.as_deref(),
                        &dispatcher,
                        execution_limits.cancel_timeout,
                        &task_id,
                        &context_id,
                        CompletionMaterial {
                            request_digest,
                            artifacts,
                            artifact_manifests,
                            evidence,
                            history: history.clone(),
                        },
                    );
                    tokio::pin!(completion);
                    tokio::select! {
                        biased;
                        () = cancellation.cancelled() => {
                            publish_cancellation_terminal(
                                control.as_ref(),
                                &tx,
                                runtime_trace.as_deref(),
                                &task_id,
                                &context_id,
                                &history,
                            )
                            .await;
                        }
                        () = &mut task_deadline => {
                            if control.claim_execution()
                                && record_terminal_trace(
                                    runtime_trace.as_deref(),
                                    &task_id,
                                    &context_id,
                                    TaskState::Failed,
                                    Vec::new(),
                                ).await
                            {
                                let _ = tx.send(Ok(task_response(
                                    &task_id,
                                    &context_id,
                                    TaskState::Failed,
                                    "SMESH task deadline exceeded during completion policy evaluation"
                                        .to_owned(),
                                    None,
                                    history.clone(),
                                    None,
                                ))).await;
                            }
                            request_dispatcher_cancel(
                                &dispatcher,
                                &task_id,
                                execution_limits.cancel_timeout,
                            ).await;
                        }
                        () = &mut completion => {}
                    }
                } else {
                    if control.claim_execution()
                        && record_terminal_trace(
                            runtime_trace.as_deref(),
                            &task_id,
                            &context_id,
                            TaskState::Failed,
                            Vec::new(),
                        )
                        .await
                    {
                        let _ = tx
                            .send(Ok(task_response(
                                &task_id,
                                &context_id,
                                TaskState::Failed,
                                "SMESH worker stream ended without a completion proposal"
                                    .to_owned(),
                                None,
                                history.clone(),
                                None,
                            )))
                            .await;
                    }
                    request_dispatcher_cancel(
                        &dispatcher,
                        &task_id,
                        execution_limits.cancel_timeout,
                    )
                    .await;
                }
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
        let (tx, rx) = tokio::sync::mpsc::channel(1);

        tokio::spawn(async move {
            let control = cancellations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&task_id)
                .cloned();
            let Some(control) = control else {
                let _ = tx.send(Err(A2AError::task_not_cancelable(&task_id))).await;
                return;
            };
            let emission = control.emission.lock().await;
            if !control.claim_cancel() {
                let _ = tx.send(Err(A2AError::task_not_cancelable(&task_id))).await;
                return;
            }
            control.cancellation.cancel();
            drop(emission);
            let outcome =
                match tokio::time::timeout(cancel_timeout, dispatcher.cancel(&task_id)).await {
                    Ok(Ok(())) => CANCEL_OUTCOME_CANCELED,
                    Ok(Err(crate::DispatchError::CancellationForcedAbort)) => {
                        CANCEL_OUTCOME_FORCED_ABORT
                    }
                    Ok(Err(_)) | Err(_) => CANCEL_OUTCOME_FAILED,
                };
            control.cancel_outcome.store(outcome, Ordering::SeqCst);
            control.cancel_done.notify_one();
            let _ =
                tokio::time::timeout(cancel_timeout, control.terminal_published.notified()).await;
        });
        Box::pin(ReceiverStream::new(rx))
    }
}

async fn record_terminal_trace(
    trace: Option<&RuntimeEventCapture>,
    task_id: &str,
    context_id: &str,
    state: TaskState,
    artifact_digests: Vec<String>,
) -> bool {
    let Some(trace) = trace else {
        return true;
    };
    let trace_state = match state {
        TaskState::Completed => RuntimeTerminalState::Completed,
        TaskState::Canceled => RuntimeTerminalState::Canceled,
        TaskState::InputRequired => RuntimeTerminalState::InputRequired,
        TaskState::Rejected => RuntimeTerminalState::Rejected,
        _ => RuntimeTerminalState::Failed,
    };
    trace
        .record_terminal(task_id, context_id, trace_state, artifact_digests)
        .await
        .is_ok()
}

async fn publish_cancellation_terminal(
    control: &ExecutionControl,
    tx: &tokio::sync::mpsc::Sender<Result<StreamResponse, A2AError>>,
    trace: Option<&RuntimeEventCapture>,
    task_id: &str,
    context_id: &str,
    history: &[Message],
) {
    if control.cancel_outcome.load(Ordering::SeqCst) == CANCEL_OUTCOME_PENDING {
        control.cancel_done.notified().await;
    }
    let (state, cancellation_outcome, text) =
        cancellation_terminal(control.cancel_outcome.load(Ordering::SeqCst));
    if record_cancellation_terminal_trace(
        trace,
        task_id,
        context_id,
        state.clone(),
        cancellation_outcome,
    )
    .await
    {
        let _ = tx
            .send(Ok(task_response(
                task_id,
                context_id,
                state,
                text.to_owned(),
                None,
                history.to_vec(),
                None,
            )))
            .await;
    }
    control.terminal_published.notify_one();
}

async fn record_cancellation_terminal_trace(
    trace: Option<&RuntimeEventCapture>,
    task_id: &str,
    context_id: &str,
    state: TaskState,
    outcome: RuntimeCancellationOutcome,
) -> bool {
    let Some(trace) = trace else {
        return true;
    };
    let trace_state = if state == TaskState::Canceled {
        RuntimeTerminalState::Canceled
    } else {
        RuntimeTerminalState::Failed
    };
    trace
        .record_cancellation_terminal(task_id, context_id, trace_state, outcome)
        .await
        .is_ok()
}

async fn send_work_event(
    control: &ExecutionControl,
    tx: &tokio::sync::mpsc::Sender<Result<StreamResponse, A2AError>>,
    event: StreamResponse,
) -> bool {
    let _guard = control.emission.lock().await;
    if control.terminal.load(Ordering::SeqCst) != TERMINAL_OPEN {
        return false;
    }
    tx.send(Ok(event)).await.is_ok()
}

async fn request_dispatcher_cancel(
    dispatcher: &Arc<dyn MeshDispatcher>,
    task_id: &str,
    timeout: Duration,
) {
    let _ = tokio::time::timeout(timeout, dispatcher.cancel(task_id)).await;
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

struct CompletionMaterial {
    request_digest: String,
    artifacts: Vec<Artifact>,
    artifact_manifests: Vec<ArtifactManifest>,
    evidence: Vec<CompletionEvidence>,
    history: Vec<Message>,
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // Keep policy-to-A2A mapping linear and auditable.
async fn finalize_completion(
    tx: &tokio::sync::mpsc::Sender<Result<StreamResponse, A2AError>>,
    policy: &VersionedCompletionPolicy,
    control: &ExecutionControl,
    runtime_trace: Option<&RuntimeEventCapture>,
    dispatcher: &Arc<dyn MeshDispatcher>,
    cancel_timeout: Duration,
    task_id: &str,
    context_id: &str,
    mut material: CompletionMaterial,
) {
    if !control.claim_execution() {
        return;
    }
    let snapshot = CompletionSnapshot {
        task_id: task_id.to_owned(),
        context_id: context_id.to_owned(),
        request_digest: material.request_digest,
        artifacts: material.artifact_manifests,
        evidence: material.evidence,
    };
    match policy.evaluate(&snapshot) {
        Ok(PolicyDecision::Accepted(receipt)) => {
            let metadata = match policy_metadata("accepted", &receipt) {
                Ok(metadata) => metadata,
                Err(_error) => {
                    if !record_terminal_trace(
                        runtime_trace,
                        task_id,
                        context_id,
                        TaskState::Failed,
                        Vec::new(),
                    )
                    .await
                    {
                        request_dispatcher_cancel(dispatcher, task_id, cancel_timeout).await;
                        return;
                    }
                    let _ = tx
                        .send(Ok(task_response(
                            task_id,
                            context_id,
                            TaskState::Failed,
                            "completion policy metadata encoding failed".to_owned(),
                            None,
                            material.history,
                            None,
                        )))
                        .await;
                    request_dispatcher_cancel(dispatcher, task_id, cancel_timeout).await;
                    return;
                }
            };
            if !record_terminal_trace(
                runtime_trace,
                task_id,
                context_id,
                TaskState::Completed,
                snapshot
                    .artifacts
                    .iter()
                    .map(|artifact| artifact.digest.clone())
                    .collect(),
            )
            .await
            {
                request_dispatcher_cancel(dispatcher, task_id, cancel_timeout).await;
                return;
            }
            for artifact in &mut material.artifacts {
                artifact.description = Some("Policy-accepted SMESH output".to_owned());
                artifact.metadata = Some(metadata.clone());
            }
            if tx
                .send(Ok(task_response(
                    task_id,
                    context_id,
                    TaskState::Completed,
                    "SMESH task completed under completion policy".to_owned(),
                    Some(material.artifacts),
                    material.history,
                    Some(metadata),
                )))
                .await
                .is_err()
            {
                request_dispatcher_cancel(dispatcher, task_id, cancel_timeout).await;
            }
        }
        Ok(PolicyDecision::AwaitingRatification(checkpoint)) => {
            send_policy_outcome(
                tx,
                task_id,
                context_id,
                &checkpoint,
                PolicyOutcomeMaterial {
                    state: TaskState::InputRequired,
                    text: "human ratification is required".to_owned(),
                    status: "awaitingRatification",
                    history: material.history,
                },
                runtime_trace,
                dispatcher,
                cancel_timeout,
            )
            .await;
        }
        Ok(PolicyDecision::Blocked(block)) => {
            let text = format!("completion policy blocked the task: {:?}", block.reasons);
            send_policy_outcome(
                tx,
                task_id,
                context_id,
                &block,
                PolicyOutcomeMaterial {
                    state: TaskState::Failed,
                    text,
                    status: "blocked",
                    history: material.history,
                },
                runtime_trace,
                dispatcher,
                cancel_timeout,
            )
            .await;
            request_dispatcher_cancel(dispatcher, task_id, cancel_timeout).await;
        }
        Err(_error) => {
            if !record_terminal_trace(
                runtime_trace,
                task_id,
                context_id,
                TaskState::Failed,
                Vec::new(),
            )
            .await
            {
                request_dispatcher_cancel(dispatcher, task_id, cancel_timeout).await;
                return;
            }
            let _ = tx
                .send(Ok(task_response(
                    task_id,
                    context_id,
                    TaskState::Failed,
                    "completion policy rejected malformed input".to_owned(),
                    None,
                    material.history,
                    None,
                )))
                .await;
            request_dispatcher_cancel(dispatcher, task_id, cancel_timeout).await;
        }
    }
}

struct PolicyOutcomeMaterial {
    state: TaskState,
    text: String,
    status: &'static str,
    history: Vec<Message>,
}

#[allow(clippy::too_many_arguments)] // Keep policy metadata, trace, cancellation, and publication explicit.
async fn send_policy_outcome(
    tx: &tokio::sync::mpsc::Sender<Result<StreamResponse, A2AError>>,
    task_id: &str,
    context_id: &str,
    record: &impl serde::Serialize,
    outcome: PolicyOutcomeMaterial,
    runtime_trace: Option<&RuntimeEventCapture>,
    dispatcher: &Arc<dyn MeshDispatcher>,
    cancel_timeout: Duration,
) {
    match policy_metadata(outcome.status, record) {
        Ok(metadata) => {
            if !record_terminal_trace(
                runtime_trace,
                task_id,
                context_id,
                outcome.state.clone(),
                Vec::new(),
            )
            .await
            {
                request_dispatcher_cancel(dispatcher, task_id, cancel_timeout).await;
                return;
            }
            let _ = tx
                .send(Ok(task_response(
                    task_id,
                    context_id,
                    outcome.state,
                    outcome.text,
                    None,
                    outcome.history,
                    Some(metadata),
                )))
                .await;
        }
        Err(error) => {
            if !record_terminal_trace(
                runtime_trace,
                task_id,
                context_id,
                TaskState::Failed,
                Vec::new(),
            )
            .await
            {
                request_dispatcher_cancel(dispatcher, task_id, cancel_timeout).await;
                return;
            }
            let _ = tx
                .send(Ok(task_response(
                    task_id,
                    context_id,
                    TaskState::Failed,
                    error.to_string(),
                    None,
                    outcome.history,
                    None,
                )))
                .await;
        }
    }
}

fn pending_ratification_request_digest(
    stored_task: Option<&Task>,
    task_id: &str,
    context_id: &str,
    policy: &VersionedCompletionPolicy,
) -> Result<Option<String>, A2AError> {
    let Some(task) = stored_task else {
        return Ok(None);
    };
    if task.status.state != TaskState::InputRequired {
        return Ok(None);
    }
    let value = task
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("smesh.completionPolicy"))
        .filter(|value| {
            value.get("status").and_then(serde_json::Value::as_str) == Some("awaitingRatification")
        })
        .and_then(|value| value.get("record"))
        .cloned()
        .ok_or_else(A2AError::invalid_agent_response)?;
    let checkpoint: PolicyCheckpoint =
        serde_json::from_value(value).map_err(|_| A2AError::invalid_agent_response())?;
    if !policy.verify_checkpoint(&checkpoint, task_id, context_id) {
        return Err(A2AError::invalid_agent_response());
    }
    Ok(Some(checkpoint.request_digest))
}

fn task_response(
    task_id: &str,
    context_id: &str,
    state: TaskState,
    text: String,
    artifacts: Option<Vec<Artifact>>,
    history: Vec<Message>,
    metadata: Option<HashMap<String, serde_json::Value>>,
) -> StreamResponse {
    StreamResponse::Task(Task {
        id: task_id.to_owned(),
        context_id: context_id.to_owned(),
        status: TaskStatus {
            state,
            message: Some(agent_message(task_id, context_id, text)),
            timestamp: Some(chrono::Utc::now()),
        },
        artifacts,
        history: Some(history),
        metadata,
    })
}

fn policy_metadata(
    status: &str,
    record: &impl serde::Serialize,
) -> Result<HashMap<String, serde_json::Value>, crate::DispatchError> {
    let record = serde_json::to_value(record).map_err(|error| {
        crate::DispatchError::Message(format!("completion policy record encoding failed: {error}"))
    })?;
    Ok(HashMap::from([(
        "smesh.completionPolicy".to_owned(),
        serde_json::json!({ "status": status, "record": record }),
    )]))
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
