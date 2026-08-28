use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use a2a::{
    Artifact, Message, Part, Role, SendMessageResponse, StreamResponse, TaskArtifactUpdateEvent,
    TaskState, TaskStatus, TaskStatusUpdateEvent,
};
use a2a_server::TaskStore;
use tokio::sync::{Notify, watch};
use tokio_util::sync::CancellationToken;

use crate::{
    AttemptDisposition, DurableDispatchEnvelope, DurableLoopbackEndpoint,
    DurableReceiverTermination, InjectedClock, MeshEvent, SqliteTaskStore, TransitionOutcome,
    content_digest,
    durable_dispatch::{DURABLE_CANCELED_SUMMARY, DurableDispatchOutcome},
};

#[derive(Clone, Debug, Default)]
pub(crate) struct DriverState {
    pub generation: u64,
    pub failure: Option<String>,
    pub waiters: usize,
}

pub(crate) struct WaiterGuard(Arc<DurableDriverControl>);

impl Drop for WaiterGuard {
    fn drop(&mut self) {
        self.0.state.send_modify(|state| state.waiters -= 1);
    }
}

pub(crate) struct DurableDriverControl {
    pub wake: Arc<Notify>,
    state: watch::Sender<DriverState>,
    cancel: CancellationToken,
    endpoint: DurableLoopbackEndpoint,
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct DriverTestGate {
    armed: Arc<AtomicBool>,
    pub reached: Arc<Notify>,
    pub release: Arc<Notify>,
}

#[cfg(test)]
impl DriverTestGate {
    pub(crate) fn new() -> Self {
        Self {
            armed: Arc::new(AtomicBool::new(true)),
            reached: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
        }
    }

    async fn enter_once(&self, cancel: &CancellationToken) -> bool {
        if !self.armed.swap(false, Ordering::SeqCst) {
            return true;
        }
        self.reached.notify_one();
        tokio::select! {
            () = cancel.cancelled() => false,
            () = self.release.notified() => true,
        }
    }
}

#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct DriverTestHooks {
    pub before_claim: Option<DriverTestGate>,
    pub after_commit_before_publish: Option<DriverTestGate>,
    pub idle: Option<Arc<Notify>>,
}

impl DurableDriverControl {
    pub(crate) fn signal_cancel(&self, dispatch_id: &str) {
        self.endpoint.signal_cancel(dispatch_id);
        self.wake.notify_one();
    }
    pub(crate) fn subscribe(&self) -> watch::Receiver<DriverState> {
        self.state.subscribe()
    }

    pub(crate) fn waiter(self: &Arc<Self>) -> WaiterGuard {
        self.state.send_modify(|state| state.waiters += 1);
        WaiterGuard(Arc::clone(self))
    }

    pub(crate) fn changed(&self) {
        self.state.send_modify(|state| {
            state.generation = state.generation.wrapping_add(1);
        });
    }

    fn failed(&self, error: &a2a::A2AError) {
        self.state.send_modify(|state| {
            state.generation = state.generation.wrapping_add(1);
            state.failure = Some(error.to_string());
        });
    }
}

pub(crate) struct DurableDriverHandle {
    control: Arc<DurableDriverControl>,
    join: Option<tokio::task::JoinHandle<Result<(), a2a::A2AError>>>,
}

impl DurableDriverHandle {
    pub(crate) fn control(&self) -> Arc<DurableDriverControl> {
        Arc::clone(&self.control)
    }

    pub(crate) fn abort_owned(&mut self) {
        let Some(join) = self.join.take() else {
            return;
        };
        self.control.state.send_modify(|state| {
            state.generation = state.generation.wrapping_add(1);
            state.failure = Some("durable gateway was dropped".to_owned());
        });
        self.control.cancel.cancel();
        self.control.endpoint.cancel_all();
        self.control.wake.notify_waiters();
        join.abort();
    }

    pub(crate) async fn shutdown(mut self) -> Result<(), a2a::A2AError> {
        self.control.state.send_modify(|state| {
            state.generation = state.generation.wrapping_add(1);
            state.failure = Some("durable gateway is shutting down".to_owned());
        });
        self.control.cancel.cancel();
        self.control.endpoint.cancel_all();
        self.control.wake.notify_waiters();
        let Some(mut join) = self.join.take() else {
            return Ok(());
        };
        if let Ok(joined) = tokio::time::timeout(Duration::from_secs(5), &mut join).await {
            joined.map_err(|_| a2a::A2AError::internal("durable outbox driver panicked"))?
        } else {
            join.abort();
            let _ = join.await;
            Err(a2a::A2AError::internal(
                "durable outbox driver shutdown timed out",
            ))
        }
    }
}

impl Drop for DurableDriverHandle {
    fn drop(&mut self) {
        self.abort_owned();
    }
}

#[allow(clippy::too_many_lines)] // The loop is one cohesive fenced-lease state machine.
pub(crate) fn spawn_durable_driver(
    store: SqliteTaskStore,
    endpoint: DurableLoopbackEndpoint,
    clock: InjectedClock,
) -> DurableDriverHandle {
    spawn_durable_driver_inner(
        store,
        endpoint,
        clock,
        #[cfg(test)]
        DriverTestHooks::default(),
    )
}

#[cfg(test)]
pub(crate) fn spawn_durable_driver_with_test_hooks(
    store: SqliteTaskStore,
    endpoint: DurableLoopbackEndpoint,
    clock: InjectedClock,
    hooks: DriverTestHooks,
) -> DurableDriverHandle {
    spawn_durable_driver_inner(store, endpoint, clock, hooks)
}

#[allow(clippy::too_many_lines)] // The loop is one cohesive fenced-lease state machine.
fn spawn_durable_driver_inner(
    store: SqliteTaskStore,
    endpoint: DurableLoopbackEndpoint,
    clock: InjectedClock,
    #[cfg(test)] hooks: DriverTestHooks,
) -> DurableDriverHandle {
    let (state, _) = watch::channel(DriverState::default());
    let control = Arc::new(DurableDriverControl {
        wake: Arc::new(Notify::new()),
        state,
        cancel: CancellationToken::new(),
        endpoint: endpoint.clone(),
    });
    let worker_control = Arc::clone(&control);
    let mut clock_changed = clock.subscribe();
    let join = tokio::spawn(async move {
        let result = async {
            loop {
                if worker_control.cancel.is_cancelled() {
                    return Ok(());
                }
                #[cfg(test)]
                if let Some(gate) = &hooks.before_claim
                    && !gate.enter_once(&worker_control.cancel).await
                {
                    return Ok(());
                }
                let Some(lease) = store
                    .claim_outbox("durable-loopback-driver", clock.now(), 60_000)
                    .await?
                else {
                    #[cfg(test)]
                    if let Some(idle) = &hooks.idle {
                        idle.notify_one();
                    }
                    tokio::select! {
                        () = worker_control.cancel.cancelled() => return Ok(()),
                        () = worker_control.wake.notified() => {},
                        changed = clock_changed.changed() => {
                            if changed.is_err() { return Ok(()); }
                        }
                    }
                    continue;
                };
                let payload = serde_json::to_string(&lease.request)
                    .map_err(|_| a2a::A2AError::internal("failed to encode durable dispatch"))?;
                let envelope = DurableDispatchEnvelope {
                    tenant_scope: lease.tenant_scope.clone(),
                    dispatch_id: lease.dispatch_id.clone(),
                    payload_digest: content_digest(payload.as_bytes()),
                    request: lease.request.clone(),
                };
                let committed_progress = if let Some(task) = store.get(&lease.task_id).await? {
                    let progress = build_progress_frame(
                        &task,
                        "SMESH swarm is processing the durable dispatch".to_owned(),
                        clock.now(),
                    );
                    let committed = store
                        .append_stream_progress(
                            &lease.tenant_scope,
                            &lease.dispatch_id,
                            progress,
                            clock.now(),
                        )
                        .await?;
                    if committed.is_some() {
                        worker_control.changed();
                    }
                    committed
                } else {
                    None
                };
                let dispatch = tokio::select! {
                    () = worker_control.cancel.cancelled() => {
                        let _ = store.finish_outbox_attempt(
                            &lease,
                            AttemptDisposition::Retry {
                                available_at: clock.now(),
                                error: "driver shutdown interrupted active dispatch".to_owned(),
                            },
                            clock.now(),
                        ).await?;
                        return Ok(());
                    }
                    result = endpoint.dispatch_once(&store, envelope, &clock) => result,
                };
                let (events, termination) = match dispatch {
                    Ok(DurableDispatchOutcome::Delivered(events)) => {
                        (events, DurableReceiverTermination::Success)
                    }
                    Ok(DurableDispatchOutcome::Interrupted(outcome)) => {
                        (outcome.events, outcome.termination)
                    }
                    Ok(DurableDispatchOutcome::Busy) => {
                        let available_at = clock
                            .now()
                            .checked_add(1_000)
                            .ok_or_else(|| a2a::A2AError::internal("retry time overflow"))?;
                        let outcome = store
                            .finish_outbox_attempt(
                                &lease,
                                AttemptDisposition::Retry {
                                    available_at,
                                    error: "durable receiver is busy".to_owned(),
                                },
                                clock.now(),
                            )
                            .await?;
                        if outcome == TransitionOutcome::DeadLettered {
                            worker_control.changed();
                        }
                        continue;
                    }
                    Err(error) => {
                        // Receiver validation/corruption errors are permanent. Busy is
                        // represented explicitly above and is the retryable class.
                        let outcome = store
                            .finish_outbox_attempt(
                                &lease,
                                AttemptDisposition::Permanent {
                                    error: error.to_string(),
                                },
                                clock.now(),
                            )
                            .await?;
                        if outcome == TransitionOutcome::DeadLettered {
                            worker_control.changed();
                        }
                        continue;
                    }
                };
                let Some(mut task) = store.get(&lease.task_id).await? else {
                    return Err(a2a::A2AError::task_not_found(&lease.task_id));
                };
                let admitted_task = task.clone();
                apply_terminal_events(
                    &mut task,
                    &lease.dispatch_id,
                    &events,
                    &termination,
                    clock.now(),
                )?;
                let public_transcript = build_public_transcript(
                    &admitted_task,
                    &task,
                    &events,
                    committed_progress,
                    clock.now(),
                );
                let result = SendMessageResponse::Task(task.clone());
                if store
                    .commit_delivery(&lease, task, result, &public_transcript, clock.now())
                    .await?
                    == TransitionOutcome::Applied
                {
                    #[cfg(test)]
                    if let Some(gate) = &hooks.after_commit_before_publish
                        && !gate.enter_once(&worker_control.cancel).await
                    {
                        return Ok(());
                    }
                    worker_control.changed();
                }
            }
        }
        .await;
        if let Err(error) = &result {
            worker_control.failed(error);
        }
        result
    });
    control.wake.notify_one();
    DurableDriverHandle {
        control,
        join: Some(join),
    }
}

fn apply_terminal_events(
    task: &mut a2a::Task,
    dispatch_id: &str,
    events: &[MeshEvent],
    termination: &DurableReceiverTermination,
    now: i64,
) -> Result<(), a2a::A2AError> {
    let mut artifacts = Vec::new();
    let mut completed_summary = None;
    for (index, event) in events.iter().enumerate() {
        match event {
            MeshEvent::Artifact {
                name,
                media_type,
                content,
            } => artifacts.push(Artifact {
                artifact_id: format!(
                    "artifact-{}",
                    &content_digest(format!("{dispatch_id}\0{index}").as_bytes())[..32]
                ),
                name: Some(name.clone()),
                description: Some("Durably replayable SMESH output".to_owned()),
                parts: vec![Part::text(content.clone()).with_media_type(media_type.clone())],
                metadata: None,
                extensions: None,
            }),
            MeshEvent::Completed { summary } => completed_summary = Some(summary.clone()),
            MeshEvent::Progress(_) | MeshEvent::Evidence(_) => {}
        }
    }
    let (state, summary, keep_artifacts) = match termination {
        DurableReceiverTermination::Success => {
            let summary = completed_summary.ok_or_else(a2a::A2AError::invalid_agent_response)?;
            if summary == DURABLE_CANCELED_SUMMARY {
                (TaskState::Canceled, summary, false)
            } else {
                (TaskState::Completed, summary, true)
            }
        }
        DurableReceiverTermination::InputRequired { message } => {
            (TaskState::InputRequired, message.clone(), false)
        }
        DurableReceiverTermination::AuthRequired { message } => {
            (TaskState::AuthRequired, message.clone(), false)
        }
    };
    let mut status_message = Message::new(Role::Agent, vec![Part::text(summary)]);
    status_message.message_id = format!("result-{}", &content_digest(dispatch_id.as_bytes())[..32]);
    status_message.task_id = Some(task.id.clone());
    status_message.context_id = Some(task.context_id.clone());
    task.status = TaskStatus {
        state,
        message: Some(status_message),
        timestamp: chrono::DateTime::from_timestamp_millis(now),
    };
    task.artifacts = (keep_artifacts && !artifacts.is_empty()).then_some(artifacts);
    Ok(())
}

fn build_progress_frame(task: &a2a::Task, progress: String, now: i64) -> StreamResponse {
    let mut progress_message = Message::new(Role::Agent, vec![Part::text(progress)]);
    progress_message.message_id = format!("progress-{}", &content_digest(task.id.as_bytes())[..32]);
    progress_message.task_id = Some(task.id.clone());
    progress_message.context_id = Some(task.context_id.clone());
    StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
        task_id: task.id.clone(),
        context_id: task.context_id.clone(),
        status: TaskStatus {
            state: TaskState::Working,
            message: Some(progress_message),
            timestamp: chrono::DateTime::from_timestamp_millis(now),
        },
        metadata: None,
    })
}

fn build_public_transcript(
    admitted_task: &a2a::Task,
    final_task: &a2a::Task,
    events: &[MeshEvent],
    committed_progress: Option<StreamResponse>,
    now: i64,
) -> Vec<StreamResponse> {
    let progress = events
        .iter()
        .find_map(|event| match event {
            MeshEvent::Progress(value) => Some(value.clone()),
            MeshEvent::Evidence(_) | MeshEvent::Artifact { .. } | MeshEvent::Completed { .. } => {
                None
            }
        })
        .unwrap_or_else(|| "SMESH swarm processed the durable dispatch".to_owned());
    let progress =
        committed_progress.unwrap_or_else(|| build_progress_frame(final_task, progress, now));
    let mut transcript = vec![StreamResponse::Task(admitted_task.clone()), progress];
    for artifact in final_task.artifacts.as_deref().unwrap_or_default() {
        transcript.push(StreamResponse::ArtifactUpdate(TaskArtifactUpdateEvent {
            task_id: final_task.id.clone(),
            context_id: final_task.context_id.clone(),
            artifact: artifact.clone(),
            append: Some(false),
            last_chunk: Some(true),
            metadata: None,
        }));
    }
    transcript.push(StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
        task_id: final_task.id.clone(),
        context_id: final_task.context_id.clone(),
        status: final_task.status.clone(),
        metadata: None,
    }));
    transcript
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_transcript_reuses_the_exact_committed_progress_frame() {
        let admitted = a2a::Task {
            id: "task-prefix-fence".to_owned(),
            context_id: "context-prefix-fence".to_owned(),
            status: TaskStatus {
                state: TaskState::Submitted,
                message: None,
                timestamp: chrono::DateTime::from_timestamp_millis(100),
            },
            artifacts: None,
            history: None,
            metadata: None,
        };
        let committed = build_progress_frame(&admitted, "committed progress".to_owned(), 100);
        let mut completed = admitted.clone();
        let events = vec![
            MeshEvent::Progress("committed progress".to_owned()),
            MeshEvent::Completed {
                summary: "completed".to_owned(),
            },
        ];
        apply_terminal_events(
            &mut completed,
            "dispatch-prefix-fence",
            &events,
            &DurableReceiverTermination::Success,
            101,
        )
        .expect("terminal task");

        let transcript =
            build_public_transcript(&admitted, &completed, &events, Some(committed.clone()), 101);

        assert_eq!(transcript[1], committed);
        assert_ne!(
            transcript[1],
            build_progress_frame(&completed, "committed progress".to_owned(), 101)
        );
    }
}
