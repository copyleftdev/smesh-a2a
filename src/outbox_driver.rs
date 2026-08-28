use std::cell::Cell;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Once;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use a2a::{
    Artifact, Message, Part, Role, SendMessageResponse, StreamResponse, TaskArtifactUpdateEvent,
    TaskState, TaskStatus, TaskStatusUpdateEvent,
};
use futures::FutureExt as _;
use tokio::sync::{Notify, watch};
use tokio_util::sync::CancellationToken;

use crate::{
    AttemptDisposition, DurableAuthority, DurableDispatchEnvelope, DurableLoopbackEndpoint,
    DurableReceiverTermination, InjectedClock, MeshEvent, TransitionOutcome, content_digest,
    durable_dispatch::{DURABLE_CANCELED_SUMMARY, DurableDispatchOutcome},
};

thread_local! {
    static REDACT_DRIVER_PANIC: Cell<bool> = const { Cell::new(false) };
}

static INSTALL_DRIVER_PANIC_HOOK: Once = Once::new();

fn install_driver_panic_hook() {
    INSTALL_DRIVER_PANIC_HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if REDACT_DRIVER_PANIC.with(Cell::get) {
                eprintln!("durable outbox driver panic (details redacted)");
            } else {
                previous(info);
            }
        }));
    });
}

struct DriverPanicScope(bool);

impl DriverPanicScope {
    fn enter() -> Self {
        Self(REDACT_DRIVER_PANIC.with(|flag| flag.replace(true)))
    }
}

impl Drop for DriverPanicScope {
    fn drop(&mut self) {
        REDACT_DRIVER_PANIC.with(|flag| flag.set(self.0));
    }
}

struct RedactedDriverPoll<F> {
    inner: Pin<Box<F>>,
}

impl<F> RedactedDriverPoll<F> {
    fn new(inner: F) -> Self {
        Self {
            inner: Box::pin(inner),
        }
    }
}

impl<F: Future> Future for RedactedDriverPoll<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let _scope = DriverPanicScope::enter();
        self.inner.as_mut().poll(context)
    }
}

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
            if state.failure.is_none() {
                state.failure = Some("durable gateway is shutting down".to_owned());
            }
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
    authority: Arc<dyn DurableAuthority>,
    endpoint: DurableLoopbackEndpoint,
    clock: InjectedClock,
) -> DurableDriverHandle {
    spawn_durable_driver_inner(
        authority,
        endpoint,
        clock,
        #[cfg(test)]
        DriverTestHooks::default(),
    )
}

#[cfg(test)]
pub(crate) fn spawn_durable_driver_with_test_hooks<A: crate::IntoDurableAuthority>(
    authority: A,
    endpoint: DurableLoopbackEndpoint,
    clock: InjectedClock,
    hooks: DriverTestHooks,
) -> DurableDriverHandle {
    spawn_durable_driver_inner(authority.into_durable_authority(), endpoint, clock, hooks)
}

#[allow(clippy::too_many_lines)] // The loop is one cohesive fenced-lease state machine.
fn spawn_durable_driver_inner(
    authority: Arc<dyn DurableAuthority>,
    endpoint: DurableLoopbackEndpoint,
    clock: InjectedClock,
    #[cfg(test)] hooks: DriverTestHooks,
) -> DurableDriverHandle {
    install_driver_panic_hook();
    let (state, _) = watch::channel(DriverState::default());
    let control = Arc::new(DurableDriverControl {
        wake: Arc::new(Notify::new()),
        state,
        cancel: CancellationToken::new(),
        endpoint: endpoint.clone(),
    });
    let worker_control = Arc::clone(&control);
    let poll_interval = authority.change_observation().poll_interval();
    let mut clock_changed = clock.subscribe();
    let join = tokio::spawn(async move {
        let result = AssertUnwindSafe(RedactedDriverPoll::new(async {
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
                let Some(lease) = authority
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
                        () = tokio::time::sleep(poll_interval.as_duration()) => {},
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
                let committed_progress =
                    if let Some(task) = authority.task_for_outbox(&lease).await? {
                        let progress = build_progress_frame(
                            &task,
                            "SMESH swarm is processing the durable dispatch".to_owned(),
                            clock.now(),
                        );
                        let committed = authority
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
                        let _ = authority.finish_outbox_attempt(
                            &lease,
                            AttemptDisposition::Retry {
                                available_at: clock.now(),
                                error: "driver shutdown interrupted active dispatch".to_owned(),
                            },
                            clock.now(),
                        ).await?;
                        return Ok(());
                    }
                    result = endpoint.dispatch_once(authority.as_ref(), envelope, &clock) => result,
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
                        let outcome = authority
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
                        let outcome = authority
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
                let Some(mut task) = authority.task_for_outbox(&lease).await? else {
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
                if authority
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
        }))
        .catch_unwind()
        .await
        .unwrap_or_else(|_| {
            Err(a2a::A2AError::internal(
                "durable outbox driver terminated unexpectedly",
            ))
        });
        if let Err(error) = &result {
            worker_control.failed(error);
            worker_control.wake.notify_waiters();
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
    use crate::{
        AdmissionOutcome, AtomicRecordCounts, AuthorityDiagnostics, AuthorityIdentity,
        AuthorityShutdown, AuthorizationAuditInput, AuthorizationAuditSink, AuthorizedTaskRead,
        CancellationAuthority, CancellationOutcome, ChangeObservation, ChangeObserver,
        OutboxAuthority, OutboxLease, OwnedTaskScope, ReceiverAdmission, ReceiverAuthority,
        ReceiverLease, SendMessageAdmission, StreamTranscriptBatch, SubscriptionCursor,
        TaskAdmission, TaskEventBatch, TaskLifecycle, TranscriptAuthority,
    };
    use async_trait::async_trait;

    struct PanickingAuthority {
        release: Arc<Notify>,
        claims: std::sync::Mutex<Vec<(String, i64, i64)>>,
    }

    fn unused() -> a2a::A2AError {
        a2a::A2AError::internal("unused panicking authority capability")
    }

    impl AuthorityIdentity for PanickingAuthority {
        fn completion_receipt_key(&self) -> Option<[u8; 32]> {
            None
        }
        fn authorization_resource_digest(&self, _: &str) -> Result<String, a2a::A2AError> {
            Err(unused())
        }
    }

    impl ChangeObserver for PanickingAuthority {
        fn change_observation(&self) -> ChangeObservation {
            ChangeObservation::default()
        }
    }

    #[async_trait]
    impl AuthorizationAuditSink for PanickingAuthority {
        async fn append_denied_authorization_decision(
            &self,
            _: AuthorizationAuditInput,
        ) -> Result<(), a2a::A2AError> {
            Err(unused())
        }
        async fn append_authorization_decision(
            &self,
            _: AuthorizationAuditInput,
        ) -> Result<(), a2a::A2AError> {
            Err(unused())
        }
    }

    #[async_trait]
    impl AuthorizedTaskRead for PanickingAuthority {
        async fn get_authorized(
            &self,
            _: &OwnedTaskScope,
            _: &str,
            _: AuthorizationAuditInput,
        ) -> Result<Option<a2a::Task>, a2a::A2AError> {
            Err(unused())
        }
        async fn list_authorized(
            &self,
            _: &OwnedTaskScope,
            _: &a2a::ListTasksRequest,
            _: AuthorizationAuditInput,
            _: &str,
        ) -> Result<a2a::ListTasksResponse, a2a::A2AError> {
            Err(unused())
        }
    }

    #[async_trait]
    impl TaskAdmission for PanickingAuthority {
        async fn replay_authorized(
            &self,
            _: &OwnedTaskScope,
            _: &str,
            _: &a2a::SendMessageRequest,
            _: bool,
            _: AuthorizationAuditInput,
        ) -> Result<Option<a2a::SendMessageResponse>, a2a::A2AError> {
            Err(unused())
        }
        async fn authorize_and_admit(
            &self,
            _: &OwnedTaskScope,
            _: SendMessageAdmission,
            _: AuthorizationAuditInput,
        ) -> Result<AdmissionOutcome, a2a::A2AError> {
            Err(unused())
        }
        async fn authorize_and_continue(
            &self,
            _: &OwnedTaskScope,
            _: SendMessageAdmission,
            _: AuthorizationAuditInput,
        ) -> Result<AdmissionOutcome, a2a::A2AError> {
            Err(unused())
        }
    }

    #[async_trait]
    impl TaskLifecycle for PanickingAuthority {
        async fn final_result_scoped(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Option<a2a::SendMessageResponse>, a2a::A2AError> {
            Err(unused())
        }
    }

    #[async_trait]
    impl CancellationAuthority for PanickingAuthority {
        async fn cancel_authorized(
            &self,
            _: &OwnedTaskScope,
            _: &str,
            _: i64,
            _: AuthorizationAuditInput,
        ) -> Result<CancellationOutcome, a2a::A2AError> {
            Err(unused())
        }
    }

    #[async_trait]
    impl OutboxAuthority for PanickingAuthority {
        async fn claim_outbox(
            &self,
            owner: &str,
            now: i64,
            duration: i64,
        ) -> Result<Option<OutboxLease>, a2a::A2AError> {
            self.claims
                .lock()
                .unwrap()
                .push((owner.to_owned(), now, duration));
            self.release.notified().await;
            panic!("secret panic payload must not escape")
        }
        async fn task_for_outbox(
            &self,
            _: &OutboxLease,
        ) -> Result<Option<a2a::Task>, a2a::A2AError> {
            Err(unused())
        }
        async fn finish_outbox_attempt(
            &self,
            _: &OutboxLease,
            _: AttemptDisposition,
            _: i64,
        ) -> Result<TransitionOutcome, a2a::A2AError> {
            Err(unused())
        }
        async fn append_stream_progress(
            &self,
            _: &str,
            _: &str,
            _: a2a::StreamResponse,
            _: i64,
        ) -> Result<Option<a2a::StreamResponse>, a2a::A2AError> {
            Err(unused())
        }
        async fn commit_delivery(
            &self,
            _: &OutboxLease,
            _: a2a::Task,
            _: a2a::SendMessageResponse,
            _: &[a2a::StreamResponse],
            _: i64,
        ) -> Result<TransitionOutcome, a2a::A2AError> {
            Err(unused())
        }
    }

    #[async_trait]
    impl ReceiverAuthority for PanickingAuthority {
        async fn begin_receive(
            &self,
            _: DurableDispatchEnvelope,
            _: &str,
            _: i64,
            _: i64,
        ) -> Result<ReceiverAdmission, a2a::A2AError> {
            Err(unused())
        }
        async fn complete_loopback_receive(
            &self,
            _: &ReceiverLease,
            _: &[MeshEvent],
            _: i64,
        ) -> Result<(), a2a::A2AError> {
            Err(unused())
        }
        async fn complete_loopback_outcome(
            &self,
            _: &ReceiverLease,
            _: &crate::DurableReceiverResult,
            _: i64,
        ) -> Result<(), a2a::A2AError> {
            Err(unused())
        }
        async fn complete_canceled_receive(
            &self,
            _: &ReceiverLease,
            _: &[MeshEvent],
            _: i64,
        ) -> Result<(), a2a::A2AError> {
            Err(unused())
        }
        async fn cancellation_requested(&self, _: &str) -> Result<bool, a2a::A2AError> {
            Err(unused())
        }
    }

    #[async_trait]
    impl TranscriptAuthority for PanickingAuthority {
        async fn stream_frames_after_scoped(
            &self,
            _: &str,
            _: &str,
            _: usize,
        ) -> Result<StreamTranscriptBatch, a2a::A2AError> {
            Err(unused())
        }
        async fn subscription_snapshot_authorized(
            &self,
            _: &OwnedTaskScope,
            _: &str,
        ) -> Result<Option<(a2a::Task, SubscriptionCursor)>, a2a::A2AError> {
            Err(unused())
        }
        async fn task_events_after_scoped(
            &self,
            _: &OwnedTaskScope,
            _: &str,
            _: u64,
        ) -> Result<TaskEventBatch, a2a::A2AError> {
            Err(unused())
        }
    }

    #[async_trait]
    impl AuthorityDiagnostics for PanickingAuthority {
        async fn authorization_decision_count(&self) -> Result<u64, a2a::A2AError> {
            Err(unused())
        }
        async fn atomic_record_counts(&self) -> Result<AtomicRecordCounts, a2a::A2AError> {
            Err(unused())
        }
        async fn durable_effect_count(&self) -> Result<u64, a2a::A2AError> {
            Err(unused())
        }
    }

    #[async_trait]
    impl AuthorityShutdown for PanickingAuthority {
        async fn shutdown(&self) -> Result<(), a2a::A2AError> {
            Ok(())
        }
        fn close_owned_sync(&self) {}
    }

    #[tokio::test]
    async fn driver_panic_publishes_one_generic_fatal_error_to_all_attached_observers() {
        let release = Arc::new(Notify::new());
        let recording = Arc::new(PanickingAuthority {
            release: release.clone(),
            claims: std::sync::Mutex::new(Vec::new()),
        });
        let authority: Arc<dyn DurableAuthority> = recording.clone();
        let handle = spawn_durable_driver(
            authority,
            DurableLoopbackEndpoint::new(),
            InjectedClock::new(10),
        );
        let mut observers = [
            handle.control().subscribe(),
            handle.control().subscribe(),
            handle.control().subscribe(),
        ];
        release.notify_one();
        for observer in &mut observers {
            tokio::time::timeout(Duration::from_secs(1), observer.changed())
                .await
                .expect("panic propagation watchdog")
                .expect("driver state remains observable");
            let failure = observer.borrow().failure.clone().expect("fatal failure");
            assert!(failure.contains("durable outbox driver terminated unexpectedly"));
            assert!(!failure.contains("secret panic payload"));
        }
        let shutdown = tokio::time::timeout(Duration::from_secs(1), handle.shutdown())
            .await
            .expect("panic shutdown watchdog")
            .expect_err("panic remains the shutdown result");
        assert!(
            shutdown
                .to_string()
                .contains("durable outbox driver terminated unexpectedly")
        );
        assert!(!shutdown.to_string().contains("secret panic payload"));
        assert_eq!(
            recording.claims.lock().unwrap().as_slice(),
            &[("durable-loopback-driver".to_owned(), 10, 60_000)]
        );
    }

    #[test]
    fn driver_panic_stderr_is_redacted_without_suppressing_unrelated_panics() {
        let executable = std::env::current_exe().expect("current test executable");
        let driver = std::process::Command::new(&executable)
            .args([
                "--exact",
                "outbox_driver::tests::driver_panic_stderr_child",
                "--nocapture",
            ])
            .env("SMESH_DRIVER_PANIC_STDERR_CHILD", "1")
            .output()
            .expect("run driver panic subprocess");
        assert!(driver.status.success(), "driver child failed: {driver:?}");
        let driver_stderr = String::from_utf8_lossy(&driver.stderr);
        assert!(!driver_stderr.contains("secret panic payload must not escape"));
        assert!(driver_stderr.contains("durable outbox driver panic (details redacted)"));
        assert!(driver_stderr.contains("durable outbox driver terminated unexpectedly"));

        let unrelated = std::process::Command::new(executable)
            .args([
                "--exact",
                "outbox_driver::tests::unrelated_panic_stderr_child",
                "--nocapture",
            ])
            .env("SMESH_UNRELATED_PANIC_STDERR_CHILD", "1")
            .output()
            .expect("run unrelated panic subprocess");
        assert!(!unrelated.status.success());
        let unrelated_stderr = String::from_utf8_lossy(&unrelated.stderr);
        assert!(unrelated_stderr.contains("unrelated panic canary must remain visible"));
    }

    #[tokio::test]
    async fn driver_panic_stderr_child() {
        if std::env::var_os("SMESH_DRIVER_PANIC_STDERR_CHILD").is_none() {
            return;
        }
        let release = Arc::new(Notify::new());
        let authority: Arc<dyn DurableAuthority> = Arc::new(PanickingAuthority {
            release: release.clone(),
            claims: std::sync::Mutex::new(Vec::new()),
        });
        let handle = spawn_durable_driver(
            authority,
            DurableLoopbackEndpoint::new(),
            InjectedClock::new(10),
        );
        let mut observer = handle.control().subscribe();
        release.notify_one();
        tokio::time::timeout(Duration::from_secs(1), observer.changed())
            .await
            .expect("driver panic child watchdog")
            .expect("driver state observable");
        eprintln!("{}", observer.borrow().failure.as_deref().expect("failure"));
        let shutdown = handle.shutdown().await.expect_err("panic shutdown error");
        eprintln!("{shutdown}");
    }

    #[test]
    fn unrelated_panic_stderr_child() {
        if std::env::var_os("SMESH_UNRELATED_PANIC_STDERR_CHILD").is_some() {
            std::panic::set_hook(Box::new(|info| {
                eprintln!("delegated pre-existing hook: {info}");
            }));
            install_driver_panic_hook();
            panic!("unrelated panic canary must remain visible");
        }
    }

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
