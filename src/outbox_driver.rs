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
    DurableReceiverTermination, InjectedClock, LeaseRenewalOutcome, MeshEvent, TransitionOutcome,
    content_digest,
    durable_dispatch::{DURABLE_CANCELED_SUMMARY, DurableDispatchError, DurableDispatchOutcome},
};

fn driver_lease_millis() -> i64 {
    if cfg!(debug_assertions)
        && let Ok(value) = std::env::var("SMESH_TEST_DRIVER_LEASE_MILLIS")
        && let Ok(value) = value.parse::<i64>()
        && (300..=60_000).contains(&value)
    {
        return value;
    }
    60_000
}

thread_local! {
    static REDACT_DRIVER_PANIC: Cell<bool> = const { Cell::new(false) };
}

static INSTALL_DRIVER_PANIC_HOOK: Once = Once::new();

pub(crate) fn install_driver_panic_hook() {
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

pub(crate) struct RedactedDriverPoll<F> {
    inner: Pin<Box<F>>,
}

impl<F> RedactedDriverPoll<F> {
    pub(crate) fn new(inner: F) -> Self {
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

pub(crate) struct AbortOnDropJoin<T> {
    join: Option<tokio::task::JoinHandle<T>>,
}

impl<T> AbortOnDropJoin<T> {
    pub(crate) fn new(join: tokio::task::JoinHandle<T>) -> Self {
        Self { join: Some(join) }
    }

    pub(crate) fn handle_mut(&mut self) -> &mut tokio::task::JoinHandle<T> {
        self.join.as_mut().expect("owned join handle is present")
    }

    pub(crate) fn abort(&self) {
        if let Some(join) = &self.join {
            join.abort();
        }
    }
}

impl<T> Drop for AbortOnDropJoin<T> {
    fn drop(&mut self) {
        if let Some(join) = &self.join {
            join.abort();
        }
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
    shutdown_requested: CancellationToken,
    join: Option<AbortOnDropJoin<Result<(), a2a::A2AError>>>,
}

impl DurableDriverHandle {
    pub(crate) fn control(&self) -> Arc<DurableDriverControl> {
        Arc::clone(&self.control)
    }

    fn request_shutdown(&self, failure: &str) {
        self.control.state.send_modify(|state| {
            state.generation = state.generation.wrapping_add(1);
            if state.failure.is_none() {
                state.failure = Some(failure.to_owned());
            }
        });
        self.shutdown_requested.cancel();
        self.control.endpoint.cancel_all();
        self.control.wake.notify_waiters();
    }

    pub(crate) fn reap_owned(&mut self) {
        self.request_shutdown("durable gateway was dropped");
        let Some(join) = self.join.take() else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            join.abort();
            return;
        };
        runtime.spawn(async move {
            let mut join = join;
            if tokio::time::timeout(Duration::from_secs(5), join.handle_mut())
                .await
                .is_err()
            {
                join.abort();
                let _ = join.handle_mut().await;
            }
        });
    }

    pub(crate) async fn shutdown(mut self) -> Result<(), a2a::A2AError> {
        self.request_shutdown("durable gateway is shutting down");
        let Some(mut join) = self.join.take() else {
            return Ok(());
        };
        if let Ok(joined) = tokio::time::timeout(Duration::from_secs(5), join.handle_mut()).await {
            joined.map_err(|_| a2a::A2AError::internal("durable outbox driver panicked"))?
        } else {
            join.abort();
            let _ = join.handle_mut().await;
            Err(a2a::A2AError::internal(
                "durable outbox driver shutdown timed out",
            ))
        }
    }
}

impl Drop for DurableDriverHandle {
    fn drop(&mut self) {
        self.reap_owned();
    }
}

#[allow(clippy::too_many_lines)] // The loop is one cohesive fenced-lease state machine.
pub(crate) fn spawn_durable_driver(
    authority: Arc<dyn DurableAuthority>,
    endpoint: DurableLoopbackEndpoint,
    clock: InjectedClock,
) -> DurableDriverHandle {
    spawn_durable_driver_with_telemetry(authority, endpoint, clock, None)
}

pub(crate) fn spawn_durable_driver_with_telemetry(
    authority: Arc<dyn DurableAuthority>,
    endpoint: DurableLoopbackEndpoint,
    clock: InjectedClock,
    telemetry: Option<crate::telemetry::TelemetryHandle>,
) -> DurableDriverHandle {
    spawn_durable_driver_inner(
        authority,
        endpoint,
        clock,
        telemetry,
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
    spawn_durable_driver_inner(
        authority.into_durable_authority(),
        endpoint,
        clock,
        None,
        hooks,
    )
}

#[allow(clippy::too_many_lines)] // The loop is one cohesive fenced-lease state machine.
fn spawn_durable_driver_inner(
    authority: Arc<dyn DurableAuthority>,
    endpoint: DurableLoopbackEndpoint,
    clock: InjectedClock,
    telemetry: Option<crate::telemetry::TelemetryHandle>,
    #[cfg(test)] hooks: DriverTestHooks,
) -> DurableDriverHandle {
    install_driver_panic_hook();
    let (state, _) = watch::channel(DriverState::default());
    let control = Arc::new(DurableDriverControl {
        wake: Arc::new(Notify::new()),
        state,
        endpoint: endpoint.clone(),
    });
    let shutdown_requested = CancellationToken::new();
    let worker_shutdown = shutdown_requested.clone();
    let worker_control = Arc::clone(&control);
    let replica_label =
        std::env::var("SMESH_A2A_REPLICA_ID").unwrap_or_else(|_| "replica".to_owned());
    let replica_id = format!(
        "{replica_label}#boot-{}",
        &content_digest(&rand::random::<[u8; 16]>())[..32]
    );
    let poll_interval = authority.change_observation().poll_interval();
    let lease_millis = driver_lease_millis();
    let renewal_period = Duration::from_millis(u64::try_from(lease_millis / 3).unwrap_or(100));
    let mut clock_changed = clock.subscribe();
    let join = tokio::spawn(async move {
        let result = AssertUnwindSafe(RedactedDriverPoll::new(async {
            loop {
                if worker_shutdown.is_cancelled() {
                    return Ok(());
                }
                if cfg!(debug_assertions)
                    && std::env::var("SMESH_TEST_DISABLE_DRIVER").as_deref() == Ok("1")
                {
                    tokio::select! {
                        () = worker_shutdown.cancelled() => return Ok(()),
                        () = tokio::time::sleep(poll_interval.as_duration()) => {},
                    }
                    continue;
                }
                #[cfg(test)]
                if let Some(gate) = &hooks.before_claim
                    && !gate.enter_once(&worker_shutdown).await
                {
                    return Ok(());
                }
                let Some(lease) = authority
                    .claim_outbox(&replica_id, clock.now(), lease_millis)
                    .await?
                else {
                    #[cfg(test)]
                    if let Some(idle) = &hooks.idle {
                        idle.notify_one();
                    }
                    tokio::select! {
                        () = worker_shutdown.cancelled() => return Ok(()),
                        () = worker_control.wake.notified() => {},
                        () = tokio::time::sleep(poll_interval.as_duration()) => {},
                        changed = clock_changed.changed() => {
                            if changed.is_err() { return Ok(()); }
                        }
                    }
                    continue;
                };
                let correlation = authority
                    .telemetry_correlation_for_outbox(&lease)
                    .await
                    .ok()
                    .flatten();
                let _correlation_guard = if let (Some(telemetry), Some(correlation)) =
                    (&telemetry, correlation)
                {
                    telemetry.remember_dispatch_correlation(
                        &lease.tenant_scope,
                        &lease.lease_token,
                        &lease.dispatch_id,
                        correlation,
                    )
                } else {
                    None
                };
                if let Some(telemetry) = &telemetry {
                    telemetry.dispatch_event(
                        crate::telemetry::EventName::DispatchClaimed,
                        "ok",
                        "claimed",
                        "outbox_claim",
                        &lease.tenant_scope,
                        &lease.lease_token,
                        &lease.dispatch_id,
                        Some(&lease.task_id),
                        Some(&lease.request.context_id),
                    );
                }
                let payload = serde_json::to_string(&lease.request)
                    .map_err(|_| a2a::A2AError::internal("failed to encode durable dispatch"))?;
                let envelope = DurableDispatchEnvelope {
                    tenant_scope: lease.tenant_scope.clone(),
                    dispatch_id: lease.dispatch_id.clone(),
                    payload_digest: content_digest(payload.as_bytes()),
                    request: lease.request.clone(),
                    execution_reservation: lease.execution_reservation.clone(),
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
                let renewal_cancel = CancellationToken::new();
                let (mut renewed_lease, renewal_join) = if authority.capabilities().lease_renewal {
                    let (tx, rx) = watch::channel(lease.clone());
                    let renewal_authority = Arc::clone(&authority);
                    let renewal_cancel_task = renewal_cancel.clone();
                    let renewal_telemetry = telemetry.clone();
                    let mut current = lease.clone();
                    let join = tokio::spawn(RedactedDriverPoll::new(async move {
                        loop {
                            tokio::select! {
                                () = renewal_cancel_task.cancelled() => return Ok(()),
                                () = tokio::time::sleep(renewal_period) => {}
                            }
                            let renewal = tokio::select! {
                                () = renewal_cancel_task.cancelled() => return Ok(()),
                                renewal = tokio::time::timeout(
                                    Duration::from_secs(5),
                                    renewal_authority.renew_outbox_lease(&current, lease_millis),
                                ) => renewal,
                            };
                            match renewal {
                                Ok(Ok(LeaseRenewalOutcome::Applied { lease_until })) => {
                                    current.lease_until = lease_until;
                                    if let Some(telemetry) = &renewal_telemetry {
                                        telemetry.dispatch_event(
                                            crate::telemetry::EventName::LeaseRenewed,
                                            "ok",
                                            "renewed",
                                            "outbox_renew",
                                            &current.tenant_scope,
                                            &current.lease_token,
                                            &current.dispatch_id,
                                            Some(&current.task_id),
                                            Some(&current.request.context_id),
                                        );
                                    }
                                    if tx.send(current.clone()).is_err() { return Ok(()); }
                                }
                                Ok(Ok(LeaseRenewalOutcome::Stale | LeaseRenewalOutcome::Unsupported)) => {
                                    if let Some(telemetry) = &renewal_telemetry {
                                        telemetry.dispatch_event(
                                            crate::telemetry::EventName::LeaseRenewed,
                                            "stale",
                                            "lost",
                                            "outbox_renew",
                                            &current.tenant_scope,
                                            &current.lease_token,
                                            &current.dispatch_id,
                                            Some(&current.task_id),
                                            Some(&current.request.context_id),
                                        );
                                    }
                                    return Err(a2a::A2AError::internal("durable lease renewal became stale"));
                                }
                                Ok(Err(error)) => {
                                    if let Some(telemetry) = &renewal_telemetry {
                                        telemetry.dispatch_event(
                                            crate::telemetry::EventName::LeaseRenewed,
                                            "failed",
                                            "fatal",
                                            "outbox_renew",
                                            &current.tenant_scope,
                                            &current.lease_token,
                                            &current.dispatch_id,
                                            Some(&current.task_id),
                                            Some(&current.request.context_id),
                                        );
                                    }
                                    return Err(error);
                                }
                                Err(_) => {
                                    if let Some(telemetry) = &renewal_telemetry {
                                        telemetry.dispatch_event(
                                            crate::telemetry::EventName::LeaseRenewed,
                                            "timeout",
                                            "fatal",
                                            "outbox_renew",
                                            &current.tenant_scope,
                                            &current.lease_token,
                                            &current.dispatch_id,
                                            Some(&current.task_id),
                                            Some(&current.request.context_id),
                                        );
                                    }
                                    return Err(a2a::A2AError::internal("durable lease renewal timed out"));
                                }
                            }
                        }
                    }));
                    (Some(rx), Some(AbortOnDropJoin::new(join)))
                } else {
                    (None, None)
                };
                if let Some(telemetry) = &telemetry {
                    telemetry.dispatch_event(
                        crate::telemetry::EventName::DispatchAttempted,
                        "ok",
                        "execute",
                        "outbox_attempt",
                        &lease.tenant_scope,
                        &lease.lease_token,
                        &lease.dispatch_id,
                        Some(&lease.task_id),
                        Some(&lease.request.context_id),
                    );
                }
                let dispatch_cancel = CancellationToken::new();
                let dispatch_future = endpoint.dispatch_once(
                    Arc::clone(&authority),
                    envelope,
                    &lease.lease_token,
                    &clock,
                    &replica_id,
                    &dispatch_cancel,
                );
                tokio::pin!(dispatch_future);
                let mut shutdown_requested = false;
                let mut sender_renewal_failed = false;
                let dispatch_result = loop {
                    tokio::select! {
                        () = worker_shutdown.cancelled(), if !shutdown_requested && !sender_renewal_failed => {
                            shutdown_requested = true;
                            dispatch_cancel.cancel();
                        }
                        result = &mut dispatch_future => break result,
                        changed = async {
                            if let Some(rx) = renewed_lease.as_mut() {
                                rx.changed().await.ok()
                            } else {
                                std::future::pending().await
                            }
                        }, if !shutdown_requested && !sender_renewal_failed => {
                            if changed.is_none() {
                                sender_renewal_failed = true;
                                dispatch_cancel.cancel();
                            }
                        }
                    }
                };
                let dispatch = if shutdown_requested || sender_renewal_failed {
                    None
                } else {
                    Some(dispatch_result)
                };
                renewal_cancel.cancel();
                if let Some(mut join) = renewal_join {
                    match tokio::time::timeout(Duration::from_secs(5), join.handle_mut()).await {
                        Ok(Ok(Ok(()))) => {}
                        Ok(Ok(Err(error))) => return Err(error),
                        Ok(Err(_)) => {
                            return Err(a2a::A2AError::internal("outbox lease renewal task panicked"));
                        }
                        Err(_) => {
                            join.abort();
                            let _ = join.handle_mut().await;
                            return Err(a2a::A2AError::internal("outbox lease renewal join timed out"));
                        }
                    }
                }
                let lease = renewed_lease
                    .as_ref()
                    .map_or_else(|| lease.clone(), |rx| rx.borrow().clone());
                if shutdown_requested {
                    let outcome = authority.finish_outbox_attempt(
                        &lease,
                        AttemptDisposition::Retry {
                            available_at: clock.now(),
                            error: "driver shutdown interrupted active dispatch".to_owned(),
                        },
                        clock.now(),
                    ).await?;
                    if outcome != TransitionOutcome::Applied {
                        return Err(a2a::A2AError::internal("active dispatch shutdown requeue fence became stale"));
                    }
                    return Ok(());
                }
                let Some(dispatch) = dispatch else {
                    if let Some(telemetry) = &telemetry {
                        telemetry.dispatch_event(
                            crate::telemetry::EventName::LeaseRenewed,
                            "failed",
                            "fatal",
                            "outbox_renew",
                            &lease.tenant_scope,
                            &lease.lease_token,
                            &lease.dispatch_id,
                            Some(&lease.task_id),
                            Some(&lease.request.context_id),
                        );
                    }
                    return Err(a2a::A2AError::internal("durable lease renewal failed"));
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
                            if let Some(telemetry) = &telemetry {
                                telemetry.dispatch_event(
                                    crate::telemetry::EventName::DispatchDeadLettered,
                                    "failed",
                                    "attempts_exhausted",
                                    "outbox_attempt",
                                    &lease.tenant_scope,
                                    &lease.lease_token,
                                    &lease.dispatch_id,
                                    Some(&lease.task_id),
                                    Some(&lease.request.context_id),
                                );
                            }
                            worker_control.changed();
                        } else if let Some(telemetry) = &telemetry {
                            telemetry.dispatch_event(
                                crate::telemetry::EventName::DispatchRetried,
                                "retry",
                                "busy",
                                "outbox_attempt",
                                &lease.tenant_scope,
                                &lease.lease_token,
                                &lease.dispatch_id,
                                Some(&lease.task_id),
                                Some(&lease.request.context_id),
                            );
                        }
                        continue;
                    }
                    Err(DurableDispatchError::FatalRenewal | DurableDispatchError::OwnerCancelled) => {
                        return Err(a2a::A2AError::internal("durable lease renewal failed"));
                    }
                    Err(DurableDispatchError::Permanent(error)) => {
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
                            if let Some(telemetry) = &telemetry {
                                telemetry.dispatch_event(
                                    crate::telemetry::EventName::DispatchDeadLettered,
                                    "failed",
                                    "permanent",
                                    "outbox_attempt",
                                    &lease.tenant_scope,
                                    &lease.lease_token,
                                    &lease.dispatch_id,
                                    Some(&lease.task_id),
                                    Some(&lease.request.context_id),
                                );
                            }
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
                let committed_state = task.status.state.clone();
                let result = SendMessageResponse::Task(task.clone());
                if authority
                    .commit_delivery(&lease, task, result, &public_transcript, clock.now())
                    .await?
                    == TransitionOutcome::Applied
                {
                    if let Some(telemetry) = &telemetry {
                        let task_state = telemetry_task_state(&committed_state);
                        let terminal = matches!(termination, DurableReceiverTermination::Success)
                            && committed_state.is_terminal();
                        telemetry.dispatch_event_with_task_state(
                            if terminal {
                                crate::telemetry::EventName::TaskTerminal
                            } else {
                                crate::telemetry::EventName::TaskTransitioned
                            },
                            "ok",
                            "committed",
                            if terminal {
                                "terminal_commit"
                            } else {
                                "task_transition"
                            },
                            &lease.tenant_scope,
                            &lease.lease_token,
                            &lease.dispatch_id,
                            Some(&lease.task_id),
                            Some(&lease.request.context_id),
                            Some(task_state),
                        );
                    }
                    #[cfg(test)]
                    if let Some(gate) = &hooks.after_commit_before_publish
                        && !gate.enter_once(&worker_shutdown).await
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
        shutdown_requested,
        join: Some(AbortOnDropJoin::new(join)),
    }
}

fn telemetry_task_state(state: &TaskState) -> &'static str {
    match state {
        TaskState::Submitted => "submitted",
        TaskState::Working => "working",
        TaskState::InputRequired => "input_required",
        TaskState::AuthRequired => "auth_required",
        TaskState::Completed => "completed",
        TaskState::Failed => "failed",
        TaskState::Canceled => "canceled",
        TaskState::Rejected => "rejected",
        TaskState::Unspecified => "unknown",
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
            } => match crate::bridge::internal_artifact_payload(content) {
                Some(crate::bridge::InternalArtifactPayload::Published { projection }) => {
                    artifacts.push(
                        serde_json::from_str(&projection)
                            .map_err(|_| a2a::A2AError::invalid_agent_response())?,
                    );
                }
                Some(crate::bridge::InternalArtifactPayload::Binary { bytes }) => {
                    use base64::Engine as _;
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(bytes)
                        .map_err(|_| a2a::A2AError::invalid_agent_response())?;
                    artifacts.push(Artifact {
                        artifact_id: format!(
                            "artifact-{}",
                            &content_digest(format!("{dispatch_id}\0{index}").as_bytes())[..32]
                        ),
                        name: Some(name.clone()),
                        description: Some("Durably replayable SMESH output".to_owned()),
                        parts: vec![Part::raw(bytes).with_media_type(media_type.clone())],
                        metadata: None,
                        extensions: None,
                    });
                }
                None => artifacts.push(Artifact {
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
            },
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
        AdmissionOutcome, AtomicRecordCounts, AuthorityCapabilities, AuthorityDiagnostics,
        AuthorityIdentity, AuthorityShutdown, AuthorizationAuditInput, AuthorizationAuditSink,
        AuthorizedTaskRead, CancellationAuthority, CancellationOutcome, ChangeObservation,
        ChangeObserver, LeaseRenewalOutcome, OutboxAuthority, OutboxLease, OwnedTaskScope,
        ReceiverAdmission, ReceiverAuthority, ReceiverLease, SendMessageAdmission,
        StreamTranscriptBatch, SubscriptionCursor, TaskAdmission, TaskEventBatch, TaskLifecycle,
        TranscriptAuthority,
    };
    use async_trait::async_trait;

    struct PanickingAuthority {
        release: Arc<Notify>,
        claims: std::sync::Mutex<Vec<(String, i64, i64)>>,
    }

    fn unused() -> a2a::A2AError {
        a2a::A2AError::internal("unused panicking authority capability")
    }

    impl crate::QuotaLeaseAuthority for PanickingAuthority {}

    impl AuthorityIdentity for PanickingAuthority {
        fn capabilities(&self) -> AuthorityCapabilities {
            AuthorityCapabilities {
                lease_renewal: false,
                quota_reservations: false,
            }
        }

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
        async fn renew_outbox_lease(
            &self,
            _: &OutboxLease,
            _: i64,
        ) -> Result<LeaseRenewalOutcome, a2a::A2AError> {
            Ok(LeaseRenewalOutcome::Unsupported)
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
        async fn renew_receiver_lease(
            &self,
            _: &ReceiverLease,
            _: i64,
        ) -> Result<LeaseRenewalOutcome, a2a::A2AError> {
            Ok(LeaseRenewalOutcome::Unsupported)
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

    crate::impl_unsupported_artifact_authority!(PanickingAuthority);

    #[tokio::test]
    async fn dropping_driver_requests_cooperative_shutdown_before_reaping_root() {
        struct ResourceGuard(Arc<Notify>);
        impl Drop for ResourceGuard {
            fn drop(&mut self) {
                self.0.notify_one();
            }
        }

        let (state, _) = watch::channel(DriverState::default());
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let control = Arc::new(DurableDriverControl {
            wake: Arc::new(Notify::new()),
            state,
            endpoint: DurableLoopbackEndpoint::new(),
        });
        let started = Arc::new(Notify::new());
        let task_started = Arc::clone(&started);
        let released = Arc::new(Notify::new());
        let task_released = Arc::clone(&released);
        let observed_cancel = Arc::new(AtomicBool::new(false));
        let task_observed_cancel = Arc::clone(&observed_cancel);
        let join = tokio::spawn(async move {
            let _resource = ResourceGuard(task_released);
            task_started.notify_one();
            task_cancel.cancelled().await;
            task_observed_cancel.store(true, Ordering::SeqCst);
            Ok(())
        });
        started.notified().await;
        let handle = DurableDriverHandle {
            control,
            shutdown_requested: cancel,
            join: Some(AbortOnDropJoin::new(join)),
        };

        drop(handle);

        tokio::time::timeout(Duration::from_secs(1), released.notified())
            .await
            .expect("drop reaper releases the root resource");
        assert!(
            observed_cancel.load(Ordering::SeqCst),
            "drop must request cooperative cancellation before any fallback abort"
        );
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
        let claims = recording.claims.lock().unwrap();
        assert_eq!(claims.len(), 1);
        assert!(claims[0].0.starts_with("replica#boot-sha256:"));
        assert_eq!((claims[0].1, claims[0].2), (10, 60_000));
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
    fn sender_renewal_panic_stderr_is_redacted_before_join_error_reporting() {
        let output =
            std::process::Command::new(std::env::current_exe().expect("current test executable"))
                .args([
                    "--exact",
                    "outbox_driver::tests::sender_renewal_panic_stderr_child",
                    "--nocapture",
                ])
                .env("SMESH_SENDER_RENEWAL_PANIC_STDERR_CHILD", "1")
                .output()
                .expect("run sender renewal panic subprocess");
        assert!(
            output.status.success(),
            "sender renewal child failed: {output:?}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("durable outbox driver panic (details redacted)"));
        assert!(stderr.contains("outbox lease renewal task panicked"));
        assert!(!stderr.contains("sender-renewal-secret-payload"));
        assert!(!stderr.contains("postgresql://secret-user:secret-password@secret-host"));
    }

    #[tokio::test]
    async fn sender_renewal_panic_stderr_child() {
        if std::env::var_os("SMESH_SENDER_RENEWAL_PANIC_STDERR_CHILD").is_none() {
            return;
        }
        install_driver_panic_hook();
        let join = tokio::spawn(RedactedDriverPoll::new(async {
            panic!(
                "sender-renewal-secret-payload at postgresql://secret-user:secret-password@secret-host"
            )
        }));
        let error = join
            .await
            .expect_err("sender renewal panic must be a JoinError");
        assert!(error.is_panic());
        eprintln!("outbox lease renewal task panicked");
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
