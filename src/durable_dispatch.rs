use std::collections::HashMap;
use std::future::Future;
#[cfg(test)]
use std::sync::OnceLock;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::outbox_driver::{AbortOnDropJoin, RedactedDriverPoll, install_driver_panic_hook};
use crate::{
    DurableAuthority, ExecutionReservation, LeaseRenewalOutcome, MeshEvent, MeshRequest,
    ReceiverLease,
};

#[derive(Debug)]
pub(crate) enum DurableDispatchError {
    FatalRenewal,
    OwnerCancelledBeforeReceive,
    PostReceiveUnresolved,
    RuntimeProposalUnresolved,
    Permanent(a2a::A2AError),
}

impl From<a2a::A2AError> for DurableDispatchError {
    fn from(value: a2a::A2AError) -> Self {
        Self::Permanent(value)
    }
}

fn receiver_lease_millis() -> i64 {
    if cfg!(debug_assertions)
        && let Ok(value) = std::env::var("SMESH_TEST_DRIVER_LEASE_MILLIS")
        && let Ok(value) = value.parse::<i64>()
        && (300..=60_000).contains(&value)
    {
        return value;
    }
    60_000
}

fn runtime_supervision_bound() -> Duration {
    #[cfg(test)]
    return Duration::from_millis(500);
    #[cfg(not(test))]
    Duration::from_secs(5)
}

fn runtime_phase_bound() -> Duration {
    #[cfg(test)]
    return Duration::from_millis(500);
    #[cfg(not(test))]
    Duration::from_secs(300)
}

async fn await_receiver_settlement<F>(settlement: F) -> Result<(), DurableDispatchError>
where
    F: Future<Output = Result<(), a2a::A2AError>>,
{
    match tokio::time::timeout(runtime_phase_bound(), settlement).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) | Err(_) => Err(DurableDispatchError::PostReceiveUnresolved),
    }
}

#[cfg(test)]
fn receiver_renewal_period(_: i64) -> Duration {
    Duration::from_millis(100)
}

#[cfg(not(test))]
fn receiver_renewal_period(lease_millis: i64) -> Duration {
    Duration::from_millis(u64::try_from(lease_millis / 3).unwrap_or(100))
}

fn cancellation_poll_period() -> Duration {
    receiver_renewal_period(receiver_lease_millis()).min(Duration::from_secs(1))
}

struct ReceiverRenewal {
    cancel: CancellationToken,
    latest: tokio::sync::watch::Receiver<Result<ReceiverLease, ()>>,
    join: Option<AbortOnDropJoin<()>>,
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct ReceiverRenewalTestHook {
    pub reached: Arc<Notify>,
    pub release_stale: Arc<Notify>,
}

#[cfg(test)]
fn receiver_renewal_test_hooks() -> &'static Mutex<HashMap<String, ReceiverRenewalTestHook>> {
    static HOOKS: OnceLock<Mutex<HashMap<String, ReceiverRenewalTestHook>>> = OnceLock::new();
    HOOKS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(test)]
pub(crate) fn install_receiver_renewal_test_hook(dispatch_id: &str) -> ReceiverRenewalTestHook {
    let hook = ReceiverRenewalTestHook {
        reached: Arc::new(Notify::new()),
        release_stale: Arc::new(Notify::new()),
    };
    receiver_renewal_test_hooks()
        .lock()
        .unwrap()
        .insert(dispatch_id.to_owned(), hook.clone());
    hook
}

impl ReceiverRenewal {
    fn start(
        authority: Arc<dyn DurableAuthority>,
        lease: &ReceiverLease,
        authority_load_fence: Arc<tokio::sync::Mutex<()>>,
    ) -> Option<Self> {
        #[cfg(test)]
        if let Some(hook) = receiver_renewal_test_hooks()
            .lock()
            .unwrap()
            .remove(&lease.dispatch_id)
        {
            let cancel = CancellationToken::new();
            let task_cancel = cancel.clone();
            let (sender, latest) = tokio::sync::watch::channel(Ok(lease.clone()));
            let join = tokio::spawn(async move {
                hook.reached.notify_one();
                tokio::select! {
                    () = task_cancel.cancelled() => {},
                    () = hook.release_stale.notified() => { let _ = sender.send(Err(())); }
                }
            });
            return Some(Self {
                cancel,
                latest,
                join: Some(AbortOnDropJoin::new(join)),
            });
        }
        if !authority.capabilities().lease_renewal {
            return None;
        }
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let (sender, latest) = tokio::sync::watch::channel(Ok(lease.clone()));
        let mut current = lease.clone();
        let lease_millis = receiver_lease_millis();
        let renewal_period = receiver_renewal_period(lease_millis);
        install_driver_panic_hook();
        let join = tokio::spawn(RedactedDriverPoll::new(async move {
            loop {
                tokio::select! {
                    () = task_cancel.cancelled() => return,
                    () = tokio::time::sleep(renewal_period) => {}
                }
                let _authority_load_guard = tokio::select! {
                    () = task_cancel.cancelled() => return,
                    guard = authority_load_fence.lock() => guard,
                };
                let renewal = tokio::select! {
                    () = task_cancel.cancelled() => return,
                    renewal = tokio::time::timeout(
                        Duration::from_secs(5),
                        authority.renew_receiver_lease(&current, lease_millis),
                    ) => renewal,
                };
                if let Ok(Ok(LeaseRenewalOutcome::Applied { lease_until })) = renewal {
                    current.lease_until = lease_until;
                    if sender.send(Ok(current.clone())).is_err() {
                        return;
                    }
                } else {
                    let _ = sender.send(Err(()));
                    return;
                }
            }
        }));
        Some(Self {
            cancel,
            latest,
            join: Some(AbortOnDropJoin::new(join)),
        })
    }

    async fn stop(&mut self) -> Result<ReceiverLease, DurableDispatchError> {
        self.cancel.cancel();
        if let Some(mut join) = self.join.take() {
            match tokio::time::timeout(Duration::from_secs(5), join.handle_mut()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return Err(DurableDispatchError::FatalRenewal),
                Err(_) => {
                    join.abort();
                    let _ = join.handle_mut().await;
                    return Err(DurableDispatchError::FatalRenewal);
                }
            }
        }
        self.latest
            .borrow()
            .clone()
            .map_err(|()| DurableDispatchError::FatalRenewal)
    }

    #[cfg(test)]
    fn from_test_join(lease: ReceiverLease, join: tokio::task::JoinHandle<()>) -> Self {
        Self::from_test_owned_join(lease, CancellationToken::new(), join)
    }

    #[cfg(test)]
    fn from_test_owned_join(
        lease: ReceiverLease,
        cancel: CancellationToken,
        join: tokio::task::JoinHandle<()>,
    ) -> Self {
        let (_, latest) = tokio::sync::watch::channel(Ok(lease));
        Self {
            cancel,
            latest,
            join: Some(AbortOnDropJoin::new(join)),
        }
    }
}

impl Drop for ReceiverRenewal {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn stop_receiver_renewal(
    renewal: &mut Option<ReceiverRenewal>,
    lease: &ReceiverLease,
) -> Result<ReceiverLease, DurableDispatchError> {
    if let Some(renewal) = renewal.as_mut() {
        renewal.stop().await
    } else {
        Ok(lease.clone())
    }
}

async fn receiver_loss(
    mut status: Option<tokio::sync::watch::Receiver<Result<ReceiverLease, ()>>>,
) {
    match status.as_mut() {
        Some(status) => loop {
            if status.borrow().is_err() || status.changed().await.is_err() {
                return;
            }
        },
        None => std::future::pending::<()>().await,
    }
}

pub(crate) const DURABLE_CANCELED_SUMMARY: &str = "SMESH durable receiver cooperatively canceled";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableInterruptionKind {
    InputRequired,
    AuthRequired,
}

/// Receiver-owned dispatch termination, kept separate from the public `MeshEvent` API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DurableReceiverTermination {
    Success,
    InputRequired { message: String },
    AuthRequired { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableReceiverResult {
    pub events: Vec<MeshEvent>,
    pub termination: DurableReceiverTermination,
}

/// Stable sender-to-receiver envelope. `MeshRequest` remains source compatible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableDispatchEnvelope {
    pub tenant_scope: String,
    pub dispatch_id: String,
    pub payload_digest: String,
    pub request: MeshRequest,
    pub execution_reservation: Option<ExecutionReservation>,
}

/// Deterministic clock used by the durable sender and receiver lease state machines.
#[derive(Debug)]
struct ClockState {
    now: AtomicI64,
    changed: tokio::sync::watch::Sender<i64>,
}

#[derive(Debug, Clone)]
pub struct InjectedClock(Arc<ClockState>);

impl InjectedClock {
    #[must_use]
    pub fn new(now_millis: i64) -> Self {
        let (changed, _) = tokio::sync::watch::channel(now_millis);
        Self(Arc::new(ClockState {
            now: AtomicI64::new(now_millis),
            changed,
        }))
    }

    #[must_use]
    pub fn now(&self) -> i64 {
        self.0.now.load(Ordering::SeqCst)
    }

    /// Advance monotonically and wake every subscribed durable driver.
    pub fn advance_to(&self, now_millis: i64) {
        let mut current = self.now();
        while now_millis > current {
            match self.0.now.compare_exchange(
                current,
                now_millis,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    self.0.changed.send_replace(now_millis);
                    return;
                }
                Err(observed) => current = observed,
            }
        }
    }

    pub(crate) fn subscribe(&self) -> tokio::sync::watch::Receiver<i64> {
        self.0.changed.subscribe()
    }
}

/// Owned real-time source for the monotonic durable-driver clock.
pub struct SystemClockTicker {
    cancel: CancellationToken,
    join: tokio::task::JoinHandle<Result<(), a2a::A2AError>>,
}

impl Drop for SystemClockTicker {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.join.abort();
    }
}

impl SystemClockTicker {
    /// Start a ticker that advances `clock` from the system Unix clock and wakes subscribers.
    #[must_use]
    pub fn spawn(clock: InjectedClock) -> Self {
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let join = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(25));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    () = stop.cancelled() => return Ok(()),
                    _ = interval.tick() => clock.advance_to(system_time_millis()?),
                }
            }
        });
        Self { cancel, join }
    }

    /// Cancel and join the ticker within the production shutdown deadline.
    ///
    /// # Errors
    ///
    /// Returns an internal error when the system clock is invalid, the task panics,
    /// or the ticker does not stop within its deadline.
    pub async fn shutdown(mut self) -> Result<(), a2a::A2AError> {
        self.cancel.cancel();
        if let Ok(joined) = tokio::time::timeout(Duration::from_secs(5), &mut self.join).await {
            joined.map_err(|_| a2a::A2AError::internal("system clock ticker panicked"))?
        } else {
            self.join.abort();
            let _ = (&mut self.join).await;
            Err(a2a::A2AError::internal(
                "system clock ticker shutdown timed out",
            ))
        }
    }
}

fn system_time_millis() -> Result<i64, a2a::A2AError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| a2a::A2AError::internal("system clock is before the Unix epoch"))?
        .as_millis();
    i64::try_from(millis).map_err(|_| a2a::A2AError::internal("system clock exceeds i64 millis"))
}

/// Repository-owned development adapter used by explicitly loopback-named builders.
/// It owns runtime work only; durable authority and settlement remain in the crate-owned coordinator.
#[derive(Clone)]
pub struct DurableLoopbackEndpoint {
    effects: Arc<AtomicUsize>,
    preparation_barrier: Option<(Arc<Notify>, Arc<Notify>)>,
    completion_barrier: Option<(Arc<Notify>, Arc<Notify>)>,
    completion_committed: Option<(Arc<Notify>, Arc<Notify>)>,
    active: Arc<Mutex<HashMap<crate::DurableDispatchCorrelation, CancellationToken>>>,
    interruption: Option<(String, DurableInterruptionKind, String, Vec<MeshEvent>)>,
    terminal_events: Option<(String, Vec<MeshEvent>)>,
    telemetry: Option<crate::telemetry::TelemetryHandle>,
    strict_authority_context: bool,
}

impl DurableLoopbackEndpoint {
    #[must_use]
    pub fn new() -> Self {
        Self::from_diagnostic_counter(Arc::new(AtomicUsize::new(0)))
    }
    #[must_use]
    /// Attach a post-commit diagnostic counter.
    ///
    /// This observable is not durable: a process crash after the `SQLite` commit
    /// and before the increment can undercount. Use `durable_effect_count` as
    /// the enforceable local transaction proof.
    pub fn from_diagnostic_counter(effects: Arc<AtomicUsize>) -> Self {
        Self {
            effects,
            preparation_barrier: None,
            completion_barrier: None,
            completion_committed: None,
            active: Arc::new(Mutex::new(HashMap::new())),
            interruption: None,
            terminal_events: None,
            telemetry: None,
            strict_authority_context: false,
        }
    }
    /// Pause capacity preparation before the coordinator admits a receiver.
    #[cfg(any(test, debug_assertions))]
    #[doc(hidden)]
    #[must_use]
    pub fn with_pre_receive_barrier(started: Arc<Notify>, release: Arc<Notify>) -> Self {
        Self {
            preparation_barrier: Some((started, release)),
            ..Self::new()
        }
    }
    #[must_use]
    pub fn with_completion_barrier(effect_started: Arc<Notify>, release: Arc<Notify>) -> Self {
        Self {
            completion_barrier: Some((effect_started, release)),
            ..Self::new()
        }
    }
    #[doc(hidden)]
    #[must_use]
    pub fn with_completion_race_barrier(
        effect_started: Arc<Notify>,
        release: Arc<Notify>,
        completion_committed: Arc<Notify>,
        publish_release: Arc<Notify>,
    ) -> Self {
        Self {
            completion_barrier: Some((effect_started, release)),
            completion_committed: Some((completion_committed, publish_release)),
            ..Self::new()
        }
    }
    #[must_use]
    pub fn with_interruption_for_text(
        text: impl Into<String>,
        kind: DurableInterruptionKind,
        message: impl Into<String>,
    ) -> Self {
        Self {
            interruption: Some((text.into(), kind, message.into(), Vec::new())),
            ..Self::new()
        }
    }
    #[cfg(any(test, debug_assertions))]
    #[doc(hidden)]
    #[must_use]
    pub fn with_interruption_events_for_test(
        text: impl Into<String>,
        kind: DurableInterruptionKind,
        message: impl Into<String>,
        events: Vec<MeshEvent>,
    ) -> Self {
        Self {
            interruption: Some((text.into(), kind, message.into(), events)),
            ..Self::new()
        }
    }
    #[cfg(any(test, debug_assertions))]
    #[doc(hidden)]
    #[must_use]
    pub fn with_terminal_events_for_test(text: impl Into<String>, events: Vec<MeshEvent>) -> Self {
        Self {
            terminal_events: Some((text.into(), events)),
            ..Self::new()
        }
    }
    #[doc(hidden)]
    #[must_use]
    pub fn with_barrier(mut self, effect_started: Arc<Notify>, release: Arc<Notify>) -> Self {
        self.completion_barrier = Some((effect_started, release));
        self
    }
    #[must_use]
    pub fn with_telemetry(mut self, telemetry: Option<crate::telemetry::TelemetryHandle>) -> Self {
        self.telemetry = telemetry;
        self
    }
    pub(crate) fn require_authority_context(mut self) -> Self {
        self.strict_authority_context = true;
        self
    }
    fn permits_development_context(&self) -> bool {
        !self.strict_authority_context
    }
    async fn receiver_committed(&self) {
        self.effects.fetch_add(1, Ordering::SeqCst);
        if let Some((committed, release)) = &self.completion_committed {
            committed.notify_one();
            release.notified().await;
        }
    }
    #[must_use]
    pub fn diagnostic_effect_counter(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.effects)
    }
}

struct PreparedLoopbackDispatch(DurableLoopbackEndpoint);

#[async_trait::async_trait]
impl crate::PreparedDurableRuntimeDispatch for PreparedLoopbackDispatch {
    async fn admit(
        self: Box<Self>,
        envelope: crate::DurableWorkEnvelope,
        cancellation: CancellationToken,
    ) -> crate::RuntimeAdapterAdmission {
        if cancellation.is_cancelled() {
            return crate::RuntimeAdapterAdmission::Rejected(
                crate::RuntimePreAdmissionFailure::Canceled,
            );
        }
        let endpoint = self.0;
        let correlation = envelope.correlation().clone();
        {
            let Ok(mut active) = endpoint.active.lock() else {
                return crate::RuntimeAdapterAdmission::Rejected(
                    crate::RuntimePreAdmissionFailure::Unavailable,
                );
            };
            if active.contains_key(&correlation) {
                return crate::RuntimeAdapterAdmission::Retryable(
                    crate::RuntimePreAdmissionFailure::DuplicateCorrelation,
                );
            }
            active.insert(correlation.clone(), cancellation.clone());
        }
        let (outcome_tx, outcome_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let result = if let Some((started, release)) = &endpoint.completion_barrier {
                started.notify_one();
                tokio::select! { () = cancellation.cancelled() => crate::RuntimeAdapterOutcome::ConfirmedStopped, () = release.notified() => loopback_proposal(&endpoint, &envelope, &cancellation) }
            } else {
                loopback_proposal(&endpoint, &envelope, &cancellation)
            };
            let _ = outcome_tx.send(result);
            if let Ok(mut active) = endpoint.active.lock() {
                active.remove(&correlation);
            }
        });
        crate::RuntimeAdapterAdmission::Admitted(crate::RuntimeAdapterExecution::new(outcome_rx))
    }
}

fn loopback_proposal(
    endpoint: &DurableLoopbackEndpoint,
    envelope: &crate::DurableWorkEnvelope,
    cancellation: &CancellationToken,
) -> crate::RuntimeAdapterOutcome {
    if cancellation.is_cancelled() {
        return crate::RuntimeAdapterOutcome::ConfirmedStopped;
    }
    if let Some((trigger, events)) = &endpoint.terminal_events
        && envelope.request().text == *trigger
    {
        return crate::RuntimeAdapterOutcome::Terminal(DurableReceiverResult {
            events: events.clone(),
            termination: DurableReceiverTermination::Success,
        });
    }
    if let Some((trigger, kind, message, events)) = &endpoint.interruption
        && envelope.request().text == *trigger
    {
        return crate::RuntimeAdapterOutcome::Terminal(DurableReceiverResult {
            events: if events.is_empty() {
                vec![MeshEvent::Progress(
                    "SMESH swarm is processing the durable dispatch".to_owned(),
                )]
            } else {
                events.clone()
            },
            termination: match kind {
                DurableInterruptionKind::InputRequired => {
                    DurableReceiverTermination::InputRequired {
                        message: message.clone(),
                    }
                }
                DurableInterruptionKind::AuthRequired => DurableReceiverTermination::AuthRequired {
                    message: message.clone(),
                },
            },
        });
    }
    let content = serde_json::json!({ "contextId": envelope.request().context_id, "result": format!("SMESH accepted: {}", envelope.request().text), "taskId": envelope.request().task_id }).to_string();
    crate::RuntimeAdapterOutcome::Terminal(DurableReceiverResult {
        events: vec![
            MeshEvent::Progress("SMESH swarm is processing the durable dispatch".to_owned()),
            MeshEvent::Artifact {
                name: "smesh-result.json".to_owned(),
                media_type: "application/json".to_owned(),
                content,
            },
            MeshEvent::Completed {
                summary: "SMESH swarm completed the task".to_owned(),
            },
        ],
        termination: DurableReceiverTermination::Success,
    })
}

#[async_trait::async_trait]
impl crate::DurableRuntimeAdapter for DurableLoopbackEndpoint {
    async fn prepare(&self) -> crate::RuntimeAdapterPreparation {
        if let Some((started, release)) = &self.preparation_barrier {
            started.notify_one();
            release.notified().await;
        }
        crate::RuntimeAdapterPreparation::Ready(Box::new(PreparedLoopbackDispatch(self.clone())))
    }
    async fn cancel_durable(
        &self,
        correlation: &crate::DurableDispatchCorrelation,
    ) -> crate::RuntimeCancellationRequest {
        let token = self
            .active
            .lock()
            .ok()
            .and_then(|active| active.get(correlation).cloned());
        if let Some(token) = token {
            token.cancel();
            crate::RuntimeCancellationRequest::Requested
        } else {
            crate::RuntimeCancellationRequest::NotActive
        }
    }
}

struct ActiveRuntime {
    cancellation: CancellationToken,
    // Retained even when the dispatch caller is forcibly dropped.
    join: Option<tokio::task::JoinHandle<()>>,
}

/// Sealed coordinator composition. Runtime adapters cannot select loopback authority.
#[allow(clippy::large_enum_variant)] // The concrete loopback endpoint seals compatibility mode.
pub(crate) enum DurableCoordinatorMode {
    Loopback(DurableLoopbackEndpoint),
    Runtime(Arc<dyn crate::DurableRuntimeAdapter>),
    #[cfg(test)]
    TestLoopbackAdapter(Arc<dyn crate::DurableRuntimeAdapter>),
    #[cfg(test)]
    TestRuntimeAdapterWithDevelopmentContext(Arc<dyn crate::DurableRuntimeAdapter>),
}

impl DurableCoordinatorMode {
    fn adapter(&self) -> &dyn crate::DurableRuntimeAdapter {
        match self {
            Self::Loopback(endpoint) => endpoint,
            Self::Runtime(adapter) => adapter.as_ref(),
            #[cfg(test)]
            Self::TestLoopbackAdapter(adapter)
            | Self::TestRuntimeAdapterWithDevelopmentContext(adapter) => adapter.as_ref(),
        }
    }

    fn permits_development_context(&self) -> bool {
        match self {
            Self::Loopback(endpoint) => endpoint.permits_development_context(),
            Self::Runtime(_) => false,
            #[cfg(test)]
            Self::TestLoopbackAdapter(_) | Self::TestRuntimeAdapterWithDevelopmentContext(_) => {
                true
            }
        }
    }

    fn terminal_is_authoritative(&self) -> bool {
        match self {
            Self::Loopback(_) => true,
            Self::Runtime(_) => false,
            #[cfg(test)]
            Self::TestLoopbackAdapter(_) => true,
            #[cfg(test)]
            Self::TestRuntimeAdapterWithDevelopmentContext(_) => false,
        }
    }

    async fn receiver_committed(&self) {
        if let Self::Loopback(endpoint) = self {
            endpoint.receiver_committed().await;
        }
    }
}

/// Authority-owned coordinator for receiver admission, runtime transport, and replay.
pub(crate) struct DurableCoordinator {
    authority: Arc<dyn DurableAuthority>,
    mode: DurableCoordinatorMode,
    clock: InjectedClock,
    telemetry: Option<crate::telemetry::TelemetryHandle>,
    active: Mutex<HashMap<crate::DurableDispatchCorrelation, ActiveRuntime>>,
    idle: Notify,
}

struct ActiveRuntimeCleanup {
    coordinator: Arc<DurableCoordinator>,
    correlation: crate::DurableDispatchCorrelation,
}

impl Drop for ActiveRuntimeCleanup {
    fn drop(&mut self) {
        if let Ok(mut active) = self.coordinator.active.lock() {
            active.remove(&self.correlation);
            if active.is_empty() {
                self.coordinator.idle.notify_waiters();
            }
        }
    }
}

impl DurableCoordinator {
    pub(crate) fn new(
        authority: Arc<dyn DurableAuthority>,
        mode: DurableCoordinatorMode,
        clock: InjectedClock,
        telemetry: Option<crate::telemetry::TelemetryHandle>,
    ) -> Self {
        Self {
            authority,
            mode,
            clock,
            telemetry,
            active: Mutex::new(HashMap::new()),
            idle: Notify::new(),
        }
    }
    pub(crate) async fn wait_for_idle(&self) -> Result<(), ()> {
        loop {
            let notified = self.idle.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.active.lock().map_err(|_| ())?.is_empty() {
                return Ok(());
            }
            notified.await;
        }
    }
    pub(crate) fn signal_cancel(self: &Arc<Self>, correlation: &crate::DurableDispatchCorrelation) {
        let active = self
            .active
            .lock()
            .ok()
            .and_then(|map| map.get(correlation).map(|entry| entry.cancellation.clone()));
        if let Some(active) = active {
            active.cancel();
        }
    }
    pub(crate) fn cancel_all(self: &Arc<Self>) {
        let active = self
            .active
            .lock()
            .map(|map| {
                map.values()
                    .map(|entry| entry.cancellation.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for item in active {
            item.cancel();
        }
    }

    #[cfg(test)]
    pub(crate) fn retain_test_runtime(
        &self,
        correlation: crate::DurableDispatchCorrelation,
        cancellation: CancellationToken,
        join: tokio::task::JoinHandle<()>,
    ) {
        self.active.lock().expect("active registry").insert(
            correlation,
            ActiveRuntime {
                cancellation,
                join: Some(join),
            },
        );
    }

    pub(crate) async fn shutdown_active(&self, grace: Duration) -> Result<(), ()> {
        let active = {
            let mut active = self.active.lock().map_err(|_| ())?;
            std::mem::take(&mut *active)
        };
        let mut complete = true;
        let mut joins = Vec::with_capacity(active.len());
        for (_, mut entry) in active {
            entry.cancellation.cancel();
            let Some(join) = entry.join.take() else {
                complete = false;
                continue;
            };
            joins.push(crate::outbox_driver::AbortOnDropJoin::new(join));
        }
        for mut join in joins {
            if tokio::time::timeout(grace, join.handle_mut())
                .await
                .is_err()
            {
                join.abort();
                let _ = join.handle_mut().await;
            }
        }
        self.idle.notify_waiters();
        complete.then_some(()).ok_or(())
    }

    pub(crate) fn abort_active(&self) {
        if let Ok(mut active) = self.active.lock() {
            for (_, mut entry) in active.drain() {
                entry.cancellation.cancel();
                if let Some(join) = entry.join.take() {
                    join.abort();
                }
            }
            self.idle.notify_waiters();
        }
    }
    async fn authoritative_replay(
        &self,
        envelope: DurableDispatchEnvelope,
        replica_id: &str,
        owner_cancel: &CancellationToken,
    ) -> Result<DurableDispatchOutcome, DurableDispatchError> {
        let replay = self.authority.begin_receive(
            envelope,
            replica_id,
            self.clock.now(),
            receiver_lease_millis(),
        );
        tokio::pin!(replay);
        let admission = tokio::select! {
            biased;
            () = owner_cancel.cancelled() => return Err(DurableDispatchError::PostReceiveUnresolved),
            () = tokio::time::sleep(runtime_phase_bound()) => {
                return Err(DurableDispatchError::PostReceiveUnresolved);
            }
            result = &mut replay => result.map_err(|_| DurableDispatchError::PostReceiveUnresolved)?,
        };
        match admission {
            crate::ReceiverAdmission::Replay(events) => {
                Ok(DurableDispatchOutcome::Delivered(events))
            }
            crate::ReceiverAdmission::ReplayOutcome(outcome) => {
                Ok(DurableDispatchOutcome::Interrupted(outcome))
            }
            _ => Err(DurableDispatchError::PostReceiveUnresolved),
        }
    }
    #[cfg(test)]
    #[allow(clippy::too_many_lines)] // Preparation through cleanup is one admission state machine.
    pub(crate) async fn dispatch_once(
        self: &Arc<Self>,
        outbox: &crate::OutboxLease,
        envelope: DurableDispatchEnvelope,
        correlation_generation: &str,
        replica_id: &str,
        owner_cancel: &CancellationToken,
    ) -> Result<DurableDispatchOutcome, DurableDispatchError> {
        self.dispatch_once_with_sender_renewal(
            outbox,
            envelope,
            correlation_generation,
            replica_id,
            owner_cancel,
            None,
            Arc::new(tokio::sync::Mutex::new(())),
        )
        .await
    }

    #[allow(clippy::too_many_lines, clippy::too_many_arguments)]
    pub(crate) async fn dispatch_once_with_sender_renewal(
        self: &Arc<Self>,
        outbox: &crate::OutboxLease,
        envelope: DurableDispatchEnvelope,
        correlation_generation: &str,
        replica_id: &str,
        owner_cancel: &CancellationToken,
        sender_renewal: Option<tokio::sync::watch::Receiver<crate::OutboxLease>>,
        sender_load_fence: Arc<tokio::sync::Mutex<()>>,
    ) -> Result<DurableDispatchOutcome, DurableDispatchError> {
        // Preparation reserves capacity only; no receiver or runtime admission
        // exists yet, so dropping it on owner shutdown is safe.
        let preparation = tokio::select! {
            biased;
            () = owner_cancel.cancelled() => return Err(DurableDispatchError::OwnerCancelledBeforeReceive),
            () = tokio::time::sleep(runtime_phase_bound()) => {
                return Ok(DurableDispatchOutcome::Busy);
            }
            preparation = self.mode.adapter().prepare() => preparation,
        };
        let prepared = match preparation {
            crate::RuntimeAdapterPreparation::Ready(value) => value,
            crate::RuntimeAdapterPreparation::Retryable(_) => {
                return Ok(DurableDispatchOutcome::Busy);
            }
            crate::RuntimeAdapterPreparation::Rejected(_) => {
                return Err(DurableDispatchError::Permanent(a2a::A2AError::internal(
                    "durable runtime unavailable",
                )));
            }
        };
        if owner_cancel.is_cancelled() {
            return Err(DurableDispatchError::OwnerCancelledBeforeReceive);
        }
        let receive = self.authority.begin_receive(
            envelope.clone(),
            replica_id,
            self.clock.now(),
            receiver_lease_millis(),
        );
        tokio::pin!(receive);
        let admission = tokio::select! {
            biased;
            () = owner_cancel.cancelled() => return Err(DurableDispatchError::PostReceiveUnresolved),
            () = tokio::time::sleep(runtime_phase_bound()) => {
                return Err(DurableDispatchError::PostReceiveUnresolved);
            }
            result = &mut receive => result.map_err(|_| DurableDispatchError::PostReceiveUnresolved)?,
        };
        let lease = match admission {
            crate::ReceiverAdmission::Replay(events) => {
                self.receiver_telemetry(
                    &envelope,
                    correlation_generation,
                    crate::telemetry::EventName::ReceiverAdmitted,
                    "ok",
                    "replay",
                    "receiver_admit",
                );
                return Ok(DurableDispatchOutcome::Delivered(events));
            }
            crate::ReceiverAdmission::ReplayOutcome(outcome) => {
                self.receiver_telemetry(
                    &envelope,
                    correlation_generation,
                    crate::telemetry::EventName::ReceiverAdmitted,
                    "ok",
                    "replay",
                    "receiver_admit",
                );
                return Ok(DurableDispatchOutcome::Interrupted(outcome));
            }
            crate::ReceiverAdmission::Busy => {
                self.receiver_telemetry(
                    &envelope,
                    correlation_generation,
                    crate::telemetry::EventName::ReceiverAdmitted,
                    "busy",
                    "busy",
                    "receiver_admit",
                );
                return Ok(DurableDispatchOutcome::Busy);
            }
            crate::ReceiverAdmission::Execute(lease) => {
                self.receiver_telemetry(
                    &envelope,
                    correlation_generation,
                    crate::telemetry::EventName::ReceiverAdmitted,
                    "ok",
                    "execute",
                    "receiver_admit",
                );
                lease
            }
        };
        // The caller owns cancellation, not the possibly-admitted future. Once
        // receive succeeds, a retained task owns every handle until actual cleanup.
        let cancellation = CancellationToken::new();
        let correlation = crate::DurableDispatchCorrelation::from_authority_parts(
            &envelope.tenant_scope,
            &envelope.dispatch_id,
            outbox.attempt_no,
            lease.lease_epoch,
        )?;
        let _cancel_on_caller_drop = cancellation.clone().drop_guard();
        let coordinator = Arc::clone(self);
        let outbox = outbox.clone();
        let generation = correlation_generation.to_owned();
        let replica = replica_id.to_owned();
        let owner_cancel = owner_cancel.clone();
        let mut sender_renewal = sender_renewal;
        let sender_load_fence = Arc::clone(&sender_load_fence);
        let receiver_load_fence = Arc::new(tokio::sync::Mutex::new(()));
        let active_correlation = correlation.clone();
        let active_cancellation = cancellation.clone();
        let (completed, completion) = tokio::sync::oneshot::channel();
        let (registered, registration) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            if registration.await.is_err() {
                return;
            }
            let _active_cleanup = ActiveRuntimeCleanup {
                coordinator: Arc::clone(&coordinator),
                correlation: active_correlation,
            };
            let mut renewal = ReceiverRenewal::start(
                Arc::clone(&coordinator.authority),
                &lease,
                Arc::clone(&receiver_load_fence),
            );
            let status = renewal.as_ref().map(|renewal| renewal.latest.clone());
            let lost = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let monitor_lost = Arc::clone(&lost);
            let monitor_cancel = cancellation.clone();
            let monitor_owner = owner_cancel.clone();
            let renewal_stopped = renewal
                .as_ref()
                .map_or_else(CancellationToken::new, |r| r.cancel.clone());
            let mut monitor = AbortOnDropJoin::new(tokio::spawn(async move {
                tokio::select! {
                    biased;
                    () = renewal_stopped.cancelled() => {},
                    () = receiver_loss(status) => {
                        monitor_lost.store(true, Ordering::SeqCst);
                        monitor_cancel.cancel();
                    }
                    () = monitor_owner.cancelled() => monitor_cancel.cancel(),
                    () = monitor_cancel.cancelled() => {}
                }
            }));
            let result = coordinator
                .run_received(
                    prepared,
                    &outbox,
                    &lease,
                    envelope.clone(),
                    &generation,
                    &replica,
                    &owner_cancel,
                    &cancellation,
                    &mut renewal,
                    &mut sender_renewal,
                    &sender_load_fence,
                    &receiver_load_fence,
                )
                .await;
            cancellation.cancel();
            let _ = monitor.handle_mut().await;
            let _ = stop_receiver_renewal(&mut renewal, &lease).await;
            let result = if lost.load(Ordering::SeqCst) {
                Err(DurableDispatchError::FatalRenewal)
            } else {
                result
            };
            let _ = completed.send(result);
        });
        {
            let mut active = self
                .active
                .lock()
                .map_err(|_| DurableDispatchError::PostReceiveUnresolved)?;
            if active.contains_key(&correlation) {
                task.abort();
                return Err(DurableDispatchError::PostReceiveUnresolved);
            }
            active.insert(
                correlation,
                ActiveRuntime {
                    cancellation: active_cancellation,
                    join: Some(task),
                },
            );
        }
        if registered.send(()).is_err() {
            return Err(DurableDispatchError::PostReceiveUnresolved);
        }
        completion
            .await
            .map_err(|_| DurableDispatchError::PostReceiveUnresolved)?
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_received(
        &self,
        prepared: Box<dyn crate::PreparedDurableRuntimeDispatch>,
        outbox: &crate::OutboxLease,
        lease: &ReceiverLease,
        envelope: DurableDispatchEnvelope,
        generation: &str,
        replica: &str,
        owner_cancel: &CancellationToken,
        cancellation: &CancellationToken,
        renewal: &mut Option<ReceiverRenewal>,
        sender_renewal: &mut Option<tokio::sync::watch::Receiver<crate::OutboxLease>>,
        sender_load_fence: &Arc<tokio::sync::Mutex<()>>,
        receiver_load_fence: &Arc<tokio::sync::Mutex<()>>,
    ) -> Result<DurableDispatchOutcome, DurableDispatchError> {
        let sender_load_guard = sender_load_fence.lock().await;
        let receiver_load_guard = receiver_load_fence.lock().await;
        let authoritative_outbox = sender_renewal
            .as_ref()
            .map_or_else(|| outbox.clone(), |latest| latest.borrow().clone());
        let authoritative_receiver = renewal
            .as_ref()
            .map_or_else(
                || Ok(lease.clone()),
                |current| current.latest.borrow().clone(),
            )
            .map_err(|()| DurableDispatchError::FatalRenewal)?;
        let loaded = tokio::select! {
            biased;
            () = receiver_loss(renewal.as_ref().map(|r| r.latest.clone())) => {
                cancellation.cancel();
                return Err(DurableDispatchError::FatalRenewal);
            }
            () = cancellation.cancelled() => {
                let _ = stop_receiver_renewal(renewal, lease).await;
                return Err(DurableDispatchError::PostReceiveUnresolved);
            }
            () = tokio::time::sleep(runtime_phase_bound()) => {
                cancellation.cancel();
                return Err(DurableDispatchError::PostReceiveUnresolved);
            }
            result = self.authority.load_runtime_authority_context(&authoritative_outbox, &authoritative_receiver, self.clock.now()) => result,
        };
        drop(receiver_load_guard);
        drop(sender_load_guard);
        let context = match loaded {
            Ok(context) => context,
            Err(_) if self.mode.permits_development_context() => {
                match loopback_development_context(outbox, lease) {
                    Ok(context) => context,
                    Err(error) => {
                        let _ = stop_receiver_renewal(renewal, lease).await;
                        return Err(error);
                    }
                }
            }
            Err(_) => {
                let _ = stop_receiver_renewal(renewal, lease).await;
                return Err(DurableDispatchError::PostReceiveUnresolved);
            }
        };
        self.run_admitted(
            prepared,
            context,
            lease,
            envelope,
            generation,
            replica,
            owner_cancel,
            cancellation,
            renewal,
        )
        .await
    }
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn run_admitted(
        &self,
        prepared: Box<dyn crate::PreparedDurableRuntimeDispatch>,
        context: crate::DurableRuntimeAuthorityContext,
        lease: &ReceiverLease,
        envelope: DurableDispatchEnvelope,
        correlation_generation: &str,
        replica_id: &str,
        owner_cancel: &CancellationToken,
        cancellation: &CancellationToken,
        renewal: &mut Option<ReceiverRenewal>,
    ) -> Result<DurableDispatchOutcome, DurableDispatchError> {
        let correlation = context.correlation().clone();
        let requested = tokio::select! {
            biased;
            () = receiver_loss(renewal.as_ref().map(|r| r.latest.clone())) => {
                cancellation.cancel();
                return Err(DurableDispatchError::FatalRenewal);
            }
            () = cancellation.cancelled() => return Err(DurableDispatchError::PostReceiveUnresolved),
            () = tokio::time::sleep(runtime_phase_bound()) => {
                cancellation.cancel();
                return Err(DurableDispatchError::PostReceiveUnresolved);
            }
            result = self.authority.cancellation_requested(&envelope.dispatch_id) =>
                result.map_err(|_| DurableDispatchError::PostReceiveUnresolved)?,
        };
        if requested {
            cancellation.cancel();
            let fenced = stop_receiver_renewal(renewal, lease).await?;
            let events = canceled_events();
            await_receiver_settlement(self.authority.complete_canceled_receive(
                &fenced,
                &events,
                self.clock.now(),
            ))
            .await?;
            return self
                .authoritative_replay(envelope, replica_id, owner_cancel)
                .await;
        }
        let durable_cancellation = {
            let authority = Arc::clone(&self.authority);
            let dispatch_id = envelope.dispatch_id.clone();
            async move {
                loop {
                    tokio::time::sleep(cancellation_poll_period()).await;
                    match authority.cancellation_requested(&dispatch_id).await {
                        Ok(true) => return Ok::<(), ()>(()),
                        Ok(false) => {}
                        Err(_) => return Err(()),
                    }
                }
            }
        };
        tokio::pin!(durable_cancellation);
        let admission = prepared.admit(
            crate::DurableWorkEnvelope::new(context),
            cancellation.clone(),
        );
        tokio::pin!(admission);
        let admission_deadline = tokio::time::sleep(runtime_phase_bound());
        tokio::pin!(admission_deadline);
        let mut admission_polled = false;
        let selected = {
            let tracked_admission = std::future::poll_fn(|cx| {
                // This task owns both the loss decision and first poll. Once
                // polling begins, admission is ambiguous until acknowledged.
                admission_polled = true;
                admission.as_mut().poll(cx)
            });
            tokio::select! {
                biased;
                () = receiver_loss(renewal.as_ref().map(|r| r.latest.clone())) => {
                    cancellation.cancel();
                    Err(DurableDispatchError::FatalRenewal)
                }
                () = owner_cancel.cancelled() => {
                    cancellation.cancel();
                    Err(DurableDispatchError::PostReceiveUnresolved)
                }
                () = cancellation.cancelled() => Err(DurableDispatchError::PostReceiveUnresolved),
                requested = &mut durable_cancellation => {
                    let _ = requested;
                    cancellation.cancel();
                    Err(DurableDispatchError::PostReceiveUnresolved)
                }
                () = &mut admission_deadline => {
                    cancellation.cancel();
                    Err(DurableDispatchError::PostReceiveUnresolved)
                }
                result = tracked_admission => Ok(result),
            }
        };
        let mut adapter_cancel_requested = false;
        let admission = match selected {
            Ok(result) => result,
            // A winning loss branch must not first-poll an untouched adapter.
            Err(error) if !admission_polled => return Err(error),
            // Already-polled admission retains its sole acknowledgement/outcome
            // ownership only for the coordinator's bounded supervision interval.
            // Expiry preserves the durable receiver as unresolved; it does not
            // assert that remote admission did or did not occur.
            Err(error) => {
                let supervised = tokio::time::timeout(runtime_supervision_bound(), async {
                    let _ = self.mode.adapter().cancel_durable(&correlation).await;
                    admission.await
                })
                .await;
                adapter_cancel_requested = true;
                match supervised {
                    Ok(admission) => admission,
                    Err(_) => return Err(error),
                }
            }
        };
        let execution = match admission {
            crate::RuntimeAdapterAdmission::Admitted(execution) => execution,
            crate::RuntimeAdapterAdmission::Rejected(_)
            | crate::RuntimeAdapterAdmission::Retryable(_) => {
                let _ = stop_receiver_renewal(renewal, lease).await;
                return Err(DurableDispatchError::PostReceiveUnresolved);
            }
        };
        let mut execution = Box::pin(execution.finish());
        let runtime_cancel = cancellation.cancelled();
        tokio::pin!(runtime_cancel);
        let mut renewal_status = renewal.as_ref().map(|renewal| renewal.latest.clone());
        let receiver_renewal_failed = async move {
            match renewal_status.as_mut() {
                Some(status) => loop {
                    if status.borrow().is_err() || status.changed().await.is_err() {
                        return;
                    }
                },
                None => std::future::pending::<()>().await,
            }
        };
        tokio::pin!(receiver_renewal_failed);
        let execution_deadline = tokio::time::sleep(runtime_phase_bound());
        tokio::pin!(execution_deadline);
        let outcome = tokio::select! {
            biased;
            () = &mut receiver_renewal_failed => {
                cancellation.cancel();
                let _ = tokio::time::timeout(runtime_supervision_bound(), async {
                    if !adapter_cancel_requested {
                        let _ = self.mode.adapter().cancel_durable(&correlation).await;
                    }
                    let _ = execution.await;
                }).await;
                let _ = stop_receiver_renewal(renewal, lease).await;
                return Err(DurableDispatchError::FatalRenewal);
            }
            outcome = &mut execution => outcome,
            requested = &mut durable_cancellation => {
                if requested.is_err() {
                    cancellation.cancel();
                    return Err(DurableDispatchError::PostReceiveUnresolved);
                }
                cancellation.cancel();
                match tokio::time::timeout(runtime_supervision_bound(), async {
                    if !adapter_cancel_requested {
                        let _ = self.mode.adapter().cancel_durable(&correlation).await;
                    }
                    execution.await
                }).await {
                    Ok(outcome) => outcome,
                    Err(_) => return Err(DurableDispatchError::PostReceiveUnresolved),
                }
            }
            () = &mut execution_deadline => {
                cancellation.cancel();
                let _ = tokio::time::timeout(runtime_supervision_bound(), async {
                    if !adapter_cancel_requested {
                        let _ = self.mode.adapter().cancel_durable(&correlation).await;
                    }
                    let _ = execution.await;
                }).await;
                let _ = stop_receiver_renewal(renewal, lease).await;
                return Err(DurableDispatchError::PostReceiveUnresolved);
            }
            () = owner_cancel.cancelled() => {
                cancellation.cancel();
                match tokio::time::timeout(runtime_supervision_bound(), async {
                    if !adapter_cancel_requested {
                        let _ = self.mode.adapter().cancel_durable(&correlation).await;
                    }
                    execution.await
                }).await {
                    Ok(outcome) => outcome,
                    Err(_) => return Err(DurableDispatchError::PostReceiveUnresolved),
                }
            }
            () = &mut runtime_cancel => {
                match tokio::time::timeout(runtime_supervision_bound(), async {
                    if !adapter_cancel_requested {
                        let _ = self.mode.adapter().cancel_durable(&correlation).await;
                    }
                    execution.await
                }).await {
                    Ok(outcome) => outcome,
                    Err(_) => return Err(DurableDispatchError::PostReceiveUnresolved),
                }
            }
        };
        let fenced = stop_receiver_renewal(renewal, lease).await?;
        match outcome {
            crate::RuntimeAdapterOutcome::Terminal(proposal) => {
                if !self.mode.terminal_is_authoritative() {
                    return Err(DurableDispatchError::RuntimeProposalUnresolved);
                }
                let cancellation_won = tokio::select! {
                    biased;
                    () = tokio::time::sleep(runtime_phase_bound()) => {
                        return Err(DurableDispatchError::PostReceiveUnresolved);
                    }
                    result = self.authority.cancellation_requested(&envelope.dispatch_id) =>
                        result.map_err(|_| DurableDispatchError::PostReceiveUnresolved)?,
                };
                if cancellation_won {
                    let events = canceled_events();
                    await_receiver_settlement(self.authority.complete_canceled_receive(
                        &fenced,
                        &events,
                        self.clock.now(),
                    ))
                    .await?;
                    return self
                        .authoritative_replay(envelope, replica_id, owner_cancel)
                        .await;
                }
                let committed_task_state = match &proposal.termination {
                    DurableReceiverTermination::Success => "completed",
                    DurableReceiverTermination::InputRequired { .. } => "input_required",
                    DurableReceiverTermination::AuthRequired { .. } => "auth_required",
                };
                let settlement = match proposal.termination {
                    DurableReceiverTermination::Success => {
                        await_receiver_settlement(self.authority.complete_loopback_receive(
                            &fenced,
                            &proposal.events,
                            self.clock.now(),
                        ))
                        .await
                    }
                    DurableReceiverTermination::InputRequired { .. }
                    | DurableReceiverTermination::AuthRequired { .. } => {
                        await_receiver_settlement(self.authority.complete_loopback_outcome(
                            &fenced,
                            &proposal,
                            self.clock.now(),
                        ))
                        .await
                    }
                };
                if settlement.is_err() {
                    let cancellation_won = tokio::select! {
                        biased;
                        () = tokio::time::sleep(runtime_phase_bound()) => {
                            return Err(DurableDispatchError::PostReceiveUnresolved);
                        }
                        result = self.authority.cancellation_requested(&envelope.dispatch_id) =>
                            result.map_err(|_| DurableDispatchError::PostReceiveUnresolved)?,
                    };
                    if !cancellation_won {
                        return Err(DurableDispatchError::PostReceiveUnresolved);
                    }
                    let events = canceled_events();
                    await_receiver_settlement(self.authority.complete_canceled_receive(
                        &fenced,
                        &events,
                        self.clock.now(),
                    ))
                    .await?;
                    return self
                        .authoritative_replay(envelope, replica_id, owner_cancel)
                        .await;
                }
                if let Some(telemetry) = &self.telemetry {
                    telemetry.dispatch_event_with_task_state(
                        crate::telemetry::EventName::ReceiverCompleted,
                        "ok",
                        "committed",
                        "receiver_execute",
                        &envelope.tenant_scope,
                        correlation_generation,
                        &envelope.dispatch_id,
                        Some(&envelope.request.task_id),
                        Some(&envelope.request.context_id),
                        Some(committed_task_state),
                    );
                }
                self.mode.receiver_committed().await;
                self.authoritative_replay(envelope, replica_id, owner_cancel)
                    .await
            }
            crate::RuntimeAdapterOutcome::ConfirmedStopped => {
                let cancellation_won = tokio::select! {
                    biased;
                    () = tokio::time::sleep(runtime_phase_bound()) => {
                        return Err(DurableDispatchError::PostReceiveUnresolved);
                    }
                    result = self.authority.cancellation_requested(&envelope.dispatch_id) =>
                        result.map_err(|_| DurableDispatchError::PostReceiveUnresolved)?,
                };
                if !cancellation_won {
                    return Err(DurableDispatchError::PostReceiveUnresolved);
                }
                let events = canceled_events();
                await_receiver_settlement(self.authority.complete_canceled_receive(
                    &fenced,
                    &events,
                    self.clock.now(),
                ))
                .await?;
                self.authoritative_replay(envelope, replica_id, owner_cancel)
                    .await
            }
            crate::RuntimeAdapterOutcome::ExecutionFailed(_)
            | crate::RuntimeAdapterOutcome::AdmittedUnknown => {
                Err(DurableDispatchError::PostReceiveUnresolved)
            }
        }
    }
    fn receiver_telemetry(
        &self,
        envelope: &DurableDispatchEnvelope,
        generation: &str,
        event: crate::telemetry::EventName,
        outcome: &'static str,
        reason: &'static str,
        operation: &'static str,
    ) {
        if let Some(telemetry) = &self.telemetry {
            telemetry.dispatch_event(
                event,
                outcome,
                reason,
                operation,
                &envelope.tenant_scope,
                generation,
                &envelope.dispatch_id,
                Some(&envelope.request.task_id),
                Some(&envelope.request.context_id),
            );
        }
    }
}

fn loopback_development_context(
    outbox: &crate::OutboxLease,
    receiver: &ReceiverLease,
) -> Result<crate::DurableRuntimeAuthorityContext, DurableDispatchError> {
    let scope = crate::DurableRuntimeScope::new(
        &outbox.tenant_scope,
        "durable-loopback",
        "durable-loopback",
        "local-development",
        crate::VisibilityScope::Tenant,
    )?;
    let correlation = crate::DurableDispatchCorrelation::new(
        scope.clone(),
        &outbox.dispatch_id,
        outbox.attempt_no,
        receiver.lease_epoch,
    )?;
    let digest = crate::content_digest(
        &serde_json::to_vec(&outbox.request)
            .map_err(|_| a2a::A2AError::internal("invalid durable runtime request"))?,
    );
    let budget = crate::ExecutionBudget::new(64 * 1024 * 1024, 1_024)
        .map_err(|_| a2a::A2AError::internal("invalid loopback runtime budget"))?;
    Ok(crate::DurableRuntimeAuthorityContext::loopback_development(
        scope,
        correlation,
        outbox.request.clone(),
        digest.clone(),
        digest,
        budget,
    )?)
}

fn canceled_events() -> Vec<MeshEvent> {
    vec![
        MeshEvent::Progress("SMESH swarm is processing the durable dispatch".to_owned()),
        MeshEvent::Completed {
            summary: DURABLE_CANCELED_SUMMARY.to_owned(),
        },
    ]
}

pub(crate) enum DurableDispatchOutcome {
    Delivered(Vec<MeshEvent>),
    Interrupted(DurableReceiverResult),
    Busy,
}

impl Default for DurableLoopbackEndpoint {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "coordinator_race_tests.rs"]
mod lifecycle_races;

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn receiver_lease() -> ReceiverLease {
        ReceiverLease {
            tenant_scope: "tenant-renewal-join".to_owned(),
            task_id: "task-renewal-join".to_owned(),
            dispatch_id: "dispatch-renewal-join".to_owned(),
            payload_digest: "sha256:receiver-renewal-join".to_owned(),
            sender_attempt_no: 1,
            sender_lease_token: "sender-renewal-join".to_owned(),
            lease_owner: "receiver-renewal-join".to_owned(),
            lease_token: "receiver-token-renewal-join".to_owned(),
            lease_epoch: 1,
            lease_until: 10_000,
            execution_reservation: None,
        }
    }

    #[tokio::test]
    async fn receiver_renewal_panic_is_fatal_even_while_latest_lease_looks_valid() {
        install_driver_panic_hook();
        let join = tokio::spawn(RedactedDriverPoll::new(async {
            panic!("receiver renewal panic canary")
        }));
        while !join.is_finished() {
            tokio::task::yield_now().await;
        }
        let mut renewal = ReceiverRenewal::from_test_join(receiver_lease(), join);
        let mut completion_committed = false;

        let result = async {
            renewal.stop().await?;
            completion_committed = true;
            Ok::<(), DurableDispatchError>(())
        }
        .await;
        assert!(matches!(result, Err(DurableDispatchError::FatalRenewal)));
        assert!(
            !completion_committed,
            "panic must suppress receiver completion"
        );
    }

    #[tokio::test]
    async fn receiver_renewal_cancellation_is_fatal_even_while_latest_lease_looks_valid() {
        let join = tokio::spawn(std::future::pending::<()>());
        join.abort();
        while !join.is_finished() {
            tokio::task::yield_now().await;
        }
        let mut renewal = ReceiverRenewal::from_test_join(receiver_lease(), join);
        let mut completion_committed = false;

        let result = async {
            renewal.stop().await?;
            completion_committed = true;
            Ok::<(), DurableDispatchError>(())
        }
        .await;
        assert!(matches!(result, Err(DurableDispatchError::FatalRenewal)));
        assert!(
            !completion_committed,
            "cancellation must suppress receiver completion"
        );
    }

    #[tokio::test]
    async fn cancelling_stop_after_join_take_aborts_renewal_and_releases_resource() {
        struct ResourceGuard {
            active: Arc<AtomicUsize>,
            released: Arc<Notify>,
        }
        impl Drop for ResourceGuard {
            fn drop(&mut self) {
                self.active.fetch_sub(1, Ordering::SeqCst);
                self.released.notify_one();
            }
        }

        let started = Arc::new(Notify::new());
        let task_started = Arc::clone(&started);
        let release = Arc::new(Notify::new());
        let task_release = Arc::clone(&release);
        let released = Arc::new(Notify::new());
        let task_released = Arc::clone(&released);
        let active = Arc::new(AtomicUsize::new(0));
        let task_active = Arc::clone(&active);
        let join = tokio::spawn(async move {
            task_active.fetch_add(1, Ordering::SeqCst);
            let _resource = ResourceGuard {
                active: task_active,
                released: task_released,
            };
            task_started.notify_one();
            task_release.notified().await;
        });
        started.notified().await;
        let mut renewal = ReceiverRenewal::from_test_join(receiver_lease(), join);
        let mut stop = Box::pin(renewal.stop());
        assert!(matches!(
            futures::poll!(&mut stop),
            std::task::Poll::Pending
        ));
        drop(stop);

        let released_result =
            tokio::time::timeout(Duration::from_millis(100), released.notified()).await;
        if released_result.is_err() {
            release.notify_waiters();
        }
        released_result.expect("cancelled stop future must abort the renewal it owns");
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn owner_cancellation_joins_receiver_renewal_before_returning() {
        struct ResourceGuard(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for ResourceGuard {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let renewal_cancel = CancellationToken::new();
        let task_cancel = renewal_cancel.clone();
        let started = Arc::new(Notify::new());
        let task_started = Arc::clone(&started);
        let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let task_released = Arc::clone(&released);
        let join = tokio::spawn(async move {
            let _resource = ResourceGuard(task_released);
            task_started.notify_one();
            task_cancel.cancelled().await;
        });
        started.notified().await;
        let mut renewal =
            ReceiverRenewal::from_test_owned_join(receiver_lease(), renewal_cancel, join);
        let owner_cancel = CancellationToken::new();
        owner_cancel.cancel();

        tokio::select! {
            () = owner_cancel.cancelled() => {
                renewal.stop().await.expect("renewal cleanup joins cleanly");
            }
            () = std::future::pending() => unreachable!(),
        }

        assert!(
            released.load(Ordering::SeqCst),
            "owner returned before renewal released its resource"
        );
    }

    #[test]
    fn receiver_renewal_panic_canary_is_redacted_from_stderr() {
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "durable_dispatch::tests::receiver_renewal_panic_is_fatal_even_while_latest_lease_looks_valid",
                "--nocapture",
            ])
            .output()
            .expect("run receiver renewal panic child");
        assert!(
            output.status.success(),
            "renewal panic child failed: {output:?}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("durable outbox driver panic (details redacted)"));
        assert!(!stderr.contains("receiver renewal panic canary"));
    }
}
