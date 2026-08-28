use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::{DurableAuthority, MeshEvent, MeshRequest};

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

/// Repository-owned durable loopback receiver. It cannot be implemented by an arbitrary dispatcher.
#[derive(Clone)]
pub struct DurableLoopbackEndpoint {
    effects: Arc<AtomicUsize>,
    completion_barrier: Option<(Arc<Notify>, Arc<Notify>)>,
    completion_committed: Option<(Arc<Notify>, Arc<Notify>)>,
    active: Arc<Mutex<HashMap<String, CancellationToken>>>,
    interruption: Option<(String, DurableInterruptionKind, String)>,
}

impl DurableLoopbackEndpoint {
    #[must_use]
    pub fn new() -> Self {
        Self::from_diagnostic_counter(Arc::new(AtomicUsize::new(0)))
    }

    #[must_use]
    /// Attach a post-commit diagnostic counter.
    ///
    /// This observable is not durable: a process crash after the SQLite commit
    /// and before the increment can undercount. Use `durable_effect_count` as
    /// the enforceable local transaction proof.
    pub fn from_diagnostic_counter(effects: Arc<AtomicUsize>) -> Self {
        Self {
            effects,
            completion_barrier: None,
            completion_committed: None,
            active: Arc::new(Mutex::new(HashMap::new())),
            interruption: None,
        }
    }

    #[must_use]
    pub fn with_completion_barrier(effect_started: Arc<Notify>, release: Arc<Notify>) -> Self {
        Self {
            effects: Arc::new(AtomicUsize::new(0)),
            completion_barrier: Some((effect_started, release)),
            completion_committed: None,
            active: Arc::new(Mutex::new(HashMap::new())),
            interruption: None,
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
            effects: Arc::new(AtomicUsize::new(0)),
            completion_barrier: Some((effect_started, release)),
            completion_committed: Some((completion_committed, publish_release)),
            active: Arc::new(Mutex::new(HashMap::new())),
            interruption: None,
        }
    }

    #[must_use]
    pub fn with_interruption_for_text(
        text: impl Into<String>,
        kind: DurableInterruptionKind,
        message: impl Into<String>,
    ) -> Self {
        Self {
            effects: Arc::new(AtomicUsize::new(0)),
            completion_barrier: None,
            completion_committed: None,
            active: Arc::new(Mutex::new(HashMap::new())),
            interruption: Some((text.into(), kind, message.into())),
        }
    }

    #[doc(hidden)]
    #[must_use]
    pub fn with_barrier(mut self, effect_started: Arc<Notify>, release: Arc<Notify>) -> Self {
        self.completion_barrier = Some((effect_started, release));
        self
    }

    #[must_use]
    pub fn diagnostic_effect_counter(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.effects)
    }

    pub(crate) fn signal_cancel(&self, dispatch_id: &str) {
        if let Ok(active) = self.active.lock()
            && let Some(token) = active.get(dispatch_id)
        {
            token.cancel();
        }
    }

    pub(crate) fn cancel_all(&self) {
        if let Ok(mut active) = self.active.lock() {
            for (_, token) in active.drain() {
                token.cancel();
            }
        }
    }

    #[allow(clippy::too_many_lines)] // Admission, cancellation, effect, and outcome form one receiver state machine.
    pub(crate) async fn dispatch_once(
        &self,
        authority: &dyn DurableAuthority,
        envelope: DurableDispatchEnvelope,
        clock: &InjectedClock,
    ) -> Result<DurableDispatchOutcome, a2a::A2AError> {
        let admission = authority
            .begin_receive(envelope.clone(), "durable-loopback", clock.now(), 60_000)
            .await?;
        match admission {
            crate::ReceiverAdmission::Replay(events) => {
                Ok(DurableDispatchOutcome::Delivered(events))
            }
            crate::ReceiverAdmission::ReplayOutcome(outcome) => {
                Ok(DurableDispatchOutcome::Interrupted(outcome))
            }
            crate::ReceiverAdmission::Busy => Ok(DurableDispatchOutcome::Busy),
            crate::ReceiverAdmission::Execute(lease) => {
                let cancellation = CancellationToken::new();
                self.active
                    .lock()
                    .map_err(|_| {
                        a2a::A2AError::internal("durable endpoint cancellation lock failed")
                    })?
                    .insert(envelope.dispatch_id.clone(), cancellation.clone());
                if authority
                    .cancellation_requested(&envelope.dispatch_id)
                    .await?
                {
                    let events = canceled_events();
                    authority
                        .complete_canceled_receive(&lease, &events, clock.now())
                        .await?;
                    if let Ok(mut active) = self.active.lock() {
                        active.remove(&envelope.dispatch_id);
                    }
                    return Ok(DurableDispatchOutcome::Delivered(events));
                }
                if let Some((started, release)) = &self.completion_barrier {
                    started.notify_one();
                    tokio::select! {
                        () = cancellation.cancelled() => {}
                        () = release.notified() => {}
                    }
                }
                if cancellation.is_cancelled()
                    || authority
                        .cancellation_requested(&envelope.dispatch_id)
                        .await?
                {
                    let events = canceled_events();
                    authority
                        .complete_canceled_receive(&lease, &events, clock.now())
                        .await?;
                    if let Ok(mut active) = self.active.lock() {
                        active.remove(&envelope.dispatch_id);
                    }
                    return Ok(DurableDispatchOutcome::Delivered(events));
                }
                if let Some((trigger, kind, message)) = &self.interruption
                    && envelope.request.text == *trigger
                {
                    let outcome = DurableReceiverResult {
                        events: vec![MeshEvent::Progress(
                            "SMESH swarm is processing the durable dispatch".to_owned(),
                        )],
                        termination: match kind {
                            DurableInterruptionKind::InputRequired => {
                                DurableReceiverTermination::InputRequired {
                                    message: message.clone(),
                                }
                            }
                            DurableInterruptionKind::AuthRequired => {
                                DurableReceiverTermination::AuthRequired {
                                    message: message.clone(),
                                }
                            }
                        },
                    };
                    authority
                        .complete_loopback_outcome(&lease, &outcome, clock.now())
                        .await?;
                    if let Ok(mut active) = self.active.lock() {
                        active.remove(&envelope.dispatch_id);
                    }
                    self.effects.fetch_add(1, Ordering::SeqCst);
                    return Ok(DurableDispatchOutcome::Interrupted(outcome));
                }
                let content = serde_json::json!({
                    "contextId": envelope.request.context_id,
                    "result": format!("SMESH accepted: {}", envelope.request.text),
                    "taskId": envelope.request.task_id,
                })
                .to_string();
                let events = vec![
                    MeshEvent::Progress(
                        "SMESH swarm is processing the durable dispatch".to_owned(),
                    ),
                    MeshEvent::Artifact {
                        name: "smesh-result.json".to_owned(),
                        media_type: "application/json".to_owned(),
                        content,
                    },
                    MeshEvent::Completed {
                        summary: "SMESH swarm completed the task".to_owned(),
                    },
                ];
                if let Err(error) = authority
                    .complete_loopback_receive(&lease, &events, clock.now())
                    .await
                {
                    if authority
                        .cancellation_requested(&envelope.dispatch_id)
                        .await?
                    {
                        let canceled = canceled_events();
                        authority
                            .complete_canceled_receive(&lease, &canceled, clock.now())
                            .await?;
                        if let Ok(mut active) = self.active.lock() {
                            active.remove(&envelope.dispatch_id);
                        }
                        return Ok(DurableDispatchOutcome::Delivered(canceled));
                    }
                    return Err(error);
                }
                if let Ok(mut active) = self.active.lock() {
                    active.remove(&envelope.dispatch_id);
                }
                self.effects.fetch_add(1, Ordering::SeqCst);
                if let Some((completed, publish_release)) = &self.completion_committed {
                    completed.notify_one();
                    publish_release.notified().await;
                }
                Ok(DurableDispatchOutcome::Delivered(events))
            }
        }
    }
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
