use std::collections::HashMap;
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
    OwnerCancelled,
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

struct ReceiverRenewal {
    cancel: CancellationToken,
    latest: tokio::sync::watch::Receiver<Result<ReceiverLease, ()>>,
    join: Option<AbortOnDropJoin<()>>,
}

impl ReceiverRenewal {
    fn start(authority: Arc<dyn DurableAuthority>, lease: &ReceiverLease) -> Option<Self> {
        if !authority.capabilities().lease_renewal {
            return None;
        }
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let (sender, latest) = tokio::sync::watch::channel(Ok(lease.clone()));
        let mut current = lease.clone();
        let lease_millis = receiver_lease_millis();
        let renewal_period = Duration::from_millis(u64::try_from(lease_millis / 3).unwrap_or(100));
        install_driver_panic_hook();
        let join = tokio::spawn(RedactedDriverPoll::new(async move {
            loop {
                tokio::select! {
                    () = task_cancel.cancelled() => return,
                    () = tokio::time::sleep(renewal_period) => {}
                }
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
        authority: Arc<dyn DurableAuthority>,
        envelope: DurableDispatchEnvelope,
        clock: &InjectedClock,
        replica_id: &str,
        owner_cancel: &CancellationToken,
    ) -> Result<DurableDispatchOutcome, DurableDispatchError> {
        let admission = authority
            .begin_receive(
                envelope.clone(),
                replica_id,
                clock.now(),
                receiver_lease_millis(),
            )
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
                let mut renewal = ReceiverRenewal::start(Arc::clone(&authority), &lease);
                let cancellation = CancellationToken::new();
                self.active
                    .lock()
                    .map_err(|_| {
                        a2a::A2AError::internal("durable endpoint cancellation lock failed")
                    })?
                    .insert(envelope.dispatch_id.clone(), cancellation.clone());
                let prepared = tokio::select! {
                    () = owner_cancel.cancelled() => Err(DurableDispatchError::OwnerCancelled),
                    result = async {
                        if authority.cancellation_requested(&envelope.dispatch_id).await? {
                            return Ok(ReceiverCompletion::Canceled(canceled_events()));
                        }
                        if let Some((started, release)) = &self.completion_barrier {
                            started.notify_one();
                            tokio::select! {
                                () = cancellation.cancelled() => {}
                                () = release.notified() => {}
                            }
                        }
                        if cancellation.is_cancelled()
                            || authority.cancellation_requested(&envelope.dispatch_id).await?
                        {
                            return Ok(ReceiverCompletion::Canceled(canceled_events()));
                        }
                        if let Some((trigger, kind, message)) = &self.interruption
                            && envelope.request.text == *trigger
                        {
                            return Ok(ReceiverCompletion::Interrupted(DurableReceiverResult {
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
                            }));
                        }
                        let content = serde_json::json!({
                            "contextId": envelope.request.context_id,
                            "result": format!("SMESH accepted: {}", envelope.request.text),
                            "taskId": envelope.request.task_id,
                        })
                        .to_string();
                        Ok(ReceiverCompletion::Delivered(vec![
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
                        ]))
                    } => result.map_err(DurableDispatchError::Permanent),
                };

                // This is the dispatch owner's finally-like cleanup. Every path,
                // including owner cancellation and preparation failure, joins renewal.
                let fenced = stop_receiver_renewal(&mut renewal, &lease).await;
                let result = async {
                    match (prepared, fenced) {
                        (_, Err(error)) | (Err(error), Ok(_)) => Err(error),
                        (Ok(_), Ok(_)) if owner_cancel.is_cancelled() => {
                            Err(DurableDispatchError::OwnerCancelled)
                        }
                        (Ok(completion), Ok(fenced)) => match completion {
                            ReceiverCompletion::Canceled(events) => {
                                authority
                                    .complete_canceled_receive(&fenced, &events, clock.now())
                                    .await?;
                                Ok(DurableDispatchOutcome::Delivered(events))
                            }
                            ReceiverCompletion::Interrupted(outcome) => {
                                authority
                                    .complete_loopback_outcome(&fenced, &outcome, clock.now())
                                    .await?;
                                self.effects.fetch_add(1, Ordering::SeqCst);
                                Ok(DurableDispatchOutcome::Interrupted(outcome))
                            }
                            ReceiverCompletion::Delivered(events) => {
                                if let Err(error) = authority
                                    .complete_loopback_receive(&fenced, &events, clock.now())
                                    .await
                                {
                                    if authority
                                        .cancellation_requested(&envelope.dispatch_id)
                                        .await?
                                    {
                                        let canceled = canceled_events();
                                        authority
                                            .complete_canceled_receive(
                                                &fenced,
                                                &canceled,
                                                clock.now(),
                                            )
                                            .await?;
                                        return Ok(DurableDispatchOutcome::Delivered(canceled));
                                    }
                                    return Err(error.into());
                                }
                                self.effects.fetch_add(1, Ordering::SeqCst);
                                if let Some((completed, publish_release)) =
                                    &self.completion_committed
                                {
                                    completed.notify_one();
                                    tokio::select! {
                                        () = owner_cancel.cancelled() => {
                                            return Err(DurableDispatchError::OwnerCancelled);
                                        }
                                        () = publish_release.notified() => {}
                                    }
                                }
                                Ok(DurableDispatchOutcome::Delivered(events))
                            }
                        },
                    }
                }
                .await;
                if let Ok(mut active) = self.active.lock() {
                    active.remove(&envelope.dispatch_id);
                }
                result
            }
        }
    }
}

enum ReceiverCompletion {
    Canceled(Vec<MeshEvent>),
    Interrupted(DurableReceiverResult),
    Delivered(Vec<MeshEvent>),
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
mod tests {
    use super::*;

    fn receiver_lease() -> ReceiverLease {
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
