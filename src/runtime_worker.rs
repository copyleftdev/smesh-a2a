use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use smesh_runtime::SmeshRuntime;
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

use crate::outbox_driver::AbortOnDropJoin;
use crate::{
    ChannelDispatcher, DispatchCommand, DispatchError, DurableDispatchCorrelation,
    DurableReceiverResult, DurableWorkEnvelope, ExecutionBudget, MeshEvent, MeshRequest,
    RuntimeAdapterOutcome,
};

const PROCESSOR_CANCEL_GRACE: Duration = Duration::from_secs(1);
const MAX_PROCESSOR_CANCEL_GRACE: Duration = Duration::from_secs(1);
const CANCELLATION_ACK_MARGIN: Duration = Duration::from_secs(1);

/// Inputs supplied to an internal runtime task processor after real SMESH ingress succeeds.
pub struct RuntimeTask {
    pub request: MeshRequest,
    pub signal_hash: String,
    pub runtime: Arc<SmeshRuntime>,
    durable_envelope: Option<DurableWorkEnvelope>,
}

impl RuntimeTask {
    /// Return immutable durable authority metadata when invoked by the durable adapter.
    #[must_use]
    pub const fn durable_envelope(&self) -> Option<&DurableWorkEnvelope> {
        self.durable_envelope.as_ref()
    }
}

/// Cancellation-aware capability for emitting untrusted runtime events.
pub struct RuntimeEventSink {
    events: mpsc::Sender<Result<MeshEvent, DispatchError>>,
    cancellation: CancellationToken,
    budget: ExecutionBudget,
    usage: Arc<Mutex<(u64, u64)>>,
    known_failure: Option<Arc<Mutex<Option<crate::RuntimeExecutionFailure>>>>,
}

impl RuntimeEventSink {
    /// Emit non-authoritative progress unless this execution has been canceled.
    ///
    /// # Errors
    ///
    /// Returns an error when the execution was canceled, its output budget is exhausted,
    /// or the bounded event channel is unavailable.
    pub async fn progress(&self, text: impl Into<String>) -> Result<(), DispatchError> {
        self.emit(MeshEvent::Progress(text.into())).await
    }

    /// Submit one private candidate artifact.
    ///
    /// # Errors
    ///
    /// Returns an error when the execution was canceled, its output budget is exhausted,
    /// or the bounded event channel is unavailable.
    pub async fn artifact(
        &self,
        name: impl Into<String>,
        media_type: impl Into<String>,
        content: impl Into<String>,
    ) -> Result<(), DispatchError> {
        self.emit(MeshEvent::Artifact {
            name: name.into(),
            media_type: media_type.into(),
            content: content.into(),
        })
        .await
    }

    /// Submit one binary-capable private candidate artifact through the
    /// internal durable event envelope without extending [`MeshEvent`].
    ///
    /// # Errors
    ///
    /// Returns an error when canceled, over budget, or the event channel closes.
    pub async fn artifact_bytes(
        &self,
        name: impl Into<String>,
        media_type: impl Into<String>,
        content: &[u8],
    ) -> Result<(), DispatchError> {
        self.emit(crate::bridge::binary_artifact_event(
            name.into(),
            media_type.into(),
            content,
        ))
        .await
    }

    /// Submit an untrusted completion proposal. This cannot complete A2A work by itself.
    ///
    /// # Errors
    ///
    /// Returns an error when the execution was canceled, its output budget is exhausted,
    /// or the bounded event channel is unavailable.
    pub async fn propose_completion(
        &self,
        summary: impl Into<String>,
    ) -> Result<(), DispatchError> {
        self.emit(MeshEvent::Completed {
            summary: summary.into(),
        })
        .await
    }

    async fn emit(&self, event: MeshEvent) -> Result<(), DispatchError> {
        let bytes = u64::try_from(
            serde_json::to_vec(&event)
                .map_err(|_| DispatchError::message("runtime event serialization failed"))?
                .len(),
        )
        .map_err(|_| DispatchError::message("runtime event serialization overflow"))?;
        {
            let mut usage = self
                .usage
                .lock()
                .map_err(|_| DispatchError::message("runtime execution budget lock failed"))?;
            let next_events = usage
                .0
                .checked_add(1)
                .ok_or_else(|| DispatchError::message("runtime event budget overflow"))?;
            let next_bytes = usage
                .1
                .checked_add(bytes)
                .ok_or_else(|| DispatchError::message("runtime output budget overflow"))?;
            if next_events > self.budget.max_event_count()
                || next_bytes > self.budget.max_output_bytes()
            {
                if let Some(known_failure) = &self.known_failure {
                    *known_failure.lock().unwrap() = Some(crate::RuntimeExecutionFailure::Budget);
                }
                return Err(DispatchError::message(
                    "runtime exceeded reserved execution budget",
                ));
            }
            *usage = (next_events, next_bytes);
        }
        send_event(&self.events, &self.cancellation, event).await
    }
}

/// Converts real runtime work into untrusted events for the gateway completion policy.
///
/// This is a trusted in-process extension point. Implementations must not detach child work;
/// returning means all work owned by the invocation has stopped. The capability-limited
/// [`RuntimeEventSink`] permits progress, private candidate artifacts, and completion proposals,
/// but not policy evidence. Independent authority adapters must supply evidence separately.
#[async_trait]
pub trait RuntimeTaskProcessor: Send + Sync + 'static {
    async fn process(
        &self,
        task: RuntimeTask,
        cancellation: CancellationToken,
        events: RuntimeEventSink,
    ) -> Result<(), DispatchError>;
}

/// Admission-only processor used by the standalone runtime mode.
///
/// It emits a private candidate admission receipt and a completion proposal, but
/// deliberately emits no review, test, contradiction, or ratification evidence.
/// The default completion policy therefore fails closed rather than treating
/// runtime ingress as completion of the requested semantic work.
#[derive(Debug, Clone, Copy, Default)]
pub struct RuntimeAdmissionProcessor;

#[async_trait]
impl RuntimeTaskProcessor for RuntimeAdmissionProcessor {
    async fn process(
        &self,
        task: RuntimeTask,
        _cancellation: CancellationToken,
        events: RuntimeEventSink,
    ) -> Result<(), DispatchError> {
        let signal_exists = {
            let network = task.runtime.network();
            let network = network.read().await;
            network.field.signals.contains_key(&task.signal_hash)
        };
        if !signal_exists {
            return Err(DispatchError::Message(
                "runtime did not retain the emitted query signal".to_owned(),
            ));
        }

        let artifact_name = "smesh-runtime-result.json";
        let media_type = "application/json";
        let content = serde_json::json!({
            "contextId": task.request.context_id,
            "result": "SMESH runtime accepted and retained the query",
            "signalHash": task.signal_hash,
            "taskId": task.request.task_id,
        })
        .to_string();
        events.artifact(artifact_name, media_type, content).await?;

        events
            .propose_completion("runtime processor proposed completion")
            .await
    }
}

async fn send_event(
    events: &mpsc::Sender<Result<MeshEvent, DispatchError>>,
    cancellation: &CancellationToken,
    event: MeshEvent,
) -> Result<(), DispatchError> {
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(DispatchError::Message("runtime task canceled".to_owned())),
        result = events.send(Ok(event)) => result.map_err(|_| {
            DispatchError::Message("runtime event receiver is closed".to_owned())
        }),
    }
}

async fn send_dispatch_error(
    events: &mpsc::Sender<Result<MeshEvent, DispatchError>>,
    cancellation: &CancellationToken,
    error: DispatchError,
) -> Result<(), DispatchError> {
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Ok(()),
        result = events.send(Err(error)) => result.map_err(|_| {
            DispatchError::Message("runtime event receiver is closed".to_owned())
        }),
    }
}

/// Bounded runtime-worker resource and cancellation settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeWorkerConfig {
    pub command_capacity: usize,
    pub max_active_tasks: usize,
    pub cancel_grace: Duration,
}

impl Default for RuntimeWorkerConfig {
    fn default() -> Self {
        Self {
            command_capacity: 64,
            max_active_tasks: 64,
            cancel_grace: PROCESSOR_CANCEL_GRACE,
        }
    }
}

/// Spawns the command consumer that owns real SMESH runtime executions.
pub struct RuntimeWorker;

impl RuntimeWorker {
    /// Validate runtime ownership and spawn the command consumer.
    ///
    /// # Errors
    ///
    /// Returns an error when the configured runtime node is absent or its identity is inconsistent.
    pub async fn spawn<P>(
        runtime: Arc<SmeshRuntime>,
        node_id: impl Into<String>,
        processor: P,
        command_capacity: usize,
    ) -> Result<(ChannelDispatcher, RuntimeWorkerHandle), DispatchError>
    where
        P: RuntimeTaskProcessor,
    {
        let capacity = command_capacity.max(1);
        Self::spawn_with_config(
            runtime,
            node_id,
            processor,
            RuntimeWorkerConfig {
                command_capacity: capacity,
                max_active_tasks: capacity,
                cancel_grace: PROCESSOR_CANCEL_GRACE,
            },
        )
        .await
    }

    /// Spawn with explicit resource and cancellation settings.
    ///
    /// # Errors
    ///
    /// Returns an error for zero bounds, zero cancellation grace, or invalid runtime ownership.
    pub async fn spawn_with_config<P>(
        runtime: Arc<SmeshRuntime>,
        node_id: impl Into<String>,
        processor: P,
        config: RuntimeWorkerConfig,
    ) -> Result<(ChannelDispatcher, RuntimeWorkerHandle), DispatchError>
    where
        P: RuntimeTaskProcessor,
    {
        if config.command_capacity == 0
            || config.max_active_tasks == 0
            || config.cancel_grace.is_zero()
            || config.cancel_grace > MAX_PROCESSOR_CANCEL_GRACE
        {
            return Err(DispatchError::Message(
                "runtime worker bounds must be non-zero and cancellation grace at most 1 second"
                    .to_owned(),
            ));
        }
        let node_id = node_id.into();
        let valid_node = {
            let network = runtime.network();
            let network = network.read().await;
            network
                .nodes
                .get(&node_id)
                .is_some_and(smesh_core::Node::identity_matches_name)
        };
        if !valid_node {
            return Err(DispatchError::Message(
                "configured runtime node is absent or has an inconsistent identity".to_owned(),
            ));
        }
        let (commands, receiver) = mpsc::channel(config.command_capacity);
        let (control, control_receiver) = mpsc::channel(config.max_active_tasks);
        let runtime_capacity = Arc::new(tokio::sync::Semaphore::new(config.max_active_tasks));
        let dispatcher = ChannelDispatcher::new(commands, node_id.clone())
            .with_control(control)
            .with_runtime_capacity(Arc::clone(&runtime_capacity))
            .with_timeout(config.cancel_grace + CANCELLATION_ACK_MARGIN);
        let shutdown = CancellationToken::new();
        let join = tokio::spawn(run_worker(
            runtime,
            node_id,
            Arc::new(processor),
            receiver,
            control_receiver,
            shutdown.clone(),
            runtime_capacity,
            config.cancel_grace,
        ));
        Ok((
            dispatcher,
            RuntimeWorkerHandle {
                shutdown,
                join: Some(join),
            },
        ))
    }
}

/// Handle used to stop the runtime command consumer and all active processors.
///
/// Dropping starts cooperative cancellation. Call [`Self::shutdown`] to also
/// wait for every tracked processor and observe worker panics.
#[must_use = "call shutdown().await to join the worker and observe failures"]
pub struct RuntimeWorkerHandle {
    shutdown: CancellationToken,
    join: Option<JoinHandle<()>>,
}

struct OwnedRuntimeWorkerTask(Option<JoinHandle<()>>);

impl OwnedRuntimeWorkerTask {
    async fn join(mut self) -> Result<(), DispatchError> {
        let result = {
            let join = self
                .0
                .as_mut()
                .ok_or_else(|| DispatchError::message("runtime worker join handle is absent"))?;
            join.await
        };
        self.0.take();
        result.map_err(|_| DispatchError::Message("runtime worker shutdown failed".to_owned()))
    }

    async fn reap_bounded(mut self) {
        let Some(join) = self.0.as_mut() else {
            return;
        };
        if tokio::time::timeout(runtime_worker_drop_watchdog(), &mut *join)
            .await
            .is_err()
        {
            join.abort();
            let _ = join.await;
        }
        self.0.take();
    }
}

impl Drop for OwnedRuntimeWorkerTask {
    fn drop(&mut self) {
        if let Some(join) = self.0.as_ref() {
            join.abort();
        }
    }
}

impl RuntimeWorkerHandle {
    /// Stop admission and wait for every tracked runtime processor to exit.
    ///
    /// # Errors
    ///
    /// Returns an error if the worker task panics after shutdown is requested.
    pub async fn shutdown(mut self) -> Result<(), DispatchError> {
        self.shutdown.cancel();
        let Some(join) = self.join.take() else {
            return Err(DispatchError::message(
                "runtime worker join handle is absent",
            ));
        };
        OwnedRuntimeWorkerTask(Some(join)).join().await
    }
}

impl Drop for RuntimeWorkerHandle {
    fn drop(&mut self) {
        self.shutdown.cancel();
        let Some(join) = self.join.take() else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            join.abort();
            return;
        };
        runtime.spawn(OwnedRuntimeWorkerTask(Some(join)).reap_bounded());
    }
}

fn runtime_worker_drop_watchdog() -> Duration {
    #[cfg(test)]
    return Duration::from_millis(100);
    #[cfg(not(test))]
    Duration::from_secs(2)
}

type ActiveTask = (
    CancellationToken,
    AbortOnDropJoin<Result<(), DispatchError>>,
);
struct DurableTaskOutcomeState {
    proposed: Vec<MeshEvent>,
    outcome: Option<oneshot::Sender<RuntimeAdapterOutcome>>,
}

type SharedDurableTaskOutcome = Arc<Mutex<DurableTaskOutcomeState>>;
type ActiveDurableTask = (
    CancellationToken,
    AbortOnDropJoin<()>,
    SharedDurableTaskOutcome,
);

fn durable_task_outcome_state(
    outcome: oneshot::Sender<RuntimeAdapterOutcome>,
) -> SharedDurableTaskOutcome {
    Arc::new(Mutex::new(DurableTaskOutcomeState {
        proposed: Vec::new(),
        outcome: Some(outcome),
    }))
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn run_worker(
    runtime: Arc<SmeshRuntime>,
    node_id: String,
    processor: Arc<dyn RuntimeTaskProcessor>,
    mut commands: mpsc::Receiver<DispatchCommand>,
    mut control: mpsc::Receiver<DispatchCommand>,
    shutdown: CancellationToken,
    runtime_capacity: Arc<tokio::sync::Semaphore>,
    cancel_grace: Duration,
) {
    let mut active = HashMap::<String, ActiveTask>::new();
    let mut active_durable = HashMap::<DurableDispatchCorrelation, ActiveDurableTask>::new();
    let mut cancelling_durable = HashSet::<DurableDispatchCorrelation>::new();
    let mut cancelling = HashSet::<String>::new();
    let mut reapers = JoinSet::<String>::new();
    let mut durable_reapers = JoinSet::<DurableDispatchCorrelation>::new();
    loop {
        let finished = active
            .iter()
            .filter(|(_, (_, join))| join.is_finished())
            .map(|(task_id, _)| task_id.clone())
            .collect::<Vec<_>>();
        for task_id in finished {
            if let Some((_, mut join)) = active.remove(&task_id) {
                let _ = join.handle_mut().await;
            }
        }
        let durable_finished = active_durable
            .iter()
            .filter(|(_, (_, join, _))| join.is_finished())
            .map(|(correlation, _)| correlation.clone())
            .collect::<Vec<_>>();
        for correlation in durable_finished {
            if let Some((_, mut join, _)) = active_durable.remove(&correlation) {
                let _ = join.handle_mut().await;
            }
        }

        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            completed = reapers.join_next(), if !reapers.is_empty() => {
                if let Some(Ok(task_id)) = completed {
                    cancelling.remove(&task_id);
                }
            }
            completed = durable_reapers.join_next(), if !durable_reapers.is_empty() => {
                if let Some(Ok(correlation)) = completed {
                    cancelling_durable.remove(&correlation);
                }
            }
            command = async {
                tokio::select! {
                    biased;
                    command = control.recv() => command,
                    command = commands.recv() => command,
                }
            } => {
                let Some(command) = command else { break; };
                match command {
                    DispatchCommand::Execute { request, budget, signal, events } => {
                        if active.contains_key(&request.task_id)
                            || cancelling.contains(&request.task_id)
                        {
                            let _ = events.try_send(Err(DispatchError::Message(
                                "runtime task ID is already active".to_owned(),
                            )));
                            continue;
                        }
                        let Ok(runtime_capacity) =
                            Arc::clone(&runtime_capacity).try_acquire_owned()
                        else {
                            let _ = events.try_send(Err(DispatchError::Message(
                                "runtime worker capacity reached".to_owned(),
                            )));
                            continue;
                        };
                        let task_id = request.task_id.clone();
                        let cancellation = CancellationToken::new();
                        let join = tokio::spawn(run_task(
                            Arc::clone(&runtime),
                            node_id.clone(),
                            Arc::clone(&processor),
                            request,
                            budget,
                            *signal,
                            cancellation.clone(),
                            events,
                            None,
                            Some(runtime_capacity),
                            None,
                        ));
                        active.insert(task_id, (cancellation, AbortOnDropJoin::new(join)));
                    }
                    DispatchCommand::ExecuteDurable {
                        envelope,
                        signal,
                        cancellation,
                        admitted,
                        outcome,
                        runtime_capacity,
                    } => {
                        let envelope = *envelope;
                        let correlation = envelope.correlation().clone();
                        if active_durable
                            .get(&correlation)
                            .is_some_and(|(_, join, _)| join.is_finished())
                            && let Some((_, mut join, _)) = active_durable.remove(&correlation)
                        {
                            let _ = join.handle_mut().await;
                        }
                        if active_durable.contains_key(&correlation)
                            || cancelling_durable.contains(&correlation)
                        {
                            let _ = admitted.send(Err(
                                crate::RuntimePreAdmissionFailure::DuplicateCorrelation,
                            ));
                            drop(outcome);
                            continue;
                        }
                        let Some(runtime_capacity) = runtime_capacity else {
                            let _ = admitted
                                .send(Err(crate::RuntimePreAdmissionFailure::Capacity));
                            drop(outcome);
                            continue;
                        };
                        let task_cancellation = cancellation.clone();
                        let outcome_state = durable_task_outcome_state(outcome);
                        let join = tokio::spawn(run_durable_task(
                            Arc::clone(&runtime),
                            node_id.clone(),
                            Arc::clone(&processor),
                            envelope,
                            *signal,
                            task_cancellation,
                            Arc::clone(&outcome_state),
                            Some(runtime_capacity),
                        ));
                        active_durable.insert(
                            correlation,
                            (cancellation, AbortOnDropJoin::new(join), outcome_state),
                        );
                        let _ = admitted.send(Ok(()));
                    }
                    DispatchCommand::CancelDurable { correlation, ack } => {
                        if let Some((cancellation, join, outcome_state)) =
                            active_durable.remove(&correlation)
                        {
                            cancelling_durable.insert(correlation.clone());
                            durable_reapers.spawn(reap_canceled_durable_task(
                                correlation,
                                cancellation,
                                join,
                                outcome_state,
                                ack,
                                cancel_grace,
                            ));
                        } else {
                            let _ = ack.send(crate::RuntimeCancellationRequest::NotActive);
                        }
                    }
                    DispatchCommand::Cancel { task_id, ack } => {
                        if let Some((cancellation, join)) = active.remove(&task_id) {
                            cancelling.insert(task_id.clone());
                            reapers.spawn(reap_canceled_task(
                                task_id,
                                cancellation,
                                join,
                                ack,
                                cancel_grace,
                            ));
                        } else {
                            let _ = ack.send(Err(DispatchError::Message(
                                "runtime task is not active".to_owned(),
                            )));
                        }
                    }
                }
            }
        }
    }

    let mut shutdown_tasks = JoinSet::new();
    for (_, (cancellation, join)) in active {
        shutdown_tasks.spawn(stop_tracked_task(cancellation, join, cancel_grace));
    }
    for (_, (cancellation, join, outcome_state)) in active_durable {
        shutdown_tasks.spawn(stop_tracked_durable_task(
            cancellation,
            join,
            outcome_state,
            cancel_grace,
        ));
    }
    while shutdown_tasks.join_next().await.is_some() {}
    while reapers.join_next().await.is_some() {}
    while durable_reapers.join_next().await.is_some() {}
}

async fn stop_tracked_task(
    cancellation: CancellationToken,
    mut join: AbortOnDropJoin<Result<(), DispatchError>>,
    cancel_grace: Duration,
) {
    cancellation.cancel();
    if tokio::time::timeout(cancel_grace, join.handle_mut())
        .await
        .is_err()
    {
        join.abort();
        let _ = join.handle_mut().await;
    }
}

async fn reap_canceled_durable_task(
    correlation: DurableDispatchCorrelation,
    cancellation: CancellationToken,
    mut join: AbortOnDropJoin<()>,
    _outcome_state: SharedDurableTaskOutcome,
    ack: oneshot::Sender<crate::RuntimeCancellationRequest>,
    cancel_grace: Duration,
) -> DurableDispatchCorrelation {
    cancellation.cancel();
    if tokio::time::timeout(cancel_grace, join.handle_mut())
        .await
        .is_err()
    {
        join.abort();
        let _ = join.handle_mut().await;
    }
    let _ = ack.send(crate::RuntimeCancellationRequest::Requested);
    correlation
}

async fn stop_tracked_durable_task(
    cancellation: CancellationToken,
    mut join: AbortOnDropJoin<()>,
    _outcome_state: SharedDurableTaskOutcome,
    cancel_grace: Duration,
) {
    cancellation.cancel();
    if tokio::time::timeout(cancel_grace, join.handle_mut())
        .await
        .is_err()
    {
        join.abort();
        let _ = join.handle_mut().await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_durable_task(
    runtime: Arc<SmeshRuntime>,
    node_id: String,
    processor: Arc<dyn RuntimeTaskProcessor>,
    envelope: DurableWorkEnvelope,
    signal: smesh_core::Signal,
    cancellation: CancellationToken,
    outcome_state: SharedDurableTaskOutcome,
    _runtime_capacity: Option<tokio::sync::OwnedSemaphorePermit>,
) {
    let (events, mut received) = mpsc::channel(32);
    let request = envelope.request().clone();
    let budget = envelope.budget();
    let task_cancellation = cancellation.clone();
    let durable = envelope.clone();
    let known_failure = Arc::new(Mutex::new(None));
    let runner = run_task(
        runtime,
        node_id,
        processor,
        request,
        budget,
        signal,
        task_cancellation,
        events,
        Some(durable),
        None,
        Some(Arc::clone(&known_failure)),
    );
    tokio::pin!(runner);
    let runner_result = loop {
        tokio::select! {
            result = &mut runner => {
                break result;
            }
            event = received.recv() => match event {
                Some(Ok(event)) => outcome_state.lock().unwrap().proposed.push(event),
                Some(Err(_)) => {}
                None => {
                    break runner.await;
                }
            }
        }
    };
    while let Some(event) = received.recv().await {
        if let Ok(event) = event {
            outcome_state.lock().unwrap().proposed.push(event);
        }
    }
    let mut outcome_state = outcome_state.lock().unwrap();
    let complete = outcome_state
        .proposed
        .iter()
        .any(|event| matches!(event, MeshEvent::Completed { .. }));
    let known_failure = *known_failure.lock().unwrap();
    let result = if let Some(failure) = known_failure {
        RuntimeAdapterOutcome::ExecutionFailed(failure)
    } else if runner_result.is_err() {
        // Forced destruction or a processor error under cancellation is not proof
        // that an observed terminal proposal completed its execution sequence.
        RuntimeAdapterOutcome::AdmittedUnknown
    } else if complete {
        RuntimeAdapterOutcome::Terminal(DurableReceiverResult {
            events: std::mem::take(&mut outcome_state.proposed),
            termination: crate::DurableReceiverTermination::Success,
        })
    } else if cancellation.is_cancelled() {
        RuntimeAdapterOutcome::ConfirmedStopped
    } else {
        // A processor returning without proposing a complete terminal sequence
        // does not establish an authoritative execution result.
        RuntimeAdapterOutcome::AdmittedUnknown
    };
    if let Some(outcome) = outcome_state.outcome.take() {
        let _ = outcome.send(result);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CancellationReapOutcome {
    CooperativeStop,
    ProcessorFailed(DispatchError),
    ForcedAbort,
}

impl CancellationReapOutcome {
    fn into_dispatch_result(self) -> Result<(), DispatchError> {
        match self {
            Self::CooperativeStop => Ok(()),
            Self::ProcessorFailed(error) => Err(error),
            Self::ForcedAbort => Err(DispatchError::CancellationForcedAbort),
        }
    }
}

async fn reap_canceled_task(
    task_id: String,
    cancellation: CancellationToken,
    mut join: AbortOnDropJoin<Result<(), DispatchError>>,
    ack: oneshot::Sender<Result<(), DispatchError>>,
    cancel_grace: Duration,
) -> String {
    cancellation.cancel();
    let outcome = match tokio::time::timeout(cancel_grace, join.handle_mut()).await {
        Ok(Ok(Ok(()))) => CancellationReapOutcome::CooperativeStop,
        Ok(Ok(Err(error))) => CancellationReapOutcome::ProcessorFailed(error),
        Ok(Err(_)) => CancellationReapOutcome::ProcessorFailed(DispatchError::Message(
            "runtime processor task failed during cancellation".to_owned(),
        )),
        Err(_) => {
            join.abort();
            let _ = join.handle_mut().await;
            CancellationReapOutcome::ForcedAbort
        }
    };
    let _ = ack.send(outcome.into_dispatch_result());
    task_id
}

#[allow(clippy::too_many_arguments)]
async fn run_task(
    runtime: Arc<SmeshRuntime>,
    node_id: String,
    processor: Arc<dyn RuntimeTaskProcessor>,
    request: MeshRequest,
    budget: ExecutionBudget,
    signal: smesh_core::Signal,
    cancellation: CancellationToken,
    events: mpsc::Sender<Result<MeshEvent, DispatchError>>,
    durable_envelope: Option<DurableWorkEnvelope>,
    _runtime_capacity: Option<tokio::sync::OwnedSemaphorePermit>,
    known_failure: Option<Arc<Mutex<Option<crate::RuntimeExecutionFailure>>>>,
) -> Result<(), DispatchError> {
    let ingress_progress = MeshEvent::Progress("SMESH runtime retained the query".to_owned());
    let ingress_progress_bytes = u64::try_from(
        serde_json::to_vec(&ingress_progress)
            .map_err(|_| DispatchError::message("runtime event serialization failed"))?
            .len(),
    )
    .map_err(|_| DispatchError::message("runtime event serialization overflow"))?;
    if budget.max_event_count() < 1 || budget.max_output_bytes() < ingress_progress_bytes {
        if let Some(known_failure) = &known_failure {
            *known_failure.lock().unwrap() = Some(crate::RuntimeExecutionFailure::Budget);
        }
        let _ = send_dispatch_error(
            &events,
            &cancellation,
            DispatchError::message("runtime reserved execution budget is too small"),
        )
        .await;
        return Ok(());
    }
    let emitted = tokio::select! {
        () = cancellation.cancelled() => return Ok(()),
        emitted = runtime.emit(signal, &node_id) => emitted,
    };
    let Some(signal_hash) = emitted else {
        if let Some(known_failure) = &known_failure {
            *known_failure.lock().unwrap() = Some(crate::RuntimeExecutionFailure::Ingress);
        }
        let _ = events.try_send(Err(DispatchError::Message(
            "runtime rejected query ingress".to_owned(),
        )));
        return Ok(());
    };
    if send_event(&events, &cancellation, ingress_progress)
        .await
        .is_err()
    {
        return Ok(());
    }
    let task = RuntimeTask {
        request,
        signal_hash,
        runtime,
        durable_envelope,
    };
    let sink = RuntimeEventSink {
        events: events.clone(),
        cancellation: cancellation.clone(),
        budget,
        usage: Arc::new(Mutex::new((1, ingress_progress_bytes))),
        known_failure: known_failure.clone(),
    };
    // Durable execution is cancellation-owned even if its coordinator is forcibly
    // dropped before it can issue a control command. The processor future is a
    // child of this task, never detached; dropping it after the bounded grace
    // destroys it before the outcome and capacity can be released.
    let durable_execution = task.durable_envelope().is_some();
    let processing = processor.process(task, cancellation.clone(), sink);
    tokio::pin!(processing);
    let result = tokio::select! {
        result = &mut processing => result,
        () = cancellation.cancelled(), if durable_execution => {
            tokio::time::timeout(MAX_PROCESSOR_CANCEL_GRACE, &mut processing)
                .await.unwrap_or(Err(DispatchError::CancellationForcedAbort))
        }
    };
    match result {
        Ok(()) => Ok(()),
        Err(error) if cancellation.is_cancelled() => Err(error),
        Err(error) => {
            if let Some(known_failure) = &known_failure {
                known_failure
                    .lock()
                    .unwrap()
                    .get_or_insert(crate::RuntimeExecutionFailure::Processor);
            }
            let _ = send_dispatch_error(&events, &cancellation, error).await;
            Ok(())
        }
    }
}

#[cfg(test)]
mod ownership_tests {
    use super::*;
    use crate::DurableRuntimeAdapter as _;

    struct Reaped(Option<oneshot::Sender<()>>);

    impl Drop for Reaped {
        fn drop(&mut self) {
            if let Some(reaped) = self.0.take() {
                let _ = reaped.send(());
            }
        }
    }

    fn production_envelope(
        scope: crate::DurableRuntimeScope,
        correlation: crate::DurableDispatchCorrelation,
        request: MeshRequest,
    ) -> crate::DurableWorkEnvelope {
        production_envelope_with_budget(
            scope,
            correlation,
            request,
            ExecutionBudget::new(4096, 8).unwrap(),
        )
    }

    fn production_envelope_with_budget(
        scope: crate::DurableRuntimeScope,
        correlation: crate::DurableDispatchCorrelation,
        request: MeshRequest,
        budget: ExecutionBudget,
    ) -> crate::DurableWorkEnvelope {
        let transport = crate::content_digest(&serde_json::to_vec(&request).unwrap());
        let authorized = crate::content_digest(b"authorized-request");
        let reservation = crate::ExecutionReservation {
            reservation_id: format!("reservation-{}", correlation.dispatch_id()),
            reservation_version: 1,
            binding_digest: crate::content_digest(correlation.dispatch_id().as_bytes()),
            policy_id: "quota-runtime".to_owned(),
            policy_revision: 1,
            policy_digest: crate::content_digest(b"quota-runtime-v1"),
            budget,
        };
        let authority = crate::DurableRuntimeAuthorityContext::production(
            scope,
            correlation,
            request,
            transport,
            authorized,
            reservation,
        )
        .unwrap();
        crate::DurableWorkEnvelope::new(authority)
    }

    #[tokio::test]
    async fn terminal_proposal_observed_before_cancellation_remains_visible() {
        struct CompletesThenCancels;

        #[async_trait]
        impl RuntimeTaskProcessor for CompletesThenCancels {
            async fn process(
                &self,
                _task: RuntimeTask,
                cancellation: CancellationToken,
                events: RuntimeEventSink,
            ) -> Result<(), DispatchError> {
                events
                    .propose_completion("observed terminal proposal")
                    .await?;
                cancellation.cancel();
                Ok(())
            }
        }

        let mut network = smesh_core::Network::new();
        network.add_node(smesh_core::Node::named("terminal-race-runtime"));
        let runtime = Arc::new(SmeshRuntime::with_network(
            network,
            smesh_runtime::RuntimeConfig::default(),
        ));
        let scope = crate::DurableRuntimeScope::new(
            "tenant-terminal",
            "account-terminal",
            "principal-terminal",
            "trusted-local",
            crate::VisibilityScope::Own,
        )
        .unwrap();
        let correlation =
            crate::DurableDispatchCorrelation::new(scope.clone(), "dispatch-terminal-race", 1, 1)
                .unwrap();
        let request = MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "task-terminal-race".to_owned(),
            context_id: "context-terminal-race".to_owned(),
            text: "complete then cancel".to_owned(),
        };
        let envelope = production_envelope(scope, correlation, request);
        let signal = envelope.request().to_signal("terminal-race-runtime");
        let cancellation = CancellationToken::new();
        let (outcome_tx, outcome_rx) = oneshot::channel();

        run_durable_task(
            runtime,
            "terminal-race-runtime".to_owned(),
            Arc::new(CompletesThenCancels),
            envelope,
            signal,
            cancellation,
            durable_task_outcome_state(outcome_tx),
            None,
        )
        .await;

        assert!(matches!(
            outcome_rx.await.unwrap(),
            crate::RuntimeAdapterOutcome::Terminal(_)
        ));
    }

    #[tokio::test]
    async fn forced_cancellation_after_terminal_observation_remains_unknown() {
        struct CompletesThenPends {
            observed: std::sync::Mutex<Option<oneshot::Sender<()>>>,
        }

        #[async_trait]
        impl RuntimeTaskProcessor for CompletesThenPends {
            async fn process(
                &self,
                _task: RuntimeTask,
                _cancellation: CancellationToken,
                events: RuntimeEventSink,
            ) -> Result<(), DispatchError> {
                events.propose_completion("sticky completion").await?;
                for index in 0..33 {
                    events
                        .progress(format!("collector barrier {index}"))
                        .await?;
                }
                self.observed
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap()
                    .send(())
                    .unwrap();
                std::future::pending().await
            }
        }

        let mut network = smesh_core::Network::new();
        network.add_node(smesh_core::Node::named("forced-terminal-runtime"));
        let runtime = Arc::new(SmeshRuntime::with_network(
            network,
            smesh_runtime::RuntimeConfig::default(),
        ));
        let (observed_tx, observed_rx) = oneshot::channel();
        let (dispatcher, worker) = RuntimeWorker::spawn_with_config(
            runtime,
            "forced-terminal-runtime",
            CompletesThenPends {
                observed: std::sync::Mutex::new(Some(observed_tx)),
            },
            RuntimeWorkerConfig {
                command_capacity: 2,
                max_active_tasks: 1,
                cancel_grace: Duration::from_millis(20),
            },
        )
        .await
        .unwrap();
        let scope = crate::DurableRuntimeScope::new(
            "tenant-forced-terminal",
            "account-forced-terminal",
            "principal-forced-terminal",
            "trusted-local",
            crate::VisibilityScope::Own,
        )
        .unwrap();
        let correlation =
            crate::DurableDispatchCorrelation::new(scope.clone(), "dispatch-forced-terminal", 1, 1)
                .unwrap();
        let request = MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "task-forced-terminal".to_owned(),
            context_id: "context-forced-terminal".to_owned(),
            text: "complete before forced cancellation".to_owned(),
        };
        let envelope = production_envelope_with_budget(
            scope,
            correlation.clone(),
            request,
            ExecutionBudget::new(65_536, 64).unwrap(),
        );
        let crate::RuntimeAdapterPreparation::Ready(permit) = dispatcher.prepare().await else {
            panic!("capacity unavailable");
        };
        let crate::RuntimeAdapterAdmission::Admitted(execution) =
            permit.admit(envelope, CancellationToken::new()).await
        else {
            panic!("not admitted");
        };
        tokio::time::timeout(Duration::from_secs(1), observed_rx)
            .await
            .expect("collector did not observe completion before cancellation")
            .unwrap();

        assert_eq!(
            dispatcher.cancel_durable(&correlation).await,
            crate::RuntimeCancellationRequest::Requested
        );
        assert_eq!(
            execution.finish().await,
            crate::RuntimeAdapterOutcome::AdmittedUnknown
        );
        worker.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn local_budget_failure_is_known_and_payload_free() {
        struct MustNotRun;

        #[async_trait]
        impl RuntimeTaskProcessor for MustNotRun {
            async fn process(
                &self,
                _task: RuntimeTask,
                _cancellation: CancellationToken,
                _events: RuntimeEventSink,
            ) -> Result<(), DispatchError> {
                panic!("processor reached after ingress budget rejection")
            }
        }

        let mut network = smesh_core::Network::new();
        network.add_node(smesh_core::Node::named("budget-failure-runtime"));
        let runtime = Arc::new(SmeshRuntime::with_network(
            network,
            smesh_runtime::RuntimeConfig::default(),
        ));
        let (dispatcher, worker) =
            RuntimeWorker::spawn(runtime, "budget-failure-runtime", MustNotRun, 1)
                .await
                .unwrap();
        let scope = crate::DurableRuntimeScope::new(
            "tenant-budget",
            "account-budget",
            "principal-budget",
            "trusted-local",
            crate::VisibilityScope::Own,
        )
        .unwrap();
        let correlation =
            crate::DurableDispatchCorrelation::new(scope.clone(), "dispatch-budget-failure", 1, 1)
                .unwrap();
        let request = MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "task-budget-failure".to_owned(),
            context_id: "context-budget-failure".to_owned(),
            text: "fail budget".to_owned(),
        };
        let envelope = production_envelope_with_budget(
            scope,
            correlation,
            request,
            ExecutionBudget::new(1, 1).unwrap(),
        );
        let crate::RuntimeAdapterPreparation::Ready(permit) = dispatcher.prepare().await else {
            panic!("capacity unavailable");
        };
        let crate::RuntimeAdapterAdmission::Admitted(execution) =
            permit.admit(envelope, CancellationToken::new()).await
        else {
            panic!("not admitted");
        };

        assert_eq!(
            execution.finish().await,
            crate::RuntimeAdapterOutcome::ExecutionFailed(crate::RuntimeExecutionFailure::Budget)
        );
        worker.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn post_ingress_event_budget_failure_is_known_and_payload_free() {
        struct CompletionExceedsBudget;

        #[async_trait]
        impl RuntimeTaskProcessor for CompletionExceedsBudget {
            async fn process(
                &self,
                _task: RuntimeTask,
                _cancellation: CancellationToken,
                events: RuntimeEventSink,
            ) -> Result<(), DispatchError> {
                events
                    .propose_completion("must exceed one-event budget")
                    .await
            }
        }

        let mut network = smesh_core::Network::new();
        network.add_node(smesh_core::Node::named("post-ingress-budget-runtime"));
        let runtime = Arc::new(SmeshRuntime::with_network(
            network,
            smesh_runtime::RuntimeConfig::default(),
        ));
        let (dispatcher, worker) = RuntimeWorker::spawn(
            runtime,
            "post-ingress-budget-runtime",
            CompletionExceedsBudget,
            1,
        )
        .await
        .unwrap();
        let scope = crate::DurableRuntimeScope::new(
            "tenant-post-ingress-budget",
            "account-post-ingress-budget",
            "principal-post-ingress-budget",
            "trusted-local",
            crate::VisibilityScope::Own,
        )
        .unwrap();
        let correlation = crate::DurableDispatchCorrelation::new(
            scope.clone(),
            "dispatch-post-ingress-budget",
            1,
            1,
        )
        .unwrap();
        let request = MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "task-post-ingress-budget".to_owned(),
            context_id: "context-post-ingress-budget".to_owned(),
            text: "exhaust budget after ingress".to_owned(),
        };
        let envelope = production_envelope_with_budget(
            scope,
            correlation,
            request,
            ExecutionBudget::new(4096, 1).unwrap(),
        );
        let crate::RuntimeAdapterPreparation::Ready(permit) = dispatcher.prepare().await else {
            panic!("capacity unavailable");
        };
        let crate::RuntimeAdapterAdmission::Admitted(execution) =
            permit.admit(envelope, CancellationToken::new()).await
        else {
            panic!("not admitted");
        };

        assert_eq!(
            execution.finish().await,
            crate::RuntimeAdapterOutcome::ExecutionFailed(crate::RuntimeExecutionFailure::Budget)
        );
        worker.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn local_ingress_failure_is_known_and_payload_free() {
        struct MustNotRun;

        #[async_trait]
        impl RuntimeTaskProcessor for MustNotRun {
            async fn process(
                &self,
                _task: RuntimeTask,
                _cancellation: CancellationToken,
                _events: RuntimeEventSink,
            ) -> Result<(), DispatchError> {
                panic!("processor reached after ingress rejection")
            }
        }

        let mut network = smesh_core::Network::new();
        network.add_node(smesh_core::Node::named("ingress-failure-runtime"));
        let runtime = Arc::new(SmeshRuntime::with_network(
            network,
            smesh_runtime::RuntimeConfig::default(),
        ));
        let (dispatcher, worker) = RuntimeWorker::spawn(
            Arc::clone(&runtime),
            "ingress-failure-runtime",
            MustNotRun,
            1,
        )
        .await
        .unwrap();
        runtime
            .network()
            .write()
            .await
            .nodes
            .remove("ingress-failure-runtime");
        let scope = crate::DurableRuntimeScope::new(
            "tenant-ingress",
            "account-ingress",
            "principal-ingress",
            "trusted-local",
            crate::VisibilityScope::Own,
        )
        .unwrap();
        let correlation =
            crate::DurableDispatchCorrelation::new(scope.clone(), "dispatch-ingress-failure", 1, 1)
                .unwrap();
        let request = MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "task-ingress-failure".to_owned(),
            context_id: "context-ingress-failure".to_owned(),
            text: "fail ingress".to_owned(),
        };
        let envelope = production_envelope(scope, correlation, request);
        let crate::RuntimeAdapterPreparation::Ready(permit) = dispatcher.prepare().await else {
            panic!("capacity unavailable");
        };
        let crate::RuntimeAdapterAdmission::Admitted(execution) =
            permit.admit(envelope, CancellationToken::new()).await
        else {
            panic!("not admitted");
        };

        assert_eq!(
            execution.finish().await,
            crate::RuntimeAdapterOutcome::ExecutionFailed(crate::RuntimeExecutionFailure::Ingress)
        );
        worker.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn known_processor_failure_is_payload_free_and_not_unknown() {
        struct Fails;

        #[async_trait]
        impl RuntimeTaskProcessor for Fails {
            async fn process(
                &self,
                _task: RuntimeTask,
                _cancellation: CancellationToken,
                _events: RuntimeEventSink,
            ) -> Result<(), DispatchError> {
                Err(DispatchError::message("secret processor detail"))
            }
        }

        let mut network = smesh_core::Network::new();
        network.add_node(smesh_core::Node::named("known-failure-runtime"));
        let runtime = Arc::new(SmeshRuntime::with_network(
            network,
            smesh_runtime::RuntimeConfig::default(),
        ));
        let (dispatcher, worker) = RuntimeWorker::spawn(runtime, "known-failure-runtime", Fails, 1)
            .await
            .unwrap();
        let scope = crate::DurableRuntimeScope::new(
            "tenant-failure",
            "account-failure",
            "principal-failure",
            "trusted-local",
            crate::VisibilityScope::Own,
        )
        .unwrap();
        let correlation =
            crate::DurableDispatchCorrelation::new(scope.clone(), "dispatch-known-failure", 1, 1)
                .unwrap();
        let request = MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "task-known-failure".to_owned(),
            context_id: "context-known-failure".to_owned(),
            text: "fail".to_owned(),
        };
        let envelope = production_envelope(scope, correlation, request);
        let crate::RuntimeAdapterPreparation::Ready(permit) = dispatcher.prepare().await else {
            panic!("capacity unavailable");
        };
        let crate::RuntimeAdapterAdmission::Admitted(execution) =
            permit.admit(envelope, CancellationToken::new()).await
        else {
            panic!("not admitted");
        };

        assert_eq!(
            execution.finish().await,
            crate::RuntimeAdapterOutcome::ExecutionFailed(
                crate::RuntimeExecutionFailure::Processor
            )
        );
        worker.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn processor_return_without_terminal_sequence_remains_unknown() {
        struct ReturnsWithoutTerminal;

        #[async_trait]
        impl RuntimeTaskProcessor for ReturnsWithoutTerminal {
            async fn process(
                &self,
                _task: RuntimeTask,
                _cancellation: CancellationToken,
                _events: RuntimeEventSink,
            ) -> Result<(), DispatchError> {
                Ok(())
            }
        }

        let mut network = smesh_core::Network::new();
        network.add_node(smesh_core::Node::named("incomplete-runtime"));
        let runtime = Arc::new(SmeshRuntime::with_network(
            network,
            smesh_runtime::RuntimeConfig::default(),
        ));
        let (dispatcher, worker) =
            RuntimeWorker::spawn(runtime, "incomplete-runtime", ReturnsWithoutTerminal, 1)
                .await
                .unwrap();
        let scope = crate::DurableRuntimeScope::new(
            "tenant-incomplete",
            "account-incomplete",
            "principal-incomplete",
            "trusted-local",
            crate::VisibilityScope::Own,
        )
        .unwrap();
        let correlation =
            crate::DurableDispatchCorrelation::new(scope.clone(), "dispatch-incomplete", 1, 1)
                .unwrap();
        let request = MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "task-incomplete".to_owned(),
            context_id: "context-incomplete".to_owned(),
            text: "incomplete".to_owned(),
        };
        let envelope = production_envelope(scope, correlation, request);
        let crate::RuntimeAdapterPreparation::Ready(permit) = dispatcher.prepare().await else {
            panic!("capacity unavailable");
        };
        let crate::RuntimeAdapterAdmission::Admitted(execution) =
            permit.admit(envelope, CancellationToken::new()).await
        else {
            panic!("not admitted");
        };

        assert_eq!(
            execution.finish().await,
            crate::RuntimeAdapterOutcome::AdmittedUnknown
        );
        worker.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn active_legacy_work_exhausts_shared_durable_prepare_capacity() {
        struct GatedLegacy {
            started: std::sync::Mutex<Option<oneshot::Sender<()>>>,
            release: Arc<tokio::sync::Notify>,
        }

        #[async_trait]
        impl RuntimeTaskProcessor for GatedLegacy {
            async fn process(
                &self,
                _task: RuntimeTask,
                _cancellation: CancellationToken,
                events: RuntimeEventSink,
            ) -> Result<(), DispatchError> {
                if let Some(started) = self.started.lock().unwrap().take() {
                    let _ = started.send(());
                }
                self.release.notified().await;
                events.propose_completion("legacy completed").await
            }
        }

        let mut network = smesh_core::Network::new();
        network.add_node(smesh_core::Node::named("shared-capacity-runtime"));
        let runtime = Arc::new(SmeshRuntime::with_network(
            network,
            smesh_runtime::RuntimeConfig::default(),
        ));
        let (started_tx, started_rx) = oneshot::channel();
        let release = Arc::new(tokio::sync::Notify::new());
        let (dispatcher, worker) = RuntimeWorker::spawn_with_config(
            runtime,
            "shared-capacity-runtime",
            GatedLegacy {
                started: std::sync::Mutex::new(Some(started_tx)),
                release: Arc::clone(&release),
            },
            RuntimeWorkerConfig {
                command_capacity: 2,
                max_active_tasks: 1,
                cancel_grace: Duration::from_millis(100),
            },
        )
        .await
        .unwrap();
        let request = MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "legacy-active".to_owned(),
            context_id: "context-capacity".to_owned(),
            text: "hold legacy capacity".to_owned(),
        };
        let _legacy_events = crate::MeshDispatcher::dispatch_bounded(
            &dispatcher,
            request,
            ExecutionBudget::new(4096, 8).unwrap(),
        );
        tokio::time::timeout(Duration::from_secs(1), started_rx)
            .await
            .expect("legacy processor did not start")
            .unwrap();

        assert!(matches!(
            dispatcher.prepare().await,
            crate::RuntimeAdapterPreparation::Retryable(
                crate::RuntimePreAdmissionFailure::Capacity
            )
        ));

        release.notify_one();
        worker.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn genuine_worker_admits_durable_envelope_and_returns_terminal_proposal() {
        struct CaptureProcessor(
            std::sync::Mutex<Option<oneshot::Sender<crate::DurableWorkEnvelope>>>,
        );

        #[async_trait]
        impl RuntimeTaskProcessor for CaptureProcessor {
            async fn process(
                &self,
                task: RuntimeTask,
                _cancellation: CancellationToken,
                events: RuntimeEventSink,
            ) -> Result<(), DispatchError> {
                self.0
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap()
                    .send(task.durable_envelope().unwrap().clone())
                    .unwrap();
                events
                    .propose_completion("runtime proposed completion")
                    .await
            }
        }

        let mut network = smesh_core::Network::new();
        network.add_node(smesh_core::Node::named("durable-runtime"));
        let runtime = Arc::new(SmeshRuntime::with_network(
            network,
            smesh_runtime::RuntimeConfig::default(),
        ));
        let (captured_tx, captured_rx) = oneshot::channel();
        let (dispatcher, worker) = RuntimeWorker::spawn(
            runtime,
            "durable-runtime",
            CaptureProcessor(std::sync::Mutex::new(Some(captured_tx))),
            2,
        )
        .await
        .unwrap();
        let scope = crate::DurableRuntimeScope::new(
            "tenant-a",
            "account-a",
            "principal-a",
            "trusted-local",
            crate::VisibilityScope::Own,
        )
        .unwrap();
        let correlation =
            crate::DurableDispatchCorrelation::new(scope.clone(), "dispatch-a", 3, 9).unwrap();
        let request = MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "same-client-task".to_owned(),
            context_id: "context-a".to_owned(),
            text: "durable runtime work".to_owned(),
        };
        let envelope = production_envelope(scope, correlation, request);
        let crate::RuntimeAdapterPreparation::Ready(permit) = dispatcher.prepare().await else {
            panic!("runtime capacity unavailable");
        };
        let crate::RuntimeAdapterAdmission::Admitted(execution) = permit
            .admit(envelope.clone(), CancellationToken::new())
            .await
        else {
            panic!("durable runtime was not admitted");
        };

        assert_eq!(captured_rx.await.unwrap(), envelope);
        let crate::RuntimeAdapterOutcome::Terminal(result) = execution.finish().await else {
            panic!("runtime result became unknown");
        };
        assert!(matches!(
            result.events.last(),
            Some(MeshEvent::Completed { summary }) if summary == "runtime proposed completion"
        ));
        worker.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn durable_cancellation_uses_full_correlation_not_shared_task_id() {
        struct CorrelatedProcessor {
            second_release: Arc<tokio::sync::Notify>,
        }

        #[async_trait]
        impl RuntimeTaskProcessor for CorrelatedProcessor {
            async fn process(
                &self,
                task: RuntimeTask,
                cancellation: CancellationToken,
                events: RuntimeEventSink,
            ) -> Result<(), DispatchError> {
                if task.durable_envelope().unwrap().correlation().dispatch_id() == "dispatch-cancel"
                {
                    cancellation.cancelled().await;
                    return Ok(());
                }
                self.second_release.notified().await;
                events.propose_completion("second completed").await
            }
        }

        fn envelope(dispatch: &str, fence: u64) -> crate::DurableWorkEnvelope {
            let scope = crate::DurableRuntimeScope::new(
                "tenant-a",
                "account-a",
                "principal-a",
                "trusted-local",
                crate::VisibilityScope::Own,
            )
            .unwrap();
            let correlation =
                crate::DurableDispatchCorrelation::new(scope.clone(), dispatch, 1, fence).unwrap();
            let request = MeshRequest {
                protocol: "a2a-v1".to_owned(),
                task_id: "shared-task-id".to_owned(),
                context_id: "context-a".to_owned(),
                text: "work".to_owned(),
            };
            production_envelope(scope, correlation, request)
        }

        let mut network = smesh_core::Network::new();
        network.add_node(smesh_core::Node::named("correlated-runtime"));
        let runtime = Arc::new(SmeshRuntime::with_network(
            network,
            smesh_runtime::RuntimeConfig::default(),
        ));
        let release = Arc::new(tokio::sync::Notify::new());
        let (dispatcher, worker) = RuntimeWorker::spawn(
            runtime,
            "correlated-runtime",
            CorrelatedProcessor {
                second_release: Arc::clone(&release),
            },
            4,
        )
        .await
        .unwrap();
        let first = envelope("dispatch-cancel", 5);
        let second = envelope("dispatch-survive", 6);
        let crate::RuntimeAdapterPreparation::Ready(first_permit) = dispatcher.prepare().await
        else {
            panic!("first capacity unavailable");
        };
        let crate::RuntimeAdapterPreparation::Ready(second_permit) = dispatcher.prepare().await
        else {
            panic!("second capacity unavailable");
        };
        let crate::RuntimeAdapterAdmission::Admitted(first_execution) = first_permit
            .admit(first.clone(), CancellationToken::new())
            .await
        else {
            panic!("first not admitted");
        };
        let crate::RuntimeAdapterAdmission::Admitted(second_execution) = second_permit
            .admit(second.clone(), CancellationToken::new())
            .await
        else {
            panic!("second not admitted");
        };

        assert_eq!(
            dispatcher.cancel_durable(first.correlation()).await,
            crate::RuntimeCancellationRequest::Requested
        );
        assert_eq!(
            first_execution.finish().await,
            crate::RuntimeAdapterOutcome::ConfirmedStopped
        );
        release.notify_one();
        assert!(matches!(
            second_execution.finish().await,
            crate::RuntimeAdapterOutcome::Terminal(_)
        ));
        worker.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    #[allow(clippy::too_many_lines)] // Keep the gated completion and immediate command ordering in one regression.
    async fn completed_durable_correlation_is_immediately_reusable() {
        struct GatedCompletion {
            calls: std::sync::atomic::AtomicUsize,
            first_started: std::sync::Mutex<Option<oneshot::Sender<()>>>,
            first_destroyed: std::sync::Mutex<Option<oneshot::Sender<()>>>,
            first_release: Arc<tokio::sync::Notify>,
        }
        struct CompletionFutureDestroyed(Option<oneshot::Sender<()>>);
        impl Drop for CompletionFutureDestroyed {
            fn drop(&mut self) {
                if let Some(destroyed) = self.0.take() {
                    let _ = destroyed.send(());
                }
            }
        }

        #[async_trait]
        impl RuntimeTaskProcessor for GatedCompletion {
            async fn process(
                &self,
                _task: RuntimeTask,
                _cancellation: CancellationToken,
                events: RuntimeEventSink,
            ) -> Result<(), DispatchError> {
                let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if call == 0 {
                    let _destroyed =
                        CompletionFutureDestroyed(self.first_destroyed.lock().unwrap().take());
                    self.first_started
                        .lock()
                        .unwrap()
                        .take()
                        .unwrap()
                        .send(())
                        .unwrap();
                    self.first_release.notified().await;
                }
                events
                    .propose_completion(format!("completed generation {}", call + 1))
                    .await
            }
        }

        let mut network = smesh_core::Network::new();
        network.add_node(smesh_core::Node::named("reusable-runtime"));
        let runtime = Arc::new(SmeshRuntime::with_network(
            network,
            smesh_runtime::RuntimeConfig::default(),
        ));
        let (started_tx, started_rx) = oneshot::channel();
        let (destroyed_tx, destroyed_rx) = oneshot::channel();
        let first_release = Arc::new(tokio::sync::Notify::new());
        let (dispatcher, worker) = RuntimeWorker::spawn_with_config(
            runtime,
            "reusable-runtime",
            GatedCompletion {
                calls: std::sync::atomic::AtomicUsize::new(0),
                first_started: std::sync::Mutex::new(Some(started_tx)),
                first_destroyed: std::sync::Mutex::new(Some(destroyed_tx)),
                first_release: Arc::clone(&first_release),
            },
            RuntimeWorkerConfig {
                command_capacity: 2,
                max_active_tasks: 2,
                cancel_grace: Duration::from_millis(100),
            },
        )
        .await
        .unwrap();
        let scope = crate::DurableRuntimeScope::new(
            "tenant-reusable",
            "account-reusable",
            "principal-reusable",
            "trusted-local",
            crate::VisibilityScope::Own,
        )
        .unwrap();
        let correlation =
            crate::DurableDispatchCorrelation::new(scope.clone(), "dispatch-reusable", 1, 4)
                .unwrap();
        let request = MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "task-reusable".to_owned(),
            context_id: "context-reusable".to_owned(),
            text: "reuse exact durable correlation".to_owned(),
        };
        let envelope = production_envelope(scope, correlation, request);
        let crate::RuntimeAdapterPreparation::Ready(first_permit) = dispatcher.prepare().await
        else {
            panic!("first capacity unavailable");
        };
        let crate::RuntimeAdapterAdmission::Admitted(first_execution) = first_permit
            .admit(envelope.clone(), CancellationToken::new())
            .await
        else {
            panic!("first execution not admitted");
        };
        started_rx.await.unwrap();
        let crate::RuntimeAdapterPreparation::Ready(replacement_permit) =
            dispatcher.prepare().await
        else {
            panic!("replacement capacity unavailable");
        };
        first_release.notify_one();
        assert!(matches!(
            first_execution.finish().await,
            crate::RuntimeAdapterOutcome::Terminal(_)
        ));
        destroyed_rx.await.unwrap();

        let crate::RuntimeAdapterAdmission::Admitted(replacement) = replacement_permit
            .admit(envelope, CancellationToken::new())
            .await
        else {
            panic!("completed exact durable correlation was not immediately reusable");
        };
        assert!(matches!(
            replacement.finish().await,
            crate::RuntimeAdapterOutcome::Terminal(_)
        ));
        worker.shutdown().await.unwrap();
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // Keep the hostile processor and capacity/reap ordering proof in one test.
    async fn durable_cancel_forces_and_reaps_a_processor_that_ignores_cancellation() {
        struct IgnoresCancellation {
            started: Arc<tokio::sync::Notify>,
            canceling: Arc<tokio::sync::Notify>,
            reaped: Arc<tokio::sync::Notify>,
        }
        struct DropSignal(Arc<tokio::sync::Notify>);
        impl Drop for DropSignal {
            fn drop(&mut self) {
                self.0.notify_one();
            }
        }

        #[async_trait]
        impl RuntimeTaskProcessor for IgnoresCancellation {
            async fn process(
                &self,
                _task: RuntimeTask,
                cancellation: CancellationToken,
                _events: RuntimeEventSink,
            ) -> Result<(), DispatchError> {
                let _drop = DropSignal(Arc::clone(&self.reaped));
                self.started.notify_one();
                cancellation.cancelled().await;
                self.canceling.notify_one();
                std::future::pending().await
            }
        }

        let mut network = smesh_core::Network::new();
        network.add_node(smesh_core::Node::named("forced-runtime"));
        let runtime = Arc::new(SmeshRuntime::with_network(
            network,
            smesh_runtime::RuntimeConfig::default(),
        ));
        let started = Arc::new(tokio::sync::Notify::new());
        let canceling = Arc::new(tokio::sync::Notify::new());
        let reaped = Arc::new(tokio::sync::Notify::new());
        let (dispatcher, worker) = RuntimeWorker::spawn_with_config(
            runtime,
            "forced-runtime",
            IgnoresCancellation {
                started: Arc::clone(&started),
                canceling: Arc::clone(&canceling),
                reaped: Arc::clone(&reaped),
            },
            RuntimeWorkerConfig {
                command_capacity: 2,
                max_active_tasks: 2,
                cancel_grace: Duration::from_millis(500),
            },
        )
        .await
        .unwrap();
        let scope = crate::DurableRuntimeScope::new(
            "tenant-force",
            "account-force",
            "principal-force",
            "trusted-local",
            crate::VisibilityScope::Own,
        )
        .unwrap();
        let correlation =
            crate::DurableDispatchCorrelation::new(scope.clone(), "dispatch-force", 1, 4).unwrap();
        let request = MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "task-force".to_owned(),
            context_id: "context-force".to_owned(),
            text: "force".to_owned(),
        };
        let envelope = production_envelope(scope, correlation, request);
        let crate::RuntimeAdapterPreparation::Ready(permit) = dispatcher.prepare().await else {
            panic!("capacity unavailable");
        };
        let crate::RuntimeAdapterAdmission::Admitted(execution) = permit
            .admit(envelope.clone(), CancellationToken::new())
            .await
        else {
            panic!("not admitted");
        };
        tokio::time::timeout(Duration::from_secs(1), started.notified())
            .await
            .unwrap();
        let crate::RuntimeAdapterPreparation::Ready(duplicate_permit) = dispatcher.prepare().await
        else {
            panic!("second capacity unavailable");
        };
        assert!(matches!(
            dispatcher.prepare().await,
            crate::RuntimeAdapterPreparation::Retryable(
                crate::RuntimePreAdmissionFailure::Capacity
            )
        ));
        let cancel_dispatcher = dispatcher.clone();
        let correlation = envelope.correlation().clone();
        let cancel =
            tokio::spawn(async move { cancel_dispatcher.cancel_durable(&correlation).await });
        tokio::time::timeout(Duration::from_secs(1), canceling.notified())
            .await
            .unwrap();
        assert!(
            matches!(
                duplicate_permit
                    .admit(envelope.clone(), CancellationToken::new())
                    .await,
                crate::RuntimeAdapterAdmission::Retryable(
                    crate::RuntimePreAdmissionFailure::DuplicateCorrelation
                )
            ),
            "duplicate entered while original cancellation was still reaping"
        );
        let crate::RuntimeAdapterPreparation::Ready(duplicate_permit) = dispatcher.prepare().await
        else {
            panic!("competing capacity unavailable");
        };
        assert_eq!(
            cancel.await.unwrap(),
            crate::RuntimeCancellationRequest::Requested
        );
        tokio::time::timeout(Duration::from_secs(1), reaped.notified())
            .await
            .expect("cancellation ack preceded processor destruction");
        // Keep the competing reservation: only the original task can free capacity.
        assert!(matches!(
            dispatcher.prepare().await,
            crate::RuntimeAdapterPreparation::Ready(_)
        ));
        let crate::RuntimeAdapterAdmission::Admitted(replacement) = duplicate_permit
            .admit(envelope, CancellationToken::new())
            .await
        else {
            panic!("same correlation was not reusable after actual reap");
        };
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(500), execution.finish())
                .await
                .expect("forced cancellation left admitted outcome unresolved"),
            crate::RuntimeAdapterOutcome::AdmittedUnknown
        );
        worker.shutdown().await.unwrap();
        let _ = replacement.finish().await;
    }

    #[tokio::test]
    async fn durable_cancellation_cannot_be_starved_by_a_prepared_data_slot() {
        struct IgnoresCancellation;

        #[async_trait]
        impl RuntimeTaskProcessor for IgnoresCancellation {
            async fn process(
                &self,
                _task: RuntimeTask,
                _cancellation: CancellationToken,
                _events: RuntimeEventSink,
            ) -> Result<(), DispatchError> {
                std::future::pending().await
            }
        }

        let mut network = smesh_core::Network::new();
        network.add_node(smesh_core::Node::named("forced-runtime"));
        let runtime = Arc::new(SmeshRuntime::with_network(
            network,
            smesh_runtime::RuntimeConfig::default(),
        ));
        let (dispatcher, worker) = RuntimeWorker::spawn_with_config(
            runtime,
            "forced-runtime",
            IgnoresCancellation,
            RuntimeWorkerConfig {
                command_capacity: 1,
                max_active_tasks: 2,
                cancel_grace: Duration::from_millis(100),
            },
        )
        .await
        .unwrap();
        let scope = crate::DurableRuntimeScope::new(
            "tenant-force",
            "account-force",
            "principal-force",
            "trusted-local",
            crate::VisibilityScope::Own,
        )
        .unwrap();
        let correlation =
            crate::DurableDispatchCorrelation::new(scope.clone(), "dispatch-force", 1, 4).unwrap();
        let request = MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "task-force".to_owned(),
            context_id: "context-force".to_owned(),
            text: "force".to_owned(),
        };
        let envelope = production_envelope(scope, correlation, request);
        let crate::RuntimeAdapterPreparation::Ready(permit) = dispatcher.prepare().await else {
            panic!("capacity unavailable");
        };
        let crate::RuntimeAdapterAdmission::Admitted(execution) = permit
            .admit(envelope.clone(), CancellationToken::new())
            .await
        else {
            panic!("not admitted");
        };
        let crate::RuntimeAdapterPreparation::Ready(duplicate_permit) = dispatcher.prepare().await
        else {
            panic!("second capacity unavailable");
        };
        assert!(matches!(
            dispatcher.prepare().await,
            crate::RuntimeAdapterPreparation::Retryable(
                crate::RuntimePreAdmissionFailure::Capacity
            )
        ));
        assert_eq!(
            dispatcher.cancel_durable(envelope.correlation()).await,
            crate::RuntimeCancellationRequest::Requested
        );
        drop(duplicate_permit);
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(500), execution.finish())
                .await
                .expect("forced cancellation left admitted outcome unresolved"),
            crate::RuntimeAdapterOutcome::AdmittedUnknown
        );
        worker.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn durable_token_cancellation_reaps_without_a_control_command() {
        durable_token_cancellation_outcome(false, false).await;
    }

    #[tokio::test]
    async fn durable_processor_error_during_cancellation_is_not_confirmed_stop() {
        durable_token_cancellation_outcome(true, false).await;
    }

    #[tokio::test]
    async fn token_forced_destruction_discards_incomplete_terminal_proposal() {
        durable_token_cancellation_outcome(false, true).await;
    }

    #[allow(clippy::too_many_lines)] // Keep admission, retained capacity, destruction, and outcome proof together.
    async fn durable_token_cancellation_outcome(fail_on_cancel: bool, propose_terminal: bool) {
        struct IgnoresCancellation(
            Arc<tokio::sync::Notify>,
            Arc<tokio::sync::Notify>,
            bool,
            bool,
        );

        #[async_trait]
        impl RuntimeTaskProcessor for IgnoresCancellation {
            async fn process(
                &self,
                _task: RuntimeTask,
                _cancellation: CancellationToken,
                _events: RuntimeEventSink,
            ) -> Result<(), DispatchError> {
                struct Destroyed(Arc<tokio::sync::Notify>);
                impl Drop for Destroyed {
                    fn drop(&mut self) {
                        self.0.notify_one();
                    }
                }
                let _destroyed = Destroyed(Arc::clone(&self.1));
                if self.3 {
                    _events
                        .propose_completion("terminal before token cancellation")
                        .await?;
                }
                self.0.notify_one();
                if self.2 {
                    _cancellation.cancelled().await;
                    return Err(DispatchError::message("processor failed while canceling"));
                }
                std::future::pending().await
            }
        }

        let mut network = smesh_core::Network::new();
        network.add_node(smesh_core::Node::named("forced-runtime"));
        let runtime = Arc::new(SmeshRuntime::with_network(
            network,
            smesh_runtime::RuntimeConfig::default(),
        ));
        let started = Arc::new(tokio::sync::Notify::new());
        let destroyed = Arc::new(tokio::sync::Notify::new());
        let cancellation = CancellationToken::new();
        let (dispatcher, worker) = RuntimeWorker::spawn_with_config(
            runtime,
            "forced-runtime",
            IgnoresCancellation(
                Arc::clone(&started),
                Arc::clone(&destroyed),
                fail_on_cancel,
                propose_terminal,
            ),
            RuntimeWorkerConfig {
                command_capacity: 2,
                max_active_tasks: 2,
                cancel_grace: Duration::from_millis(100),
            },
        )
        .await
        .unwrap();
        let scope = crate::DurableRuntimeScope::new(
            "tenant-force",
            "account-force",
            "principal-force",
            "trusted-local",
            crate::VisibilityScope::Own,
        )
        .unwrap();
        let correlation =
            crate::DurableDispatchCorrelation::new(scope.clone(), "dispatch-force", 1, 4).unwrap();
        let request = MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "task-force".to_owned(),
            context_id: "context-force".to_owned(),
            text: "force".to_owned(),
        };
        let envelope = production_envelope(scope, correlation, request);
        let crate::RuntimeAdapterPreparation::Ready(permit) = dispatcher.prepare().await else {
            panic!("capacity unavailable");
        };
        let crate::RuntimeAdapterAdmission::Admitted(execution) =
            permit.admit(envelope.clone(), cancellation.clone()).await
        else {
            panic!("not admitted");
        };
        let crate::RuntimeAdapterPreparation::Ready(duplicate_permit) = dispatcher.prepare().await
        else {
            panic!("second capacity unavailable");
        };
        assert!(matches!(
            dispatcher.prepare().await,
            crate::RuntimeAdapterPreparation::Retryable(
                crate::RuntimePreAdmissionFailure::Capacity
            )
        ));
        tokio::time::timeout(Duration::from_secs(1), started.notified())
            .await
            .unwrap();
        cancellation.cancel();
        let outcome = tokio::time::timeout(Duration::from_secs(2), execution.finish())
            .await
            .expect("token cancellation left an uncooperative processor alive");
        assert_eq!(outcome, crate::RuntimeAdapterOutcome::AdmittedUnknown);
        tokio::time::timeout(Duration::from_secs(1), destroyed.notified())
            .await
            .unwrap();
        // Keep the competing reservation held: recovered capacity must belong
        // to the destroyed execution, not to that reservation.
        assert!(matches!(
            dispatcher.prepare().await,
            crate::RuntimeAdapterPreparation::Ready(_)
        ));
        drop(duplicate_permit);
        worker.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn dropping_worker_handle_aborts_and_reaps_its_join() {
        let (started_tx, started_rx) = oneshot::channel();
        let (reaped_tx, reaped_rx) = oneshot::channel();
        let join = tokio::spawn(async move {
            let _reaped = Reaped(Some(reaped_tx));
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        started_rx.await.unwrap();
        let handle = RuntimeWorkerHandle {
            shutdown: CancellationToken::new(),
            join: Some(join),
        };

        drop(handle);

        tokio::time::timeout(Duration::from_secs(1), reaped_rx)
            .await
            .expect("dropped worker handle detached its join")
            .unwrap();
    }

    #[tokio::test]
    async fn canceling_worker_shutdown_aborts_and_reaps_its_taken_join() {
        let shutdown = CancellationToken::new();
        let observed_shutdown = shutdown.clone();
        let (started_tx, started_rx) = oneshot::channel();
        let (reaped_tx, reaped_rx) = oneshot::channel();
        let join = tokio::spawn(async move {
            let _reaped = Reaped(Some(reaped_tx));
            observed_shutdown.cancelled().await;
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        let handle = RuntimeWorkerHandle {
            shutdown,
            join: Some(join),
        };
        let shutdown_task = tokio::spawn(handle.shutdown());
        started_rx.await.unwrap();

        shutdown_task.abort();
        let _ = shutdown_task.await;

        tokio::time::timeout(Duration::from_secs(1), reaped_rx)
            .await
            .expect("canceled worker shutdown detached its taken join")
            .unwrap();
    }

    #[tokio::test]
    async fn canceling_worker_shutdown_aborts_an_active_owned_processor() {
        let shutdown = CancellationToken::new();
        let observed_shutdown = shutdown.clone();
        let (root_started_tx, root_started_rx) = oneshot::channel();
        let (processor_reaped_tx, processor_reaped_rx) = oneshot::channel();
        let processor = tokio::spawn(async move {
            let _reaped = Reaped(Some(processor_reaped_tx));
            std::future::pending::<()>().await;
        });
        let join = tokio::spawn(async move {
            let _active_processor = AbortOnDropJoin::new(processor);
            observed_shutdown.cancelled().await;
            let _ = root_started_tx.send(());
            std::future::pending::<()>().await;
        });
        let handle = RuntimeWorkerHandle {
            shutdown,
            join: Some(join),
        };
        let shutdown_task = tokio::spawn(handle.shutdown());
        root_started_rx.await.unwrap();

        shutdown_task.abort();
        let _ = shutdown_task.await;

        tokio::time::timeout(Duration::from_secs(1), processor_reaped_rx)
            .await
            .expect("canceled worker shutdown detached an active processor")
            .unwrap();
    }

    #[test]
    fn shutting_down_drop_reaper_runtime_aborts_the_worker_join() {
        let worker_runtime = tokio::runtime::Runtime::new().unwrap();
        let (started_tx, started_rx) = oneshot::channel();
        let (reaped_tx, reaped_rx) = oneshot::channel();
        let join = worker_runtime.spawn(async move {
            let _reaped = Reaped(Some(reaped_tx));
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        worker_runtime.block_on(started_rx).unwrap();
        let handle = RuntimeWorkerHandle {
            shutdown: CancellationToken::new(),
            join: Some(join),
        };
        let reaper_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        reaper_runtime.block_on(async move {
            drop(handle);
            tokio::task::yield_now().await;
        });
        drop(reaper_runtime);

        worker_runtime
            .block_on(async { tokio::time::timeout(Duration::from_secs(1), reaped_rx).await })
            .expect("reaper runtime shutdown detached the worker join")
            .unwrap();
    }
}
