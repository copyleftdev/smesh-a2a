use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use smesh_runtime::SmeshRuntime;
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

use crate::{
    ChannelDispatcher, DispatchCommand, DispatchError, ExecutionBudget, MeshEvent, MeshRequest,
};

const PROCESSOR_CANCEL_GRACE: Duration = Duration::from_secs(1);
const MAX_PROCESSOR_CANCEL_GRACE: Duration = Duration::from_secs(1);
const CANCELLATION_ACK_MARGIN: Duration = Duration::from_secs(1);

/// Inputs supplied to an internal runtime task processor after real SMESH ingress succeeds.
pub struct RuntimeTask {
    pub request: MeshRequest,
    pub signal_hash: String,
    pub runtime: Arc<SmeshRuntime>,
}

/// Cancellation-aware capability for emitting untrusted runtime events.
pub struct RuntimeEventSink {
    events: mpsc::Sender<Result<MeshEvent, DispatchError>>,
    cancellation: CancellationToken,
    budget: ExecutionBudget,
    usage: Arc<Mutex<(u64, u64)>>,
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
        let dispatcher = ChannelDispatcher::new(commands, node_id.clone())
            .with_timeout(config.cancel_grace + CANCELLATION_ACK_MARGIN);
        let shutdown = CancellationToken::new();
        let join = tokio::spawn(run_worker(
            runtime,
            node_id,
            Arc::new(processor),
            receiver,
            shutdown.clone(),
            config.max_active_tasks,
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

type ActiveTask = (CancellationToken, JoinHandle<Result<(), DispatchError>>);

async fn run_worker(
    runtime: Arc<SmeshRuntime>,
    node_id: String,
    processor: Arc<dyn RuntimeTaskProcessor>,
    mut commands: mpsc::Receiver<DispatchCommand>,
    shutdown: CancellationToken,
    max_active_tasks: usize,
    cancel_grace: Duration,
) {
    let mut active = HashMap::<String, ActiveTask>::new();
    let mut cancelling = HashSet::<String>::new();
    let mut reapers = JoinSet::<String>::new();
    loop {
        let finished = active
            .iter()
            .filter(|(_, (_, join))| join.is_finished())
            .map(|(task_id, _)| task_id.clone())
            .collect::<Vec<_>>();
        for task_id in finished {
            if let Some((_, join)) = active.remove(&task_id) {
                let _ = join.await;
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
            command = commands.recv() => {
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
                        if active.len() + cancelling.len() >= max_active_tasks {
                            let _ = events.try_send(Err(DispatchError::Message(
                                "runtime worker capacity reached".to_owned(),
                            )));
                            continue;
                        }
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
                        ));
                        active.insert(task_id, (cancellation, join));
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
    while shutdown_tasks.join_next().await.is_some() {}
    while reapers.join_next().await.is_some() {}
}

async fn stop_tracked_task(
    cancellation: CancellationToken,
    mut join: JoinHandle<Result<(), DispatchError>>,
    cancel_grace: Duration,
) {
    cancellation.cancel();
    if tokio::time::timeout(cancel_grace, &mut join).await.is_err() {
        join.abort();
        let _ = join.await;
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
    mut join: JoinHandle<Result<(), DispatchError>>,
    ack: oneshot::Sender<Result<(), DispatchError>>,
    cancel_grace: Duration,
) -> String {
    cancellation.cancel();
    let outcome = match tokio::time::timeout(cancel_grace, &mut join).await {
        Ok(Ok(Ok(()))) => CancellationReapOutcome::CooperativeStop,
        Ok(Ok(Err(error))) => CancellationReapOutcome::ProcessorFailed(error),
        Ok(Err(_)) => CancellationReapOutcome::ProcessorFailed(DispatchError::Message(
            "runtime processor task failed during cancellation".to_owned(),
        )),
        Err(_) => {
            join.abort();
            let _ = join.await;
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
) -> Result<(), DispatchError> {
    let ingress_progress = MeshEvent::Progress("SMESH runtime retained the query".to_owned());
    let ingress_progress_bytes = u64::try_from(
        serde_json::to_vec(&ingress_progress)
            .map_err(|_| DispatchError::message("runtime event serialization failed"))?
            .len(),
    )
    .map_err(|_| DispatchError::message("runtime event serialization overflow"))?;
    if budget.max_event_count() < 1 || budget.max_output_bytes() < ingress_progress_bytes {
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
    };
    let sink = RuntimeEventSink {
        events: events.clone(),
        cancellation: cancellation.clone(),
        budget,
        usage: Arc::new(Mutex::new((1, ingress_progress_bytes))),
    };
    match processor.process(task, cancellation.clone(), sink).await {
        Ok(()) => Ok(()),
        Err(error) if cancellation.is_cancelled() => Err(error),
        Err(error) => {
            let _ = send_dispatch_error(&events, &cancellation, error).await;
            Ok(())
        }
    }
}

#[cfg(test)]
mod ownership_tests {
    use super::*;

    struct Reaped(Option<oneshot::Sender<()>>);

    impl Drop for Reaped {
        fn drop(&mut self) {
            if let Some(reaped) = self.0.take() {
                let _ = reaped.send(());
            }
        }
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
