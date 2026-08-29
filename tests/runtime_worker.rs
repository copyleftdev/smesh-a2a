use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use a2a::{
    Message, Part, Role, SendMessageRequest, SendMessageResponse, StreamResponse,
    TRANSPORT_PROTOCOL_JSONRPC, TaskState,
};
use a2a_client::A2AClientFactory;
use a2a_client::agent_card::AgentCardResolver;
use a2a_server::{AgentExecutor, ExecutorContext};
use async_trait::async_trait;
use futures::StreamExt;
use smesh_a2a::{
    DispatchError, ExecutionBudget, GatewayConfig, InputLimits, MeshDispatcher, MeshEvent,
    MeshRequest, RuntimeAdmissionProcessor, RuntimeEventSink, RuntimeTask, RuntimeTaskProcessor,
    RuntimeWorker, RuntimeWorkerConfig, SmeshExecutor, build_router,
};
use smesh_core::{Network, Node, SignalType};
use smesh_runtime::{MeshConfig, RuntimeConfig, SmeshRuntime};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

fn runtime_named(name: &str) -> Arc<SmeshRuntime> {
    let mut network = Network::new();
    network.add_node(Node::named(name));
    Arc::new(SmeshRuntime::with_network(
        network,
        RuntimeConfig::default(),
    ))
}

fn runtime() -> Arc<SmeshRuntime> {
    runtime_named("runtime-node")
}

#[tokio::test]
async fn undersized_runtime_budget_is_observed_on_the_event_stream() {
    let runtime = runtime();
    let (dispatcher, worker) =
        RuntimeWorker::spawn(runtime, "runtime-node", RuntimeAdmissionProcessor, 1)
            .await
            .unwrap();
    let request = MeshRequest {
        protocol: "a2a-v1".to_owned(),
        task_id: "tiny-budget".to_owned(),
        context_id: "tiny-budget-context".to_owned(),
        text: "tiny".to_owned(),
    };
    let events = dispatcher
        .dispatch_bounded(request, ExecutionBudget::new(1, 1).unwrap())
        .collect::<Vec<_>>()
        .await;
    assert!(matches!(
        events.as_slice(),
        [Err(DispatchError::Message(message))]
            if message == "runtime reserved execution budget is too small"
    ));
    worker.shutdown().await.unwrap();
}

#[tokio::test]
async fn real_runtime_worker_emits_query_and_admission_proposal_without_evidence() {
    let runtime = runtime();
    let mesh = runtime
        .join_mesh(
            MeshConfig {
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                ..MeshConfig::default()
            },
            "runtime-node",
        )
        .await
        .unwrap();
    assert_ne!(mesh.listen_addr().port(), 0);
    let (dispatcher, worker) = RuntimeWorker::spawn(
        Arc::clone(&runtime),
        "runtime-node",
        RuntimeAdmissionProcessor,
        8,
    )
    .await
    .unwrap();
    let request = MeshRequest {
        protocol: "a2a-v1".to_owned(),
        task_id: "task-runtime".to_owned(),
        context_id: "context-runtime".to_owned(),
        text: "inspect the real runtime".to_owned(),
    };
    let expected_request = request.clone();

    let events = dispatcher
        .dispatch(request)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert!(matches!(events.first(), Some(MeshEvent::Progress(_))));
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, MeshEvent::Artifact { .. }))
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, MeshEvent::Evidence(_)))
            .count(),
        0
    );
    assert!(matches!(events.last(), Some(MeshEvent::Completed { .. })));

    let network = runtime.network();
    let network = network.read().await;
    let queries = network
        .field
        .signals
        .values()
        .filter(|signal| signal.signal_type == SignalType::Query)
        .collect::<Vec<_>>();
    assert_eq!(
        queries.len(),
        1,
        "the worker must use the genuine runtime emit path"
    );
    let query = queries[0];
    assert_eq!(query.origin_node_id, "runtime-node");
    assert!(!query.origin_hash.is_empty());
    assert_eq!(
        serde_json::from_slice::<MeshRequest>(&query.payload).unwrap(),
        expected_request
    );
    drop(network);

    worker.shutdown().await.unwrap();
    mesh.shutdown().await;
}

#[tokio::test]
async fn runtime_worker_query_crosses_a_real_quic_socket_to_a_peer() {
    let runtime_a = runtime_named("runtime-a");
    let runtime_b = runtime_named("runtime-b");
    let mesh_a = runtime_a
        .join_mesh(
            MeshConfig {
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                peer_discovery: false,
                ..MeshConfig::default()
            },
            "runtime-a",
        )
        .await
        .unwrap();
    let mesh_b = runtime_b
        .join_mesh(
            MeshConfig {
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                bootstrap: vec![mesh_a.listen_addr()],
                peer_discovery: false,
                ..MeshConfig::default()
            },
            "runtime-b",
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut changed = tokio::time::interval(Duration::from_millis(10));
        changed.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            changed.tick().await;
            if runtime_a.peers().connected_count().await == 1
                && runtime_b.peers().connected_count().await == 1
            {
                break;
            }
        }
    })
    .await
    .unwrap();
    let (dispatcher, worker) = RuntimeWorker::spawn(
        Arc::clone(&runtime_a),
        "runtime-a",
        RuntimeAdmissionProcessor,
        8,
    )
    .await
    .unwrap();
    let events = dispatcher
        .dispatch(MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "task-cross-wire".to_owned(),
            context_id: "context-cross-wire".to_owned(),
            text: "cross the real mesh".to_owned(),
        })
        .collect::<Vec<_>>()
        .await;
    assert!(events.iter().all(Result::is_ok));
    let signal_hash = {
        let network = runtime_a.network();
        let network = network.read().await;
        network
            .field
            .signals
            .values()
            .find(|signal| signal.signal_type == SignalType::Query)
            .unwrap()
            .origin_hash
            .clone()
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut changed = tokio::time::interval(Duration::from_millis(10));
        changed.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            changed.tick().await;
            let network = runtime_b.network();
            if network
                .read()
                .await
                .field
                .signals
                .contains_key(&signal_hash)
            {
                break;
            }
        }
    })
    .await
    .unwrap();

    worker.shutdown().await.unwrap();
    mesh_b.shutdown().await;
    mesh_a.shutdown().await;
}

#[tokio::test]
async fn runtime_admission_alone_cannot_complete_through_gateway_policy() {
    let (dispatcher, worker) =
        RuntimeWorker::spawn(runtime(), "runtime-node", RuntimeAdmissionProcessor, 8)
            .await
            .unwrap();
    let executor = SmeshExecutor::new(dispatcher, InputLimits::default(), "runtime-node");
    let events = executor
        .execute(ExecutorContext {
            message: Some(Message::new(
                Role::User,
                vec![Part::text("process through the real runtime")],
            )),
            task_id: "task-policy".to_owned(),
            stored_task: None,
            context_id: "context-policy".to_owned(),
            metadata: None,
            user: None,
            service_params: HashMap::new(),
            tenant: None,
        })
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert!(
        !events
            .iter()
            .any(|event| matches!(event, StreamResponse::ArtifactUpdate(_)))
    );
    assert!(matches!(
        events.last(),
        Some(StreamResponse::Task(task))
            if task.status.state == TaskState::Failed
                && task.artifacts.is_none()
    ));
    worker.shutdown().await.unwrap();
}

#[tokio::test]
async fn official_client_reaches_real_runtime_but_admission_alone_fails_closed() {
    let runtime = runtime();
    let mesh = runtime
        .join_mesh(
            MeshConfig {
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                ..MeshConfig::default()
            },
            "runtime-node",
        )
        .await
        .unwrap();
    let (dispatcher, worker) = RuntimeWorker::spawn(
        Arc::clone(&runtime),
        "runtime-node",
        RuntimeAdmissionProcessor,
        8,
    )
    .await
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let base_url = format!("http://{address}");
    let app = build_router(GatewayConfig::new(&base_url, "runtime-node"), dispatcher);
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let card = AgentCardResolver::new(None)
        .resolve(&base_url)
        .await
        .unwrap();
    let client = A2AClientFactory::builder()
        .preferred_bindings(vec![TRANSPORT_PROTOCOL_JSONRPC.to_owned()])
        .build()
        .create_from_card(&card)
        .await
        .unwrap();
    let response = client
        .send_message(&SendMessageRequest {
            message: Message::new(Role::User, vec![Part::text("official runtime request")]),
            configuration: None,
            metadata: None,
            tenant: None,
        })
        .await
        .unwrap();
    let SendMessageResponse::Task(task) = response else {
        panic!("expected a tracked runtime task");
    };
    assert_eq!(task.status.state, TaskState::Failed);
    assert!(task.artifacts.is_none());
    assert_eq!(runtime.peers().connected_count().await, 0);
    assert_ne!(mesh.listen_addr().port(), 0);

    server.abort();
    worker.shutdown().await.unwrap();
    mesh.shutdown().await;
}

#[tokio::test]
async fn runtime_worker_fails_closed_when_configured_node_is_absent() {
    let runtime = Arc::new(SmeshRuntime::with_network(
        Network::new(),
        RuntimeConfig::default(),
    ));
    let result = RuntimeWorker::spawn(runtime, "missing-node", RuntimeAdmissionProcessor, 8).await;
    let Err(DispatchError::Message(message)) = result else {
        panic!("missing runtime node must fail startup");
    };
    assert!(message.contains("absent or has an inconsistent identity"));
}

#[derive(Clone, Default)]
struct HoldingProcessor {
    started: Arc<Notify>,
    cancel_seen: Arc<Notify>,
    release_exit: Arc<Notify>,
    stopped: Arc<AtomicBool>,
}

#[async_trait]
impl RuntimeTaskProcessor for HoldingProcessor {
    async fn process(
        &self,
        _task: RuntimeTask,
        cancellation: CancellationToken,
        _events: RuntimeEventSink,
    ) -> Result<(), DispatchError> {
        self.started.notify_one();
        cancellation.cancelled().await;
        self.cancel_seen.notify_one();
        self.release_exit.notified().await;
        self.stopped.store(true, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
async fn cancellation_acknowledges_only_after_runtime_processing_stops() {
    let processor = HoldingProcessor::default();
    let started = Arc::clone(&processor.started);
    let cancel_seen = Arc::clone(&processor.cancel_seen);
    let release_exit = Arc::clone(&processor.release_exit);
    let stopped = Arc::clone(&processor.stopped);
    let (dispatcher, worker) = RuntimeWorker::spawn(runtime(), "runtime-node", processor, 8)
        .await
        .unwrap();
    let request = MeshRequest {
        protocol: "a2a-v1".to_owned(),
        task_id: "task-cancel".to_owned(),
        context_id: "context-cancel".to_owned(),
        text: "hold until canceled".to_owned(),
    };
    let mut events = dispatcher.dispatch(request);
    assert!(matches!(
        events.next().await,
        Some(Ok(MeshEvent::Progress(_)))
    ));
    tokio::time::timeout(Duration::from_secs(1), started.notified())
        .await
        .unwrap();

    let cancel = tokio::spawn({
        let dispatcher = dispatcher.clone();
        async move { dispatcher.cancel("task-cancel").await }
    });
    tokio::time::timeout(Duration::from_secs(1), cancel_seen.notified())
        .await
        .unwrap();
    assert!(!cancel.is_finished());
    release_exit.notify_one();
    cancel.await.unwrap().unwrap();

    assert!(stopped.load(Ordering::SeqCst));
    let remaining = events.collect::<Vec<_>>().await;
    assert!(
        !remaining
            .iter()
            .any(|event| matches!(event, Ok(MeshEvent::Completed { .. })))
    );
    worker.shutdown().await.unwrap();
}

#[derive(Clone, Default)]
struct FailingOnCancelProcessor {
    started: Arc<Notify>,
}

#[async_trait]
impl RuntimeTaskProcessor for FailingOnCancelProcessor {
    async fn process(
        &self,
        _task: RuntimeTask,
        cancellation: CancellationToken,
        _events: RuntimeEventSink,
    ) -> Result<(), DispatchError> {
        self.started.notify_one();
        cancellation.cancelled().await;
        Err(DispatchError::Message(
            "processor reported cancellation failure".to_owned(),
        ))
    }
}

#[tokio::test]
async fn processor_error_during_cancellation_is_preserved_in_acknowledgement() {
    let processor = FailingOnCancelProcessor::default();
    let started = Arc::clone(&processor.started);
    let (dispatcher, worker) = RuntimeWorker::spawn(runtime(), "runtime-node", processor, 8)
        .await
        .unwrap();
    let mut events = dispatcher.dispatch(MeshRequest {
        protocol: "a2a-v1".to_owned(),
        task_id: "task-cancel-error".to_owned(),
        context_id: "context-cancel-error".to_owned(),
        text: "return an error after cancellation".to_owned(),
    });
    assert!(matches!(
        events.next().await,
        Some(Ok(MeshEvent::Progress(_)))
    ));
    tokio::time::timeout(Duration::from_secs(1), started.notified())
        .await
        .unwrap();

    let error = dispatcher.cancel("task-cancel-error").await.unwrap_err();
    assert!(error.to_string().contains("reported cancellation failure"));
    assert!(events.collect::<Vec<_>>().await.is_empty());
    worker.shutdown().await.unwrap();
}

#[derive(Clone, Default)]
struct PanickingOnCancelProcessor {
    started: Arc<Notify>,
}

#[async_trait]
impl RuntimeTaskProcessor for PanickingOnCancelProcessor {
    async fn process(
        &self,
        _task: RuntimeTask,
        cancellation: CancellationToken,
        _events: RuntimeEventSink,
    ) -> Result<(), DispatchError> {
        self.started.notify_one();
        cancellation.cancelled().await;
        panic!("injected processor cancellation panic");
    }
}

#[tokio::test]
async fn processor_panic_during_cancellation_is_not_acknowledged_as_clean() {
    let processor = PanickingOnCancelProcessor::default();
    let started = Arc::clone(&processor.started);
    let (dispatcher, worker) = RuntimeWorker::spawn(runtime(), "runtime-node", processor, 8)
        .await
        .unwrap();
    let mut events = dispatcher.dispatch(MeshRequest {
        protocol: "a2a-v1".to_owned(),
        task_id: "task-cancel-panic".to_owned(),
        context_id: "context-cancel-panic".to_owned(),
        text: "panic after cancellation".to_owned(),
    });
    assert!(matches!(
        events.next().await,
        Some(Ok(MeshEvent::Progress(_)))
    ));
    tokio::time::timeout(Duration::from_secs(1), started.notified())
        .await
        .unwrap();

    let error = dispatcher.cancel("task-cancel-panic").await.unwrap_err();
    assert!(error.to_string().contains("processor task failed"));
    assert!(events.collect::<Vec<_>>().await.is_empty());
    worker.shutdown().await.unwrap();
}

#[derive(Clone, Default)]
struct IgnoringProcessor {
    started: Arc<Notify>,
}

#[async_trait]
impl RuntimeTaskProcessor for IgnoringProcessor {
    async fn process(
        &self,
        _task: RuntimeTask,
        _cancellation: CancellationToken,
        _events: RuntimeEventSink,
    ) -> Result<(), DispatchError> {
        self.started.notify_one();
        std::future::pending().await
    }
}

#[tokio::test]
async fn noncooperative_processor_is_aborted_before_cancel_acknowledgement() {
    let processor = IgnoringProcessor::default();
    let started = Arc::clone(&processor.started);
    let (dispatcher, worker) = RuntimeWorker::spawn_with_config(
        runtime(),
        "runtime-node",
        processor,
        RuntimeWorkerConfig {
            command_capacity: 8,
            max_active_tasks: 8,
            cancel_grace: Duration::from_millis(10),
        },
    )
    .await
    .unwrap();
    let mut events = dispatcher.dispatch(MeshRequest {
        protocol: "a2a-v1".to_owned(),
        task_id: "task-abort".to_owned(),
        context_id: "context-abort".to_owned(),
        text: "ignore cooperative cancellation".to_owned(),
    });
    assert!(matches!(
        events.next().await,
        Some(Ok(MeshEvent::Progress(_)))
    ));
    tokio::time::timeout(Duration::from_secs(1), started.notified())
        .await
        .unwrap();

    let error = tokio::time::timeout(Duration::from_secs(1), dispatcher.cancel("task-abort"))
        .await
        .unwrap()
        .unwrap_err();
    assert!(error.to_string().contains("forced abort"));
    assert!(events.collect::<Vec<_>>().await.is_empty());
    worker.shutdown().await.unwrap();
}

#[tokio::test]
async fn immediate_cancel_cannot_overtake_an_accepted_execute_command() {
    let (dispatcher, worker) = RuntimeWorker::spawn_with_config(
        runtime(),
        "runtime-node",
        IgnoringProcessor::default(),
        RuntimeWorkerConfig {
            command_capacity: 8,
            max_active_tasks: 8,
            cancel_grace: Duration::from_millis(10),
        },
    )
    .await
    .unwrap();
    let events = dispatcher.dispatch(MeshRequest {
        protocol: "a2a-v1".to_owned(),
        task_id: "task-immediate-cancel".to_owned(),
        context_id: "context-immediate-cancel".to_owned(),
        text: "cancel immediately".to_owned(),
    });

    let error = tokio::time::timeout(
        Duration::from_secs(1),
        dispatcher.cancel("task-immediate-cancel"),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(error.to_string().contains("forced abort"));
    assert!(
        !events
            .collect::<Vec<_>>()
            .await
            .iter()
            .any(|event| matches!(event, Ok(MeshEvent::Completed { .. })))
    );
    worker.shutdown().await.unwrap();
}

#[tokio::test]
async fn runtime_worker_capacity_and_unknown_cancellation_fail_closed() {
    let (dispatcher, worker) = RuntimeWorker::spawn_with_config(
        runtime(),
        "runtime-node",
        IgnoringProcessor::default(),
        RuntimeWorkerConfig {
            command_capacity: 4,
            max_active_tasks: 1,
            cancel_grace: Duration::from_millis(10),
        },
    )
    .await
    .unwrap();
    let mut first = dispatcher.dispatch(MeshRequest {
        protocol: "a2a-v1".to_owned(),
        task_id: "task-capacity-first".to_owned(),
        context_id: "context-capacity".to_owned(),
        text: "first".to_owned(),
    });
    assert!(matches!(
        first.next().await,
        Some(Ok(MeshEvent::Progress(_)))
    ));
    let second = dispatcher
        .dispatch(MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "task-capacity-second".to_owned(),
            context_id: "context-capacity".to_owned(),
            text: "second".to_owned(),
        })
        .collect::<Vec<_>>()
        .await;
    assert!(
        matches!(second.as_slice(), [Err(DispatchError::Message(message))] if message.contains("capacity"))
    );
    assert!(dispatcher.cancel("unknown-task").await.is_err());
    assert!(matches!(
        dispatcher.cancel("task-capacity-first").await,
        Err(DispatchError::CancellationForcedAbort)
    ));
    worker.shutdown().await.unwrap();
}

#[tokio::test]
async fn shutdown_cancels_noncooperative_processors_concurrently() {
    let (dispatcher, worker) = RuntimeWorker::spawn_with_config(
        runtime(),
        "runtime-node",
        IgnoringProcessor::default(),
        RuntimeWorkerConfig {
            command_capacity: 4,
            max_active_tasks: 2,
            cancel_grace: Duration::from_millis(10),
        },
    )
    .await
    .unwrap();
    let mut first = dispatcher.dispatch(MeshRequest {
        protocol: "a2a-v1".to_owned(),
        task_id: "shutdown-first".to_owned(),
        context_id: "shutdown-context".to_owned(),
        text: "first".to_owned(),
    });
    let mut second = dispatcher.dispatch(MeshRequest {
        protocol: "a2a-v1".to_owned(),
        task_id: "shutdown-second".to_owned(),
        context_id: "shutdown-context".to_owned(),
        text: "second".to_owned(),
    });
    assert!(matches!(
        first.next().await,
        Some(Ok(MeshEvent::Progress(_)))
    ));
    assert!(matches!(
        second.next().await,
        Some(Ok(MeshEvent::Progress(_)))
    ));

    tokio::time::timeout(Duration::from_secs(1), worker.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert!(first.collect::<Vec<_>>().await.is_empty());
    assert!(second.collect::<Vec<_>>().await.is_empty());
}
