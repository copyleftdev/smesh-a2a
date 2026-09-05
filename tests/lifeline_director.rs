use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use futures::StreamExt as _;
use futures::stream::{self, BoxStream};
use smesh_a2a::{
    DispatchError, LifelineDirectorManifest, LifelineResponseDirector, LifelineTopologyManifest,
    MeshDispatcher, MeshEvent, MeshRequest, RunningLifelineTopology,
};
use wait_timeout::ChildExt as _;

const CHECKED_MANIFEST: &str = include_str!("../deploy/lifeline-director.json");

#[derive(Clone)]
struct HostileSyncState {
    card: serde_json::Value,
    cancel_count: Arc<AtomicUsize>,
    methods: Arc<Mutex<Vec<String>>>,
}

async fn hostile_sync_card(State(state): State<HostileSyncState>) -> Json<serde_json::Value> {
    Json(state.card)
}

async fn hostile_sync_rpc(
    State(state): State<HostileSyncState>,
    Json(request): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let method = request["method"].as_str().unwrap();
    state.methods.lock().unwrap().push(method.to_owned());
    let task_state = if method == "CancelTask" {
        state.cancel_count.fetch_add(1, Ordering::SeqCst);
        "TASK_STATE_FAILED"
    } else {
        assert_eq!(method, "SendMessage");
        "TASK_STATE_WORKING"
    };
    Json(serde_json::json!({
        "jsonrpc": "2.0",
        "id": request["id"].clone(),
        "result": {
            "task": {
                "id": "hostile-sync-task",
                "contextId": "lifeline-incident-0047",
                "status": {"state": task_state}
            }
        }
    }))
}

#[derive(Clone)]
struct HostileReconnectState {
    card: serde_json::Value,
    methods: Arc<Mutex<Vec<RecordedRequest>>>,
}

type RecordedRequest = (String, Option<String>);

async fn hostile_reconnect_card(
    State(state): State<HostileReconnectState>,
) -> Json<serde_json::Value> {
    Json(state.card)
}

async fn hostile_reconnect_rpc(
    State(state): State<HostileReconnectState>,
    Json(request): Json<serde_json::Value>,
) -> Response {
    let method = request["method"].as_str().unwrap();
    let requested_task_id = request
        .pointer("/params/id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    state
        .methods
        .lock()
        .unwrap()
        .push((method.to_owned(), requested_task_id));
    let task_id = if method == "GetTask" {
        "foreign-task"
    } else {
        "hostile-stream-task"
    };
    let task_state = if method == "CancelTask" {
        "TASK_STATE_CANCELED"
    } else {
        "TASK_STATE_WORKING"
    };
    let response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": request["id"].clone(),
        "result": {
            "task": {
                "id": task_id,
                "contextId": "lifeline-incident-0047",
                "status": {"state": task_state}
            }
        }
    });
    if method == "SendStreamingMessage" {
        (
            [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
            format!("data: {response}\n\n"),
        )
            .into_response()
    } else {
        Json(response).into_response()
    }
}

fn manifest_for_topology(
    topology: &RunningLifelineTopology,
    override_gateway: Option<(&str, &str)>,
) -> LifelineDirectorManifest {
    let mut value: serde_json::Value = serde_json::from_str(CHECKED_MANIFEST).unwrap();
    for gateway in value["gateways"].as_array_mut().unwrap() {
        let gateway_id = gateway["id"].as_str().unwrap().to_owned();
        let endpoint = topology
            .endpoints()
            .iter()
            .find(|endpoint| endpoint.gateway_id() == gateway_id)
            .unwrap();
        gateway["discoveryUrl"] = override_gateway
            .filter(|(override_id, _)| *override_id == gateway_id)
            .map_or_else(
                || endpoint.base_url().into(),
                |(_, url)| url.to_owned().into(),
            );
    }
    LifelineDirectorManifest::from_json(&serde_json::to_string(&value).unwrap()).unwrap()
}

async fn card_for_mock_gateway(
    topology: &RunningLifelineTopology,
    gateway_id: &str,
    origin: &str,
) -> serde_json::Value {
    let endpoint = topology
        .endpoints()
        .iter()
        .find(|endpoint| endpoint.gateway_id() == gateway_id)
        .unwrap();
    let mut card: serde_json::Value = reqwest::get(format!(
        "{}/.well-known/agent-card.json",
        endpoint.base_url()
    ))
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    for interface in card["supportedInterfaces"].as_array_mut().unwrap() {
        let path = match interface["protocolBinding"].as_str().unwrap() {
            "JSONRPC" => "/jsonrpc",
            "HTTP+JSON" => "/rest",
            binding => panic!("unexpected binding {binding}"),
        };
        interface["url"] = format!("{origin}{path}").into();
    }
    card
}

async fn run_hostile_reconnect() -> (bool, Vec<RecordedRequest>) {
    let topology_manifest =
        LifelineTopologyManifest::from_json(include_str!("../deploy/lifeline-topology.json"))
            .unwrap()
            .with_ephemeral_loopback_ports();
    let topology = topology_manifest.launch().await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let card = card_for_mock_gateway(&topology, "atlas-primary", &origin).await;
    let methods = Arc::new(Mutex::new(Vec::new()));
    let mock = axum::serve(
        listener,
        Router::new()
            .route("/.well-known/agent-card.json", get(hostile_reconnect_card))
            .route("/jsonrpc", post(hostile_reconnect_rpc))
            .with_state(HostileReconnectState {
                card,
                methods: methods.clone(),
            }),
    );
    let mock_task = tokio::spawn(async move { mock.await.unwrap() });
    let director = LifelineResponseDirector::new(manifest_for_topology(
        &topology,
        Some(("atlas-primary", origin.as_str())),
    ));

    let failed = director.run().await.is_err();

    mock_task.abort();
    topology.shutdown().await.unwrap();
    let observed = methods.lock().unwrap().clone();
    (failed, observed)
}

#[derive(Clone)]
struct BarrierDispatcher {
    shared: Arc<BarrierState>,
}

struct BarrierState {
    barrier: tokio::sync::Barrier,
    active: AtomicUsize,
    peak: AtomicUsize,
    contexts: Mutex<Vec<String>>,
}

impl BarrierDispatcher {
    fn new(parties: usize) -> Self {
        Self {
            shared: Arc::new(BarrierState {
                barrier: tokio::sync::Barrier::new(parties),
                active: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
                contexts: Mutex::new(Vec::new()),
            }),
        }
    }
}

#[async_trait]
impl MeshDispatcher for BarrierDispatcher {
    fn dispatch(
        &self,
        request: MeshRequest,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        if request.text.contains("evidence packet") {
            return smesh_a2a::LoopbackDispatcher.dispatch(request);
        }
        let active = self.shared.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.shared.peak.fetch_max(active, Ordering::SeqCst);
        self.shared
            .contexts
            .lock()
            .unwrap()
            .push(request.context_id.clone());
        let shared = self.shared.clone();
        let downstream = smesh_a2a::LoopbackDispatcher.dispatch(request);
        Box::pin(
            stream::once(async move {
                shared.barrier.wait().await;
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                shared.active.fetch_sub(1, Ordering::SeqCst);
                Ok(MeshEvent::Progress("all children admitted".to_owned()))
            })
            .chain(downstream),
        )
    }

    async fn cancel(&self, _task_id: &str) -> Result<(), DispatchError> {
        Ok(())
    }
}

#[derive(Clone, Default)]
struct FailoverDispatcher {
    shipment_attempts: Arc<AtomicUsize>,
    cancellation_attempts: Arc<AtomicUsize>,
    fail_primary: bool,
    fail_fallback: bool,
}

#[async_trait]
impl MeshDispatcher for FailoverDispatcher {
    fn dispatch(
        &self,
        request: MeshRequest,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        if request.text.contains("shipment routes") {
            let attempt = self.shipment_attempts.fetch_add(1, Ordering::SeqCst);
            if attempt == 0 && self.fail_primary {
                return Box::pin(stream::once(async {
                    Err(DispatchError::message("primary failed"))
                }));
            }
            if attempt == 0 {
                return Box::pin(
                    stream::once(async { Ok(MeshEvent::Progress("primary admitted".to_owned())) })
                        .chain(stream::pending()),
                );
            }
            if self.fail_fallback {
                return Box::pin(stream::once(async {
                    Err(DispatchError::message("fallback failed"))
                }));
            }
        }
        smesh_a2a::LoopbackDispatcher.dispatch(request)
    }

    async fn cancel(&self, _task_id: &str) -> Result<(), DispatchError> {
        self.cancellation_attempts.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
async fn failed_primary_is_not_redelegated_without_confirmed_cancellation() {
    let dispatcher = FailoverDispatcher {
        fail_primary: true,
        ..FailoverDispatcher::default()
    };
    let topology_manifest =
        LifelineTopologyManifest::from_json(include_str!("../deploy/lifeline-topology.json"))
            .unwrap()
            .with_ephemeral_loopback_ports();
    let topology = topology_manifest
        .launch_with_dispatcher(dispatcher.clone())
        .await
        .unwrap();
    let manifest = manifest_for_topology(&topology, None);

    let result = LifelineResponseDirector::new(manifest).run().await;

    assert!(result.is_err());
    assert_eq!(dispatcher.shipment_attempts.load(Ordering::SeqCst), 1);
    topology.shutdown().await.unwrap();
}

#[test]
fn checked_manifest_defines_one_context_and_four_concurrent_child_operations() {
    let manifest = LifelineDirectorManifest::from_json(CHECKED_MANIFEST).unwrap();

    assert!(manifest.is_fictional());
    assert_eq!(manifest.run_id(), "lifeline-director-0047");
    assert_eq!(manifest.root_context_id(), "lifeline-incident-0047");
    assert_eq!(manifest.gateways().len(), 6);
    assert_eq!(manifest.operations().len(), 4);
    assert_eq!(
        manifest
            .operations()
            .iter()
            .map(smesh_a2a::LifelineDirectorOperation::id)
            .collect::<Vec<_>>(),
        [
            "lot-genealogy",
            "exposure-cohort",
            "shipment-routing",
            "recall-criteria"
        ]
    );
    assert_eq!(manifest.review().gateway_id(), "sentinel");
    assert_eq!(manifest.logistics().primary_gateway_id(), "atlas-primary");
    assert_eq!(manifest.logistics().fallback_gateway_id(), "atlas-fallback");
}

#[tokio::test]
async fn official_director_resolves_and_selects_only_public_card_interfaces() {
    let topology_manifest =
        LifelineTopologyManifest::from_json(include_str!("../deploy/lifeline-topology.json"))
            .unwrap()
            .with_ephemeral_loopback_ports();
    let topology = topology_manifest.launch().await.unwrap();
    let manifest = manifest_for_topology(&topology, None);
    let director = LifelineResponseDirector::new(manifest);

    let resolved = director.resolve_gateways().await.unwrap();

    assert_eq!(resolved.len(), 6);
    assert_eq!(
        resolved
            .iter()
            .map(smesh_a2a::ResolvedLifelineGateway::gateway_id)
            .collect::<Vec<_>>(),
        [
            "meridian",
            "atlas-primary",
            "helix",
            "harbor",
            "sentinel",
            "atlas-fallback"
        ]
    );
    assert!(
        resolved
            .iter()
            .all(smesh_a2a::ResolvedLifelineGateway::interfaces_are_local)
    );
    assert!(
        resolved
            .iter()
            .all(smesh_a2a::ResolvedLifelineGateway::card_contract_matches)
    );

    topology.shutdown().await.unwrap();
}

#[tokio::test]
async fn unavailable_primary_discovery_uses_fallback_without_restarting_siblings() {
    let topology_manifest =
        LifelineTopologyManifest::from_json(include_str!("../deploy/lifeline-topology.json"))
            .unwrap()
            .with_ephemeral_loopback_ports();
    let topology = topology_manifest.launch().await.unwrap();
    let unavailable = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unavailable_origin = format!("http://{}", unavailable.local_addr().unwrap());
    let manifest = manifest_for_topology(
        &topology,
        Some(("atlas-primary", unavailable_origin.as_str())),
    );

    let run = LifelineResponseDirector::new(manifest).run().await.unwrap();

    assert_eq!(run.initial_operations().len(), 3);
    assert!(run.all_protocol_ids_are_captured());
    assert!(
        run.fallback_operation()
            .is_some_and(smesh_a2a::LifelineDirectorOperationReceipt::is_completed)
    );
    assert!(
        run.fallback_operation()
            .unwrap()
            .replaces_task_id()
            .is_none()
    );
    assert_eq!(run.review().unwrap().reference_task_ids().len(), 4);
    let evidence = serde_json::to_value(&run).unwrap();
    assert_eq!(
        evidence["discoveryFailures"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(
        evidence["discoveryFailures"][0]["gatewayId"],
        "atlas-primary"
    );
    drop(unavailable);
    topology.shutdown().await.unwrap();
}

#[tokio::test]
async fn director_rejects_non_v1_public_interfaces() {
    assert_meridian_card_rejected(|card| {
        for interface in &mut card.supported_interfaces {
            interface.protocol_version = "0.3.0".to_owned();
        }
    })
    .await;
}

#[tokio::test]
async fn director_rejects_unreviewed_public_modalities() {
    assert_meridian_card_rejected(|card| {
        card.default_output_modes = vec!["text/html".to_owned()];
    })
    .await;
}

async fn assert_meridian_card_rejected(mutator: impl FnOnce(&mut a2a::AgentCard)) {
    let topology_manifest =
        LifelineTopologyManifest::from_json(include_str!("../deploy/lifeline-topology.json"))
            .unwrap()
            .with_ephemeral_loopback_ports();
    let topology = topology_manifest.launch().await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let mut card = topology.card("meridian").unwrap().clone();
    mutator(&mut card);
    for interface in &mut card.supported_interfaces {
        interface.url = if interface.protocol_binding == a2a::TRANSPORT_PROTOCOL_JSONRPC {
            format!("{origin}/jsonrpc")
        } else {
            format!("{origin}/rest")
        };
    }
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/.well-known/agent-card.json",
                get(move || {
                    let card = card.clone();
                    async move { axum::Json(card) }
                }),
            ),
        )
        .await
        .unwrap();
    });
    let manifest = manifest_for_topology(&topology, Some(("meridian", origin.as_str())));

    let result = LifelineResponseDirector::new(manifest)
        .resolve_gateways()
        .await;

    assert!(result.is_err());
    server.abort();
    topology.shutdown().await.unwrap();
}

#[tokio::test]
async fn director_does_not_follow_card_discovery_redirects() {
    let topology_manifest =
        LifelineTopologyManifest::from_json(include_str!("../deploy/lifeline-topology.json"))
            .unwrap()
            .with_ephemeral_loopback_ports();
    let topology = topology_manifest.launch().await.unwrap();
    let redirect_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let redirect_origin = format!("http://{}", redirect_listener.local_addr().unwrap());
    let target_origin = format!("http://{}", target_listener.local_addr().unwrap());
    let mut redirected_card = topology.card("meridian").unwrap().clone();
    for interface in &mut redirected_card.supported_interfaces {
        interface.url = if interface.protocol_binding == a2a::TRANSPORT_PROTOCOL_JSONRPC {
            format!("{redirect_origin}/jsonrpc")
        } else {
            format!("{redirect_origin}/rest")
        };
    }
    let target_hits = Arc::new(AtomicUsize::new(0));
    let target_hits_for_handler = target_hits.clone();
    let target_router = Router::new().fallback(get(move || {
        let card = redirected_card.clone();
        let hits = target_hits_for_handler.clone();
        async move {
            hits.fetch_add(1, Ordering::SeqCst);
            axum::Json(card)
        }
    }));
    let redirect_target = format!("{target_origin}/.well-known/agent-card.json");
    let redirect_router = Router::new().fallback(get(move || {
        let target = redirect_target.clone();
        async move { Redirect::temporary(&target) }
    }));
    let redirect_task =
        tokio::spawn(async move { axum::serve(redirect_listener, redirect_router).await });
    let target_task =
        tokio::spawn(async move { axum::serve(target_listener, target_router).await });

    let director = LifelineResponseDirector::new(manifest_for_topology(
        &topology,
        Some(("meridian", redirect_origin.as_str())),
    ));

    assert!(director.resolve_gateways().await.is_err());
    assert_eq!(target_hits.load(Ordering::SeqCst), 0);

    redirect_task.abort();
    target_task.abort();
    let _ = redirect_task.await;
    let _ = target_task.await;
    topology.shutdown().await.unwrap();
}

#[tokio::test]
async fn nonterminal_sync_response_is_canceled_before_director_failure() {
    let topology_manifest =
        LifelineTopologyManifest::from_json(include_str!("../deploy/lifeline-topology.json"))
            .unwrap()
            .with_ephemeral_loopback_ports();
    let topology = topology_manifest.launch().await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let card = card_for_mock_gateway(&topology, "meridian", &origin).await;
    let cancel_count = Arc::new(AtomicUsize::new(0));
    let methods = Arc::new(Mutex::new(Vec::new()));
    let mock = axum::serve(
        listener,
        Router::new()
            .route("/.well-known/agent-card.json", get(hostile_sync_card))
            .route("/jsonrpc", post(hostile_sync_rpc))
            .with_state(HostileSyncState {
                card,
                cancel_count: cancel_count.clone(),
                methods: methods.clone(),
            }),
    );
    let mock_task = tokio::spawn(async move { mock.await.unwrap() });
    let director = LifelineResponseDirector::new(manifest_for_topology(
        &topology,
        Some(("meridian", origin.as_str())),
    ));

    let result = director.run().await;

    mock_task.abort();
    topology.shutdown().await.unwrap();
    assert!(result.is_err());
    assert_eq!(*methods.lock().unwrap(), vec!["SendMessage", "CancelTask"]);
    assert_eq!(cancel_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn changed_get_task_identity_is_canceled_and_rejected() {
    let (failed, methods) = run_hostile_reconnect().await;

    assert!(failed);
    assert_eq!(
        methods,
        vec![
            ("SendStreamingMessage".to_owned(), None),
            ("GetTask".to_owned(), Some("hostile-stream-task".to_owned())),
            (
                "CancelTask".to_owned(),
                Some("hostile-stream-task".to_owned())
            )
        ]
    );
}

#[tokio::test]
async fn director_commissions_four_unique_children_under_one_root_context() {
    let topology_manifest =
        LifelineTopologyManifest::from_json(include_str!("../deploy/lifeline-topology.json"))
            .unwrap()
            .with_ephemeral_loopback_ports();
    let topology = topology_manifest.launch().await.unwrap();
    let manifest = manifest_for_topology(&topology, None);
    let director = LifelineResponseDirector::new(manifest);

    let run = director.run().await.unwrap();

    assert_eq!(run.initial_operations().len(), 4);
    assert!(run.initial_operations().iter().all(|operation| {
        operation.context_id() == run.root_context_id() && operation.is_completed()
    }));
    let message_ids = run
        .initial_operations()
        .iter()
        .map(smesh_a2a::LifelineDirectorOperationReceipt::message_id)
        .collect::<std::collections::HashSet<_>>();
    let task_ids = run
        .initial_operations()
        .iter()
        .map(smesh_a2a::LifelineDirectorOperationReceipt::task_id)
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(message_ids.len(), 4);
    assert_eq!(task_ids.len(), 4);
    assert!(!message_ids.contains(""));
    assert!(!task_ids.contains(""));
    let meridian = run
        .initial_operations()
        .iter()
        .find(|operation| operation.operation_id() == "lot-genealogy")
        .unwrap();
    let harbor = run
        .initial_operations()
        .iter()
        .find(|operation| operation.operation_id() == "exposure-cohort")
        .unwrap();
    let atlas = run
        .initial_operations()
        .iter()
        .find(|operation| operation.operation_id() == "shipment-routing")
        .unwrap();
    assert_eq!(meridian.binding(), a2a::TRANSPORT_PROTOCOL_JSONRPC);
    assert_eq!(harbor.binding(), a2a::TRANSPORT_PROTOCOL_HTTP_JSON);
    assert!(atlas.used_streaming());
    assert!(atlas.used_get_task());

    topology.shutdown().await.unwrap();
}

#[tokio::test]
async fn director_reaches_all_four_dispatchers_before_any_child_completes() {
    let dispatcher = BarrierDispatcher::new(4);
    let topology_manifest =
        LifelineTopologyManifest::from_json(include_str!("../deploy/lifeline-topology.json"))
            .unwrap()
            .with_ephemeral_loopback_ports();
    let topology = topology_manifest
        .launch_with_dispatcher(dispatcher.clone())
        .await
        .unwrap();
    let director = LifelineResponseDirector::new(manifest_for_topology(&topology, None));

    let run = tokio::time::timeout(std::time::Duration::from_secs(5), director.run())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(run.initial_operations().len(), 4);
    assert!(
        run.initial_operations()
            .iter()
            .find(|operation| operation.operation_id() == "shipment-routing")
            .unwrap()
            .used_subscribe()
    );
    assert_eq!(dispatcher.shared.peak.load(Ordering::SeqCst), 4);
    {
        let contexts = dispatcher.shared.contexts.lock().unwrap();
        assert_eq!(contexts.len(), 4);
        assert!(
            contexts
                .iter()
                .all(|context| context == run.root_context_id())
        );
    }

    topology.shutdown().await.unwrap();
}

#[tokio::test]
async fn stalled_primary_is_canceled_and_redelegated_without_restarting_siblings() {
    let dispatcher = FailoverDispatcher::default();
    let topology_manifest =
        LifelineTopologyManifest::from_json(include_str!("../deploy/lifeline-topology.json"))
            .unwrap()
            .with_ephemeral_loopback_ports();
    let topology = topology_manifest
        .launch_with_dispatcher(dispatcher.clone())
        .await
        .unwrap();
    let director = LifelineResponseDirector::new(manifest_for_topology(&topology, None));

    let run = tokio::time::timeout(std::time::Duration::from_secs(8), director.run())
        .await
        .unwrap()
        .unwrap();

    let primary = run
        .initial_operations()
        .iter()
        .find(|operation| operation.operation_id() == "shipment-routing")
        .unwrap();
    let fallback = run.fallback_operation().unwrap();
    assert!(primary.is_canceled());
    assert!(primary.used_cancel());
    assert!(fallback.is_completed(), "{fallback:?}");
    assert_eq!(fallback.gateway_id(), "atlas-fallback");
    assert_eq!(fallback.replaces_task_id(), Some(primary.task_id()));
    assert_ne!(fallback.message_id(), primary.message_id());
    assert_ne!(fallback.task_id(), primary.task_id());
    assert_eq!(fallback.context_id(), run.root_context_id());
    assert_eq!(
        run.initial_operations()
            .iter()
            .filter(|operation| operation.is_completed())
            .count(),
        3
    );
    assert!(
        run.review()
            .is_some_and(smesh_a2a::LifelineDirectorOperationReceipt::is_completed)
    );
    let review_references = run
        .review()
        .unwrap()
        .reference_task_ids()
        .iter()
        .map(String::as_str)
        .collect::<std::collections::HashSet<_>>();
    let expected_review_references = run
        .initial_operations()
        .iter()
        .chain(run.fallback_operation())
        .map(smesh_a2a::LifelineDirectorOperationReceipt::task_id)
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(review_references, expected_review_references);
    assert_eq!(fallback.reference_task_ids(), [primary.task_id()]);
    assert_eq!(dispatcher.shipment_attempts.load(Ordering::SeqCst), 2);
    assert_eq!(dispatcher.cancellation_attempts.load(Ordering::SeqCst), 1);
    assert!(run.all_protocol_ids_are_captured());
    assert!(run.captured_message_ids().len() > 6);
    assert_eq!(run.captured_task_ids().len(), 6);

    topology.shutdown().await.unwrap();
}

#[tokio::test]
async fn failed_fallback_stops_after_one_redelegation_without_tertiary_retry() {
    let dispatcher = FailoverDispatcher {
        fail_fallback: true,
        ..FailoverDispatcher::default()
    };
    let topology =
        LifelineTopologyManifest::from_json(include_str!("../deploy/lifeline-topology.json"))
            .unwrap()
            .with_ephemeral_loopback_ports()
            .launch_with_dispatcher(dispatcher.clone())
            .await
            .unwrap();
    let director = LifelineResponseDirector::new(manifest_for_topology(&topology, None));

    let result = tokio::time::timeout(std::time::Duration::from_secs(8), director.run())
        .await
        .unwrap();

    assert!(result.is_err());
    assert_eq!(dispatcher.shipment_attempts.load(Ordering::SeqCst), 2);
    topology.shutdown().await.unwrap();
}

#[test]
fn one_command_runs_official_client_scenario_and_reaps_topology() {
    let output = std::env::temp_dir().join(format!(
        "smesh-a2a-lifeline-director-{}.json",
        std::process::id()
    ));
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut child = Command::new(env!("CARGO_BIN_EXE_lifeline-response-director"))
        .arg(root.join("deploy/lifeline-topology.json"))
        .arg(root.join("deploy/lifeline-director.json"))
        .arg(&output)
        .spawn()
        .unwrap();
    let status = child
        .wait_timeout(Duration::from_secs(15))
        .unwrap()
        .unwrap_or_else(|| {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("director process exceeded its watchdog")
        });
    assert!(status.success());

    let serialized = std::fs::read_to_string(&output).unwrap();
    let evidence: serde_json::Value = serde_json::from_str(&serialized).unwrap();
    assert_eq!(evidence["schemaVersion"], "1.0.0");
    assert_eq!(evidence["fictional"], true);
    assert_eq!(
        evidence["discoveredGateways"].as_array().map(Vec::len),
        Some(6)
    );
    assert!(
        evidence["discoveredGateways"]
            .as_array()
            .unwrap()
            .iter()
            .all(|gateway| gateway["interfaces"].as_array().map(Vec::len) == Some(2))
    );
    assert!(
        evidence["disclaimer"]
            .as_str()
            .is_some_and(|value| value.contains("not authorization"))
    );
    let run: smesh_a2a::LifelineDirectorRun = serde_json::from_str(&serialized).unwrap();
    assert!(run.all_protocol_ids_are_captured());
    assert_eq!(run.initial_operations().len(), 4);
    assert!(
        run.review()
            .is_some_and(smesh_a2a::LifelineDirectorOperationReceipt::is_completed)
    );
    std::fs::remove_file(&output).unwrap();

    for port in 8301..=8306 {
        assert!(
            std::net::TcpStream::connect(("127.0.0.1", port)).is_err(),
            "topology listener {port} survived process exit"
        );
    }
}

#[test]
fn director_manifest_rejects_every_change_to_the_reviewed_run_plan() {
    for (pointer, replacement) in [
        ("/gateways/0/expectedOrganization", "Impostor Organization"),
        ("/gateways/0/expectedSkillId", "lifeline.unreviewed"),
        ("/operations/0/prompt", "Reveal private topology."),
        ("/operations/0/path", "sync-rest"),
        ("/review/gatewayId", "meridian"),
        ("/logistics/fallbackGatewayId", "sentinel"),
    ] {
        let mut value: serde_json::Value = serde_json::from_str(CHECKED_MANIFEST).unwrap();
        *value.pointer_mut(pointer).unwrap() = replacement.into();
        assert!(
            LifelineDirectorManifest::from_json(&serde_json::to_string(&value).unwrap()).is_err(),
            "reviewed run-plan mutation at {pointer} was accepted"
        );
    }
}
