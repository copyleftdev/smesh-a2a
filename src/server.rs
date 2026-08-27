use std::sync::Arc;

use a2a::{A2AError, ListTasksRequest, ListTasksResponse, Task};
use a2a_server::{DefaultRequestHandler, RequestHandler, StaticAgentCard, TaskStore};
use async_trait::async_trait;
use axum::Router;
use tower_http::limit::RequestBodyLimitLayer;

use crate::{
    BoundedTaskStore, CompletionPolicySpec, ExecutionLimits, InputLimits, MeshDispatcher,
    PolicyError, RuntimeEventCapture, SmeshExecutor, SqliteTaskStore, VersionedCompletionPolicy,
    build_agent_card, guard::GuardedRequestHandler,
};

struct SharedTaskStore<S>(Arc<S>);

/// A task store that declares whether completion receipts must use durable key material.
pub trait CompletionPolicyStore: TaskStore {
    /// Return the durable receipt key for persistent stores, or `None` for ephemeral stores.
    fn durable_receipt_key(&self) -> Option<[u8; 32]>;
}

impl CompletionPolicyStore for BoundedTaskStore {
    fn durable_receipt_key(&self) -> Option<[u8; 32]> {
        None
    }
}

impl CompletionPolicyStore for SqliteTaskStore {
    fn durable_receipt_key(&self) -> Option<[u8; 32]> {
        Some(self.completion_receipt_key())
    }
}

impl<S> Clone for SharedTaskStore<S> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

#[async_trait]
impl<S> TaskStore for SharedTaskStore<S>
where
    S: TaskStore,
{
    async fn create(&self, task: Task) -> Result<u64, A2AError> {
        self.0.create(task).await
    }

    async fn update(&self, task: Task) -> Result<u64, A2AError> {
        self.0.update(task).await
    }

    async fn get(&self, task_id: &str) -> Result<Option<Task>, A2AError> {
        self.0.get(task_id).await
    }

    async fn list(&self, request: &ListTasksRequest) -> Result<ListTasksResponse, A2AError> {
        self.0.list(request).await
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayConfig {
    pub public_base_url: String,
    pub gateway_node_id: String,
    pub input_limits: InputLimits,
    pub max_body_bytes: usize,
    pub max_tasks: usize,
    pub execution_limits: ExecutionLimits,
}

impl GatewayConfig {
    #[must_use]
    pub fn new(public_base_url: impl Into<String>, gateway_node_id: impl Into<String>) -> Self {
        Self {
            public_base_url: public_base_url.into(),
            gateway_node_id: gateway_node_id.into(),
            input_limits: InputLimits::default(),
            max_body_bytes: 128 * 1024,
            max_tasks: 1024,
            execution_limits: ExecutionLimits::default(),
        }
    }
}

/// Compose the official A2A routers around a SMESH executor.
pub fn build_router<D>(config: GatewayConfig, dispatcher: D) -> Router
where
    D: MeshDispatcher,
{
    let store = BoundedTaskStore::new(config.max_tasks);
    build_router_with_store(config, dispatcher, store)
}

/// Compose the official A2A routers with canonical runtime/gateway trace capture.
pub fn build_router_with_trace<D>(
    config: GatewayConfig,
    dispatcher: D,
    trace: Arc<RuntimeEventCapture>,
) -> Router
where
    D: MeshDispatcher,
{
    let store = BoundedTaskStore::new(config.max_tasks);
    compose_router_with_policy_and_trace(
        config,
        dispatcher,
        store,
        VersionedCompletionPolicy::default(),
        Some(trace),
    )
}

fn build_router_with_store<D, S>(config: GatewayConfig, dispatcher: D, store: S) -> Router
where
    D: MeshDispatcher,
    S: TaskStore,
{
    compose_router_with_policy_and_trace(
        config,
        dispatcher,
        store,
        VersionedCompletionPolicy::default(),
        None,
    )
}

/// Compose the A2A router with a persistent store and its durable receipt key.
///
/// # Errors
///
/// Returns an error if the built-in completion-policy profile is invalid.
pub fn build_router_with_sqlite<D>(
    config: GatewayConfig,
    dispatcher: D,
    store: SqliteTaskStore,
) -> Result<Router, PolicyError>
where
    D: MeshDispatcher,
{
    let policy = VersionedCompletionPolicy::new_with_receipt_key(
        CompletionPolicySpec::development(),
        store.completion_receipt_key(),
    )?;
    build_router_with_policy(config, dispatcher, store, policy)
}

/// Compose the traced A2A router with a persistent store and its durable receipt key.
///
/// # Errors
///
/// Returns an error if the built-in completion-policy profile is invalid.
pub fn build_router_with_sqlite_and_trace<D>(
    config: GatewayConfig,
    dispatcher: D,
    store: SqliteTaskStore,
    trace: Arc<RuntimeEventCapture>,
) -> Result<Router, PolicyError>
where
    D: MeshDispatcher,
{
    let policy = VersionedCompletionPolicy::new_with_receipt_key(
        CompletionPolicySpec::development(),
        store.completion_receipt_key(),
    )?;
    build_router_with_policy_and_trace(config, dispatcher, store, policy, Some(trace))
}

/// Compose the A2A router with explicit store and completion-policy boundaries.
///
/// # Errors
///
/// Returns an error when a persistent SQLite store and policy use different receipt keys.
pub fn build_router_with_policy<D, S>(
    config: GatewayConfig,
    dispatcher: D,
    store: S,
    policy: VersionedCompletionPolicy,
) -> Result<Router, PolicyError>
where
    D: MeshDispatcher,
    S: CompletionPolicyStore + 'static,
{
    build_router_with_policy_and_trace(config, dispatcher, store, policy, None)
}

/// Compose the traced A2A router with explicit store and completion-policy boundaries.
///
/// # Errors
///
/// Returns an error when a persistent SQLite store and policy use different receipt keys.
pub fn build_router_with_policy_and_trace<D, S>(
    config: GatewayConfig,
    dispatcher: D,
    store: S,
    policy: VersionedCompletionPolicy,
    trace: Option<Arc<RuntimeEventCapture>>,
) -> Result<Router, PolicyError>
where
    D: MeshDispatcher,
    S: CompletionPolicyStore + 'static,
{
    if let Some(receipt_key) = store.durable_receipt_key()
        && receipt_key != policy.receipt_key()
    {
        return Err(PolicyError::InvalidPolicy(
            "persistent task store and completion policy use different receipt keys".to_owned(),
        ));
    }
    Ok(compose_router_with_policy_and_trace(
        config, dispatcher, store, policy, trace,
    ))
}

fn compose_router_with_policy_and_trace<D, S>(
    config: GatewayConfig,
    dispatcher: D,
    store: S,
    policy: VersionedCompletionPolicy,
    trace: Option<Arc<RuntimeEventCapture>>,
) -> Router
where
    D: MeshDispatcher,
    S: TaskStore,
{
    let max_body_bytes = config.max_body_bytes;
    let store = SharedTaskStore(Arc::new(store));
    let guard_policy = policy.clone();
    let mut executor = SmeshExecutor::new(dispatcher, config.input_limits, config.gateway_node_id)
        .with_execution_limits(config.execution_limits)
        .with_completion_policy(policy);
    if let Some(trace) = trace {
        executor = executor.with_runtime_trace(trace);
    }
    let inner: Arc<dyn RequestHandler> =
        Arc::new(DefaultRequestHandler::new(executor, store.clone()));
    let handler = Arc::new(GuardedRequestHandler::new(inner, store, guard_policy));
    let card = Arc::new(StaticAgentCard::new(build_agent_card(
        &config.public_base_url,
    )));

    Router::new()
        .nest(
            "/jsonrpc",
            a2a_server::jsonrpc::jsonrpc_router(handler.clone()),
        )
        .nest("/rest", a2a_server::rest::rest_router(handler))
        .merge(a2a_server::agent_card::agent_card_router(card))
        .layer(RequestBodyLimitLayer::new(max_body_bytes))
}
