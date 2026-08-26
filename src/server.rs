use std::sync::Arc;

use a2a::{A2AError, ListTasksRequest, ListTasksResponse, Task};
use a2a_server::{DefaultRequestHandler, RequestHandler, StaticAgentCard, TaskStore};
use async_trait::async_trait;
use axum::Router;
use tower_http::limit::RequestBodyLimitLayer;

use crate::{
    BoundedTaskStore, ExecutionLimits, InputLimits, MeshDispatcher, SmeshExecutor,
    build_agent_card, guard::GuardedRequestHandler,
};

struct SharedTaskStore<S>(Arc<S>);

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

/// Compose the official A2A routers around a SMESH executor and injected task store.
///
/// The injected store keeps protocol guards and the SDK request handler on the same
/// authoritative task view. The router wraps the supplied store in an internal
/// reference-counted adapter before cloning it, so even a store with deep-copy
/// [`Clone`] semantics cannot split the guard and SDK views. Production persistence
/// adapters can implement [`TaskStore`] without changing the public A2A routing layer.
pub fn build_router_with_store<D, S>(config: GatewayConfig, dispatcher: D, store: S) -> Router
where
    D: MeshDispatcher,
    S: TaskStore,
{
    let max_body_bytes = config.max_body_bytes;
    let store = SharedTaskStore(Arc::new(store));
    let executor = SmeshExecutor::new(dispatcher, config.input_limits, config.gateway_node_id)
        .with_execution_limits(config.execution_limits);
    let inner: Arc<dyn RequestHandler> =
        Arc::new(DefaultRequestHandler::new(executor, store.clone()));
    let handler = Arc::new(GuardedRequestHandler::new(inner, store));
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
