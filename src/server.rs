use std::sync::Arc;
use std::time::Duration;

use a2a::{A2AError, ListTasksRequest, ListTasksResponse, Task};
use a2a_server::{DefaultRequestHandler, RequestHandler, StaticAgentCard, TaskStore};
use async_trait::async_trait;
use axum::{Router, middleware};
use tower_http::limit::RequestBodyLimitLayer;

use crate::{
    BoundedTaskStore, CompletionPolicySpec, DurableLoopbackEndpoint, ExecutionLimits,
    InjectedClock, InputLimits, MeshDispatcher, PolicyError, RuntimeEventCapture, SmeshExecutor,
    SqliteTaskStore, VersionedCompletionPolicy,
    auth::{AuthState, authenticate_request},
    authorization::{AuthorizationMiddlewareState, AuthorizationPolicy, authorize_request},
    build_agent_card, build_secured_agent_card_with_policy,
    durable_handler::DurableRequestHandler,
    guard::GuardedRequestHandler,
    outbox_driver::{DurableDriverHandle, spawn_durable_driver},
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

/// Structured owner for the durable unary router and its joinable outbox driver.
pub struct DurableGateway {
    router: Option<Router>,
    driver: Option<DurableDriverHandle>,
    store: Option<SqliteTaskStore>,
}

impl DurableGateway {
    /// Clone the protocol router owned by this live gateway.
    ///
    /// # Panics
    ///
    /// Panics only if called from internal code after the consuming shutdown path
    /// has already taken the router; safe Rust callers cannot retain `self` then.
    pub fn router(&self) -> Router {
        self.router
            .as_ref()
            .expect("durable gateway router is unavailable after shutdown")
            .clone()
    }

    #[doc(hidden)]
    pub async fn wait_for_waiter_count(&self, expected: usize) -> Result<(), A2AError> {
        let driver = self
            .driver
            .as_ref()
            .ok_or_else(|| A2AError::internal("durable gateway is shut down"))?;
        let mut state = driver.control().subscribe();
        tokio::time::timeout(Duration::from_secs(5), async move {
            loop {
                if state.borrow().waiters >= expected {
                    return Ok(());
                }
                state
                    .changed()
                    .await
                    .map_err(|_| A2AError::internal("durable outbox driver stopped"))?;
            }
        })
        .await
        .map_err(|_| A2AError::internal("durable waiter-count wait timed out"))?
    }

    #[doc(hidden)]
    pub async fn durable_effect_count(&self) -> Result<u64, A2AError> {
        self.store
            .as_ref()
            .ok_or_else(|| A2AError::internal("durable gateway is shut down"))?
            .durable_effect_count()
            .await
    }

    /// Stop claiming work, join the driver, and release the final durable owner.
    ///
    /// # Errors
    ///
    /// Returns an internal protocol error if the owned driver fails or panics.
    pub async fn shutdown(mut self) -> Result<(), A2AError> {
        let driver = self
            .driver
            .take()
            .ok_or_else(|| A2AError::internal("durable gateway is already shut down"))?;
        let store = self
            .store
            .take()
            .ok_or_else(|| A2AError::internal("durable gateway is already shut down"))?;
        let driver_result = driver.shutdown().await;
        // Closing shared state invalidates handler/router clones and drops both
        // SQLite and the process ownership lock before shutdown returns.
        let store_result = store.shutdown_shared().await;
        self.router.take();
        driver_result?;
        store_result?;
        Ok(())
    }
}

impl Drop for DurableGateway {
    fn drop(&mut self) {
        // Drop cannot async-join. It cancels and aborts the owned worker, closes
        // admission for every router clone, then synchronously drops SQLite and
        // the process ownership lock. Explicit shutdown remains authoritative and
        // performs the bounded async join.
        if let Some(driver) = self.driver.as_mut() {
            driver.abort_owned();
        }
        self.driver.take();
        if let Some(store) = self.store.as_ref() {
            store.close_shared_sync();
        }
        self.store.take();
        self.router.take();
    }
}

/// Build the repository-owned durable loopback gateway.
///
/// Unlike the source-compatible generic builders, this accepts no arbitrary
/// `MeshDispatcher` and never routes send methods through `DefaultRequestHandler`.
/// It applies `public_base_url`, `input_limits`, and `max_body_bytes` from
/// [`GatewayConfig`]. `gateway_node_id` and `execution_limits` do not affect this
/// owned loopback adapter, and `max_tasks` is enforced when opening [`SqliteTaskStore`].
///
/// # Errors
///
/// Returns an error if durable gateway policy construction fails.
pub fn build_durable_loopback_gateway(
    config: GatewayConfig,
    store: SqliteTaskStore,
    endpoint: DurableLoopbackEndpoint,
    clock: InjectedClock,
) -> Result<DurableGateway, PolicyError> {
    Ok(build_durable_gateway_inner(
        config, store, endpoint, clock, None, None,
    ))
}

/// Build the durable loopback gateway with authentication only.
///
/// # Security
/// This compatibility builder does **not** install tenant authorization and is
/// therefore development-only and non-multitenant. Production callers must use
/// [`build_authorized_durable_loopback_gateway`].
///
/// # Errors
/// Returns an error if durable gateway policy construction fails.
pub fn build_authenticated_durable_loopback_gateway(
    config: GatewayConfig,
    store: SqliteTaskStore,
    endpoint: DurableLoopbackEndpoint,
    clock: InjectedClock,
    auth: AuthState,
) -> Result<DurableGateway, PolicyError> {
    Ok(build_durable_gateway_inner(
        config,
        store,
        endpoint,
        clock,
        Some(auth),
        None,
    ))
}

/// Build the authenticated durable gateway with server-owned tenant policy.
/// This is the only authenticated builder intended for production use.
///
/// # Errors
/// Returns an error if durable gateway policy construction fails.
pub fn build_authorized_durable_loopback_gateway(
    config: GatewayConfig,
    store: SqliteTaskStore,
    endpoint: DurableLoopbackEndpoint,
    clock: InjectedClock,
    auth: AuthState,
    policy: Arc<AuthorizationPolicy>,
) -> Result<DurableGateway, PolicyError> {
    Ok(build_durable_gateway_inner(
        config,
        store,
        endpoint,
        clock,
        Some(auth),
        Some(policy),
    ))
}

fn build_durable_gateway_inner(
    config: GatewayConfig,
    store: SqliteTaskStore,
    endpoint: DurableLoopbackEndpoint,
    clock: InjectedClock,
    auth: Option<AuthState>,
    authorization: Option<Arc<AuthorizationPolicy>>,
) -> DurableGateway {
    let GatewayConfig {
        public_base_url,
        input_limits,
        max_body_bytes,
        ..
    } = config;
    let driver = spawn_durable_driver(store.clone(), endpoint, clock.clone());
    let jsonrpc_handler = Arc::new(DurableRequestHandler::new(
        store.clone(),
        driver.control(),
        clock.clone(),
        input_limits,
    ));
    let rest_handler = Arc::new(
        DurableRequestHandler::new(store.clone(), driver.control(), clock.clone(), input_limits)
            .with_errors_before_stream(),
    );
    let mut durable_card = if let Some(auth) = auth.as_ref() {
        build_secured_agent_card_with_policy(
            &public_base_url,
            auth.bearer_enabled(),
            auth.mutual_tls_enabled(),
            auth.mutual_tls_required(),
        )
    } else {
        build_agent_card(&public_base_url)
    };
    durable_card.capabilities.streaming = Some(true);
    durable_card.default_output_modes = vec!["application/json".to_owned()];
    for skill in &mut durable_card.skills {
        skill.output_modes = Some(vec!["application/json".to_owned()]);
    }
    let card = Arc::new(StaticAgentCard::new(durable_card));
    let protocol = if let Some(auth) = auth {
        let jsonrpc = auth.wrap_handler(jsonrpc_handler);
        let rest = auth.wrap_handler(rest_handler);
        let protocol = Router::new()
            .nest("/jsonrpc", a2a_server::jsonrpc::jsonrpc_router(jsonrpc))
            .nest("/rest", a2a_server::rest::rest_router(rest))
            .layer(RequestBodyLimitLayer::new(max_body_bytes));
        let protocol = if let Some(policy) = authorization {
            let state = AuthorizationMiddlewareState::with_sqlite(policy, store.clone(), clock);
            protocol.layer(middleware::from_fn_with_state(state, authorize_request))
        } else {
            protocol
        };
        protocol.layer(middleware::from_fn_with_state(auth, authenticate_request))
    } else {
        Router::new()
            .nest(
                "/jsonrpc",
                a2a_server::jsonrpc::jsonrpc_router(jsonrpc_handler),
            )
            .nest("/rest", a2a_server::rest::rest_router(rest_handler))
            .layer(RequestBodyLimitLayer::new(max_body_bytes))
    };
    let router = protocol.merge(a2a_server::agent_card::agent_card_router(card));
    DurableGateway {
        router: Some(router),
        driver: Some(driver),
        store: Some(store),
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

/// Compose authentication-only official JSON-RPC and REST routers.
///
/// # Security
/// Upstream `DefaultRequestHandler` loses explicit tenant scope after spawning;
/// this compatibility API is development-only and must not be used as a
/// multitenant production boundary. The production binary refuses this path.
pub fn build_authenticated_router<D>(
    config: GatewayConfig,
    dispatcher: D,
    auth: AuthState,
) -> Router
where
    D: MeshDispatcher,
{
    build_authenticated_router_inner(config, dispatcher, auth, None)
}

/// Compose authenticated protocol routers while preserving canonical runtime trace capture.
pub fn build_authenticated_router_with_trace<D>(
    config: GatewayConfig,
    dispatcher: D,
    auth: AuthState,
    trace: Arc<RuntimeEventCapture>,
) -> Router
where
    D: MeshDispatcher,
{
    build_authenticated_router_inner(config, dispatcher, auth, Some(trace))
}

fn build_authenticated_router_inner<D>(
    config: GatewayConfig,
    dispatcher: D,
    auth: AuthState,
    trace: Option<Arc<RuntimeEventCapture>>,
) -> Router
where
    D: MeshDispatcher,
{
    let max_body_bytes = config.max_body_bytes;
    let store = SharedTaskStore(Arc::new(BoundedTaskStore::new(config.max_tasks)));
    let policy = VersionedCompletionPolicy::default();
    let mut executor = SmeshExecutor::new(dispatcher, config.input_limits, config.gateway_node_id)
        .with_execution_limits(config.execution_limits)
        .with_completion_policy(policy.clone());
    if let Some(trace) = trace {
        executor = executor.with_runtime_trace(trace);
    }
    let executor = auth.wrap_executor(executor);
    let inner: Arc<dyn RequestHandler> =
        Arc::new(DefaultRequestHandler::new(executor, store.clone()));
    let guarded: Arc<dyn RequestHandler> =
        Arc::new(GuardedRequestHandler::new(inner, store, policy));
    let handler = auth.wrap_handler(guarded);
    let card = Arc::new(StaticAgentCard::new(build_secured_agent_card_with_policy(
        &config.public_base_url,
        auth.bearer_enabled(),
        auth.mutual_tls_enabled(),
        auth.mutual_tls_required(),
    )));
    let protected = Router::new()
        .nest(
            "/jsonrpc",
            a2a_server::jsonrpc::jsonrpc_router(handler.clone()),
        )
        .nest("/rest", a2a_server::rest::rest_router(handler))
        .layer(RequestBodyLimitLayer::new(max_body_bytes))
        .layer(middleware::from_fn_with_state(auth, authenticate_request));
    protected.merge(a2a_server::agent_card::agent_card_router(card))
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

/// Compose the compatibility/task-snapshot A2A router with SQLite-backed task state.
///
/// This builder still routes through the upstream `DefaultRequestHandler`; it does
/// not provide repository-owned durable dispatch or receiver effect replay. Use
/// `build_durable_loopback_gateway` for that production loopback boundary.
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

/// Compose the traced compatibility/task-snapshot router with SQLite-backed task state.
///
/// Like `build_router_with_sqlite`, this is not durable dispatch and does not
/// provide receiver effect idempotency or replay.
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
