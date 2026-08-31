use std::sync::Arc;
use std::time::Duration;

use a2a::{A2AError, ListTasksRequest, ListTasksResponse, Task};
use a2a_server::{DefaultRequestHandler, RequestHandler, StaticAgentCard, TaskStore};
use async_trait::async_trait;
use axum::body::Body;
use axum::extract::{Extension, OriginalUri, Path};
use axum::http::{HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse as _, Response};
use axum::routing::get;
use axum::{Router, middleware};
use tower_http::limit::RequestBodyLimitLayer;

use crate::{
    ArtifactGcHandle, ArtifactOrphanScannerHandle, ArtifactPromoterHandle, BoundedTaskStore,
    CompletionPolicySpec, DurableAuthority, DurableLoopbackEndpoint, ExecutionLimits,
    InjectedClock, InputLimits, IntoDurableAuthority, MeshDispatcher, Operation, OwnedTaskScope,
    PolicyError, RuntimeEventCapture, SmeshExecutor, SqliteTaskStore, VersionedCompletionPolicy,
    auth::{AuthState, authenticate_request},
    authorization::{AuthorizationMiddlewareState, AuthorizationPolicy, authorize_request},
    build_agent_card, build_secured_agent_card_with_policy,
    card::LiveAgentCard,
    content_digest,
    durable_authority::DurableAuthorityParts,
    durable_handler::DurableRequestHandler,
    guard::GuardedRequestHandler,
    outbox_driver::{
        DurableDriverHandle, spawn_durable_driver, spawn_durable_driver_with_telemetry,
    },
    spawn_artifact_gc, spawn_artifact_orphan_scanner, spawn_artifact_promoter,
    spawn_artifact_promoter_with_telemetry,
};

struct SharedTaskStore<S>(Arc<S>);

async fn quota_retry_after_header(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let mut response = next.run(request).await;
    if response.status() == StatusCode::TOO_MANY_REQUESTS {
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    }
    response
}

#[allow(clippy::too_many_lines)]
async fn artifact_resolver(
    method: Method,
    Path(artifact_id): Path<String>,
    OriginalUri(uri): OriginalUri,
    Extension(authority): Extension<Arc<dyn DurableAuthority>>,
    Extension(context): Extension<Arc<crate::AuthorizationContext>>,
    headers: axum::http::HeaderMap,
) -> Response {
    const NOT_FOUND: &str = "artifact not found";
    let Some(artifact_authority) = authority.artifact_authority() else {
        return (StatusCode::NOT_FOUND, NOT_FOUND).into_response();
    };
    if headers.contains_key(header::RANGE) {
        return (
            StatusCode::RANGE_NOT_SATISFIABLE,
            [(header::ACCEPT_RANGES, "none")],
            "range requests are unsupported",
        )
            .into_response();
    }
    if !matches!(method, Method::GET | Method::HEAD)
        || !canonical_artifact_resolver_request(&uri, &artifact_id)
        || context.authorize(Operation::ArtifactResolve).is_err()
    {
        return (StatusCode::NOT_FOUND, NOT_FOUND).into_response();
    }
    let Ok(visibility) = context.visibility(Operation::ArtifactResolve) else {
        return (StatusCode::NOT_FOUND, NOT_FOUND).into_response();
    };
    let Ok(scope) = OwnedTaskScope::new(context.tenant_id(), context.account_id(), visibility)
    else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let Ok(owner_digest) = authority.authorization_resource_digest(context.account_id()) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let Ok(resource_digest) = authority.authorization_resource_digest(&artifact_id) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| i64::try_from(value.as_millis()).ok())
        .unwrap_or(0);
    let Ok(subject) = crate::QuotaSubject::new(
        context.tenant_id(),
        context.account_id(),
        context.principal_scope(),
    ) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let decision_id = content_digest(&rand::random::<[u8; 32]>());
    let quota_intent = if let Some(policy) = authority.quota_policy_snapshot() {
        match policy.operation_intent(&subject, crate::QuotaOperation::TaskGet, &decision_id, 0) {
            Ok(intent) => Some(intent),
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        }
    } else {
        None
    };
    let Ok(audit) = crate::AuthorizationAuditInput::new(
        decision_id,
        context.tenant_id(),
        context.account_id(),
        context.policy_id(),
        context.policy_revision(),
        context.policy_digest(),
        "artifactResolve",
        crate::AuthorizationDecisionEffect::Deny,
        "preflight",
        "artifact",
        resource_digest,
        None,
        now,
    ) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let resolution = match artifact_authority
        .begin_artifact_resolution(
            &scope,
            &artifact_id,
            None,
            &owner_digest,
            artifact_authority
                .artifact_runtime_limits()
                .read_lease_millis,
            quota_intent.as_ref(),
            audit,
            now,
        )
        .await
    {
        Ok(Some(value)) => value,
        Ok(None) => return (StatusCode::NOT_FOUND, NOT_FOUND).into_response(),
        Err(error) => {
            return if error.code == -32_010 {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            }
            .into_response();
        }
    };
    let metadata = resolution.metadata();
    let Ok(bytes) = artifact_authority
        .read_artifact_resolution(&resolution)
        .await
    else {
        let _ = artifact_authority
            .finish_artifact_resolution(&resolution, 0, false)
            .await;
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if !matches!(
        artifact_authority
            .finish_artifact_resolution(&resolution, bytes.len() as u64, true)
            .await,
        Ok(true)
    ) {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let Ok(etag) = HeaderValue::from_str(&format!("\"{}\"", metadata.content_digest)) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let Ok(media) = HeaderValue::from_str(&metadata.media_type) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let Ok(length) = HeaderValue::from_str(&metadata.plaintext_length.to_string()) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let mut response = Response::new(if method == Method::HEAD {
        Body::empty()
    } else {
        Body::from(bytes)
    });
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(header::ETAG, etag);
    response.headers_mut().insert(header::CONTENT_TYPE, media);
    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, length);
    response
        .headers_mut()
        .insert(header::ACCEPT_RANGES, HeaderValue::from_static("none"));
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store, no-transform"),
    );
    response.headers_mut().insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn canonical_artifact_resolver_request(uri: &Uri, artifact_id: &str) -> bool {
    crate::artifact::validate_artifact_id(artifact_id).is_ok()
        && uri.query().is_none()
        && uri.path() == format!("/artifacts/v1/{artifact_id}")
}

/// A task store that declares whether completion receipts must use durable key material.
#[async_trait]
pub trait CompletionPolicyStore: TaskStore {
    /// Return the durable receipt key for persistent stores, or `None` for ephemeral stores.
    fn durable_receipt_key(&self) -> Option<[u8; 32]>;

    /// Whether `list` is a repository-owned, self-authenticating snapshot source.
    ///
    /// Generic implementations remain false and are checked against current `get`
    /// rows. The two repository stores return true because the guard calls their
    /// `list` method directly and they authenticate frozen pages internally.
    fn list_pages_are_self_authenticating(&self) -> bool {
        false
    }

    /// Validate that a list page originated from this authoritative store.
    ///
    /// Generic stores use current-row validation. Stores that issue frozen snapshots may
    /// override this hook for follow-up pages while retaining authoritative provenance.
    async fn validate_list_page(
        &self,
        request: &ListTasksRequest,
        response: &ListTasksResponse,
    ) -> Result<(), A2AError> {
        validate_current_list_page(self, request, response).await
    }
}

async fn validate_current_list_page<S: TaskStore + Sync + ?Sized>(
    store: &S,
    request: &ListTasksRequest,
    response: &ListTasksResponse,
) -> Result<(), A2AError> {
    for task in &response.tasks {
        let mut expected = store
            .get(&task.id)
            .await?
            .ok_or_else(|| A2AError::task_not_found(&task.id))?;
        if !request.include_artifacts.unwrap_or(false) {
            expected.artifacts = None;
        }
        if let Some(limit) = request
            .history_length
            .and_then(|value| usize::try_from(value).ok())
        {
            if limit == 0 {
                expected.history = None;
            } else if let Some(history) = expected.history.as_mut()
                && history.len() > limit
            {
                history.drain(..history.len() - limit);
            }
        }
        if &expected != task {
            return Err(A2AError::invalid_agent_response());
        }
    }
    Ok(())
}

#[async_trait]
impl CompletionPolicyStore for BoundedTaskStore {
    fn durable_receipt_key(&self) -> Option<[u8; 32]> {
        None
    }

    fn list_pages_are_self_authenticating(&self) -> bool {
        true
    }
}

#[async_trait]
impl CompletionPolicyStore for SqliteTaskStore {
    fn durable_receipt_key(&self) -> Option<[u8; 32]> {
        Some(self.completion_receipt_key())
    }

    fn list_pages_are_self_authenticating(&self) -> bool {
        true
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

#[async_trait]
impl<S> CompletionPolicyStore for SharedTaskStore<S>
where
    S: CompletionPolicyStore,
{
    fn durable_receipt_key(&self) -> Option<[u8; 32]> {
        self.0.durable_receipt_key()
    }

    fn list_pages_are_self_authenticating(&self) -> bool {
        self.0.list_pages_are_self_authenticating()
    }

    async fn validate_list_page(
        &self,
        request: &ListTasksRequest,
        response: &ListTasksResponse,
    ) -> Result<(), A2AError> {
        self.0.validate_list_page(request, response).await
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
    projector: Option<crate::telemetry::AuditProjectorWorker>,
    callback_worker: Option<crate::CallbackWorkerHandle>,
    push_readiness: Arc<crate::push::PushReadiness>,
    driver: Option<DurableDriverHandle>,
    promoter: Option<ArtifactPromoterHandle>,
    gc: Option<ArtifactGcHandle>,
    orphan_scanner: Option<ArtifactOrphanScannerHandle>,
    authority: Option<Arc<dyn DurableAuthority>>,
}

impl DurableGateway {
    #[must_use]
    pub fn push_readiness(&self) -> Arc<crate::push::PushReadiness> {
        Arc::clone(&self.push_readiness)
    }

    /// Transfer ownership of the required production callback worker.
    ///
    /// # Errors
    /// Returns an error if a worker is already owned or the readiness generation differs.
    pub fn own_callback_worker(
        &mut self,
        worker: crate::CallbackWorkerHandle,
    ) -> Result<(), A2AError> {
        if self.callback_worker.is_some() || !Arc::ptr_eq(worker.readiness(), &self.push_readiness)
        {
            return Err(A2AError::internal("callback worker ownership mismatch"));
        }
        self.callback_worker = Some(worker);
        Ok(())
    }

    /// Start the optional projector after both the authority and OTLP owner exist.
    ///
    /// # Errors
    /// Returns an error for invalid configuration or a failed worker spawn.
    pub fn start_audit_projector(
        &mut self,
        telemetry: crate::telemetry::TelemetryHandle,
        config: crate::telemetry::AuditProjectorConfig,
    ) -> Result<bool, crate::telemetry::AuditProjectorError> {
        if self.projector.is_some() {
            return Ok(true);
        }
        let authority = self
            .authority
            .as_ref()
            .ok_or(crate::telemetry::AuditProjectorError::Unsupported)?;
        if authority.audit_projection_authority().is_none() {
            return Ok(false);
        }
        self.projector = Some(crate::telemetry::AuditProjectorWorker::spawn(
            Arc::clone(authority),
            telemetry,
            config,
        )?);
        Ok(true)
    }
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
        self.authority
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
        let callback_result = if let Some(worker) = self.callback_worker.take() {
            worker.shutdown(Duration::from_secs(5)).await
        } else {
            Ok(())
        };
        if callback_result.is_err() {
            self.push_readiness.mark_fatal();
            eprintln!("smesh.callback.shutdown_failed category=worker");
        }
        let projector_result = if let Some(projector) = self.projector.take() {
            projector.shutdown(Duration::from_secs(5)).await
        } else {
            Ok(())
        };
        if projector_result.is_err() {
            eprintln!("smesh.telemetry.shutdown_failed category=audit_projector");
        }
        let driver = self
            .driver
            .take()
            .ok_or_else(|| A2AError::internal("durable gateway is already shut down"))?;
        let authority = self
            .authority
            .take()
            .ok_or_else(|| A2AError::internal("durable gateway is already shut down"))?;
        let driver_result = driver.shutdown().await;
        let promoter_result = if let Some(promoter) = self.promoter.take() {
            promoter.shutdown().await
        } else {
            Ok(())
        };
        let gc_result = if let Some(gc) = self.gc.take() {
            gc.shutdown().await
        } else {
            Ok(())
        };
        let orphan_result = if let Some(orphan_scanner) = self.orphan_scanner.take() {
            orphan_scanner.shutdown().await
        } else {
            Ok(())
        };
        // Closing shared state invalidates handler/router clones and drops both
        // SQLite and the process ownership lock before shutdown returns.
        let authority_result = authority.shutdown().await;
        self.router.take();
        // A callback panic is already contained: readiness stays fatal, every
        // callback task has been joined, and no further callback mutation can
        // be admitted. Preserve that health evidence without converting an
        // otherwise graceful process shutdown into failure.
        drop(callback_result);
        driver_result?;
        promoter_result?;
        gc_result?;
        orphan_result?;
        authority_result?;
        projector_result.map_err(|_| A2AError::internal("optional telemetry shutdown failed"))?;
        Ok(())
    }
}

impl Drop for DurableGateway {
    fn drop(&mut self) {
        // Drop cannot async-join. Dropping the driver requests cooperative
        // cancellation and transfers its abort-on-drop root join into a bounded
        // Tokio reaper. Closing the authority then rejects new work and closes
        // durable pools; explicit shutdown remains authoritative and joins inline.
        self.projector.take();
        self.callback_worker.take();
        self.driver.take();
        self.promoter.take();
        self.gc.take();
        self.orphan_scanner.take();
        if let Some(authority) = self.authority.as_ref() {
            authority.close_owned_sync();
        }
        self.authority.take();
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
pub fn build_durable_loopback_gateway<A: IntoDurableAuthority>(
    config: GatewayConfig,
    store: A,
    endpoint: DurableLoopbackEndpoint,
    clock: InjectedClock,
) -> Result<DurableGateway, PolicyError> {
    build_durable_loopback_gateway_with_telemetry(config, store, endpoint, clock, None)
}

/// Build the repository-owned durable gateway with an optional telemetry handle.
///
/// # Errors
/// Returns an error if durable gateway policy construction fails.
pub fn build_durable_loopback_gateway_with_telemetry<A: IntoDurableAuthority>(
    config: GatewayConfig,
    store: A,
    endpoint: DurableLoopbackEndpoint,
    clock: InjectedClock,
    telemetry: Option<crate::telemetry::TelemetryHandle>,
) -> Result<DurableGateway, PolicyError> {
    let parts = store.into_durable_authority_parts();
    Ok(build_durable_gateway_inner(
        config, parts, endpoint, clock, None, None, telemetry,
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
pub fn build_authenticated_durable_loopback_gateway<A: IntoDurableAuthority>(
    config: GatewayConfig,
    store: A,
    endpoint: DurableLoopbackEndpoint,
    clock: InjectedClock,
    auth: AuthState,
) -> Result<DurableGateway, PolicyError> {
    let parts = store.into_durable_authority_parts();
    Ok(build_durable_gateway_inner(
        config,
        parts,
        endpoint,
        clock,
        Some(auth),
        None,
        None,
    ))
}

/// Build the authenticated durable gateway with server-owned tenant policy.
/// This is the only authenticated builder intended for production use.
///
/// # Errors
/// Returns an error if durable gateway policy construction fails.
pub fn build_authorized_durable_loopback_gateway<A: IntoDurableAuthority>(
    config: GatewayConfig,
    store: A,
    endpoint: DurableLoopbackEndpoint,
    clock: InjectedClock,
    auth: AuthState,
    policy: Arc<AuthorizationPolicy>,
) -> Result<DurableGateway, PolicyError> {
    let authority = store.into_durable_authority();
    Ok(build_durable_gateway_inner(
        config,
        DurableAuthorityParts {
            authority,
            local: None,
        },
        endpoint,
        clock,
        Some(auth),
        Some(policy),
        None,
    ))
}

/// Build the production authorized durable gateway with an optional telemetry handle.
///
/// # Errors
/// Returns an error if durable gateway policy construction fails.
pub fn build_authorized_durable_loopback_gateway_with_telemetry<A: IntoDurableAuthority>(
    config: GatewayConfig,
    store: A,
    endpoint: DurableLoopbackEndpoint,
    clock: InjectedClock,
    auth: AuthState,
    policy: Arc<AuthorizationPolicy>,
    telemetry: Option<crate::telemetry::TelemetryHandle>,
) -> Result<DurableGateway, PolicyError> {
    let authority = store.into_durable_authority();
    Ok(build_durable_gateway_inner(
        config,
        DurableAuthorityParts {
            authority,
            local: None,
        },
        endpoint,
        clock,
        Some(auth),
        Some(policy),
        telemetry,
    ))
}

#[allow(clippy::too_many_lines)]
fn build_durable_gateway_inner(
    config: GatewayConfig,
    parts: DurableAuthorityParts,
    endpoint: DurableLoopbackEndpoint,
    clock: InjectedClock,
    auth: Option<AuthState>,
    authorization: Option<Arc<AuthorizationPolicy>>,
    telemetry: Option<crate::telemetry::TelemetryHandle>,
) -> DurableGateway {
    let DurableAuthorityParts { authority, local } = parts;
    let GatewayConfig {
        public_base_url,
        input_limits,
        max_body_bytes,
        ..
    } = config;
    let endpoint = endpoint.with_telemetry(telemetry.clone());
    let driver = if telemetry.is_some() {
        spawn_durable_driver_with_telemetry(
            Arc::clone(&authority),
            endpoint,
            clock.clone(),
            telemetry.clone(),
        )
    } else {
        spawn_durable_driver(Arc::clone(&authority), endpoint, clock.clone())
    };
    let push_readiness = Arc::new(crate::push::PushReadiness::new());
    let jsonrpc_handler = Arc::new(
        DurableRequestHandler::new_with_local(
            Arc::clone(&authority),
            local.clone(),
            driver.control(),
            clock.clone(),
            input_limits,
        )
        .with_telemetry(telemetry.clone())
        .with_push_readiness(Arc::clone(&push_readiness)),
    );
    let rest_handler = Arc::new(
        DurableRequestHandler::new_with_local(
            Arc::clone(&authority),
            local,
            driver.control(),
            clock.clone(),
            input_limits,
        )
        .with_errors_before_stream()
        .with_telemetry(telemetry.clone())
        .with_push_readiness(Arc::clone(&push_readiness)),
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
    let card = Arc::new(LiveAgentCard::new(
        durable_card,
        Arc::clone(&push_readiness),
    ));
    let protocol = if let Some(auth) = auth {
        let jsonrpc = auth.wrap_handler(jsonrpc_handler);
        let rest = auth.wrap_handler(rest_handler);
        let artifacts = Router::new()
            .route(
                "/artifacts/v1/{artifact_id}",
                get(artifact_resolver).head(artifact_resolver),
            )
            .layer(Extension(Arc::clone(&authority)));
        let protocol = Router::new()
            .nest("/jsonrpc", a2a_server::jsonrpc::jsonrpc_router(jsonrpc))
            .nest("/rest", a2a_server::rest::rest_router(rest))
            .merge(artifacts)
            .layer(RequestBodyLimitLayer::new(max_body_bytes));
        let protocol = if let Some(policy) = authorization {
            let state =
                AuthorizationMiddlewareState::with_audit(policy, Arc::clone(&authority), clock);
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
    let protocol = protocol.layer(middleware::from_fn(quota_retry_after_header));
    let router = protocol.merge(a2a_server::agent_card::agent_card_router(card));
    let promoter = if telemetry.is_some() {
        spawn_artifact_promoter_with_telemetry(Arc::clone(&authority), telemetry)
    } else {
        spawn_artifact_promoter(Arc::clone(&authority))
    };
    let gc = spawn_artifact_gc(Arc::clone(&authority));
    let orphan_scanner = spawn_artifact_orphan_scanner(Arc::clone(&authority));
    DurableGateway {
        router: Some(router),
        projector: None,
        callback_worker: None,
        push_readiness,
        driver: Some(driver),
        promoter,
        gc,
        orphan_scanner,
        authority: Some(authority),
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
    S: CompletionPolicyStore,
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
    S: CompletionPolicyStore,
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

#[cfg(test)]
mod artifact_resolver_path_tests {
    use axum::http::Uri;

    use super::canonical_artifact_resolver_request;

    #[test]
    fn resolver_rejects_noncanonical_and_authority_alias_paths() {
        for uri in [
            "/artifacts/v1/a%23b",
            "/artifacts/v1/a%3Fb",
            "/artifacts/v1/a%2Fb",
            "/artifacts/v1/%2E",
            "/artifacts/v1/%2E%2E",
            "/artifacts/v1/%61",
            "/artifacts/v1/a?b",
        ] {
            let uri: Uri = uri.parse().unwrap();
            assert!(
                !canonical_artifact_resolver_request(&uri, "a"),
                "resolver accepted alternate lookup authority {uri}"
            );
        }
        let canonical: Uri = "/artifacts/v1/artifact-0123_ab.~".parse().unwrap();
        assert!(canonical_artifact_resolver_request(
            &canonical,
            "artifact-0123_ab.~"
        ));
    }
}
