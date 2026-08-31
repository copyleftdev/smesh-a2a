use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use a2a::{
    A2AError, AgentCard, CancelTaskRequest, DeleteTaskPushNotificationConfigRequest,
    GetExtendedAgentCardRequest, GetTaskPushNotificationConfigRequest, GetTaskRequest,
    ListTaskPushNotificationConfigsRequest, ListTaskPushNotificationConfigsResponse,
    ListTasksRequest, ListTasksResponse, SendMessageRequest, SendMessageResponse, StreamResponse,
    SubscribeToTaskRequest, Task, TaskPushNotificationConfig, TaskState, TaskStatus,
};
use a2a_server::{RequestHandler, ServiceParams};
use async_trait::async_trait;
use futures::{
    StreamExt,
    stream::{self, BoxStream},
};
#[cfg(test)]
use tokio::sync::Notify;

use crate::{
    AdmissionOutcome, AuthorizationAuditInput, AuthorizationContext, AuthorizationDecisionEffect,
    AuthorizedMutation, CancellationOutcome, DurableAuthority, InjectedClock, InputLimits,
    OwnedTaskScope, SendMessageAdmission, SubscriptionCursor,
    authorization::{Operation, current_authorization_context, current_quota_reservation},
    content_digest,
    durable_authority::LocalDevelopmentCompatibility,
    outbox_driver::{DurableDriverControl, WaiterGuard},
};

fn authorized_mutation(
    store: &dyn DurableAuthority,
    command: SendMessageAdmission,
    operation: crate::QuotaOperation,
) -> Result<AuthorizedMutation<SendMessageAdmission>, A2AError> {
    if let Some(quota) = current_quota_reservation() {
        return Ok(AuthorizedMutation::with_quota(command, quota));
    }
    let Some(policy) = store.quota_policy_snapshot() else {
        return Ok(AuthorizedMutation::without_quota(command));
    };
    let context =
        current_authorization_context().ok_or_else(crate::quota::quota_authority_unavailable)?;
    let subject = crate::QuotaSubject::new(
        context.tenant_id(),
        context.account_id(),
        context.principal_scope(),
    )
    .map_err(|_| crate::quota::quota_authority_unavailable())?;
    let input_bytes = u64::try_from(
        serde_json::to_vec(&command.request)
            .map_err(|_| A2AError::internal("failed to measure quota input"))?
            .len(),
    )
    .map_err(|_| A2AError::invalid_request("quota input is too large"))?;
    let semantic_id = command.request.message.message_id.clone();
    let intent = policy
        .operation_intent(&subject, operation, &semantic_id, input_bytes)
        .map_err(|_| crate::quota::quota_authority_unavailable())?;
    Ok(AuthorizedMutation::with_quota_intent(command, intent))
}

fn quota_operation_intent(
    store: &dyn DurableAuthority,
    context: &AuthorizationContext,
    operation: crate::QuotaOperation,
    semantic_id: &str,
) -> Result<Option<crate::QuotaIntent>, A2AError> {
    let Some(policy) = store.quota_policy_snapshot() else {
        return Ok(None);
    };
    let subject = crate::QuotaSubject::new(
        context.tenant_id(),
        context.account_id(),
        context.principal_scope(),
    )
    .map_err(|_| crate::quota::quota_authority_unavailable())?;
    policy
        .operation_intent(&subject, operation, semantic_id, 0)
        .map(Some)
        .map_err(|_| crate::quota::quota_authority_unavailable())
}

async fn charge_public_egress<T: serde::Serialize>(
    store: &Arc<dyn DurableAuthority>,
    context: Option<&AuthorizationContext>,
    now: i64,
    value: &T,
    events: u64,
) -> Result<(), A2AError> {
    let Some(policy) = store.quota_policy_snapshot() else {
        return Ok(());
    };
    let context = context.ok_or_else(crate::quota::quota_authority_unavailable)?;
    let encoded = serde_json::to_vec(value)
        .map_err(|_| A2AError::internal("failed to serialize public quota egress"))?;
    let bytes = u64::try_from(encoded.len())
        .map_err(|_| A2AError::invalid_request("public quota egress is too large"))?;
    let subject = crate::QuotaSubject::new(
        context.tenant_id(),
        context.account_id(),
        context.principal_scope(),
    )
    .map_err(|_| crate::quota::quota_authority_unavailable())?;
    let entropy: [u8; 32] = rand::random();
    let semantic_id = content_digest([encoded.as_slice(), &entropy].concat().as_slice());
    let intent = policy
        .egress_intent(&subject, &semantic_id, bytes, events)
        .map_err(|_| crate::quota::quota_authority_unavailable())?;
    tokio::time::timeout(
        QUOTA_LEASE_CALL_TIMEOUT,
        store.charge_quota_egress(&intent, now),
    )
    .await
    .map_err(|_| crate::quota::quota_authority_unavailable())??;
    Ok(())
}

const QUOTA_LEASE_DURATION_MILLIS: i64 = 30_000;
const QUOTA_LEASE_RENEW_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
const QUOTA_LEASE_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

struct QuotaLeaseGuard {
    store: Arc<dyn DurableAuthority>,
    lease: Arc<Mutex<crate::QuotaLease>>,
    clock: InjectedClock,
    cancellation: tokio_util::sync::CancellationToken,
    renewal: Mutex<Option<tokio::task::JoinHandle<()>>>,
    failure: Arc<Mutex<Option<A2AError>>>,
}

impl QuotaLeaseGuard {
    fn start(
        store: Arc<dyn DurableAuthority>,
        lease: crate::QuotaLease,
        clock: InjectedClock,
    ) -> Arc<Self> {
        let lease = Arc::new(Mutex::new(lease));
        let cancellation = tokio_util::sync::CancellationToken::new();
        let failure = Arc::new(Mutex::new(None));
        let guard = Arc::new(Self {
            store: Arc::clone(&store),
            lease: Arc::clone(&lease),
            clock: clock.clone(),
            cancellation: cancellation.clone(),
            renewal: Mutex::new(None),
            failure: Arc::clone(&failure),
        });
        let renewal = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = cancellation.cancelled() => break,
                    () = tokio::time::sleep(QUOTA_LEASE_RENEW_INTERVAL) => {}
                }
                let current = if let Ok(lease) = lease.lock() {
                    lease.clone()
                } else {
                    if let Ok(mut slot) = failure.lock() {
                        *slot = Some(A2AError::internal("quota lease state failed"));
                    }
                    break;
                };
                let outcome = tokio::time::timeout(
                    QUOTA_LEASE_CALL_TIMEOUT,
                    store.renew_quota_lease(&current, clock.now(), QUOTA_LEASE_DURATION_MILLIS),
                )
                .await;
                let Ok(Ok(crate::LeaseRenewalOutcome::Applied { lease_until })) = outcome else {
                    if let Ok(mut slot) = failure.lock() {
                        *slot = Some(crate::quota::quota_authority_unavailable());
                    }
                    break;
                };
                if let Ok(mut lease) = lease.lock() {
                    lease.lease_until = lease_until;
                } else {
                    if let Ok(mut slot) = failure.lock() {
                        *slot = Some(A2AError::internal("quota lease state failed"));
                    }
                    break;
                }
            }
        });
        *guard
            .renewal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(renewal);
        guard
    }

    fn failure(&self) -> Option<A2AError> {
        match self.failure.lock() {
            Ok(failure) => failure.clone(),
            Err(_) => Some(A2AError::internal("quota lease failure state failed")),
        }
    }
}

impl Drop for QuotaLeaseGuard {
    fn drop(&mut self) {
        self.cancellation.cancel();
        let renewal = self
            .renewal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let lease = self
            .lease
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let store = Arc::clone(&self.store);
        let now = self.clock.now();
        tokio::spawn(async move {
            if let Some(renewal) = renewal {
                let _ = renewal.await;
            }
            let _ = tokio::time::timeout(
                QUOTA_LEASE_CALL_TIMEOUT,
                store.release_quota_lease(&lease, now),
            )
            .await;
        });
    }
}

struct DurableStreamState {
    store: Arc<dyn DurableAuthority>,
    local: Option<Arc<dyn LocalDevelopmentCompatibility>>,
    driver_state: tokio::sync::watch::Receiver<crate::outbox_driver::DriverState>,
    poll_interval: crate::PollInterval,
    _waiter: WaiterGuard,
    message_id: String,
    last_sequence: usize,
    pending: VecDeque<StreamResponse>,
    closed: bool,
    finished: bool,
    interruption: Option<String>,
    history_length: Option<i32>,
    emit_stream_errors: bool,
    authorization: Option<AuthorizationContext>,
    scope: Option<OwnedTaskScope>,
    quota_lease: Option<Arc<QuotaLeaseGuard>>,
    clock: InjectedClock,
    telemetry_context: Option<crate::telemetry::RequestTelemetryContext>,
}

struct DurableTaskEventStreamState {
    store: Arc<dyn DurableAuthority>,
    local: Option<Arc<dyn LocalDevelopmentCompatibility>>,
    driver_state: tokio::sync::watch::Receiver<crate::outbox_driver::DriverState>,
    poll_interval: crate::PollInterval,
    _waiter: WaiterGuard,
    task_id: String,
    last_revision: u64,
    pending: VecDeque<StreamResponse>,
    closed: bool,
    emit_stream_errors: bool,
    authorization: Option<AuthorizationContext>,
    scope: Option<OwnedTaskScope>,
    quota_lease: Option<Arc<QuotaLeaseGuard>>,
    clock: InjectedClock,
    telemetry_context: Option<crate::telemetry::RequestTelemetryContext>,
}

pub(crate) struct DurableRequestHandler {
    store: Arc<dyn DurableAuthority>,
    local: Option<Arc<dyn LocalDevelopmentCompatibility>>,
    driver: Arc<DurableDriverControl>,
    clock: InjectedClock,
    input_limits: InputLimits,
    errors_before_stream: bool,
    telemetry: Option<crate::telemetry::TelemetryHandle>,
    push_readiness: Option<Arc<crate::push::PushReadiness>>,
    #[cfg(test)]
    after_empty_read: Option<(Arc<Notify>, Arc<Notify>)>,
}

impl DurableRequestHandler {
    async fn authorization_for(
        &self,
        operation: Operation,
        resource_kind: &str,
        resource: &str,
    ) -> Result<Option<(AuthorizationContext, OwnedTaskScope)>, A2AError> {
        let Some(context) = current_authorization_context() else {
            return Ok(None);
        };
        let Ok(visibility) = context.visibility(operation) else {
            let audit = self
                .audit(&context, operation, resource_kind, resource)?
                .decided(AuthorizationDecisionEffect::Deny, "role_denied", None);
            self.store
                .append_denied_authorization_decision(audit)
                .await?;
            if let Some(telemetry) = &self.telemetry {
                telemetry.authorization_decision("denied", "role_denied", "authorize");
            }
            return Err(A2AError::invalid_request("forbidden"));
        };
        let scope = OwnedTaskScope::new_with_principal(
            context.tenant_id(),
            context.account_id(),
            context.principal_scope(),
            visibility,
        )?;
        Ok(Some((context, scope)))
    }

    fn audit(
        &self,
        context: &AuthorizationContext,
        operation: Operation,
        resource_kind: &str,
        resource: &str,
    ) -> Result<AuthorizationAuditInput, A2AError> {
        let resource_digest = self.store.authorization_resource_digest(resource)?;
        let entropy: [u8; 32] = rand::random();
        let operation_name = format!("{operation:?}");
        let decision_id = content_digest(
            [
                context.tenant_id().as_bytes(),
                context.account_id().as_bytes(),
                operation_name.as_bytes(),
                resource_digest.as_bytes(),
                &entropy,
            ]
            .concat()
            .as_slice(),
        );
        AuthorizationAuditInput::new(
            decision_id,
            context.tenant_id(),
            context.account_id(),
            context.policy_id(),
            context.policy_revision(),
            context.policy_digest(),
            operation_name,
            AuthorizationDecisionEffect::Allow,
            "policy_grant",
            resource_kind,
            resource_digest,
            None,
            self.clock.now(),
        )
    }

    async fn acquire_quota_stream_lease(
        &self,
        context: Option<&AuthorizationContext>,
        kind: crate::QuotaLeaseKind,
        resource: &str,
        reconnect: bool,
    ) -> Result<Option<Arc<QuotaLeaseGuard>>, A2AError> {
        let Some(policy) = self.store.quota_policy_snapshot() else {
            return Ok(None);
        };
        let context = context.ok_or_else(crate::quota::quota_authority_unavailable)?;
        let subject = crate::QuotaSubject::new(
            context.tenant_id(),
            context.account_id(),
            context.principal_scope(),
        )
        .map_err(|_| crate::quota::quota_authority_unavailable())?;
        let entropy: [u8; 32] = rand::random();
        let semantic_id = content_digest(
            [kind.as_str().as_bytes(), resource.as_bytes(), &entropy]
                .concat()
                .as_slice(),
        );
        let intent = policy
            .lease_intent(&subject, kind, &semantic_id, reconnect)
            .map_err(|_| crate::quota::quota_authority_unavailable())?;
        let resource_digest = self.store.authorization_resource_digest(resource)?;
        let lease = match tokio::time::timeout(
            QUOTA_LEASE_CALL_TIMEOUT,
            self.store.acquire_quota_lease(
                &intent,
                kind,
                &resource_digest,
                self.clock.now(),
                QUOTA_LEASE_DURATION_MILLIS,
            ),
        )
        .await
        {
            Ok(Ok(lease)) => {
                if let Some(telemetry) = &self.telemetry {
                    telemetry.quota_decision("ok", "lease_acquire");
                }
                lease
            }
            Ok(Err(error)) => {
                if let Some(telemetry) = &self.telemetry {
                    telemetry.quota_decision(
                        if error.code == a2a::error_code::QUOTA_EXCEEDED {
                            "quota_exceeded"
                        } else {
                            "unavailable"
                        },
                        "lease_acquire",
                    );
                }
                return Err(error);
            }
            Err(_) => {
                if let Some(telemetry) = &self.telemetry {
                    telemetry.quota_decision("unavailable", "lease_acquire");
                }
                return Err(crate::quota::quota_authority_unavailable());
            }
        };
        Ok(Some(QuotaLeaseGuard::start(
            Arc::clone(&self.store),
            lease,
            self.clock.clone(),
        )))
    }

    async fn audit_unsupported(
        &self,
        operation: Operation,
        resource_kind: &str,
        resource: &str,
    ) -> Result<(), A2AError> {
        let Some((context, _)) = self
            .authorization_for(operation, resource_kind, resource)
            .await?
        else {
            return Ok(());
        };
        self.store
            .append_authorization_decision(self.audit(
                &context,
                operation,
                resource_kind,
                resource,
            )?)
            .await
    }

    async fn canonicalize_continuation(
        &self,
        request: &mut SendMessageRequest,
        authorization: Option<&(AuthorizationContext, OwnedTaskScope)>,
    ) -> Result<Option<Task>, A2AError> {
        let Some(task_id) = request.message.task_id.as_deref() else {
            return Ok(None);
        };
        let task = if let Some((context, scope)) = authorization {
            self.store
                .get_authorized(
                    scope,
                    task_id,
                    self.audit(context, Operation::TaskContinue, "task", task_id)?,
                )
                .await?
        } else {
            self.local()?.get(task_id).await?
        }
        .ok_or_else(|| {
            A2AError::task_not_found(if authorization.is_some() {
                "resource"
            } else {
                task_id
            })
        })?;
        if let Some(context_id) = request.message.context_id.as_deref() {
            if context_id != task.context_id {
                return Err(A2AError::invalid_params("continuation contextId mismatch"));
            }
        } else {
            request.message.context_id = Some(task.context_id.clone());
        }
        Ok(Some(task))
    }

    #[cfg(test)]
    pub(crate) fn new<A: crate::IntoDurableAuthority>(
        store: A,
        driver: Arc<DurableDriverControl>,
        clock: InjectedClock,
        input_limits: InputLimits,
    ) -> Self {
        let parts = store.into_durable_authority_parts();
        Self::new_with_local(parts.authority, parts.local, driver, clock, input_limits)
    }

    pub(crate) fn new_with_local(
        store: Arc<dyn DurableAuthority>,
        local: Option<Arc<dyn LocalDevelopmentCompatibility>>,
        driver: Arc<DurableDriverControl>,
        clock: InjectedClock,
        input_limits: InputLimits,
    ) -> Self {
        Self {
            store,
            local,
            driver,
            clock,
            input_limits,
            errors_before_stream: false,
            telemetry: None,
            push_readiness: None,
            #[cfg(test)]
            after_empty_read: None,
        }
    }

    fn local(&self) -> Result<&Arc<dyn LocalDevelopmentCompatibility>, A2AError> {
        self.local
            .as_ref()
            .ok_or_else(|| A2AError::internal("local development compatibility is unavailable"))
    }

    pub(crate) fn with_errors_before_stream(mut self) -> Self {
        self.errors_before_stream = true;
        self
    }

    pub(crate) fn with_telemetry(
        mut self,
        telemetry: Option<crate::telemetry::TelemetryHandle>,
    ) -> Self {
        self.telemetry = telemetry;
        self
    }

    pub(crate) fn with_push_readiness(
        mut self,
        readiness: Arc<crate::push::PushReadiness>,
    ) -> Self {
        self.push_readiness = Some(readiness);
        self
    }

    fn ensure_driver_healthy(&self) -> Result<(), A2AError> {
        if let Some(failure) = self.driver.subscribe().borrow().failure.clone() {
            return Err(A2AError::internal(failure));
        }
        Ok(())
    }

    fn preflight_stream_error(
        &self,
        error: A2AError,
    ) -> Result<BoxStream<'static, Result<StreamResponse, A2AError>>, A2AError> {
        if self.errors_before_stream
            || matches!(
                error.code,
                a2a::error_code::QUOTA_EXCEEDED | a2a::error_code::QUOTA_AUTHORITY_UNAVAILABLE
            )
        {
            Err(error)
        } else {
            Ok(Box::pin(stream::once(async move { Err(error) })))
        }
    }

    #[cfg(test)]
    pub(crate) fn with_after_empty_read_gate(
        mut self,
        reached: Arc<Notify>,
        release: Arc<Notify>,
    ) -> Self {
        self.after_empty_read = Some((reached, release));
        self
    }

    pub(crate) async fn wait_for_result(
        &self,
        message_id: &str,
        scope: Option<&OwnedTaskScope>,
    ) -> Result<SendMessageResponse, A2AError> {
        let _waiter = self.driver.waiter();
        // Subscribe before the durable read. Notifications are only hints; the
        // bounded poll interval also observes commits made by another process.
        let mut state = self.driver.subscribe();
        let poll_interval = self.store.change_observation().poll_interval();
        loop {
            let result = if let Some(scope) = scope {
                self.store
                    .final_result_scoped(scope.tenant_scope(), message_id)
                    .await?
            } else {
                self.local()?.final_result(message_id).await?
            };
            if let Some(result) = result {
                return Ok(result);
            }
            #[cfg(test)]
            if let Some((reached, release)) = &self.after_empty_read {
                reached.notify_one();
                release.notified().await;
            }
            if let Some(failure) = &state.borrow().failure {
                return Err(A2AError::internal(failure.clone()));
            }
            tokio::select! {
                changed = state.changed() => changed
                    .map_err(|_| A2AError::internal("durable outbox driver stopped"))?,
                () = tokio::time::sleep(poll_interval.as_duration()) => {},
            }
        }
    }

    fn reject_message_options(request: &SendMessageRequest) -> Result<(), A2AError> {
        if request.tenant.is_some() {
            return Err(A2AError::invalid_params(
                "tenant is not supported by the single-tenant gateway",
            ));
        }
        if request
            .configuration
            .as_ref()
            .and_then(|configuration| configuration.accepted_output_modes.as_ref())
            .is_some_and(|modes| !modes.iter().any(|mode| mode == "application/json"))
        {
            return Err(A2AError::invalid_params(
                "acceptedOutputModes must include application/json",
            ));
        }
        if request
            .configuration
            .as_ref()
            .and_then(|configuration| configuration.history_length)
            .is_some_and(|length| length < 0)
        {
            return Err(A2AError::invalid_params(
                "historyLength must be a non-negative integer",
            ));
        }
        Ok(())
    }

    async fn inline_callback_intent(
        &self,
        request: &SendMessageRequest,
        authorization: Option<&(AuthorizationContext, OwnedTaskScope)>,
    ) -> Result<Option<crate::callback_authority::CallbackIntent>, A2AError> {
        let Some(config) = request
            .configuration
            .as_ref()
            .and_then(|c| c.task_push_notification_config.as_ref())
        else {
            return Ok(None);
        };
        let Some(authority) = self.store.callback_authority() else {
            return Err(A2AError::push_notification_not_supported());
        };
        if self
            .push_readiness
            .as_ref()
            .is_some_and(|readiness| !readiness.is_ready())
        {
            return Err(A2AError::internal(
                "callback delivery worker is unavailable",
            ));
        }
        if request.message.task_id.is_some()
            || !config.task_id.is_empty()
            || config.tenant.is_some()
            || config.token.is_some()
            || config.authentication.is_some()
        {
            return Err(A2AError::invalid_params(
                "invalid inline callback configuration",
            ));
        }
        let (_, scope) = authorization.ok_or_else(|| A2AError::invalid_request("forbidden"))?;
        let enrollment = authority
            .resolve_callback_enrollment(scope, &config.url)
            .await?
            .ok_or_else(|| A2AError::invalid_params("callback enrollment is not authorized"))?;
        let config_id = config
            .id
            .as_deref()
            .map(crate::CallbackConfigId::new)
            .transpose()?;
        Ok(Some(crate::callback_authority::CallbackIntent {
            config_id,
            enrollment,
        }))
    }

    fn admission_task(
        &self,
        request: &SendMessageRequest,
        authorization: Option<&(AuthorizationContext, OwnedTaskScope)>,
    ) -> Result<Task, A2AError> {
        if request.message.message_id.is_empty() {
            return Err(A2AError::invalid_params(
                "messageId is required for durable admission",
            ));
        }
        let identity = if let Some((context, _)) = authorization {
            content_digest(
                format!(
                    "task-v2\0{}\0{}\0{}",
                    context.tenant_id(),
                    context.account_id(),
                    request.message.message_id,
                )
                .as_bytes(),
            )
        } else {
            content_digest(request.message.message_id.as_bytes())
        };
        let task_id = request
            .message
            .task_id
            .clone()
            .unwrap_or_else(|| format!("task-{}", &identity[..32]));
        let context_id = request
            .message
            .context_id
            .clone()
            .unwrap_or_else(|| format!("context-{}", &identity[32..]));
        Ok(Task {
            id: task_id,
            context_id,
            status: TaskStatus {
                state: TaskState::Submitted,
                message: None,
                timestamp: chrono::DateTime::from_timestamp_millis(self.clock.now()),
            },
            artifacts: None,
            history: Some(vec![request.message.clone()]),
            metadata: None,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn stream_from_message(
        &self,
        message_id: String,
        last_sequence: usize,
        pending: VecDeque<StreamResponse>,
        history_length: Option<i32>,
        authorization: Option<(AuthorizationContext, OwnedTaskScope)>,
        quota_lease: Option<Arc<QuotaLeaseGuard>>,
    ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
        let (context, scope) = authorization.unzip();
        let state = DurableStreamState {
            store: self.store.clone(),
            local: self.local.clone(),
            driver_state: self.driver.subscribe(),
            poll_interval: self.store.change_observation().poll_interval(),
            _waiter: self.driver.waiter(),
            message_id,
            last_sequence,
            pending,
            closed: false,
            finished: false,
            interruption: None,
            history_length,
            emit_stream_errors: !self.errors_before_stream,
            authorization: context,
            scope,
            quota_lease,
            clock: self.clock.clone(),
            telemetry_context: crate::telemetry::capture_request_telemetry_context(),
        };
        Box::pin(stream::unfold(state, |mut state| async move {
            let telemetry_context = state.telemetry_context.clone();
            crate::telemetry::scope_request_telemetry_context(telemetry_context, async move {
                loop {
                    if state.finished {
                        return None;
                    }
                    if let Some(error) =
                        state.quota_lease.as_ref().and_then(|lease| lease.failure())
                    {
                        state.finished = true;
                        return Some((Err(error), state));
                    }
                    if let Some(frame) = state.pending.pop_front() {
                        if let Err(error) = charge_public_egress(
                            &state.store,
                            state.authorization.as_ref(),
                            state.clock.now(),
                            &frame,
                            1,
                        )
                        .await
                        {
                            state.finished = true;
                            return Some((Err(error), state));
                        }
                        state.last_sequence += 1;
                        return Some((Ok(frame), state));
                    }
                    if state.closed {
                        state.finished = true;
                        if !state.emit_stream_errors {
                            return None;
                        }
                        return state
                            .interruption
                            .take()
                            .map(|error| (Err(A2AError::internal(error)), state));
                    }
                    let batch = match if let Some(scope) = state.scope.as_ref() {
                        state
                            .store
                            .stream_frames_after_scoped(
                                scope.tenant_scope(),
                                &state.message_id,
                                state.last_sequence,
                            )
                            .await
                    } else if let Some(local) = state.local.as_ref() {
                        local
                            .stream_frames_after(&state.message_id, state.last_sequence)
                            .await
                    } else {
                        Err(A2AError::internal(
                            "local development compatibility is unavailable",
                        ))
                    } {
                        Ok(batch) => batch,
                        Err(error) => {
                            state.finished = true;
                            if !state.emit_stream_errors {
                                return None;
                            }
                            return Some((Err(error), state));
                        }
                    };
                    state.closed = batch.closed;
                    state.interruption = batch.interruption;
                    state.pending.extend(
                        batch
                            .frames
                            .into_iter()
                            .map(|frame| project_stream_response(frame, state.history_length)),
                    );
                    if !state.pending.is_empty() {
                        continue;
                    }
                    if state.closed {
                        continue;
                    }
                    let failure = { state.driver_state.borrow().failure.clone() };
                    if let Some(failure) = failure {
                        state.finished = true;
                        if !state.emit_stream_errors {
                            return None;
                        }
                        return Some((Err(A2AError::internal(failure)), state));
                    }
                    let change = tokio::select! {
                        change = state.driver_state.changed() => change,
                        () = tokio::time::sleep(state.poll_interval.as_duration()) => Ok(()),
                    };
                    if change.is_err() {
                        state.finished = true;
                        if !state.emit_stream_errors {
                            return None;
                        }
                        return Some((
                            Err(A2AError::internal("durable outbox driver stopped")),
                            state,
                        ));
                    }
                }
            })
            .await
        }))
    }

    #[allow(clippy::too_many_lines)]
    fn stream_from_task_revision(
        &self,
        task_id: String,
        last_revision: u64,
        authorization: Option<(AuthorizationContext, OwnedTaskScope)>,
        quota_lease: Option<Arc<QuotaLeaseGuard>>,
    ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
        let (context, scope) = authorization.unzip();
        let state = DurableTaskEventStreamState {
            store: self.store.clone(),
            local: self.local.clone(),
            driver_state: self.driver.subscribe(),
            poll_interval: self.store.change_observation().poll_interval(),
            _waiter: self.driver.waiter(),
            task_id,
            last_revision,
            pending: VecDeque::new(),
            closed: false,
            emit_stream_errors: !self.errors_before_stream,
            authorization: context,
            scope,
            quota_lease,
            clock: self.clock.clone(),
            telemetry_context: crate::telemetry::capture_request_telemetry_context(),
        };
        Box::pin(stream::unfold(state, |mut state| async move {
            let telemetry_context = state.telemetry_context.clone();
            crate::telemetry::scope_request_telemetry_context(telemetry_context, async move {
                loop {
                    if let Some(error) =
                        state.quota_lease.as_ref().and_then(|lease| lease.failure())
                    {
                        state.quota_lease = None;
                        state.pending.clear();
                        state.closed = true;
                        return Some((Err(error), state));
                    }
                    if let Some(frame) = state.pending.pop_front() {
                        if let Err(error) = charge_public_egress(
                            &state.store,
                            state.authorization.as_ref(),
                            state.clock.now(),
                            &frame,
                            1,
                        )
                        .await
                        {
                            state.closed = true;
                            return Some((Err(error), state));
                        }
                        return Some((Ok(frame), state));
                    }
                    if state.closed {
                        return None;
                    }
                    let batch = if let Some(scope) = state.scope.as_ref() {
                        state
                            .store
                            .task_events_after_scoped(scope, &state.task_id, state.last_revision)
                            .await
                    } else if let Some(local) = state.local.as_ref() {
                        local
                            .task_events_after(&state.task_id, state.last_revision)
                            .await
                    } else {
                        Err(A2AError::internal(
                            "local development compatibility is unavailable",
                        ))
                    };
                    match batch {
                        Ok(batch) => {
                            state.last_revision = batch.last_revision;
                            state.closed = batch.closed;
                            state.pending.extend(batch.frames);
                            if !state.pending.is_empty() || state.closed {
                                continue;
                            }
                        }
                        Err(error) => {
                            state.closed = true;
                            if !state.emit_stream_errors {
                                return None;
                            }
                            return Some((Err(error), state));
                        }
                    }
                    let failure = state.driver_state.borrow().failure.clone();
                    if let Some(failure) = failure {
                        state.closed = true;
                        if !state.emit_stream_errors {
                            return None;
                        }
                        return Some((Err(A2AError::internal(failure)), state));
                    }
                    let change = tokio::select! {
                        change = state.driver_state.changed() => change,
                        () = tokio::time::sleep(state.poll_interval.as_duration()) => Ok(()),
                    };
                    if change.is_err() {
                        state.closed = true;
                        if !state.emit_stream_errors {
                            return None;
                        }
                        return Some((
                            Err(A2AError::internal("durable outbox driver stopped")),
                            state,
                        ));
                    }
                }
            })
            .await
        }))
    }
}

pub(crate) fn project_send_response(
    response: SendMessageResponse,
    history_length: Option<i32>,
) -> SendMessageResponse {
    match response {
        SendMessageResponse::Task(task) => {
            SendMessageResponse::Task(project_task(task, history_length))
        }
        message @ SendMessageResponse::Message(_) => message,
    }
}

fn project_stream_response(frame: StreamResponse, history_length: Option<i32>) -> StreamResponse {
    match frame {
        StreamResponse::Task(task) => StreamResponse::Task(project_task(task, history_length)),
        frame => frame,
    }
}

fn project_task(mut task: Task, history_length: Option<i32>) -> Task {
    if let Some(length) = history_length {
        if length == 0 {
            task.history = None;
        } else if let (Ok(limit), Some(history)) = (usize::try_from(length), task.history.as_mut())
            && history.len() > limit
        {
            history.drain(..history.len() - limit);
        }
    }
    task
}

#[allow(clippy::too_many_lines)]
fn public_push_config(config: &crate::CallbackConfig) -> TaskPushNotificationConfig {
    TaskPushNotificationConfig {
        url: config.canonical_url().to_owned(),
        id: Some(config.config_id().as_str().to_owned()),
        task_id: config.task_id().to_owned(),
        token: None,
        authentication: None,
        tenant: None,
    }
}

#[allow(clippy::too_many_lines)]
#[async_trait]
impl RequestHandler for DurableRequestHandler {
    async fn send_message(
        &self,
        _params: &ServiceParams,
        mut request: SendMessageRequest,
    ) -> Result<SendMessageResponse, A2AError> {
        let operation = if request.message.task_id.is_some() {
            Operation::TaskContinue
        } else {
            Operation::TaskCreate
        };
        let authorization = self
            .authorization_for(operation, "message", &request.message.message_id)
            .await?;
        // Health is a true admission preflight: a failed driver must not permit
        // canonicalization reads followed by any durable mutation.
        self.ensure_driver_healthy()?;
        Self::reject_message_options(&request)?;
        let callback_intent = self
            .inline_callback_intent(&request, authorization.as_ref())
            .await?;
        let continuation_task = self
            .canonicalize_continuation(&mut request, authorization.as_ref())
            .await?;
        let history_length = request
            .configuration
            .as_ref()
            .and_then(|configuration| configuration.history_length);
        let return_immediately = request
            .configuration
            .as_ref()
            .and_then(|configuration| configuration.return_immediately)
            .unwrap_or(false);
        let durable_message_id = authorization.as_ref().map_or_else(
            || request.message.message_id.clone(),
            |(context, _)| {
                crate::authorized_message_identity(
                    context.tenant_id(),
                    context.account_id(),
                    &request.message.message_id,
                )
            },
        );
        let replay = if let Some((context, scope)) = authorization.as_ref()
            && !self.store.capabilities().quota_reservations
        {
            self.store
                .replay_authorized(
                    scope,
                    context.account_id(),
                    &request,
                    false,
                    self.audit(context, operation, "message", &request.message.message_id)?,
                )
                .await?
        } else if authorization.is_some() {
            // Authorized replay is part of the same atomic mutation path as
            // quota reservation insertion/verification below.
            None
        } else {
            self.local()?.replay(&request, false).await?
        };
        if let Some(replay) = replay {
            if matches!(&replay, SendMessageResponse::Task(task)
                if task.status.state.is_terminal()
                    || matches!(task.status.state, TaskState::InputRequired | TaskState::AuthRequired))
                || return_immediately
            {
                let response = project_send_response(replay, history_length);
                charge_public_egress(
                    &self.store,
                    authorization.as_ref().map(|(context, _)| context),
                    self.clock.now(),
                    &response,
                    1,
                )
                .await?;
                return Ok(response);
            }
            self.driver.wake.notify_one();
            let response = self
                .wait_for_result(
                    &durable_message_id,
                    authorization.as_ref().map(|(_, scope)| scope),
                )
                .await
                .map(|result| project_send_response(result, history_length))?;
            charge_public_egress(
                &self.store,
                authorization.as_ref().map(|(context, _)| context),
                self.clock.now(),
                &response,
                1,
            )
            .await?;
            return Ok(response);
        }
        let admission = if let Some(task) = continuation_task {
            let command = SendMessageAdmission {
                request: request.clone(),
                streaming: false,
                task: task.clone(),
                original_result: SendMessageResponse::Task(task.clone()),
                input_limits: self.input_limits,
                now: self.clock.now(),
                max_attempts: 8,
            };
            if let Some((context, scope)) = authorization.as_ref() {
                self.store
                    .authorize_and_continue_mutation(
                        scope,
                        authorized_mutation(
                            self.store.as_ref(),
                            command,
                            crate::QuotaOperation::TaskContinue,
                        )?,
                        self.audit(context, Operation::TaskContinue, "task", &task.id)?,
                    )
                    .await?
            } else {
                self.local()?.continue_task(command).await?
            }
        } else {
            let task = self.admission_task(&request, authorization.as_ref())?;
            let command = SendMessageAdmission {
                request: request.clone(),
                streaming: false,
                task: task.clone(),
                original_result: SendMessageResponse::Task(task.clone()),
                input_limits: self.input_limits,
                now: self.clock.now(),
                max_attempts: 8,
            };
            if let Some((context, scope)) = authorization.as_ref() {
                let mut mutation = authorized_mutation(
                    self.store.as_ref(),
                    command,
                    crate::QuotaOperation::TaskCreate,
                )?;
                if let Some(intent) = callback_intent.clone() {
                    mutation = mutation.with_callback_intent(intent);
                }
                self.store
                    .authorize_and_admit_mutation(
                        scope,
                        mutation,
                        self.audit(
                            context,
                            Operation::TaskCreate,
                            "message",
                            &request.message.message_id,
                        )?,
                    )
                    .await?
            } else {
                self.local()?.admit(command).await?
            }
        };
        let admission_reason = match &admission {
            AdmissionOutcome::Admitted(_) => "admitted",
            AdmissionOutcome::Replay(_) => "replay",
        };
        let response = match admission {
            AdmissionOutcome::Replay(result) if matches!(&result, SendMessageResponse::Task(task) if task.status.state.is_terminal()) => {
                project_send_response(result, history_length)
            }
            AdmissionOutcome::Admitted(_) if return_immediately => {
                let admitted = if let Some((context, scope)) = authorization.as_ref() {
                    self.store
                        .replay_authorized(
                            scope,
                            context.account_id(),
                            &request,
                            false,
                            self.audit(context, operation, "message", &request.message.message_id)?,
                        )
                        .await?
                } else {
                    self.local()?.replay(&request, false).await?
                }
                .ok_or_else(|| A2AError::internal("admitted result is missing"))?;
                self.driver.wake.notify_one();
                project_send_response(admitted, history_length)
            }
            AdmissionOutcome::Replay(result) if return_immediately => {
                self.driver.wake.notify_one();
                project_send_response(result, history_length)
            }
            AdmissionOutcome::Admitted(_) | AdmissionOutcome::Replay(_) => {
                self.driver.wake.notify_one();
                self.wait_for_result(
                    &durable_message_id,
                    authorization.as_ref().map(|(_, scope)| scope),
                )
                .await
                .map(|result| project_send_response(result, history_length))?
            }
        };
        charge_public_egress(
            &self.store,
            authorization.as_ref().map(|(context, _)| context),
            self.clock.now(),
            &response,
            1,
        )
        .await?;
        if let Some(telemetry) = &self.telemetry {
            let (task_id, context_id) = match &response {
                SendMessageResponse::Task(task) => {
                    (Some(task.id.as_str()), Some(task.context_id.as_str()))
                }
                SendMessageResponse::Message(message) => {
                    (message.task_id.as_deref(), message.context_id.as_deref())
                }
            };
            telemetry.durable_event(
                crate::telemetry::EventName::TaskAdmitted,
                "ok",
                admission_reason,
                "send_message",
                task_id,
                context_id,
                Some(&durable_message_id),
            );
        }
        Ok(response)
    }

    async fn send_streaming_message(
        &self,
        _params: &ServiceParams,
        mut request: SendMessageRequest,
    ) -> Result<BoxStream<'static, Result<StreamResponse, A2AError>>, A2AError> {
        let operation = if request.message.task_id.is_some() {
            Operation::TaskContinue
        } else {
            Operation::TaskCreate
        };
        let authorization = match self
            .authorization_for(operation, "message", &request.message.message_id)
            .await
        {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let continuation_task = match self
            .canonicalize_continuation(&mut request, authorization.as_ref())
            .await
        {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let admitted = async {
            self.ensure_driver_healthy()?;
            Self::reject_message_options(&request)?;
            let callback_intent = self
                .inline_callback_intent(&request, authorization.as_ref())
                .await?;
            let replay = if let Some((context, scope)) = authorization.as_ref()
                && !self.store.capabilities().quota_reservations
            {
                self.store
                    .replay_authorized(
                        scope,
                        context.account_id(),
                        &request,
                        true,
                        self.audit(context, operation, "message", &request.message.message_id)?,
                    )
                    .await?
            } else if authorization.is_some() {
                // Authorized replay must verify the server task-local quota
                // binding in authorize_and_*_mutation atomically.
                None
            } else {
                self.local()?.replay(&request, true).await?
            };
            if let Some(result) = replay {
                let (task_id, context_id) = match result {
                    SendMessageResponse::Task(task) => (task.id, task.context_id),
                    SendMessageResponse::Message(message) => (
                        message.task_id.ok_or_else(|| {
                            A2AError::internal("replayed stream task correlation is missing")
                        })?,
                        message.context_id.ok_or_else(|| {
                            A2AError::internal("replayed stream context correlation is missing")
                        })?,
                    ),
                };
                return Ok::<_, A2AError>((
                    request.message.message_id.clone(),
                    true,
                    task_id,
                    context_id,
                ));
            }
            let task = if let Some(task) = continuation_task {
                task
            } else {
                self.admission_task(&request, authorization.as_ref())?
            };
            let command = SendMessageAdmission {
                request: request.clone(),
                streaming: true,
                task: task.clone(),
                original_result: SendMessageResponse::Task(task.clone()),
                input_limits: self.input_limits,
                now: self.clock.now(),
                max_attempts: 8,
            };
            let outcome = if request.message.task_id.is_some() {
                if let Some((context, scope)) = authorization.as_ref() {
                    self.store
                        .authorize_and_continue_mutation(
                            scope,
                            authorized_mutation(
                                self.store.as_ref(),
                                command,
                                crate::QuotaOperation::TaskContinue,
                            )?,
                            self.audit(context, Operation::TaskContinue, "task", &task.id)?,
                        )
                        .await?
                } else {
                    self.local()?.continue_task(command).await?
                }
            } else if let Some((context, scope)) = authorization.as_ref() {
                let mut mutation = authorized_mutation(
                    self.store.as_ref(),
                    command,
                    crate::QuotaOperation::SendStream,
                )?;
                if let Some(intent) = callback_intent.clone() {
                    mutation = mutation.with_callback_intent(intent);
                }
                self.store
                    .authorize_and_admit_mutation(
                        scope,
                        mutation,
                        self.audit(
                            context,
                            Operation::TaskCreate,
                            "message",
                            &request.message.message_id,
                        )?,
                    )
                    .await?
            } else {
                self.local()?.admit(command).await?
            };
            let (reconnect, task_id, context_id) = match outcome {
                AdmissionOutcome::Admitted(record) => (false, record.task_id, task.context_id),
                AdmissionOutcome::Replay(SendMessageResponse::Task(task)) => {
                    (true, task.id, task.context_id)
                }
                AdmissionOutcome::Replay(SendMessageResponse::Message(message)) => (
                    true,
                    message.task_id.ok_or_else(|| {
                        A2AError::internal("replayed stream task correlation is missing")
                    })?,
                    message.context_id.ok_or_else(|| {
                        A2AError::internal("replayed stream context correlation is missing")
                    })?,
                ),
            };
            Ok::<_, A2AError>((
                request.message.message_id.clone(),
                reconnect,
                task_id,
                context_id,
            ))
        }
        .await;
        let (message_id, reconnect, task_id, context_id) = match admitted {
            Ok(value) => value,
            Err(error) => return self.preflight_stream_error(error),
        };
        let message_id = authorization
            .as_ref()
            .map_or(message_id.clone(), |(context, _)| {
                crate::authorized_message_identity(
                    context.tenant_id(),
                    context.account_id(),
                    &message_id,
                )
            });
        let quota_lease = match self
            .acquire_quota_stream_lease(
                authorization.as_ref().map(|(context, _)| context),
                crate::QuotaLeaseKind::MessageStream,
                &message_id,
                reconnect,
            )
            .await
        {
            Ok(lease) => lease,
            Err(error) => return self.preflight_stream_error(error),
        };
        // The durable slot is acquired before the stream is returned to the
        // transport, so REST cannot establish SSE headers on a denied lease.
        self.driver.wake.notify_one();
        if let Some(telemetry) = &self.telemetry {
            telemetry.durable_event(
                crate::telemetry::EventName::TaskAdmitted,
                "ok",
                if reconnect { "replay" } else { "admitted" },
                "send_streaming_message",
                Some(&task_id),
                Some(&context_id),
                Some(&message_id),
            );
        }
        let history_length = request
            .configuration
            .as_ref()
            .and_then(|configuration| configuration.history_length);
        Ok(self.stream_from_message(
            message_id,
            0,
            VecDeque::new(),
            history_length,
            authorization,
            quota_lease,
        ))
    }

    async fn get_task(
        &self,
        _params: &ServiceParams,
        request: GetTaskRequest,
    ) -> Result<Task, A2AError> {
        let authorization = self
            .authorization_for(Operation::TaskGet, "task", &request.id)
            .await?;
        if request.tenant.is_some() {
            return Err(A2AError::invalid_params("tenant is not supported"));
        }
        if request.history_length.is_some_and(|length| length < 0) {
            return Err(A2AError::invalid_params(
                "historyLength must be a non-negative integer",
            ));
        }
        if request.history_length.is_some() {
            self.audit_unsupported(Operation::HistoryRead, "task", &request.id)
                .await?;
        }
        let task = if let Some((context, scope)) = authorization.as_ref() {
            let audit = self.audit(context, Operation::TaskGet, "task", &request.id)?;
            let quota_intent = quota_operation_intent(
                self.store.as_ref(),
                context,
                crate::QuotaOperation::TaskGet,
                audit.decision_id(),
            )?;
            self.store
                .get_authorized_with_quota(scope, &request.id, audit, quota_intent.as_ref())
                .await?
        } else {
            self.local()?.get(&request.id).await?
        };
        let Some(task) = task else {
            if let Some(telemetry) = &self.telemetry {
                telemetry.durable_event(
                    crate::telemetry::EventName::TaskTransitioned,
                    "not_found",
                    "not_found",
                    "get_task",
                    Some(&request.id),
                    None,
                    None,
                );
            }
            return Err(A2AError::task_not_found(if authorization.is_some() {
                "resource"
            } else {
                &request.id
            }));
        };
        if task
            .artifacts
            .as_ref()
            .is_some_and(|artifacts| !artifacts.is_empty())
        {
            self.audit_unsupported(Operation::ArtifactRead, "task", &request.id)
                .await?;
        }
        let task = project_task(task, request.history_length);
        charge_public_egress(
            &self.store,
            authorization.as_ref().map(|(context, _)| context),
            self.clock.now(),
            &task,
            1,
        )
        .await?;
        if let Some(telemetry) = &self.telemetry {
            telemetry.durable_event(
                crate::telemetry::EventName::TaskTransitioned,
                "ok",
                "read",
                "get_task",
                Some(&task.id),
                Some(&task.context_id),
                None,
            );
        }
        Ok(task)
    }

    async fn list_tasks(
        &self,
        _params: &ServiceParams,
        request: ListTasksRequest,
    ) -> Result<ListTasksResponse, A2AError> {
        let authorization = self
            .authorization_for(Operation::TaskList, "task-list", "visible-set")
            .await?;
        if request.tenant.is_some() {
            return Err(A2AError::invalid_params("tenant is not supported"));
        }
        if request.history_length.is_some() {
            self.audit_unsupported(Operation::HistoryRead, "task-list", "visible-set")
                .await?;
        }
        if request.include_artifacts == Some(true) {
            self.audit_unsupported(Operation::ArtifactRead, "task-list", "visible-set")
                .await?;
        }
        let response = if let Some((context, scope)) = authorization.as_ref() {
            let visibility = match scope.visibility() {
                crate::VisibilityScope::Own => "own",
                crate::VisibilityScope::Tenant => "tenant",
            };
            let cursor_scope = content_digest(
                format!(
                    "{}\0{}\0{}\0{}\0{}\0{}\0{}",
                    context.tenant_id(),
                    context.account_id(),
                    context.policy_id(),
                    context.policy_revision(),
                    context.policy_digest(),
                    scope.owner_account_id(),
                    visibility,
                )
                .as_bytes(),
            );
            let audit = self.audit(context, Operation::TaskList, "task-list", "visible-set")?;
            let quota_intent = quota_operation_intent(
                self.store.as_ref(),
                context,
                crate::QuotaOperation::TaskList,
                audit.decision_id(),
            )?;
            self.store
                .list_authorized_with_quota(
                    scope,
                    &request,
                    audit,
                    &cursor_scope,
                    quota_intent.as_ref(),
                )
                .await
        } else {
            self.local()?.list(&request).await
        }?;
        charge_public_egress(
            &self.store,
            authorization.as_ref().map(|(context, _)| context),
            self.clock.now(),
            &response,
            u64::try_from(response.tasks.len())
                .unwrap_or(u64::MAX)
                .max(1),
        )
        .await?;
        if let Some(telemetry) = &self.telemetry {
            telemetry.durable_event(
                crate::telemetry::EventName::TaskTransitioned,
                "ok",
                "read",
                "list_tasks",
                None,
                None,
                None,
            );
        }
        Ok(response)
    }

    async fn cancel_task(
        &self,
        _params: &ServiceParams,
        request: CancelTaskRequest,
    ) -> Result<Task, A2AError> {
        let authorization = self
            .authorization_for(Operation::TaskCancel, "task", &request.id)
            .await?;
        if request.tenant.is_some() {
            return Err(A2AError::invalid_params(
                "tenant is not supported by the single-tenant gateway",
            ));
        }
        let outcome = if let Some((context, scope)) = authorization.as_ref() {
            let audit = self.audit(context, Operation::TaskCancel, "task", &request.id)?;
            let quota_intent = quota_operation_intent(
                self.store.as_ref(),
                context,
                crate::QuotaOperation::TaskCancel,
                audit.decision_id(),
            )?;
            let quota_reservation = current_quota_reservation();
            let outcome = self
                .store
                .cancel_authorized_with_quota(
                    scope,
                    &request.id,
                    self.clock.now(),
                    audit.clone(),
                    quota_reservation.as_ref(),
                    quota_intent.as_ref(),
                )
                .await;
            match outcome {
                Ok(outcome) => outcome,
                Err(error) if error.code == a2a::error_code::TASK_NOT_FOUND => {
                    self.store
                        .append_authorization_decision(audit.decided(
                            AuthorizationDecisionEffect::Allow,
                            "resource_not_found",
                            None,
                        ))
                        .await?;
                    return Err(A2AError::task_not_found("resource"));
                }
                Err(error) => return Err(error),
            }
        } else {
            self.local()?.cancel(&request.id, self.clock.now()).await?
        };
        let immediate_cancel = matches!(&outcome, CancellationOutcome::Canceled(_));
        if let Some(telemetry) = &self.telemetry {
            let (task_id, context_id) = match &outcome {
                CancellationOutcome::Canceled(task) => {
                    (Some(task.id.as_str()), Some(task.context_id.as_str()))
                }
                CancellationOutcome::AwaitReceiver { .. } => (Some(request.id.as_str()), None),
            };
            telemetry.durable_event(
                crate::telemetry::EventName::CancellationRequested,
                "ok",
                "durable_ack",
                "cancel_task",
                task_id,
                context_id,
                None,
            );
        }
        let task = match outcome {
            CancellationOutcome::Canceled(task) => {
                self.driver.changed();
                task
            }
            CancellationOutcome::AwaitReceiver {
                dispatch_id,
                message_id,
            } => {
                self.driver.signal_cancel(&dispatch_id);
                let result = self
                    .wait_for_result(&message_id, authorization.as_ref().map(|(_, scope)| scope))
                    .await?;
                let SendMessageResponse::Task(task) = result else {
                    return Err(A2AError::invalid_agent_response());
                };
                task
            }
        };
        charge_public_egress(
            &self.store,
            authorization.as_ref().map(|(context, _)| context),
            self.clock.now(),
            &task,
            1,
        )
        .await?;
        if let Some(telemetry) = &self.telemetry {
            telemetry.durable_event(
                crate::telemetry::EventName::CancellationAcknowledged,
                "canceled",
                "committed",
                "cancel_task",
                Some(&task.id),
                Some(&task.context_id),
                None,
            );
            if !immediate_cancel {
                telemetry.durable_event(
                    crate::telemetry::EventName::CancellationStopped,
                    "canceled",
                    "cooperative_stop",
                    "cancel_task",
                    Some(&task.id),
                    Some(&task.context_id),
                    None,
                );
            }
            if immediate_cancel {
                let message_id = task
                    .history
                    .as_deref()
                    .and_then(|history| history.first())
                    .map(|message| message.message_id.as_str());
                telemetry.durable_event(
                    crate::telemetry::EventName::TaskTerminal,
                    "canceled",
                    "committed",
                    "terminal_commit",
                    Some(&task.id),
                    Some(&task.context_id),
                    message_id,
                );
            }
        }
        Ok(task)
    }

    async fn subscribe_to_task(
        &self,
        _params: &ServiceParams,
        request: SubscribeToTaskRequest,
    ) -> Result<BoxStream<'static, Result<StreamResponse, A2AError>>, A2AError> {
        let authorization = match self
            .authorization_for(Operation::TaskSubscribe, "task", &request.id)
            .await
        {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        self.ensure_driver_healthy()?;
        if request.tenant.is_some() {
            return Err(A2AError::invalid_params(
                "tenant is not supported by the single-tenant gateway",
            ));
        }
        if let Some((context, _)) = authorization.as_ref()
            && let Some(intent) = quota_operation_intent(
                self.store.as_ref(),
                context,
                crate::QuotaOperation::Subscribe,
                &content_digest(
                    format!(
                        "subscribe-request-v1\0{}\0{}",
                        request.id,
                        rand::random::<u128>()
                    )
                    .as_bytes(),
                ),
            )?
        {
            tokio::time::timeout(
                QUOTA_LEASE_CALL_TIMEOUT,
                self.store.charge_quota_request(&intent, self.clock.now()),
            )
            .await
            .map_err(|_| crate::quota::quota_authority_unavailable())??;
        }
        let captured = async {
            let snapshot = if let Some((_, scope)) = authorization.as_ref() {
                self.store
                    .subscription_snapshot_authorized(scope, &request.id)
                    .await?
            } else {
                self.local()?.subscription_snapshot(&request.id).await?
            };
            let Some((snapshot, cursor)) = snapshot else {
                return Err(A2AError::task_not_found(if authorization.is_some() {
                    "resource"
                } else {
                    &request.id
                }));
            };
            if snapshot.status.state.is_terminal() {
                return Err(A2AError::unsupported_operation(
                    "terminal tasks cannot be subscribed",
                ));
            }
            Ok::<_, A2AError>((snapshot, cursor))
        }
        .await;
        let (snapshot, cursor) = match captured {
            Ok(captured) => captured,
            Err(error) => return Err(error),
        };
        let quota_lease = self
            .acquire_quota_stream_lease(
                authorization.as_ref().map(|(context, _)| context),
                crate::QuotaLeaseKind::TaskSubscription,
                &request.id,
                false,
            )
            .await?;
        charge_public_egress(
            &self.store,
            authorization.as_ref().map(|(context, _)| context),
            self.clock.now(),
            &StreamResponse::Task(snapshot.clone()),
            1,
        )
        .await?;
        if let Some(telemetry) = &self.telemetry {
            telemetry.durable_event(
                crate::telemetry::EventName::TaskTransitioned,
                "ok",
                "replay",
                "subscribe_to_task",
                Some(&snapshot.id),
                Some(&snapshot.context_id),
                None,
            );
        }
        let tail = match cursor {
            SubscriptionCursor::Transcript { message_id, cursor } => self.stream_from_message(
                message_id,
                cursor,
                VecDeque::new(),
                None,
                authorization.clone(),
                quota_lease,
            ),
            SubscriptionCursor::TaskRevision(revision) => self.stream_from_task_revision(
                request.id,
                revision,
                authorization.clone(),
                quota_lease,
            ),
        };
        Ok(Box::pin(
            stream::once(async move { Ok(StreamResponse::Task(snapshot)) }).chain(tail),
        ))
    }

    async fn create_push_config(
        &self,
        _params: &ServiceParams,
        request: TaskPushNotificationConfig,
    ) -> Result<TaskPushNotificationConfig, A2AError> {
        if request.task_id.is_empty()
            || request.tenant.is_some()
            || request.token.is_some()
            || request.authentication.is_some()
        {
            return Err(A2AError::invalid_params("invalid callback configuration"));
        }
        let (_context, scope) = self
            .authorization_for(Operation::PushCreate, "task", &request.task_id)
            .await?
            .ok_or_else(|| A2AError::invalid_request("forbidden"))?;
        let Some(authority) = self.store.callback_authority() else {
            self.audit_unsupported(Operation::PushCreate, "task", &request.task_id)
                .await?;
            return Err(A2AError::push_notification_not_supported());
        };
        if self
            .push_readiness
            .as_ref()
            .is_some_and(|readiness| !readiness.is_ready())
        {
            return Err(A2AError::internal(
                "callback delivery worker is unavailable",
            ));
        }
        let enrollment = authority
            .resolve_callback_enrollment(&scope, &request.url)
            .await?
            .ok_or_else(|| A2AError::invalid_params("callback enrollment is not authorized"))?;
        let id = request
            .id
            .as_deref()
            .map(crate::CallbackConfigId::new)
            .transpose()?;
        let command = crate::ConfigCreateCommand::new(
            scope,
            request.task_id.clone(),
            id,
            enrollment.enrollment_id(),
            enrollment.enrollment_generation(),
            enrollment.canonical_url(),
            enrollment.url_digest(),
            self.clock.now(),
        )?;
        let config = authority.create_callback_config(command).await?;
        if let Some(telemetry) = &self.telemetry {
            telemetry.durable_event(
                crate::telemetry::EventName::PushConfigChanged,
                "ok",
                "committed",
                "callback_config_created",
                None,
                None,
                None,
            );
        }
        Ok(public_push_config(&config))
    }

    async fn get_push_config(
        &self,
        _params: &ServiceParams,
        request: GetTaskPushNotificationConfigRequest,
    ) -> Result<TaskPushNotificationConfig, A2AError> {
        if request.task_id.is_empty() || request.tenant.is_some() {
            return Err(A2AError::invalid_params("invalid callback request"));
        }
        let (_context, scope) = self
            .authorization_for(Operation::PushGet, "task", &request.task_id)
            .await?
            .ok_or_else(|| A2AError::invalid_request("forbidden"))?;
        let Some(authority) = self.store.callback_authority() else {
            self.audit_unsupported(Operation::PushGet, "task", &request.task_id)
                .await?;
            return Err(A2AError::push_notification_not_supported());
        };
        let command = crate::ConfigGetCommand::new(
            scope,
            request.task_id,
            crate::CallbackConfigId::new(request.id)?,
        )?;
        authority
            .get_callback_config(command)
            .await?
            .map(|c| public_push_config(&c))
            .ok_or_else(|| A2AError::task_not_found("resource"))
    }

    async fn list_push_configs(
        &self,
        _params: &ServiceParams,
        request: ListTaskPushNotificationConfigsRequest,
    ) -> Result<ListTaskPushNotificationConfigsResponse, A2AError> {
        if request.task_id.is_empty() || request.tenant.is_some() {
            return Err(A2AError::invalid_params("invalid callback request"));
        }
        let (_context, scope) = self
            .authorization_for(Operation::PushList, "task", &request.task_id)
            .await?
            .ok_or_else(|| A2AError::invalid_request("forbidden"))?;
        let Some(authority) = self.store.callback_authority() else {
            self.audit_unsupported(Operation::PushList, "task", &request.task_id)
                .await?;
            return Err(A2AError::push_notification_not_supported());
        };
        let raw = request.page_size.unwrap_or(50);
        let size = u16::try_from(raw)
            .map_err(|_| A2AError::invalid_params("invalid callback page size"))?;
        let command = crate::ConfigListCommand::new(
            scope,
            request.task_id,
            crate::ConfigPageSize::new(size)?,
            request.page_token,
        )?;
        let page = authority.list_callback_configs(command).await?;
        Ok(ListTaskPushNotificationConfigsResponse {
            configs: page.configs().iter().map(public_push_config).collect(),
            next_page_token: page.next_page_token().map(ToOwned::to_owned),
        })
    }

    async fn delete_push_config(
        &self,
        _params: &ServiceParams,
        request: DeleteTaskPushNotificationConfigRequest,
    ) -> Result<(), A2AError> {
        if request.task_id.is_empty() || request.tenant.is_some() {
            return Err(A2AError::invalid_params("invalid callback request"));
        }
        let (_context, scope) = self
            .authorization_for(Operation::PushDelete, "task", &request.task_id)
            .await?
            .ok_or_else(|| A2AError::invalid_request("forbidden"))?;
        let Some(authority) = self.store.callback_authority() else {
            self.audit_unsupported(Operation::PushDelete, "task", &request.task_id)
                .await?;
            return Err(A2AError::push_notification_not_supported());
        };
        let command = crate::ConfigDeleteCommand::new(
            scope,
            request.task_id,
            crate::CallbackConfigId::new(request.id)?,
            self.clock.now(),
        )?;
        let _ = authority.delete_callback_config(command).await?;
        if let Some(telemetry) = &self.telemetry {
            telemetry.durable_event(
                crate::telemetry::EventName::PushConfigChanged,
                "ok",
                "committed",
                "callback_config_deleted",
                None,
                None,
                None,
            );
        }
        Ok(())
    }

    async fn get_extended_agent_card(
        &self,
        _params: &ServiceParams,
        _request: GetExtendedAgentCardRequest,
    ) -> Result<AgentCard, A2AError> {
        self.audit_unsupported(Operation::ExtendedCard, "agent-card", "extended")
            .await?;
        Err(A2AError::unsupported_operation(
            "extended agent card is not supported",
        ))
    }
}
