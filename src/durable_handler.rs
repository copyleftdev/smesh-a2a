use std::collections::VecDeque;
use std::sync::Arc;

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

fn authorized_mutation(command: SendMessageAdmission) -> AuthorizedMutation<SendMessageAdmission> {
    match current_quota_reservation() {
        Some(quota) => AuthorizedMutation::with_quota(command, quota),
        None => AuthorizedMutation::without_quota(command),
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
    _authorization: Option<AuthorizationContext>,
    scope: Option<OwnedTaskScope>,
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
    _authorization: Option<AuthorizationContext>,
    scope: Option<OwnedTaskScope>,
}

pub(crate) struct DurableRequestHandler {
    store: Arc<dyn DurableAuthority>,
    local: Option<Arc<dyn LocalDevelopmentCompatibility>>,
    driver: Arc<DurableDriverControl>,
    clock: InjectedClock,
    input_limits: InputLimits,
    errors_before_stream: bool,
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
            return Err(A2AError::invalid_request("forbidden"));
        };
        let scope = OwnedTaskScope::new(context.tenant_id(), context.account_id(), visibility)?;
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
        if self.errors_before_stream {
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
            .and_then(|configuration| configuration.task_push_notification_config.as_ref())
            .is_some()
        {
            return Err(A2AError::push_notification_not_supported());
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
            _authorization: context,
            scope,
        };
        Box::pin(stream::unfold(state, |mut state| async move {
            loop {
                if state.finished {
                    return None;
                }
                if let Some(frame) = state.pending.pop_front() {
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
        }))
    }

    fn stream_from_task_revision(
        &self,
        task_id: String,
        last_revision: u64,
        authorization: Option<(AuthorizationContext, OwnedTaskScope)>,
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
            _authorization: context,
            scope,
        };
        Box::pin(stream::unfold(state, |mut state| async move {
            loop {
                if let Some(frame) = state.pending.pop_front() {
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
                return Ok(project_send_response(replay, history_length));
            }
            self.driver.wake.notify_one();
            return self
                .wait_for_result(
                    &durable_message_id,
                    authorization.as_ref().map(|(_, scope)| scope),
                )
                .await
                .map(|result| project_send_response(result, history_length));
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
                        authorized_mutation(command),
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
                self.store
                    .authorize_and_admit_mutation(
                        scope,
                        authorized_mutation(command),
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
        match admission {
            AdmissionOutcome::Replay(result) if matches!(&result, SendMessageResponse::Task(task) if task.status.state.is_terminal()) => {
                Ok(project_send_response(result, history_length))
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
                Ok(project_send_response(admitted, history_length))
            }
            AdmissionOutcome::Replay(result) if return_immediately => {
                self.driver.wake.notify_one();
                Ok(project_send_response(result, history_length))
            }
            AdmissionOutcome::Admitted(_) | AdmissionOutcome::Replay(_) => {
                self.driver.wake.notify_one();
                self.wait_for_result(
                    &durable_message_id,
                    authorization.as_ref().map(|(_, scope)| scope),
                )
                .await
                .map(|result| project_send_response(result, history_length))
            }
        }
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
            if replay.is_some() {
                return Ok::<_, A2AError>(request.message.message_id.clone());
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
            if request.message.task_id.is_some() {
                if let Some((context, scope)) = authorization.as_ref() {
                    self.store
                        .authorize_and_continue_mutation(
                            scope,
                            authorized_mutation(command),
                            self.audit(context, Operation::TaskContinue, "task", &task.id)?,
                        )
                        .await?;
                } else {
                    self.local()?.continue_task(command).await?;
                }
            } else if let Some((context, scope)) = authorization.as_ref() {
                self.store
                    .authorize_and_admit_mutation(
                        scope,
                        authorized_mutation(command),
                        self.audit(
                            context,
                            Operation::TaskCreate,
                            "message",
                            &request.message.message_id,
                        )?,
                    )
                    .await?;
            } else {
                self.local()?.admit(command).await?;
            }
            Ok::<_, A2AError>(request.message.message_id.clone())
        }
        .await;
        let message_id = match admitted {
            Ok(message_id) => message_id,
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
        // SQLite is authoritative; this only shortens the driver's idle path.
        self.driver.wake.notify_one();
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
            self.store
                .get_authorized(
                    scope,
                    &request.id,
                    self.audit(context, Operation::TaskGet, "task", &request.id)?,
                )
                .await?
        } else {
            self.local()?.get(&request.id).await?
        }
        .ok_or_else(|| {
            A2AError::task_not_found(if authorization.is_some() {
                "resource"
            } else {
                &request.id
            })
        })?;
        if task
            .artifacts
            .as_ref()
            .is_some_and(|artifacts| !artifacts.is_empty())
        {
            self.audit_unsupported(Operation::ArtifactRead, "task", &request.id)
                .await?;
        }
        Ok(project_task(task, request.history_length))
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
        if let Some((context, scope)) = authorization.as_ref() {
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
            self.store
                .list_authorized(
                    scope,
                    &request,
                    self.audit(context, Operation::TaskList, "task-list", "visible-set")?,
                    &cursor_scope,
                )
                .await
        } else {
            self.local()?.list(&request).await
        }
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
        if let Some((context, scope)) = authorization.as_ref()
            && self
                .store
                .get_authorized(
                    scope,
                    &request.id,
                    self.audit(context, Operation::TaskCancel, "task", &request.id)?,
                )
                .await?
                .is_none()
        {
            return Err(A2AError::task_not_found("resource"));
        }
        let outcome = if let Some((context, scope)) = authorization.as_ref() {
            self.store
                .cancel_authorized_with_quota(
                    scope,
                    &request.id,
                    self.clock.now(),
                    self.audit(context, Operation::TaskCancel, "task", &request.id)?,
                    current_quota_reservation().as_ref(),
                )
                .await?
        } else {
            self.local()?.cancel(&request.id, self.clock.now()).await?
        };
        match outcome {
            CancellationOutcome::Canceled(task) => {
                self.driver.changed();
                Ok(task)
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
                Ok(task)
            }
        }
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
        let captured = async {
            self.ensure_driver_healthy()?;
            if request.tenant.is_some() {
                return Err(A2AError::invalid_params(
                    "tenant is not supported by the single-tenant gateway",
                ));
            }
            if let Some((context, scope)) = authorization.as_ref()
                && self
                    .store
                    .get_authorized(
                        scope,
                        &request.id,
                        self.audit(context, Operation::TaskSubscribe, "task", &request.id)?,
                    )
                    .await?
                    .is_none()
            {
                return Err(A2AError::task_not_found("resource"));
            }
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
        let tail = match cursor {
            SubscriptionCursor::Transcript { message_id, cursor } => self.stream_from_message(
                message_id,
                cursor,
                VecDeque::new(),
                None,
                authorization.clone(),
            ),
            SubscriptionCursor::TaskRevision(revision) => {
                self.stream_from_task_revision(request.id, revision, authorization.clone())
            }
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
        self.audit_unsupported(Operation::PushCreate, "task", &request.task_id)
            .await?;
        Err(A2AError::push_notification_not_supported())
    }

    async fn get_push_config(
        &self,
        _params: &ServiceParams,
        request: GetTaskPushNotificationConfigRequest,
    ) -> Result<TaskPushNotificationConfig, A2AError> {
        self.audit_unsupported(Operation::PushGet, "task", &request.task_id)
            .await?;
        Err(A2AError::push_notification_not_supported())
    }

    async fn list_push_configs(
        &self,
        _params: &ServiceParams,
        request: ListTaskPushNotificationConfigsRequest,
    ) -> Result<ListTaskPushNotificationConfigsResponse, A2AError> {
        self.audit_unsupported(Operation::PushList, "task", &request.task_id)
            .await?;
        Err(A2AError::push_notification_not_supported())
    }

    async fn delete_push_config(
        &self,
        _params: &ServiceParams,
        request: DeleteTaskPushNotificationConfigRequest,
    ) -> Result<(), A2AError> {
        self.audit_unsupported(Operation::PushDelete, "task", &request.task_id)
            .await?;
        Err(A2AError::push_notification_not_supported())
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
