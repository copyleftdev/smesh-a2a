use std::collections::VecDeque;
use std::sync::Arc;

use a2a::{
    A2AError, AgentCard, CancelTaskRequest, DeleteTaskPushNotificationConfigRequest,
    GetExtendedAgentCardRequest, GetTaskPushNotificationConfigRequest, GetTaskRequest,
    ListTaskPushNotificationConfigsRequest, ListTaskPushNotificationConfigsResponse,
    ListTasksRequest, ListTasksResponse, SendMessageRequest, SendMessageResponse, StreamResponse,
    SubscribeToTaskRequest, Task, TaskPushNotificationConfig, TaskState, TaskStatus,
};
use a2a_server::{RequestHandler, ServiceParams, TaskStore};
use async_trait::async_trait;
use futures::{
    StreamExt,
    stream::{self, BoxStream},
};
#[cfg(test)]
use tokio::sync::Notify;

use crate::{
    AdmissionOutcome, CancellationOutcome, InjectedClock, InputLimits, SendMessageAdmission,
    SqliteTaskStore, content_digest,
    outbox_driver::{DurableDriverControl, WaiterGuard},
    sqlite_store::SubscriptionCursor,
};

struct DurableStreamState {
    store: SqliteTaskStore,
    driver_state: tokio::sync::watch::Receiver<crate::outbox_driver::DriverState>,
    _waiter: WaiterGuard,
    message_id: String,
    last_sequence: usize,
    pending: VecDeque<StreamResponse>,
    closed: bool,
    finished: bool,
    interruption: Option<String>,
    history_length: Option<i32>,
    emit_stream_errors: bool,
}

pub(crate) struct DurableRequestHandler {
    store: SqliteTaskStore,
    driver: Arc<DurableDriverControl>,
    clock: InjectedClock,
    input_limits: InputLimits,
    errors_before_stream: bool,
    #[cfg(test)]
    after_empty_read: Option<(Arc<Notify>, Arc<Notify>)>,
}

impl DurableRequestHandler {
    async fn canonicalize_continuation(
        &self,
        request: &mut SendMessageRequest,
    ) -> Result<Option<Task>, A2AError> {
        let Some(task_id) = request.message.task_id.as_deref() else {
            return Ok(None);
        };
        let task = self
            .store
            .get(task_id)
            .await?
            .ok_or_else(|| A2AError::task_not_found(task_id))?;
        if let Some(context_id) = request.message.context_id.as_deref() {
            if context_id != task.context_id {
                return Err(A2AError::invalid_params("continuation contextId mismatch"));
            }
        } else {
            request.message.context_id = Some(task.context_id.clone());
        }
        Ok(Some(task))
    }

    pub(crate) fn new(
        store: SqliteTaskStore,
        driver: Arc<DurableDriverControl>,
        clock: InjectedClock,
        input_limits: InputLimits,
    ) -> Self {
        Self {
            store,
            driver,
            clock,
            input_limits,
            errors_before_stream: false,
            #[cfg(test)]
            after_empty_read: None,
        }
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
    ) -> Result<SendMessageResponse, A2AError> {
        let _waiter = self.driver.waiter();
        // Subscribe before the SQLite read: watch retains the generation/failure
        // even when completion races this read.
        let mut state = self.driver.subscribe();
        loop {
            if let Some(result) = self.store.final_result_for_message(message_id).await? {
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
            state
                .changed()
                .await
                .map_err(|_| A2AError::internal("durable outbox driver stopped"))?;
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

    fn admission_task(&self, request: &SendMessageRequest) -> Result<Task, A2AError> {
        if request.message.message_id.is_empty() {
            return Err(A2AError::invalid_params(
                "messageId is required for durable admission",
            ));
        }
        let identity = content_digest(request.message.message_id.as_bytes());
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

    fn stream_from_message(
        &self,
        message_id: String,
        last_sequence: usize,
        pending: VecDeque<StreamResponse>,
        history_length: Option<i32>,
    ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
        let state = DurableStreamState {
            store: self.store.clone(),
            driver_state: self.driver.subscribe(),
            _waiter: self.driver.waiter(),
            message_id,
            last_sequence,
            pending,
            closed: false,
            finished: false,
            interruption: None,
            history_length,
            emit_stream_errors: !self.errors_before_stream,
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
                let batch = match state
                    .store
                    .stream_frames_after(&state.message_id, state.last_sequence)
                    .await
                {
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
                if state.driver_state.changed().await.is_err() {
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
    ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
        let state = (
            self.store.clone(),
            self.driver.subscribe(),
            self.driver.waiter(),
            task_id,
            last_revision,
            VecDeque::new(),
            false,
            !self.errors_before_stream,
        );
        Box::pin(stream::unfold(state, |mut state| async move {
            loop {
                if let Some(frame) = state.5.pop_front() {
                    return Some((Ok(frame), state));
                }
                if state.6 {
                    return None;
                }
                match state.0.task_events_after(&state.3, state.4).await {
                    Ok(batch) => {
                        state.4 = batch.last_revision;
                        state.6 = batch.closed;
                        state.5.extend(batch.frames);
                        if !state.5.is_empty() || state.6 {
                            continue;
                        }
                    }
                    Err(error) => {
                        state.6 = true;
                        if !state.7 {
                            return None;
                        }
                        return Some((Err(error), state));
                    }
                }
                let failure = state.1.borrow().failure.clone();
                if let Some(failure) = failure {
                    state.6 = true;
                    if !state.7 {
                        return None;
                    }
                    return Some((Err(A2AError::internal(failure)), state));
                }
                if state.1.changed().await.is_err() {
                    state.6 = true;
                    if !state.7 {
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

#[async_trait]
impl RequestHandler for DurableRequestHandler {
    async fn send_message(
        &self,
        _params: &ServiceParams,
        mut request: SendMessageRequest,
    ) -> Result<SendMessageResponse, A2AError> {
        // Health is a true admission preflight: a failed driver must not permit
        // canonicalization reads followed by any durable mutation.
        self.ensure_driver_healthy()?;
        Self::reject_message_options(&request)?;
        let continuation_task = self.canonicalize_continuation(&mut request).await?;
        let history_length = request
            .configuration
            .as_ref()
            .and_then(|configuration| configuration.history_length);
        let return_immediately = request
            .configuration
            .as_ref()
            .and_then(|configuration| configuration.return_immediately)
            .unwrap_or(false);
        if let Some(replay) = self.store.replay_send_message(&request, false).await? {
            if matches!(&replay, SendMessageResponse::Task(task)
                if task.status.state.is_terminal()
                    || matches!(task.status.state, TaskState::InputRequired | TaskState::AuthRequired))
                || return_immediately
            {
                return Ok(project_send_response(replay, history_length));
            }
            self.driver.wake.notify_one();
            return self
                .wait_for_result(&request.message.message_id)
                .await
                .map(|result| project_send_response(result, history_length));
        }
        let admission = if let Some(task) = continuation_task {
            self.store
                .admit_continuation(SendMessageAdmission {
                    request: request.clone(),
                    streaming: false,
                    task: task.clone(),
                    original_result: SendMessageResponse::Task(task.clone()),
                    input_limits: self.input_limits,
                    now: self.clock.now(),
                    max_attempts: 8,
                })
                .await?
        } else {
            let task = self.admission_task(&request)?;
            self.store
                .admit_send_message(SendMessageAdmission {
                    request: request.clone(),
                    streaming: false,
                    task: task.clone(),
                    original_result: SendMessageResponse::Task(task.clone()),
                    input_limits: self.input_limits,
                    now: self.clock.now(),
                    max_attempts: 8,
                })
                .await?
        };
        match admission {
            AdmissionOutcome::Replay(result) if matches!(&result, SendMessageResponse::Task(task) if task.status.state.is_terminal()) => {
                Ok(project_send_response(result, history_length))
            }
            AdmissionOutcome::Admitted(_) if return_immediately => {
                let admitted = self
                    .store
                    .replay_send_message(&request, false)
                    .await?
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
                self.wait_for_result(&request.message.message_id)
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
        let admitted = async {
            self.ensure_driver_healthy()?;
            Self::reject_message_options(&request)?;
            let continuation_task = self.canonicalize_continuation(&mut request).await?;
            if self
                .store
                .replay_send_message(&request, true)
                .await?
                .is_some()
            {
                return Ok::<_, A2AError>(request.message.message_id.clone());
            }
            let task = if let Some(task) = continuation_task {
                task
            } else {
                self.admission_task(&request)?
            };
            let command = SendMessageAdmission {
                request: request.clone(),
                streaming: true,
                task: task.clone(),
                original_result: SendMessageResponse::Task(task),
                input_limits: self.input_limits,
                now: self.clock.now(),
                max_attempts: 8,
            };
            if request.message.task_id.is_some() {
                self.store.admit_continuation(command).await?;
            } else {
                self.store.admit_send_message(command).await?;
            }
            Ok::<_, A2AError>(request.message.message_id.clone())
        }
        .await;
        let message_id = match admitted {
            Ok(message_id) => message_id,
            Err(error) => return self.preflight_stream_error(error),
        };
        // SQLite is authoritative; this only shortens the driver's idle path.
        self.driver.wake.notify_one();
        let history_length = request
            .configuration
            .as_ref()
            .and_then(|configuration| configuration.history_length);
        Ok(self.stream_from_message(message_id, 0, VecDeque::new(), history_length))
    }

    async fn get_task(
        &self,
        _params: &ServiceParams,
        request: GetTaskRequest,
    ) -> Result<Task, A2AError> {
        if request.tenant.is_some() {
            return Err(A2AError::invalid_params("tenant is not supported"));
        }
        if request.history_length.is_some_and(|length| length < 0) {
            return Err(A2AError::invalid_params(
                "historyLength must be a non-negative integer",
            ));
        }
        let history_length = request.history_length;
        let mut task = self
            .store
            .get(&request.id)
            .await?
            .ok_or_else(|| A2AError::task_not_found(&request.id))?;
        if let Some(length) = history_length {
            if length == 0 {
                task.history = None;
            } else if let (Ok(limit), Some(history)) =
                (usize::try_from(length), task.history.as_mut())
                && history.len() > limit
            {
                history.drain(..history.len() - limit);
            }
        }
        Ok(task)
    }

    async fn list_tasks(
        &self,
        _params: &ServiceParams,
        request: ListTasksRequest,
    ) -> Result<ListTasksResponse, A2AError> {
        if request.tenant.is_some() {
            return Err(A2AError::invalid_params("tenant is not supported"));
        }
        self.store.list(&request).await
    }

    async fn cancel_task(
        &self,
        _params: &ServiceParams,
        request: CancelTaskRequest,
    ) -> Result<Task, A2AError> {
        if request.tenant.is_some() {
            return Err(A2AError::invalid_params(
                "tenant is not supported by the single-tenant gateway",
            ));
        }
        match self
            .store
            .request_cancellation(&request.id, self.clock.now())
            .await?
        {
            CancellationOutcome::Canceled(task) => {
                self.driver.changed();
                Ok(task)
            }
            CancellationOutcome::AwaitReceiver {
                dispatch_id,
                message_id,
            } => {
                self.driver.signal_cancel(&dispatch_id);
                let result = self.wait_for_result(&message_id).await?;
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
        let captured = async {
            self.ensure_driver_healthy()?;
            if request.tenant.is_some() {
                return Err(A2AError::invalid_params(
                    "tenant is not supported by the single-tenant gateway",
                ));
            }
            let Some((snapshot, cursor)) = self.store.subscription_snapshot(&request.id).await?
            else {
                return Err(A2AError::task_not_found(&request.id));
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
            Err(error) => return self.preflight_stream_error(error),
        };
        let tail = match cursor {
            SubscriptionCursor::Transcript { message_id, cursor } => {
                self.stream_from_message(message_id, cursor, VecDeque::new(), None)
            }
            SubscriptionCursor::TaskRevision(revision) => {
                self.stream_from_task_revision(request.id, revision)
            }
        };
        Ok(Box::pin(
            stream::once(async move { Ok(StreamResponse::Task(snapshot)) }).chain(tail),
        ))
    }

    async fn create_push_config(
        &self,
        _params: &ServiceParams,
        _request: TaskPushNotificationConfig,
    ) -> Result<TaskPushNotificationConfig, A2AError> {
        Err(A2AError::push_notification_not_supported())
    }

    async fn get_push_config(
        &self,
        _params: &ServiceParams,
        _request: GetTaskPushNotificationConfigRequest,
    ) -> Result<TaskPushNotificationConfig, A2AError> {
        Err(A2AError::push_notification_not_supported())
    }

    async fn list_push_configs(
        &self,
        _params: &ServiceParams,
        _request: ListTaskPushNotificationConfigsRequest,
    ) -> Result<ListTaskPushNotificationConfigsResponse, A2AError> {
        Err(A2AError::push_notification_not_supported())
    }

    async fn delete_push_config(
        &self,
        _params: &ServiceParams,
        _request: DeleteTaskPushNotificationConfigRequest,
    ) -> Result<(), A2AError> {
        Err(A2AError::push_notification_not_supported())
    }

    async fn get_extended_agent_card(
        &self,
        _params: &ServiceParams,
        _request: GetExtendedAgentCardRequest,
    ) -> Result<AgentCard, A2AError> {
        Err(A2AError::unsupported_operation(
            "extended agent card is not supported",
        ))
    }
}
