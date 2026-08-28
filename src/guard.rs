use std::sync::Arc;

use a2a::{
    A2AError, AgentCard, CancelTaskRequest, DeleteTaskPushNotificationConfigRequest,
    GetExtendedAgentCardRequest, GetTaskPushNotificationConfigRequest, GetTaskRequest,
    ListTaskPushNotificationConfigsRequest, ListTaskPushNotificationConfigsResponse,
    ListTasksRequest, ListTasksResponse, PartContent, SendMessageRequest, SendMessageResponse,
    StreamResponse, SubscribeToTaskRequest, Task, TaskPushNotificationConfig, TaskState,
};
use a2a_server::{RequestHandler, ServiceParams};
use async_trait::async_trait;
use futures::{StreamExt, stream::BoxStream};

use crate::{
    ArtifactManifest, CompletionReceipt, VersionedCompletionPolicy, artifact_set_digest,
    content_digest, server::CompletionPolicyStore,
};

/// Single-tenant preflight guard around the official request handler.
pub(crate) struct GuardedRequestHandler<S> {
    inner: Arc<dyn RequestHandler>,
    store: S,
    completion_policy: VersionedCompletionPolicy,
}

impl<S> GuardedRequestHandler<S>
where
    S: CompletionPolicyStore,
{
    pub(crate) fn new(
        inner: Arc<dyn RequestHandler>,
        store: S,
        completion_policy: VersionedCompletionPolicy,
    ) -> Self {
        Self {
            inner,
            store,
            completion_policy,
        }
    }

    fn reject_tenant<T>(tenant: Option<&String>) -> Result<(), A2AError> {
        let _ = std::marker::PhantomData::<T>;
        if tenant.is_some() {
            return Err(A2AError::invalid_params(
                "tenant is not supported by the single-tenant gateway",
            ));
        }
        Ok(())
    }

    fn validate_history_length(history_length: Option<i32>) -> Result<(), A2AError> {
        if history_length.is_some_and(|length| !(0..=100).contains(&length)) {
            return Err(A2AError::invalid_params(
                "historyLength must be between 0 and 100",
            ));
        }
        Ok(())
    }

    fn apply_history_length(task: &mut Task, history_length: Option<i32>) {
        let Some(length) = history_length else {
            return;
        };
        if length == 0 {
            task.history = None;
            return;
        }
        let Ok(limit) = usize::try_from(length) else {
            return;
        };
        if let Some(history) = task.history.as_mut()
            && history.len() > limit
        {
            history.drain(..history.len() - limit);
        }
    }

    fn validate_visible_task(&self, task: &Task) -> Result<(), A2AError> {
        validate_task_with_policy(&self.completion_policy, task)
    }

    fn validate_list_structure(
        request: &ListTasksRequest,
        response: &ListTasksResponse,
    ) -> Result<(), A2AError> {
        let expected_page_size = request.page_size.unwrap_or(50);
        if response.page_size != expected_page_size
            || !(1..=100).contains(&response.page_size)
            || response.total_size < 0
            || response.tasks.len() > usize::try_from(response.page_size).unwrap_or(0)
            || usize::try_from(response.total_size).unwrap_or(0) < response.tasks.len()
        {
            return Err(A2AError::invalid_agent_response());
        }
        let mut ids = std::collections::HashSet::with_capacity(response.tasks.len());
        let mut previous: Option<&Task> = None;
        for task in &response.tasks {
            if task.id.is_empty()
                || !ids.insert(task.id.as_str())
                || request
                    .context_id
                    .as_ref()
                    .is_some_and(|value| task.context_id != *value)
                || request
                    .status
                    .as_ref()
                    .is_some_and(|value| task.status.state != *value)
                || request.status_timestamp_after.is_some_and(|after| {
                    task.status
                        .timestamp
                        .is_none_or(|timestamp| timestamp < after)
                })
                || (!request.include_artifacts.unwrap_or(false) && task.artifacts.is_some())
            {
                return Err(A2AError::invalid_agent_response());
            }
            if let Some(limit) = request
                .history_length
                .and_then(|value| usize::try_from(value).ok())
                && task
                    .history
                    .as_ref()
                    .is_some_and(|history| limit == 0 || history.len() > limit)
            {
                return Err(A2AError::invalid_agent_response());
            }
            if let Some(left) = previous {
                let invalid = match (left.status.timestamp, task.status.timestamp) {
                    (None, Some(_)) => true,
                    (Some(left_time), Some(right_time)) => {
                        left_time < right_time || (left_time == right_time && left.id > task.id)
                    }
                    (None, None) => left.id > task.id,
                    (Some(_), None) => false,
                };
                if invalid {
                    return Err(A2AError::invalid_agent_response());
                }
            }
            previous = Some(task);
        }
        Ok(())
    }

    async fn reject_terminal_subscription(&self, task_id: &str) -> Result<(), A2AError> {
        if self
            .store
            .get(task_id)
            .await?
            .is_some_and(|task| task.status.state.is_terminal())
        {
            return Err(A2AError::unsupported_operation(
                "terminal tasks cannot be subscribed to",
            ));
        }
        Ok(())
    }

    async fn preflight_message(&self, request: &SendMessageRequest) -> Result<(), A2AError> {
        Self::reject_tenant::<SendMessageRequest>(request.tenant.as_ref())?;
        if let Some(task_id) = request.message.task_id.as_deref()
            && self
                .store
                .get(task_id)
                .await?
                .is_some_and(|task| task.status.state.is_terminal())
        {
            return Err(A2AError::unsupported_operation(
                "terminal tasks cannot accept additional messages",
            ));
        }
        Ok(())
    }
}

fn validate_task_with_policy(
    policy: &VersionedCompletionPolicy,
    task: &Task,
) -> Result<(), A2AError> {
    validate_task_with_policy_projection(policy, task, false)
}

fn validate_task_with_policy_projection(
    policy: &VersionedCompletionPolicy,
    task: &Task,
    artifacts_projected_out: bool,
) -> Result<(), A2AError> {
    if task.status.state != TaskState::Completed {
        if task
            .artifacts
            .as_ref()
            .is_some_and(|artifacts| !artifacts.is_empty())
        {
            return Err(A2AError::invalid_agent_response());
        }
        let completion_metadata = task
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("smesh.completionPolicy"));
        if task.status.state == TaskState::InputRequired {
            let value = completion_metadata
                .filter(|value| {
                    value.get("status").and_then(serde_json::Value::as_str)
                        == Some("awaitingRatification")
                })
                .and_then(|value| value.get("record"))
                .cloned()
                .ok_or_else(A2AError::invalid_agent_response)?;
            let checkpoint: crate::PolicyCheckpoint =
                serde_json::from_value(value).map_err(|_| A2AError::invalid_agent_response())?;
            if !policy.verify_checkpoint(&checkpoint, &task.id, &task.context_id) {
                return Err(A2AError::invalid_agent_response());
            }
        } else if let Some(value) = completion_metadata
            && !(task.status.state == TaskState::Failed
                && value.get("status").and_then(serde_json::Value::as_str) == Some("blocked"))
        {
            // Accepted receipts belong only to completed tasks, awaiting-ratification
            // checkpoints belong only to InputRequired, and policy blocks belong only
            // to Failed. Reject arbitrary or cross-state policy metadata.
            return Err(A2AError::invalid_agent_response());
        }
        return Ok(());
    }
    let value = task
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("smesh.completionPolicy"))
        .filter(|value| value.get("status").and_then(serde_json::Value::as_str) == Some("accepted"))
        .and_then(|value| value.get("record"))
        .cloned()
        .ok_or_else(A2AError::invalid_agent_response)?;
    let receipt: CompletionReceipt =
        serde_json::from_value(value).map_err(|_| A2AError::invalid_agent_response())?;
    if receipt.task_id != task.id
        || receipt.context_id != task.context_id
        || receipt.policy_id != policy.spec().policy_id
        || receipt.policy_version != policy.spec().version
        || receipt.policy_hash != policy.policy_hash()
        || !policy.verify_receipt(&receipt)
    {
        return Err(A2AError::invalid_agent_response());
    }
    let Some(artifacts) = task.artifacts.as_ref() else {
        // The signed receipt proves the accepted artifact-set digest plus task,
        // context, and policy binding. List projection may omit artifact bodies;
        // full task responses must still recompute the digest below.
        return if artifacts_projected_out {
            Ok(())
        } else {
            Err(A2AError::invalid_agent_response())
        };
    };
    let mut manifests = Vec::with_capacity(artifacts.len());
    for artifact in artifacts {
        let name = artifact
            .name
            .clone()
            .ok_or_else(A2AError::invalid_agent_response)?;
        let [part] = artifact.parts.as_slice() else {
            return Err(A2AError::invalid_agent_response());
        };
        let PartContent::Text(content) = &part.content else {
            return Err(A2AError::invalid_agent_response());
        };
        let media_type = part
            .media_type
            .clone()
            .ok_or_else(A2AError::invalid_agent_response)?;
        manifests.push(ArtifactManifest {
            name,
            media_type,
            digest: content_digest(content.as_bytes()),
        });
    }
    let digest = artifact_set_digest(&manifests).map_err(|_| A2AError::invalid_agent_response())?;
    if receipt.artifact_set_digest != digest {
        return Err(A2AError::invalid_agent_response());
    }
    Ok(())
}

fn validate_stream(
    policy: VersionedCompletionPolicy,
    stream: BoxStream<'static, Result<StreamResponse, A2AError>>,
) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
    Box::pin(stream.map(move |result| match result {
        Ok(StreamResponse::Task(task)) => {
            validate_task_with_policy(&policy, &task)?;
            Ok(StreamResponse::Task(task))
        }
        Ok(StreamResponse::ArtifactUpdate(_)) => Err(A2AError::invalid_agent_response()),
        other => other,
    }))
}

#[async_trait]
impl<S> RequestHandler for GuardedRequestHandler<S>
where
    S: CompletionPolicyStore,
{
    async fn send_message(
        &self,
        params: &ServiceParams,
        request: SendMessageRequest,
    ) -> Result<SendMessageResponse, A2AError> {
        self.preflight_message(&request).await?;
        let response = self.inner.send_message(params, request).await?;
        if let SendMessageResponse::Task(task) = &response {
            self.validate_visible_task(task)?;
        }
        Ok(response)
    }

    async fn send_streaming_message(
        &self,
        params: &ServiceParams,
        request: SendMessageRequest,
    ) -> Result<BoxStream<'static, Result<StreamResponse, A2AError>>, A2AError> {
        self.preflight_message(&request).await?;
        let stream = self.inner.send_streaming_message(params, request).await?;
        Ok(validate_stream(self.completion_policy.clone(), stream))
    }

    async fn get_task(
        &self,
        params: &ServiceParams,
        request: GetTaskRequest,
    ) -> Result<Task, A2AError> {
        Self::reject_tenant::<GetTaskRequest>(request.tenant.as_ref())?;
        Self::validate_history_length(request.history_length)?;
        let history_length = request.history_length;
        let mut task = self.inner.get_task(params, request).await?;
        self.validate_visible_task(&task)?;
        Self::apply_history_length(&mut task, history_length);
        Ok(task)
    }

    async fn list_tasks(
        &self,
        _params: &ServiceParams,
        request: ListTasksRequest,
    ) -> Result<ListTasksResponse, A2AError> {
        Self::reject_tenant::<ListTasksRequest>(request.tenant.as_ref())?;
        Self::validate_history_length(request.history_length)?;
        // Listing is a store operation, not executor work. Read the page once from the
        // authoritative store so snapshot creation and provenance validation cannot be
        // separated by a mutable-row race or substituted by an injected handler.
        let response = self.store.list(&request).await?;
        Self::validate_list_structure(&request, &response)?;
        if !self.store.list_pages_are_self_authenticating() {
            self.store.validate_list_page(&request, &response).await?;
        }
        for task in &response.tasks {
            // Validate the exact frozen projection returned to the caller. A newer live
            // row must never repair an invalid historical snapshot, and a valid frozen
            // revision must not be rejected merely because the live task later changed.
            validate_task_with_policy_projection(
                &self.completion_policy,
                task,
                !request.include_artifacts.unwrap_or(false),
            )?;
        }
        Ok(response)
    }

    async fn cancel_task(
        &self,
        params: &ServiceParams,
        request: CancelTaskRequest,
    ) -> Result<Task, A2AError> {
        Self::reject_tenant::<CancelTaskRequest>(request.tenant.as_ref())?;
        let task = self.inner.cancel_task(params, request).await?;
        self.validate_visible_task(&task)?;
        Ok(task)
    }

    async fn subscribe_to_task(
        &self,
        params: &ServiceParams,
        request: SubscribeToTaskRequest,
    ) -> Result<BoxStream<'static, Result<StreamResponse, A2AError>>, A2AError> {
        Self::reject_tenant::<SubscribeToTaskRequest>(request.tenant.as_ref())?;
        self.reject_terminal_subscription(&request.id).await?;
        match self.inner.subscribe_to_task(params, request.clone()).await {
            Ok(stream) => {
                // A completion can race the execution-manager lookup and still
                // yield a terminal snapshot. Do not turn that race into a valid
                // subscription to a task that is already terminal in the ledger.
                self.reject_terminal_subscription(&request.id).await?;
                Ok(validate_stream(self.completion_policy.clone(), stream))
            }
            Err(error) => {
                // The task can become terminal after the preflight read but before
                // the SDK execution manager resolves the subscription. Re-check so
                // that race has the same result as an already-terminal task.
                self.reject_terminal_subscription(&request.id).await?;
                Err(error)
            }
        }
    }

    async fn create_push_config(
        &self,
        params: &ServiceParams,
        request: TaskPushNotificationConfig,
    ) -> Result<TaskPushNotificationConfig, A2AError> {
        Self::reject_tenant::<TaskPushNotificationConfig>(request.tenant.as_ref())?;
        self.inner.create_push_config(params, request).await
    }

    async fn get_push_config(
        &self,
        params: &ServiceParams,
        request: GetTaskPushNotificationConfigRequest,
    ) -> Result<TaskPushNotificationConfig, A2AError> {
        Self::reject_tenant::<GetTaskPushNotificationConfigRequest>(request.tenant.as_ref())?;
        self.inner.get_push_config(params, request).await
    }

    async fn list_push_configs(
        &self,
        params: &ServiceParams,
        request: ListTaskPushNotificationConfigsRequest,
    ) -> Result<ListTaskPushNotificationConfigsResponse, A2AError> {
        Self::reject_tenant::<ListTaskPushNotificationConfigsRequest>(request.tenant.as_ref())?;
        self.inner.list_push_configs(params, request).await
    }

    async fn delete_push_config(
        &self,
        params: &ServiceParams,
        request: DeleteTaskPushNotificationConfigRequest,
    ) -> Result<(), A2AError> {
        Self::reject_tenant::<DeleteTaskPushNotificationConfigRequest>(request.tenant.as_ref())?;
        self.inner.delete_push_config(params, request).await
    }

    async fn get_extended_agent_card(
        &self,
        params: &ServiceParams,
        request: GetExtendedAgentCardRequest,
    ) -> Result<AgentCard, A2AError> {
        Self::reject_tenant::<GetExtendedAgentCardRequest>(request.tenant.as_ref())?;
        self.inner.get_extended_agent_card(params, request).await
    }
}
