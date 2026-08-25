use std::sync::Arc;

use a2a::{
    A2AError, AgentCard, CancelTaskRequest, DeleteTaskPushNotificationConfigRequest,
    GetExtendedAgentCardRequest, GetTaskPushNotificationConfigRequest, GetTaskRequest,
    ListTaskPushNotificationConfigsRequest, ListTaskPushNotificationConfigsResponse,
    ListTasksRequest, ListTasksResponse, SendMessageRequest, SendMessageResponse, StreamResponse,
    SubscribeToTaskRequest, Task, TaskPushNotificationConfig,
};
use a2a_server::{RequestHandler, ServiceParams, TaskStore};
use async_trait::async_trait;
use futures::stream::BoxStream;

use crate::BoundedTaskStore;

/// Single-tenant preflight guard around the official request handler.
pub(crate) struct GuardedRequestHandler {
    inner: Arc<dyn RequestHandler>,
    store: BoundedTaskStore,
}

impl GuardedRequestHandler {
    pub(crate) fn new(inner: Arc<dyn RequestHandler>, store: BoundedTaskStore) -> Self {
        Self { inner, store }
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

#[async_trait]
impl RequestHandler for GuardedRequestHandler {
    async fn send_message(
        &self,
        params: &ServiceParams,
        request: SendMessageRequest,
    ) -> Result<SendMessageResponse, A2AError> {
        self.preflight_message(&request).await?;
        self.inner.send_message(params, request).await
    }

    async fn send_streaming_message(
        &self,
        params: &ServiceParams,
        request: SendMessageRequest,
    ) -> Result<BoxStream<'static, Result<StreamResponse, A2AError>>, A2AError> {
        self.preflight_message(&request).await?;
        self.inner.send_streaming_message(params, request).await
    }

    async fn get_task(
        &self,
        params: &ServiceParams,
        request: GetTaskRequest,
    ) -> Result<Task, A2AError> {
        Self::reject_tenant::<GetTaskRequest>(request.tenant.as_ref())?;
        self.inner.get_task(params, request).await
    }

    async fn list_tasks(
        &self,
        params: &ServiceParams,
        request: ListTasksRequest,
    ) -> Result<ListTasksResponse, A2AError> {
        Self::reject_tenant::<ListTasksRequest>(request.tenant.as_ref())?;
        self.inner.list_tasks(params, request).await
    }

    async fn cancel_task(
        &self,
        params: &ServiceParams,
        request: CancelTaskRequest,
    ) -> Result<Task, A2AError> {
        Self::reject_tenant::<CancelTaskRequest>(request.tenant.as_ref())?;
        self.inner.cancel_task(params, request).await
    }

    async fn subscribe_to_task(
        &self,
        params: &ServiceParams,
        request: SubscribeToTaskRequest,
    ) -> Result<BoxStream<'static, Result<StreamResponse, A2AError>>, A2AError> {
        Self::reject_tenant::<SubscribeToTaskRequest>(request.tenant.as_ref())?;
        self.inner.subscribe_to_task(params, request).await
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
