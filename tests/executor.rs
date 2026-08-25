use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use a2a::{Message, Part, Role, StreamResponse, TaskState};
use a2a_server::{AgentExecutor, ExecutorContext};
use async_trait::async_trait;
use futures::StreamExt;
use futures::stream::{self, BoxStream};
use smesh_a2a::{
    DispatchError, ExecutionLimits, InputLimits, MeshDispatcher, MeshEvent, MeshRequest,
    SmeshExecutor,
};

#[derive(Clone, Default)]
struct RecordingDispatcher {
    requests: Arc<Mutex<Vec<MeshRequest>>>,
}

#[async_trait]
impl MeshDispatcher for RecordingDispatcher {
    fn dispatch(
        &self,
        request: MeshRequest,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        self.requests.lock().unwrap().push(request);
        Box::pin(stream::iter([
            Ok(MeshEvent::Progress("claimed by reviewer".into())),
            Ok(MeshEvent::Artifact {
                name: "review.md".into(),
                media_type: "text/markdown".into(),
                content: "all clear".into(),
            }),
            Ok(MeshEvent::Completed {
                summary: "review complete".into(),
            }),
        ]))
    }

    async fn cancel(&self, _task_id: &str) -> Result<(), DispatchError> {
        Ok(())
    }
}

fn context(text: &str) -> ExecutorContext {
    context_with_id("task-1", text)
}

fn context_with_id(task_id: &str, text: &str) -> ExecutorContext {
    ExecutorContext {
        message: Some(Message::new(Role::User, vec![Part::text(text)])),
        task_id: task_id.into(),
        stored_task: None,
        context_id: "context-1".into(),
        metadata: None,
        user: None,
        service_params: HashMap::new(),
        tenant: None,
    }
}

#[tokio::test]
async fn executor_streams_work_artifact_and_terminal_completion() {
    let dispatcher = RecordingDispatcher::default();
    let recorded = dispatcher.requests.clone();
    let executor = SmeshExecutor::new(dispatcher, InputLimits::default(), "gateway-node");

    let events: Vec<_> = executor.execute(context("review it")).collect().await;
    let events: Vec<_> = events.into_iter().collect::<Result<_, _>>().unwrap();

    assert_eq!(recorded.lock().unwrap()[0].text, "review it");
    assert!(matches!(
        &events[0],
        StreamResponse::Task(task) if task.status.state == TaskState::Working
    ));
    assert!(matches!(&events[1], StreamResponse::StatusUpdate(_)));
    assert!(matches!(&events[2], StreamResponse::ArtifactUpdate(_)));
    assert!(matches!(
        &events[3],
        StreamResponse::Task(task) if task.status.state == TaskState::Completed
    ));
}

#[derive(Clone, Default)]
struct EmptyDispatcher;

#[async_trait]
impl MeshDispatcher for EmptyDispatcher {
    fn dispatch(
        &self,
        _request: MeshRequest,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        Box::pin(stream::empty())
    }

    async fn cancel(&self, _task_id: &str) -> Result<(), DispatchError> {
        Ok(())
    }
}

#[tokio::test]
async fn executor_fails_a_task_if_the_mesh_stream_ends_without_a_terminal_event() {
    let executor = SmeshExecutor::new(EmptyDispatcher, InputLimits::default(), "gateway-node");

    let events: Vec<_> = executor.execute(context("review it")).collect().await;
    let events: Vec<_> = events.into_iter().collect::<Result<_, _>>().unwrap();

    assert!(matches!(
        events.last(),
        Some(StreamResponse::Task(task)) if task.status.state == TaskState::Failed
    ));
}

#[derive(Clone, Default)]
struct HoldingDispatcher;

#[async_trait]
impl MeshDispatcher for HoldingDispatcher {
    fn dispatch(
        &self,
        _request: MeshRequest,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        Box::pin(stream::pending())
    }

    async fn cancel(&self, _task_id: &str) -> Result<(), DispatchError> {
        Ok(())
    }
}

#[tokio::test]
async fn cancellation_wakes_and_closes_the_original_execution_stream() {
    let executor = SmeshExecutor::new(HoldingDispatcher, InputLimits::default(), "gateway-node");
    let mut execution = executor.execute(context("hold"));
    assert!(matches!(
        execution.next().await,
        Some(Ok(StreamResponse::Task(task))) if task.status.state == TaskState::Working
    ));

    let cancel_events: Vec<_> = executor
        .cancel(ExecutorContext {
            message: None,
            task_id: "task-1".into(),
            stored_task: None,
            context_id: "context-1".into(),
            metadata: None,
            user: None,
            service_params: HashMap::new(),
            tenant: None,
        })
        .collect()
        .await;
    assert!(matches!(
        cancel_events.as_slice(),
        [Ok(StreamResponse::StatusUpdate(update))] if update.status.state == TaskState::Canceled
    ));

    let closed = tokio::time::timeout(Duration::from_millis(100), execution.next()).await;
    assert!(closed.unwrap().is_none());
}

#[derive(Clone, Default)]
struct ArtifactBurstDispatcher;

#[async_trait]
impl MeshDispatcher for ArtifactBurstDispatcher {
    fn dispatch(
        &self,
        _request: MeshRequest,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        Box::pin(stream::iter([
            Ok(MeshEvent::Artifact {
                name: "one".into(),
                media_type: "text/plain".into(),
                content: "one".into(),
            }),
            Ok(MeshEvent::Artifact {
                name: "two".into(),
                media_type: "text/plain".into(),
                content: "two".into(),
            }),
            Ok(MeshEvent::Completed {
                summary: "done".into(),
            }),
        ]))
    }

    async fn cancel(&self, _task_id: &str) -> Result<(), DispatchError> {
        Ok(())
    }
}

#[tokio::test]
async fn executor_fails_when_worker_exceeds_artifact_budget() {
    let executor = SmeshExecutor::new(
        ArtifactBurstDispatcher,
        InputLimits::default(),
        "gateway-node",
    )
    .with_execution_limits(ExecutionLimits {
        max_artifacts: 1,
        ..ExecutionLimits::default()
    });

    let events: Vec<_> = executor.execute(context("burst")).collect().await;
    let events: Vec<_> = events.into_iter().collect::<Result<_, _>>().unwrap();

    assert!(matches!(
        events.last(),
        Some(StreamResponse::Task(task)) if task.status.state == TaskState::Failed
    ));
}

#[tokio::test]
async fn executor_fails_after_worker_inactivity_timeout() {
    let executor = SmeshExecutor::new(HoldingDispatcher, InputLimits::default(), "gateway-node")
        .with_execution_limits(ExecutionLimits {
            worker_idle_timeout: Duration::from_millis(10),
            ..ExecutionLimits::default()
        });

    let events = tokio::time::timeout(
        Duration::from_millis(100),
        executor.execute(context("idle")).collect::<Vec<_>>(),
    )
    .await
    .unwrap();
    let events: Vec<_> = events.into_iter().collect::<Result<_, _>>().unwrap();

    assert!(matches!(
        events.last(),
        Some(StreamResponse::Task(task)) if task.status.state == TaskState::Failed
    ));
}

#[tokio::test]
async fn executor_fails_after_total_task_deadline() {
    let executor = SmeshExecutor::new(HoldingDispatcher, InputLimits::default(), "gateway-node")
        .with_execution_limits(ExecutionLimits {
            worker_idle_timeout: Duration::from_secs(1),
            task_timeout: Duration::from_millis(10),
            ..ExecutionLimits::default()
        });

    let events = tokio::time::timeout(
        Duration::from_millis(100),
        executor.execute(context("deadline")).collect::<Vec<_>>(),
    )
    .await
    .unwrap();
    let events: Vec<_> = events.into_iter().collect::<Result<_, _>>().unwrap();
    assert!(matches!(
        events.last(),
        Some(StreamResponse::Task(task)) if task.status.state == TaskState::Failed
    ));
}

#[tokio::test]
async fn executor_rejects_work_above_concurrency_limit() {
    let executor = SmeshExecutor::new(HoldingDispatcher, InputLimits::default(), "gateway-node")
        .with_execution_limits(ExecutionLimits {
            max_concurrent_tasks: 1,
            ..ExecutionLimits::default()
        });
    let mut first = executor.execute(context_with_id("first", "hold"));
    assert!(matches!(
        first.next().await,
        Some(Ok(StreamResponse::Task(task))) if task.status.state == TaskState::Working
    ));

    let second = tokio::time::timeout(
        Duration::from_millis(100),
        executor
            .execute(context_with_id("second", "overflow"))
            .collect::<Vec<_>>(),
    )
    .await
    .unwrap();
    let second: Vec<_> = second.into_iter().collect::<Result<_, _>>().unwrap();
    assert!(matches!(
        second.as_slice(),
        [StreamResponse::Task(task)] if task.status.state == TaskState::Rejected
    ));

    let _ = executor
        .cancel(ExecutorContext {
            message: None,
            task_id: "first".into(),
            stored_task: None,
            context_id: "context-1".into(),
            metadata: None,
            user: None,
            service_params: HashMap::new(),
            tenant: None,
        })
        .collect::<Vec<_>>()
        .await;
}

#[derive(Clone, Default)]
struct SeventeenEventDispatcher;

#[async_trait]
impl MeshDispatcher for SeventeenEventDispatcher {
    fn dispatch(
        &self,
        _request: MeshRequest,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        let mut events = (0..16)
            .map(|index| Ok(MeshEvent::Progress(format!("progress-{index}"))))
            .collect::<Vec<_>>();
        events.push(Ok(MeshEvent::Completed {
            summary: "should exceed clamped budget".into(),
        }));
        Box::pin(stream::iter(events))
    }

    async fn cancel(&self, _task_id: &str) -> Result<(), DispatchError> {
        Ok(())
    }
}

#[tokio::test]
async fn caller_supplied_event_budget_is_clamped_below_a2a_broadcast_capacity() {
    let executor = SmeshExecutor::new(
        SeventeenEventDispatcher,
        InputLimits::default(),
        "gateway-node",
    )
    .with_execution_limits(ExecutionLimits {
        max_events: 256,
        ..ExecutionLimits::default()
    });

    let events: Vec<_> = executor.execute(context("clamp")).collect().await;
    let events: Vec<_> = events.into_iter().collect::<Result<_, _>>().unwrap();
    assert!(matches!(
        events.last(),
        Some(StreamResponse::Task(task)) if task.status.state == TaskState::Failed
    ));
}
