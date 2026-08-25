use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use a2a::{
    CancelTaskRequest, Message, Part, Role, SendMessageConfiguration, SendMessageRequest,
    SendMessageResponse, TRANSPORT_PROTOCOL_HTTP_JSON, TRANSPORT_PROTOCOL_JSONRPC, TaskState,
    error_code,
};
use a2a_client::A2AClientFactory;
use a2a_client::agent_card::AgentCardResolver;
use async_trait::async_trait;
use futures::{
    StreamExt,
    stream::{self, BoxStream},
};
use smesh_a2a::{
    DispatchError, GatewayConfig, LoopbackDispatcher, MeshDispatcher, MeshEvent, MeshRequest,
    build_router,
};

#[tokio::test]
async fn official_client_discovers_and_completes_a_jsonrpc_task() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let base_url = format!("http://{address}");
    let app = build_router(
        GatewayConfig::new(&base_url, "gateway-node"),
        LoopbackDispatcher,
    );
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let card = AgentCardResolver::new(None)
        .resolve(&base_url)
        .await
        .unwrap();
    let client = A2AClientFactory::builder()
        .preferred_bindings(vec![TRANSPORT_PROTOCOL_JSONRPC.to_owned()])
        .build()
        .create_from_card(&card)
        .await
        .unwrap();
    let response = client
        .send_message(&SendMessageRequest {
            message: Message::new(Role::User, vec![Part::text("review this crate")]),
            configuration: None,
            metadata: None,
            tenant: None,
        })
        .await
        .unwrap();

    match response {
        SendMessageResponse::Task(task) => {
            assert_eq!(task.status.state, TaskState::Completed);
            assert_eq!(task.artifacts.as_ref().map(Vec::len), Some(1));
            assert_eq!(task.history.as_ref().map(Vec::len), Some(1));
        }
        SendMessageResponse::Message(_) => panic!("expected a tracked task"),
    }

    server.abort();
}

#[tokio::test]
async fn official_client_completes_a_rest_task() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let base_url = format!("http://{address}");
    let app = build_router(
        GatewayConfig::new(&base_url, "gateway-node"),
        LoopbackDispatcher,
    );
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let card = AgentCardResolver::new(None)
        .resolve(&base_url)
        .await
        .unwrap();
    let client = A2AClientFactory::builder()
        .preferred_bindings(vec![TRANSPORT_PROTOCOL_HTTP_JSON.to_owned()])
        .build()
        .create_from_card(&card)
        .await
        .unwrap();
    let response = client
        .send_message(&SendMessageRequest {
            message: Message::new(Role::User, vec![Part::text("review over REST")]),
            configuration: None,
            metadata: None,
            tenant: None,
        })
        .await
        .unwrap();

    let SendMessageResponse::Task(task) = response else {
        panic!("expected a tracked task");
    };
    assert_eq!(task.status.state, TaskState::Completed);
    assert_eq!(task.artifacts.as_ref().map(Vec::len), Some(1));

    server.abort();
}

#[tokio::test]
async fn official_client_receives_ordered_streaming_updates() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let base_url = format!("http://{address}");
    let app = build_router(
        GatewayConfig::new(&base_url, "gateway-node"),
        LoopbackDispatcher,
    );
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let card = AgentCardResolver::new(None)
        .resolve(&base_url)
        .await
        .unwrap();
    let client = A2AClientFactory::builder()
        .preferred_bindings(vec![TRANSPORT_PROTOCOL_JSONRPC.to_owned()])
        .build()
        .create_from_card(&card)
        .await
        .unwrap();
    let mut stream = client
        .send_streaming_message(&SendMessageRequest {
            message: Message::new(Role::User, vec![Part::text("stream review")]),
            configuration: None,
            metadata: None,
            tenant: None,
        })
        .await
        .unwrap();

    let mut states = Vec::new();
    let mut artifacts = 0;
    let mut first_was_task = None;
    while let Some(event) = stream.next().await {
        match event.unwrap() {
            a2a::StreamResponse::Task(task) => {
                first_was_task.get_or_insert(true);
                states.push(task.status.state);
            }
            a2a::StreamResponse::StatusUpdate(update) => {
                first_was_task.get_or_insert(false);
                states.push(update.status.state);
            }
            a2a::StreamResponse::ArtifactUpdate(_) => {
                first_was_task.get_or_insert(false);
                artifacts += 1;
            }
            a2a::StreamResponse::Message(_) => {
                first_was_task.get_or_insert(false);
            }
        }
    }

    assert_eq!(first_was_task, Some(true));
    assert_eq!(states.first(), Some(&TaskState::Working));
    assert!(states.contains(&TaskState::Working));
    assert_eq!(states.last(), Some(&TaskState::Completed));
    assert_eq!(artifacts, 1);

    server.abort();
}

#[tokio::test]
async fn terminal_task_id_cannot_be_reused() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let base_url = format!("http://{address}");
    let app = build_router(
        GatewayConfig::new(&base_url, "gateway-node"),
        LoopbackDispatcher,
    );
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let card = AgentCardResolver::new(None)
        .resolve(&base_url)
        .await
        .unwrap();
    let client = A2AClientFactory::builder()
        .preferred_bindings(vec![TRANSPORT_PROTOCOL_JSONRPC.to_owned()])
        .build()
        .create_from_card(&card)
        .await
        .unwrap();
    let first = client
        .send_message(&SendMessageRequest {
            message: Message::new(Role::User, vec![Part::text("first")]),
            configuration: None,
            metadata: None,
            tenant: None,
        })
        .await
        .unwrap();
    let SendMessageResponse::Task(first) = first else {
        panic!("expected task");
    };
    assert_eq!(first.status.state, TaskState::Completed);

    let mut follow_up = Message::new(Role::User, vec![Part::text("reuse")]);
    follow_up.task_id = Some(first.id.clone());
    let error = client
        .send_message(&SendMessageRequest {
            message: follow_up,
            configuration: None,
            metadata: None,
            tenant: None,
        })
        .await
        .unwrap_err();

    assert_eq!(error.code, error_code::UNSUPPORTED_OPERATION);

    server.abort();
}

#[tokio::test]
async fn invalid_input_becomes_a_terminal_rejected_task() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let base_url = format!("http://{address}");
    let app = build_router(
        GatewayConfig::new(&base_url, "gateway-node"),
        LoopbackDispatcher,
    );
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let card = AgentCardResolver::new(None)
        .resolve(&base_url)
        .await
        .unwrap();
    let client = A2AClientFactory::builder()
        .preferred_bindings(vec![TRANSPORT_PROTOCOL_JSONRPC.to_owned()])
        .build()
        .create_from_card(&card)
        .await
        .unwrap();
    let response = client
        .send_message(&SendMessageRequest {
            message: Message::new(Role::User, vec![Part::url("https://example.invalid/file")]),
            configuration: None,
            metadata: None,
            tenant: None,
        })
        .await
        .unwrap();

    let SendMessageResponse::Task(task) = response else {
        panic!("expected a rejected tracked task");
    };
    assert_eq!(task.status.state, TaskState::Rejected);

    server.abort();
}

#[derive(Clone, Default)]
struct SafeBurstDispatcher;

#[async_trait]
impl MeshDispatcher for SafeBurstDispatcher {
    fn dispatch(
        &self,
        _request: MeshRequest,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        let mut events = (0..15)
            .map(|index| Ok(MeshEvent::Progress(format!("progress-{index}"))))
            .collect::<Vec<_>>();
        events.push(Ok(MeshEvent::Completed {
            summary: "burst complete".into(),
        }));
        Box::pin(stream::iter(events))
    }

    async fn cancel(&self, _task_id: &str) -> Result<(), DispatchError> {
        Ok(())
    }
}

#[tokio::test]
async fn maximum_safe_event_burst_does_not_overrun_a2a_subscription_buffer() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let base_url = format!("http://{address}");
    let app = build_router(
        GatewayConfig::new(&base_url, "gateway-node"),
        SafeBurstDispatcher,
    );
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let card = AgentCardResolver::new(None)
        .resolve(&base_url)
        .await
        .unwrap();
    let client = A2AClientFactory::builder()
        .preferred_bindings(vec![TRANSPORT_PROTOCOL_JSONRPC.to_owned()])
        .build()
        .create_from_card(&card)
        .await
        .unwrap();
    let events = client
        .send_streaming_message(&SendMessageRequest {
            message: Message::new(Role::User, vec![Part::text("burst")]),
            configuration: None,
            metadata: None,
            tenant: None,
        })
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await;

    assert_eq!(events.len(), 17);
    assert!(matches!(
        events.last(),
        Some(Ok(a2a::StreamResponse::Task(task))) if task.status.state == TaskState::Completed
    ));

    server.abort();
}

#[derive(Clone, Default)]
struct HoldingDispatcher {
    canceled: Arc<Mutex<HashSet<String>>>,
}

#[async_trait]
impl MeshDispatcher for HoldingDispatcher {
    fn dispatch(
        &self,
        _request: MeshRequest,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        Box::pin(stream::pending())
    }

    async fn cancel(&self, task_id: &str) -> Result<(), DispatchError> {
        self.canceled.lock().unwrap().insert(task_id.to_owned());
        Ok(())
    }
}

#[tokio::test]
async fn official_client_cancellation_reaches_the_mesh_dispatcher() {
    let dispatcher = HoldingDispatcher::default();
    let canceled = Arc::clone(&dispatcher.canceled);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let base_url = format!("http://{address}");
    let app = build_router(GatewayConfig::new(&base_url, "gateway-node"), dispatcher);
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let card = AgentCardResolver::new(None)
        .resolve(&base_url)
        .await
        .unwrap();
    let client = A2AClientFactory::builder()
        .preferred_bindings(vec![TRANSPORT_PROTOCOL_JSONRPC.to_owned()])
        .build()
        .create_from_card(&card)
        .await
        .unwrap();
    let response = client
        .send_message(&SendMessageRequest {
            message: Message::new(Role::User, vec![Part::text("wait for cancellation")]),
            configuration: Some(SendMessageConfiguration {
                accepted_output_modes: None,
                task_push_notification_config: None,
                history_length: None,
                return_immediately: Some(true),
            }),
            metadata: None,
            tenant: None,
        })
        .await
        .unwrap();
    let SendMessageResponse::Task(task) = response else {
        panic!("expected a tracked task");
    };

    let canceled_task = client
        .cancel_task(&CancelTaskRequest {
            id: task.id.clone(),
            metadata: None,
            tenant: None,
        })
        .await
        .unwrap();

    assert_eq!(canceled_task.status.state, TaskState::Canceled);
    assert!(canceled.lock().unwrap().contains(&task.id));

    server.abort();
}

#[tokio::test]
async fn cancellation_terminates_the_active_stream_without_post_cancel_work() {
    let dispatcher = HoldingDispatcher::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let base_url = format!("http://{address}");
    let app = build_router(GatewayConfig::new(&base_url, "gateway-node"), dispatcher);
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let card = AgentCardResolver::new(None)
        .resolve(&base_url)
        .await
        .unwrap();
    let client = A2AClientFactory::builder()
        .preferred_bindings(vec![TRANSPORT_PROTOCOL_JSONRPC.to_owned()])
        .build()
        .create_from_card(&card)
        .await
        .unwrap();
    let mut stream = client
        .send_streaming_message(&SendMessageRequest {
            message: Message::new(Role::User, vec![Part::text("hold")]),
            configuration: None,
            metadata: None,
            tenant: None,
        })
        .await
        .unwrap();
    let first = stream.next().await.unwrap().unwrap();
    let a2a::StreamResponse::Task(working) = first else {
        panic!("stream must begin with a task");
    };
    assert_eq!(working.status.state, TaskState::Working);

    let canceled_task = client
        .cancel_task(&CancelTaskRequest {
            id: working.id,
            metadata: None,
            tenant: None,
        })
        .await
        .unwrap();
    assert_eq!(canceled_task.status.state, TaskState::Canceled);

    let remaining = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        stream.collect::<Vec<_>>(),
    )
    .await
    .unwrap();
    for event in remaining {
        match event.unwrap() {
            a2a::StreamResponse::Task(task) => {
                assert_ne!(task.status.state, TaskState::Working);
                assert_ne!(task.status.state, TaskState::Completed);
            }
            a2a::StreamResponse::StatusUpdate(update) => {
                assert_ne!(update.status.state, TaskState::Working);
                assert_ne!(update.status.state, TaskState::Completed);
            }
            _ => {}
        }
    }

    server.abort();
}
