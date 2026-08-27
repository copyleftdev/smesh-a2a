use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use a2a::{
    A2AError, Artifact, GetTaskRequest, ListTasksRequest, ListTasksResponse, Message, Part,
    PartContent, Role, SendMessageConfiguration, SendMessageRequest, SendMessageResponse,
    StreamResponse, SubscribeToTaskRequest, TRANSPORT_PROTOCOL_HTTP_JSON,
    TRANSPORT_PROTOCOL_JSONRPC, Task, TaskState, TaskStatus, error_code,
};
use a2a_client::agent_card::AgentCardResolver;
use a2a_client::{A2AClient, A2AClientFactory, Transport};
use a2a_server::TaskStore;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::{StreamExt, stream::BoxStream};
use smesh_a2a::{
    ArtifactManifest, BoundedTaskStore, CompletionEvidence, CompletionPolicyStore,
    CompletionReceipt, DispatchError, GatewayConfig, LoopbackDispatcher, MeshDispatcher, MeshEvent,
    MeshRequest, VersionedCompletionPolicy, artifact_set_digest, build_router_with_policy,
    content_digest,
};
use tokio::sync::{Notify, mpsc};
use tokio_stream::wrappers::ReceiverStream;

struct TestServer {
    base_url: String,
    task: tokio::task::JoinHandle<()>,
}

impl TestServer {
    async fn start<D: MeshDispatcher>(dispatcher: D) -> Self {
        Self::start_with_store(dispatcher, BoundedTaskStore::new(1024)).await
    }

    async fn start_with_store<D, S>(dispatcher: D, store: S) -> Self
    where
        D: MeshDispatcher,
        S: CompletionPolicyStore + Clone + 'static,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let base_url = format!("http://{address}");
        let app = build_router_with_policy(
            GatewayConfig::new(&base_url, "task-management-test"),
            dispatcher,
            store,
            VersionedCompletionPolicy::default(),
        )
        .unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { base_url, task }
    }

    async fn client(&self, binding: &str) -> A2AClient<Box<dyn Transport>> {
        let card = AgentCardResolver::new(None)
            .resolve(&self.base_url)
            .await
            .unwrap();
        A2AClientFactory::builder()
            .preferred_bindings(vec![binding.to_owned()])
            .build()
            .create_from_card(&card)
            .await
            .unwrap()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn send_request(text: &str, context_id: Option<&str>) -> SendMessageRequest {
    let mut message = Message::new(Role::User, vec![Part::text(text)]);
    message.context_id = context_id.map(str::to_owned);
    SendMessageRequest {
        message,
        configuration: None,
        metadata: None,
        tenant: None,
    }
}

fn immediate_request(text: &str) -> SendMessageRequest {
    let mut request = send_request(text, None);
    request.configuration = Some(SendMessageConfiguration {
        accepted_output_modes: None,
        task_push_notification_config: None,
        history_length: None,
        return_immediately: Some(true),
    });
    request
}

async fn expect_subscribe_error(
    result: Result<BoxStream<'static, Result<StreamResponse, a2a::A2AError>>, a2a::A2AError>,
) -> a2a::A2AError {
    match result {
        Ok(mut stream) => match tokio::time::timeout(Duration::from_secs(2), stream.next()).await {
            Ok(Some(Err(error))) => error,
            Ok(Some(Ok(_))) => panic!("expected subscription error, received an event"),
            Ok(None) => panic!("expected subscription error, stream closed cleanly"),
            Err(error) => panic!("timed out waiting for subscription error: {error}"),
        },
        Err(error) => error,
    }
}

async fn send_completed(client: &A2AClient<Box<dyn Transport>>, text: &str, context: &str) -> Task {
    let response = client
        .send_message(&send_request(text, Some(context)))
        .await
        .unwrap();
    let SendMessageResponse::Task(task) = response else {
        panic!("expected tracked task");
    };
    assert_eq!(task.status.state, TaskState::Completed);
    task
}

fn fixture_task(id: &str, context_id: &str, timestamp: &str) -> Task {
    Task {
        id: id.to_owned(),
        context_id: context_id.to_owned(),
        status: TaskStatus {
            state: TaskState::Working,
            message: None,
            timestamp: Some(
                chrono::DateTime::parse_from_rfc3339(timestamp)
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
        },
        artifacts: None,
        history: Some(vec![Message::new(Role::User, vec![Part::text(id)])]),
        metadata: None,
    }
}

#[tokio::test]
async fn official_clients_receive_the_most_recent_bounded_history_messages() {
    let store = BoundedTaskStore::new(8);
    let history = ["oldest", "middle", "newest"]
        .into_iter()
        .map(|text| Message::new(Role::User, vec![Part::text(text)]))
        .collect::<Vec<_>>();
    let expected_ids = history[1..]
        .iter()
        .map(|message| message.message_id.clone())
        .collect::<Vec<_>>();
    store
        .create(Task {
            id: "history-task".to_owned(),
            context_id: "history-context".to_owned(),
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: Some(chrono::Utc::now()),
            },
            artifacts: None,
            history: Some(history),
            metadata: None,
        })
        .await
        .unwrap();
    let server = TestServer::start_with_store(LoopbackDispatcher, store).await;

    for binding in [TRANSPORT_PROTOCOL_JSONRPC, TRANSPORT_PROTOCOL_HTTP_JSON] {
        let client = server.client(binding).await;
        let task = client
            .get_task(&GetTaskRequest {
                id: "history-task".to_owned(),
                history_length: Some(2),
                tenant: None,
            })
            .await
            .unwrap();
        assert_eq!(
            task.history
                .unwrap()
                .into_iter()
                .map(|message| message.message_id)
                .collect::<Vec<_>>(),
            expected_ids
        );

        let listed = client
            .list_tasks(&ListTasksRequest {
                context_id: Some("history-context".to_owned()),
                status: Some(TaskState::Working),
                page_size: Some(10),
                page_token: None,
                history_length: Some(2),
                status_timestamp_after: None,
                include_artifacts: Some(false),
                tenant: None,
            })
            .await
            .unwrap();
        assert_eq!(listed.tasks.len(), 1);
        assert_eq!(
            listed.tasks[0]
                .history
                .as_ref()
                .unwrap()
                .iter()
                .map(|message| message.message_id.clone())
                .collect::<Vec<_>>(),
            expected_ids
        );
    }
}

#[tokio::test]
async fn preloaded_tasks_cannot_bypass_policy_receipt_and_artifact_visibility_guards() {
    let store = BoundedTaskStore::new(8);
    for (id, state) in [
        ("unverified-completed", TaskState::Completed),
        ("unverified-working", TaskState::Working),
    ] {
        let mut task = fixture_task(id, "unverified-context", "2026-01-01T00:00:00Z");
        task.status.state = state;
        task.artifacts = Some(vec![Artifact {
            artifact_id: format!("artifact-{id}"),
            name: Some("unverified.txt".to_owned()),
            description: None,
            parts: vec![Part::text("candidate").with_media_type("text/plain")],
            metadata: None,
            extensions: None,
        }]);
        store.create(task).await.unwrap();
    }
    let server = TestServer::start_with_store(LoopbackDispatcher, store.clone()).await;
    let client = server.client(TRANSPORT_PROTOCOL_JSONRPC).await;
    let valid = send_completed(&client, "valid receipt", "unverified-context").await;
    let mut replayed_receipt = valid;
    replayed_receipt.id = "replayed-receipt".to_owned();
    replayed_receipt
        .metadata
        .as_mut()
        .unwrap()
        .get_mut("smesh.completionPolicy")
        .unwrap()["record"]["taskId"] = serde_json::Value::String("replayed-receipt".to_owned());
    let record = &mut replayed_receipt
        .metadata
        .as_mut()
        .unwrap()
        .get_mut("smesh.completionPolicy")
        .unwrap()["record"];
    record["policyVersion"] = serde_json::json!(1_u32);
    record["assuranceBps"] = serde_json::json!(10_000_u16);
    let receipt: CompletionReceipt = serde_json::from_value(
        replayed_receipt.metadata.as_ref().unwrap()["smesh.completionPolicy"]["record"].clone(),
    )
    .unwrap();
    assert_eq!(receipt.task_id, replayed_receipt.id);
    let artifacts = replayed_receipt.artifacts.as_ref().unwrap();
    let manifests = artifacts
        .iter()
        .map(|artifact| {
            let [part] = artifact.parts.as_slice() else {
                panic!("fixture artifact must have one part");
            };
            let PartContent::Text(content) = &part.content else {
                panic!("fixture artifact must be text");
            };
            ArtifactManifest {
                name: artifact.name.clone().unwrap(),
                media_type: part.media_type.clone().unwrap(),
                digest: content_digest(content.as_bytes()),
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(
        receipt.artifact_set_digest,
        artifact_set_digest(&manifests).unwrap()
    );
    store.create(replayed_receipt).await.unwrap();

    for id in [
        "unverified-completed",
        "unverified-working",
        "replayed-receipt",
    ] {
        let error = client
            .get_task(&GetTaskRequest {
                id: id.to_owned(),
                history_length: None,
                tenant: None,
            })
            .await
            .unwrap_err();
        assert_eq!(error.code, error_code::INVALID_AGENT_RESPONSE);
    }
    let list_error = client
        .list_tasks(&ListTasksRequest {
            context_id: Some("unverified-context".to_owned()),
            status: None,
            page_size: Some(10),
            page_token: None,
            history_length: None,
            status_timestamp_after: None,
            include_artifacts: Some(true),
            tenant: None,
        })
        .await
        .unwrap_err();
    assert_eq!(list_error.code, error_code::INVALID_AGENT_RESPONSE);
}

#[tokio::test]
async fn official_clients_get_tasks_with_bounded_history_and_not_found_errors() {
    for binding in [TRANSPORT_PROTOCOL_JSONRPC, TRANSPORT_PROTOCOL_HTTP_JSON] {
        let server = TestServer::start(LoopbackDispatcher).await;
        let client = server.client(binding).await;
        let created = send_completed(&client, "bounded history", "get-context").await;

        let without_history = client
            .get_task(&GetTaskRequest {
                id: created.id.clone(),
                history_length: Some(0),
                tenant: None,
            })
            .await
            .unwrap();
        assert!(
            without_history.history.is_none(),
            "historyLength=0 must omit history over {binding}"
        );

        let with_one_message = client
            .get_task(&GetTaskRequest {
                id: created.id.clone(),
                history_length: Some(1),
                tenant: None,
            })
            .await
            .unwrap();
        assert_eq!(with_one_message.history.as_ref().map(Vec::len), Some(1));

        let negative = client
            .get_task(&GetTaskRequest {
                id: created.id.clone(),
                history_length: Some(-1),
                tenant: None,
            })
            .await
            .unwrap_err();
        assert_eq!(negative.code, error_code::INVALID_PARAMS);

        let missing = client
            .get_task(&GetTaskRequest {
                id: "missing-task".to_owned(),
                history_length: None,
                tenant: None,
            })
            .await
            .unwrap_err();
        assert_eq!(missing.code, error_code::TASK_NOT_FOUND);

        let projected = client
            .list_tasks(&ListTasksRequest {
                context_id: Some(created.context_id.clone()),
                status: Some(TaskState::Completed),
                page_size: Some(10),
                page_token: None,
                history_length: Some(0),
                status_timestamp_after: None,
                include_artifacts: Some(false),
                tenant: None,
            })
            .await
            .unwrap();
        assert_eq!(projected.tasks.len(), 1);
        assert!(projected.tasks[0].artifacts.is_none());
    }
}

async fn assert_cursor_survives_concurrent_insert(
    client: &A2AClient<Box<dyn Transport>>,
    store: &BoundedTaskStore,
    binding: &str,
    expected: HashSet<String>,
    inserted_task: Task,
) -> ListTasksRequest {
    let page_request = ListTasksRequest {
        context_id: None,
        status: Some(TaskState::Working),
        page_size: Some(2),
        page_token: None,
        history_length: Some(0),
        status_timestamp_after: None,
        include_artifacts: Some(false),
        tenant: None,
    };
    let page_one = client.list_tasks(&page_request).await.unwrap();
    let page_one_repeat = client.list_tasks(&page_request).await.unwrap();
    assert_eq!(
        page_one
            .tasks
            .iter()
            .map(|task| &task.id)
            .collect::<Vec<_>>(),
        page_one_repeat
            .tasks
            .iter()
            .map(|task| &task.id)
            .collect::<Vec<_>>(),
        "first page must be stable over {binding}"
    );
    assert_eq!(page_one.tasks.len(), 2);
    assert!(!page_one.next_page_token.is_empty());
    assert_eq!(page_one.total_size, 3);
    assert!(page_one.tasks.iter().all(|task| task.history.is_none()));
    assert!(page_one.tasks.iter().all(|task| task.artifacts.is_none()));

    let mut token_bytes = URL_SAFE_NO_PAD
        .decode(&page_one.next_page_token)
        .expect("server-issued cursor");
    let signature = token_bytes.split_off(token_bytes.len() - 32);
    let mut forged_payload: serde_json::Value =
        serde_json::from_slice(&token_bytes).expect("cursor payload");
    forged_payload["taskId"] = serde_json::Value::String(page_one.tasks[0].id.clone());
    forged_payload["statusTimestamp"] =
        serde_json::to_value(page_one.tasks[0].status.timestamp).unwrap();
    let mut forged_bytes = serde_json::to_vec(&forged_payload).unwrap();
    forged_bytes.extend_from_slice(&signature);
    let forged_token = URL_SAFE_NO_PAD.encode(forged_bytes);
    let forged_error = client
        .list_tasks(&ListTasksRequest {
            page_token: Some(forged_token),
            ..page_request.clone()
        })
        .await
        .unwrap_err();
    assert_eq!(forged_error.code, error_code::INVALID_PARAMS);

    let replay_error = client
        .list_tasks(&ListTasksRequest {
            page_token: Some(page_one.next_page_token.clone()),
            include_artifacts: Some(true),
            ..page_request.clone()
        })
        .await
        .unwrap_err();
    assert_eq!(replay_error.code, error_code::INVALID_PARAMS);

    let oversized_error = client
        .list_tasks(&ListTasksRequest {
            page_token: Some("a".repeat(4097)),
            ..page_request.clone()
        })
        .await
        .unwrap_err();
    assert_eq!(oversized_error.code, error_code::INVALID_PARAMS);

    let inserted_after_page_one = inserted_task.id.clone();
    store.create(inserted_task).await.unwrap();
    let page_two = client
        .list_tasks(&ListTasksRequest {
            page_token: Some(page_one.next_page_token.clone()),
            ..page_request.clone()
        })
        .await
        .unwrap();
    assert_eq!(page_two.tasks.len(), 1);
    assert_eq!(page_two.total_size, 4);
    assert!(page_two.next_page_token.is_empty());
    assert!(
        page_two
            .tasks
            .iter()
            .all(|task| task.id != inserted_after_page_one)
    );
    let actual: HashSet<String> = page_one
        .tasks
        .iter()
        .chain(&page_two.tasks)
        .map(|task| task.id.clone())
        .collect();
    assert_eq!(actual, expected);
    page_request
}

#[tokio::test]
async fn official_clients_list_tasks_with_filters_stable_pagination_and_projection() {
    for binding in [TRANSPORT_PROTOCOL_JSONRPC, TRANSPORT_PROTOCOL_HTTP_JSON] {
        let store = BoundedTaskStore::new(16);
        let initial = [
            fixture_task("task-first", "shared-context", "2026-01-01T00:00:00Z"),
            fixture_task("task-second", "shared-context", "2026-01-01T00:00:01Z"),
            fixture_task("task-other", "other-context", "2026-01-01T00:00:02Z"),
        ];
        for task in &initial {
            store.create(task.clone()).await.unwrap();
        }
        let server = TestServer::start_with_store(LoopbackDispatcher, store.clone()).await;
        let client = server.client(binding).await;
        let expected = initial.iter().map(|task| task.id.clone()).collect();
        let inserted = fixture_task("task-inserted", "new-context", "2026-01-01T00:00:03Z");
        let page_request =
            assert_cursor_survives_concurrent_insert(&client, &store, binding, expected, inserted)
                .await;

        let shared = client
            .list_tasks(&ListTasksRequest {
                context_id: Some("shared-context".to_owned()),
                status: Some(TaskState::Working),
                page_size: Some(10),
                page_token: None,
                history_length: Some(1),
                status_timestamp_after: None,
                include_artifacts: Some(true),
                tenant: None,
            })
            .await
            .unwrap();
        assert_eq!(shared.tasks.len(), 2);
        assert!(
            shared
                .tasks
                .iter()
                .all(|task| task.context_id == "shared-context")
        );
        assert!(shared.tasks.iter().all(|task| task.artifacts.is_none()));
        assert!(
            shared
                .tasks
                .iter()
                .all(|task| task.history.as_ref().map(Vec::len) == Some(1))
        );

        let invalid_history = client
            .list_tasks(&ListTasksRequest {
                history_length: Some(-1),
                ..page_request.clone()
            })
            .await
            .unwrap_err();
        assert_eq!(invalid_history.code, error_code::INVALID_PARAMS);

        let invalid_token = client
            .list_tasks(&ListTasksRequest {
                page_token: Some("not-a-cursor".to_owned()),
                ..page_request.clone()
            })
            .await
            .unwrap_err();
        assert_eq!(invalid_token.code, error_code::INVALID_PARAMS);
    }
}

type MeshEventResult = Result<MeshEvent, DispatchError>;
type EventSender = mpsc::Sender<MeshEventResult>;

#[derive(Clone, Default)]
struct ControlledDispatcher {
    senders: Arc<Mutex<HashMap<String, EventSender>>>,
    started: Arc<Notify>,
}

impl ControlledDispatcher {
    async fn sender_for(&self, task_id: &str) -> EventSender {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let notified = self.started.notified();
                if let Some(sender) = self.senders.lock().unwrap().get(task_id).cloned() {
                    return sender;
                }
                notified.await;
            }
        })
        .await
        .expect("dispatcher was started")
    }
}

#[async_trait]
impl MeshDispatcher for ControlledDispatcher {
    fn dispatch(
        &self,
        request: MeshRequest,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        let (sender, receiver) = mpsc::channel(8);
        self.senders.lock().unwrap().insert(request.task_id, sender);
        self.started.notify_waiters();
        Box::pin(ReceiverStream::new(receiver))
    }

    async fn cancel(&self, task_id: &str) -> Result<(), DispatchError> {
        self.senders.lock().unwrap().remove(task_id);
        Ok(())
    }
}

#[derive(Default)]
struct DeepCloneTaskStore {
    tasks: Mutex<HashMap<String, Task>>,
}

impl Clone for DeepCloneTaskStore {
    fn clone(&self) -> Self {
        Self {
            tasks: Mutex::new(self.tasks.lock().unwrap().clone()),
        }
    }
}

impl CompletionPolicyStore for DeepCloneTaskStore {
    fn durable_receipt_key(&self) -> Option<[u8; 32]> {
        None
    }
}

#[async_trait]
impl TaskStore for DeepCloneTaskStore {
    async fn create(&self, task: Task) -> Result<u64, A2AError> {
        self.tasks.lock().unwrap().insert(task.id.clone(), task);
        Ok(1)
    }

    async fn update(&self, task: Task) -> Result<u64, A2AError> {
        self.tasks.lock().unwrap().insert(task.id.clone(), task);
        Ok(1)
    }

    async fn get(&self, task_id: &str) -> Result<Option<Task>, A2AError> {
        Ok(self.tasks.lock().unwrap().get(task_id).cloned())
    }

    async fn list(&self, request: &ListTasksRequest) -> Result<ListTasksResponse, A2AError> {
        let tasks = self.tasks.lock().unwrap();
        let visible = tasks
            .values()
            .filter(|task| {
                request
                    .context_id
                    .as_ref()
                    .is_none_or(|context| task.context_id == *context)
            })
            .cloned()
            .collect::<Vec<_>>();
        Ok(ListTasksResponse {
            total_size: i32::try_from(visible.len()).unwrap(),
            page_size: request.page_size.unwrap_or(50),
            tasks: visible,
            next_page_token: String::new(),
        })
    }
}

#[derive(Clone)]
struct InconsistentListTaskStore {
    inner: BoundedTaskStore,
}

impl CompletionPolicyStore for InconsistentListTaskStore {
    fn durable_receipt_key(&self) -> Option<[u8; 32]> {
        None
    }
}

#[async_trait]
impl TaskStore for InconsistentListTaskStore {
    async fn create(&self, task: Task) -> Result<u64, A2AError> {
        self.inner.create(task).await
    }

    async fn update(&self, task: Task) -> Result<u64, A2AError> {
        self.inner.update(task).await
    }

    async fn get(&self, task_id: &str) -> Result<Option<Task>, A2AError> {
        self.inner.get(task_id).await
    }

    async fn list(&self, request: &ListTasksRequest) -> Result<ListTasksResponse, A2AError> {
        let mut response = self.inner.list(request).await?;
        if let Some(task) = response.tasks.first_mut() {
            task.status.state = TaskState::Completed;
            task.artifacts = Some(vec![Artifact {
                artifact_id: "forged-list-artifact".to_owned(),
                name: Some("forged.txt".to_owned()),
                description: None,
                parts: vec![Part::text("forged")],
                metadata: None,
                extensions: None,
            }]);
        }
        Ok(response)
    }
}

#[derive(Clone)]
struct RacingTaskStore {
    inner: BoundedTaskStore,
    armed_task: Arc<Mutex<Option<String>>>,
    armed_reads: Arc<AtomicUsize>,
}

impl RacingTaskStore {
    fn new() -> Self {
        Self {
            inner: BoundedTaskStore::new(16),
            armed_task: Arc::new(Mutex::new(None)),
            armed_reads: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn arm_completion_race(&self, task_id: &str) {
        *self.armed_task.lock().unwrap() = Some(task_id.to_owned());
        self.armed_reads.store(0, Ordering::SeqCst);
    }
}

impl CompletionPolicyStore for RacingTaskStore {
    fn durable_receipt_key(&self) -> Option<[u8; 32]> {
        None
    }
}

#[async_trait]
impl TaskStore for RacingTaskStore {
    async fn create(&self, task: Task) -> Result<u64, A2AError> {
        self.inner.create(task).await
    }

    async fn update(&self, task: Task) -> Result<u64, A2AError> {
        self.inner.update(task).await
    }

    async fn get(&self, task_id: &str) -> Result<Option<Task>, A2AError> {
        let mut task = self.inner.get(task_id).await?;
        let armed = self.armed_task.lock().unwrap().as_deref() == Some(task_id);
        if armed
            && self.armed_reads.fetch_add(1, Ordering::SeqCst) > 0
            && let Some(task) = task.as_mut()
        {
            task.status.state = TaskState::Completed;
        }
        Ok(task)
    }

    async fn list(&self, request: &ListTasksRequest) -> Result<ListTasksResponse, A2AError> {
        self.inner.list(request).await
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Full official-client evidence-to-terminal stream contract.
async fn official_clients_subscribe_to_ordered_updates_until_terminal_closure() {
    for binding in [TRANSPORT_PROTOCOL_JSONRPC, TRANSPORT_PROTOCOL_HTTP_JSON] {
        let dispatcher = ControlledDispatcher::default();
        let server = TestServer::start(dispatcher.clone()).await;
        let client = server.client(binding).await;
        let response = client
            .send_message(&immediate_request("subscribe to active task"))
            .await
            .unwrap();
        let SendMessageResponse::Task(task) = response else {
            panic!("expected tracked task");
        };
        assert_eq!(task.status.state, TaskState::Working);

        let mut subscription = client
            .subscribe_to_task(&SubscribeToTaskRequest {
                id: task.id.clone(),
                tenant: None,
            })
            .await
            .unwrap();
        let sender = dispatcher.sender_for(&task.id).await;
        let subject_digest = artifact_set_digest(&[ArtifactManifest {
            name: "result.json".to_owned(),
            media_type: "application/json".to_owned(),
            digest: content_digest(b"{\"ok\":true}"),
        }])
        .unwrap();
        sender
            .send(Ok(MeshEvent::Progress("runtime claimed task".to_owned())))
            .await
            .unwrap();
        sender
            .send(Ok(MeshEvent::Evidence(CompletionEvidence::Review {
                id: "controlled-review".to_owned(),
                issuer: "review-authority".to_owned(),
                subject_digest: subject_digest.clone(),
                evidence: b"controlled review".to_vec(),
                evidence_digest: content_digest(b"controlled review"),
                approved: true,
                assurance_bps: 9_000,
            })))
            .await
            .unwrap();
        sender
            .send(Ok(MeshEvent::Evidence(CompletionEvidence::Test {
                id: "controlled-test".to_owned(),
                issuer: "test-authority".to_owned(),
                subject_digest: subject_digest.clone(),
                evidence: b"controlled test".to_vec(),
                evidence_digest: content_digest(b"controlled test"),
                passed: true,
                assurance_bps: 9_000,
            })))
            .await
            .unwrap();
        sender
            .send(Ok(MeshEvent::Evidence(CompletionEvidence::Contradiction {
                id: "controlled-contradiction-clearance".to_owned(),
                issuer: "contradiction-monitor".to_owned(),
                subject_digest,
                evidence: b"controlled contradiction clearance".to_vec(),
                evidence_digest: content_digest(b"controlled contradiction clearance"),
                blocking: false,
            })))
            .await
            .unwrap();
        sender
            .send(Ok(MeshEvent::Artifact {
                name: "result.json".to_owned(),
                media_type: "application/json".to_owned(),
                content: "{\"ok\":true}".to_owned(),
            }))
            .await
            .unwrap();
        sender
            .send(Ok(MeshEvent::Completed {
                summary: "runtime completed task".to_owned(),
            }))
            .await
            .unwrap();
        dispatcher.senders.lock().unwrap().remove(&task.id);
        drop(sender);

        let events = tokio::time::timeout(
            Duration::from_secs(2),
            subscription.by_ref().collect::<Vec<_>>(),
        )
        .await
        .expect("subscription closed after terminal event");
        let events = events.into_iter().collect::<Result<Vec<_>, _>>().unwrap();
        let [
            StreamResponse::Task(snapshot),
            StreamResponse::StatusUpdate(progress),
            StreamResponse::Task(completed),
        ] = events.as_slice()
        else {
            panic!("unexpected subscription sequence: {events:?}");
        };
        assert_eq!(snapshot.status.state, TaskState::Working);
        assert_eq!(progress.status.state, TaskState::Working);
        assert!(matches!(
            progress.status.message.as_ref().map(|message| message.parts.as_slice()),
            Some([Part { content: PartContent::Text(text), .. }]) if text == "SMESH worker reported progress"
        ));
        let artifacts = completed.artifacts.as_ref().expect("accepted artifact");
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].name.as_deref(), Some("result.json"));
        assert!(matches!(
            artifacts[0].parts.as_slice(),
            [Part {
                content: PartContent::Text(content),
                media_type: Some(media_type),
                ..
            }] if content == "{\"ok\":true}" && media_type == "application/json"
        ));
        assert_eq!(completed.status.state, TaskState::Completed);
    }
}

#[tokio::test]
async fn inconsistent_list_results_cannot_bypass_authoritative_store_validation() {
    let store = InconsistentListTaskStore {
        inner: BoundedTaskStore::new(8),
    };
    store
        .create(fixture_task(
            "inconsistent-list",
            "inconsistent-context",
            "2026-01-01T00:00:00Z",
        ))
        .await
        .unwrap();
    let server = TestServer::start_with_store(LoopbackDispatcher, store).await;
    let client = server.client(TRANSPORT_PROTOCOL_JSONRPC).await;
    let error = client
        .list_tasks(&ListTasksRequest {
            context_id: Some("inconsistent-context".to_owned()),
            status: Some(TaskState::Working),
            page_size: Some(10),
            page_token: None,
            history_length: None,
            status_timestamp_after: None,
            include_artifacts: Some(true),
            tenant: None,
        })
        .await
        .unwrap_err();
    assert_eq!(error.code, error_code::INVALID_AGENT_RESPONSE);
}

#[tokio::test]
async fn injected_store_is_shared_even_when_its_clone_would_deep_copy_state() {
    let server =
        TestServer::start_with_store(LoopbackDispatcher, DeepCloneTaskStore::default()).await;
    let client = server.client(TRANSPORT_PROTOCOL_HTTP_JSON).await;
    let terminal = send_completed(&client, "deep clone guard", "shared-store-context").await;

    let error = expect_subscribe_error(
        client
            .subscribe_to_task(&SubscribeToTaskRequest {
                id: terminal.id,
                tenant: None,
            })
            .await,
    )
    .await;
    assert_eq!(error.code, error_code::UNSUPPORTED_OPERATION);
}

#[tokio::test]
async fn terminal_subscription_races_never_misclassify_existing_tasks_as_missing() {
    let store = RacingTaskStore::new();
    let dispatcher = ControlledDispatcher::default();
    let server = TestServer::start_with_store(dispatcher, store.clone()).await;
    let client = server.client(TRANSPORT_PROTOCOL_HTTP_JSON).await;

    let response = client
        .send_message(&immediate_request("race active execution"))
        .await
        .unwrap();
    let SendMessageResponse::Task(active) = response else {
        panic!("expected active task");
    };
    store.arm_completion_race(&active.id);
    let active_error = expect_subscribe_error(
        client
            .subscribe_to_task(&SubscribeToTaskRequest {
                id: active.id,
                tenant: None,
            })
            .await,
    )
    .await;
    assert_eq!(active_error.code, error_code::UNSUPPORTED_OPERATION);

    let orphan_id = "orphaned-active-task".to_owned();
    store
        .create(Task {
            id: orphan_id.clone(),
            context_id: "race-context".to_owned(),
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: Some(chrono::Utc::now()),
            },
            artifacts: None,
            history: None,
            metadata: None,
        })
        .await
        .unwrap();
    store.arm_completion_race(&orphan_id);
    let teardown_error = expect_subscribe_error(
        client
            .subscribe_to_task(&SubscribeToTaskRequest {
                id: orphan_id,
                tenant: None,
            })
            .await,
    )
    .await;
    assert_eq!(teardown_error.code, error_code::UNSUPPORTED_OPERATION);
}

#[tokio::test]
async fn subscriptions_distinguish_missing_from_terminal_tasks() {
    // The official JSON-RPC client's streaming transport currently discards
    // non-SSE error bodies. Exercise error semantics with its REST transport;
    // the JSON-RPC wire response is covered separately below.
    for binding in [TRANSPORT_PROTOCOL_HTTP_JSON] {
        let server = TestServer::start(LoopbackDispatcher).await;
        let client = server.client(binding).await;
        let terminal = send_completed(&client, "already done", "terminal-context").await;

        let terminal_error = expect_subscribe_error(
            client
                .subscribe_to_task(&SubscribeToTaskRequest {
                    id: terminal.id,
                    tenant: None,
                })
                .await,
        )
        .await;
        assert_eq!(
            terminal_error.code,
            error_code::UNSUPPORTED_OPERATION,
            "terminal subscription must be unsupported over {binding}"
        );

        let missing_error = expect_subscribe_error(
            client
                .subscribe_to_task(&SubscribeToTaskRequest {
                    id: "missing-task".to_owned(),
                    tenant: None,
                })
                .await,
        )
        .await;
        assert_eq!(missing_error.code, error_code::TASK_NOT_FOUND);
    }
}

#[tokio::test]
async fn jsonrpc_subscription_errors_remain_distinguishable_on_the_wire() {
    let server = TestServer::start(LoopbackDispatcher).await;
    let client = server.client(TRANSPORT_PROTOCOL_JSONRPC).await;
    let terminal = send_completed(&client, "already done", "terminal-context").await;
    let http = a2a_client::default_reqwest_client(None).unwrap();

    for (id, tenant, expected_code) in [
        (terminal.id.clone(), None, error_code::UNSUPPORTED_OPERATION),
        ("missing-task".to_owned(), None, error_code::TASK_NOT_FOUND),
        (
            terminal.id,
            Some("caller-controlled"),
            error_code::INVALID_PARAMS,
        ),
    ] {
        let mut params = serde_json::json!({ "id": id });
        if let Some(tenant) = tenant {
            params["tenant"] = serde_json::Value::String(tenant.to_owned());
        }
        let response = http
            .post(format!("{}/jsonrpc", server.base_url))
            .header("Accept", "text/event-stream")
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": a2a::jsonrpc::methods::SUBSCRIBE_TO_TASK,
                "params": params
            }))
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(
            body["error"]["code"].as_i64(),
            Some(i64::from(expected_code))
        );
    }
}

#[tokio::test]
async fn task_management_operations_reject_caller_supplied_tenants() {
    let server = TestServer::start(LoopbackDispatcher).await;
    let client = server.client(TRANSPORT_PROTOCOL_JSONRPC).await;
    let task = send_completed(&client, "tenant guard", "tenant-context").await;

    let get_error = client
        .get_task(&GetTaskRequest {
            id: task.id.clone(),
            history_length: None,
            tenant: Some("caller-controlled".to_owned()),
        })
        .await
        .unwrap_err();
    assert_eq!(get_error.code, error_code::INVALID_PARAMS);

    let list_error = client
        .list_tasks(&ListTasksRequest {
            context_id: None,
            status: None,
            page_size: None,
            page_token: None,
            history_length: None,
            status_timestamp_after: None,
            include_artifacts: None,
            tenant: Some("caller-controlled".to_owned()),
        })
        .await
        .unwrap_err();
    assert_eq!(list_error.code, error_code::INVALID_PARAMS);

    // The official REST Subscribe client currently omits `tenant`, while its
    // JSON-RPC streaming client discards non-SSE error bodies. The JSON-RPC wire
    // test above verifies that Subscribe still rejects caller-controlled tenants.
}
