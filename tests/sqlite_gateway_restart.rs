use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use a2a::{
    GetTaskRequest, Message, Part, PartContent, Role, SendMessageRequest, SendMessageResponse,
    TRANSPORT_PROTOCOL_JSONRPC, Task, TaskState, TaskStatus,
};
use a2a_client::agent_card::AgentCardResolver;
use a2a_client::{A2AClient, A2AClientFactory, Transport};
use a2a_server::TaskStore;
use smesh_a2a::{
    CompletionPolicySpec, CompletionReceipt, GatewayConfig, LoopbackDispatcher, SqliteTaskStore,
    VersionedCompletionPolicy, build_router_with_policy, build_router_with_sqlite,
};

fn database_path() -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "smesh-a2a-gateway-restart-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    directory.join("tasks.sqlite3")
}

fn cleanup(path: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    let _ = std::fs::remove_dir(path.parent().unwrap());
}

async fn start_gateway(
    path: &Path,
) -> (
    String,
    tokio::task::JoinHandle<()>,
    VersionedCompletionPolicy,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let base_url = format!("http://{address}");
    let store = SqliteTaskStore::open(path, 32).await.unwrap();
    let verifier = VersionedCompletionPolicy::new_with_receipt_key(
        CompletionPolicySpec::development(),
        store.completion_receipt_key(),
    )
    .unwrap();
    let app = build_router_with_sqlite(
        GatewayConfig::new(&base_url, "persistent-gateway"),
        LoopbackDispatcher,
        store,
    )
    .unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base_url, server, verifier)
}

async fn client(base_url: &str) -> A2AClient<Box<dyn Transport>> {
    let card = AgentCardResolver::new(None)
        .resolve(base_url)
        .await
        .unwrap();
    A2AClientFactory::builder()
        .preferred_bindings(vec![TRANSPORT_PROTOCOL_JSONRPC.to_owned()])
        .build()
        .create_from_card(&card)
        .await
        .unwrap()
}

#[tokio::test]
async fn generic_router_rejects_a_fresh_policy_for_a_persistent_store() {
    let path = database_path();
    let store = SqliteTaskStore::open(&path, 4).await.unwrap();
    let result = build_router_with_policy(
        GatewayConfig::new("http://127.0.0.1:3000", "persistent-gateway"),
        LoopbackDispatcher,
        store,
        VersionedCompletionPolicy::default(),
    );
    assert!(result.is_err());
    cleanup(&path);
}

#[tokio::test]
async fn completed_task_receipt_and_artifact_remain_visible_after_gateway_restart() {
    let path = database_path();
    let (base_url, server, _) = start_gateway(&path).await;
    let response = client(&base_url)
        .await
        .send_message(&SendMessageRequest {
            message: Message::new(Role::User, vec![Part::text("persist this result")]),
            configuration: None,
            metadata: None,
            tenant: None,
        })
        .await
        .unwrap();
    let SendMessageResponse::Task(task) = response else {
        panic!("expected tracked task");
    };
    assert_eq!(task.status.state, TaskState::Completed);
    let task_id = task.id.clone();
    server.abort();
    let _ = server.await;

    let (base_url, restarted, verifier) = start_gateway(&path).await;
    let recovered = client(&base_url)
        .await
        .get_task(&GetTaskRequest {
            id: task_id,
            history_length: None,
            tenant: None,
        })
        .await
        .unwrap();
    assert_eq!(recovered, task);
    let mut record =
        recovered.metadata.as_ref().unwrap()["smesh.completionPolicy"]["record"].clone();
    record["policyVersion"] = serde_json::json!(1_u32);
    record["assuranceBps"] = serde_json::json!(10_000_u16);
    let receipt: CompletionReceipt = serde_json::from_value(record).unwrap();
    assert!(verifier.verify_receipt(&receipt));
    restarted.abort();
    let _ = restarted.await;
    cleanup(&path);
}

#[tokio::test]
async fn gateway_exposes_orphaned_nonterminal_task_as_failed_after_restart() {
    let path = database_path();
    let store = SqliteTaskStore::open(&path, 32).await.unwrap();
    let old_timestamp = chrono::Utc::now() - chrono::Duration::days(1);
    let mut history = Message::new(Role::User, vec![Part::text("preserve me")]);
    history.message_id = "orphan-history".to_owned();
    store
        .create(Task {
            id: "orphaned".to_owned(),
            context_id: "restart-context".to_owned(),
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: Some(old_timestamp),
            },
            artifacts: None,
            history: Some(vec![history.clone()]),
            metadata: Some(
                serde_json::from_value(serde_json::json!({"request": "metadata"})).unwrap(),
            ),
        })
        .await
        .unwrap();
    drop(store);

    let (base_url, server, _) = start_gateway(&path).await;
    let recovered = client(&base_url)
        .await
        .get_task(&GetTaskRequest {
            id: "orphaned".to_owned(),
            history_length: None,
            tenant: None,
        })
        .await
        .unwrap();
    assert_eq!(recovered.status.state, TaskState::Failed);
    assert!(
        recovered
            .status
            .timestamp
            .is_some_and(|value| value > old_timestamp)
    );
    assert!(matches!(
        recovered
            .status
            .message
            .as_ref()
            .map(|message| message.parts.as_slice()),
        Some([Part { content: PartContent::Text(text), .. }])
            if text.contains("restart") && text.contains("orphaned")
    ));
    assert_eq!(recovered.history, Some(vec![history]));
    assert!(recovered.artifacts.is_none());
    assert_eq!(
        recovered.metadata.unwrap().get("request"),
        Some(&serde_json::json!("metadata"))
    );
    server.abort();
    let _ = server.await;
    cleanup(&path);
}
