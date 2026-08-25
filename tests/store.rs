use a2a::{A2AError, Task, TaskState, TaskStatus};
use a2a_server::TaskStore;
use smesh_a2a::BoundedTaskStore;

fn task(id: &str) -> Task {
    Task {
        id: id.into(),
        context_id: "context".into(),
        status: TaskStatus {
            state: TaskState::Submitted,
            message: None,
            timestamp: Some(chrono::Utc::now()),
        },
        artifacts: None,
        history: None,
        metadata: None,
    }
}

#[tokio::test]
async fn store_rejects_new_tasks_at_capacity_without_losing_existing_tasks() {
    let store = BoundedTaskStore::new(1);
    store.create(task("one")).await.unwrap();

    let error: A2AError = store.create(task("two")).await.unwrap_err();

    assert!(error.message.contains("capacity"));
    assert!(store.get("one").await.unwrap().is_some());
    assert!(store.get("two").await.unwrap().is_none());
}

#[tokio::test]
async fn store_never_allows_a_terminal_task_to_regress() {
    let store = BoundedTaskStore::new(2);
    let mut completed = task("terminal");
    completed.status.state = TaskState::Completed;
    store.create(completed.clone()).await.unwrap();

    let mut stale = completed;
    stale.status.state = TaskState::Working;
    let error = store.update(stale).await.unwrap_err();

    assert_eq!(
        store.get("terminal").await.unwrap().unwrap().status.state,
        TaskState::Completed
    );
    assert!(error.message.contains("terminal"));
}
