#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use a2a::{
    Artifact, ListTasksRequest, Message, Part, PartContent, Role, Task, TaskState, TaskStatus,
};
use a2a_server::TaskStore;
use smesh_a2a::{
    ArtifactManifest, CompletionEvidence, CompletionPolicySpec, CompletionReceipt,
    CompletionSnapshot, PolicyDecision, SqliteTaskStore, VersionedCompletionPolicy,
    artifact_set_digest, content_digest,
};

fn task(id: &str, state: TaskState) -> Task {
    Task {
        id: id.to_owned(),
        context_id: "restart-context".to_owned(),
        status: TaskStatus {
            state,
            message: None,
            timestamp: Some(chrono::Utc::now()),
        },
        artifacts: None,
        history: None,
        metadata: None,
    }
}

fn rich_task(id: &str, state: TaskState) -> Task {
    let mut value = task(id, state);
    value.artifacts = Some(vec![Artifact {
        artifact_id: format!("artifact-{id}"),
        name: Some("result.txt".to_owned()),
        description: Some("durable result".to_owned()),
        parts: vec![Part::text("preserved artifact").with_media_type("text/plain")],
        metadata: Some(
            serde_json::from_value(serde_json::json!({"artifact": "metadata"})).unwrap(),
        ),
        extensions: None,
    }]);
    let mut history_message = Message::new(Role::User, vec![Part::text("preserved history")]);
    history_message.message_id = format!("history-{id}");
    value.history = Some(vec![history_message]);
    value.metadata = Some(
        serde_json::from_value(serde_json::json!({"task": "metadata", "unicode": "雪"})).unwrap(),
    );
    value
}

fn completion_receipt(policy: &VersionedCompletionPolicy, task_id: &str) -> CompletionReceipt {
    let artifact = ArtifactManifest {
        name: "result.txt".to_owned(),
        media_type: "text/plain".to_owned(),
        digest: content_digest(b"preserved artifact"),
    };
    let subject_digest = artifact_set_digest(std::slice::from_ref(&artifact)).unwrap();
    let evidence = vec![
        CompletionEvidence::Review {
            id: "crash-review".to_owned(),
            issuer: "review-authority".to_owned(),
            subject_digest: subject_digest.clone(),
            evidence: b"crash review".to_vec(),
            evidence_digest: content_digest(b"crash review"),
            approved: true,
            assurance_bps: 10_000,
        },
        CompletionEvidence::Test {
            id: "crash-test".to_owned(),
            issuer: "test-authority".to_owned(),
            subject_digest: subject_digest.clone(),
            evidence: b"crash test".to_vec(),
            evidence_digest: content_digest(b"crash test"),
            passed: true,
            assurance_bps: 10_000,
        },
        CompletionEvidence::Contradiction {
            id: "crash-clearance".to_owned(),
            issuer: "contradiction-monitor".to_owned(),
            subject_digest,
            evidence: b"crash clearance".to_vec(),
            evidence_digest: content_digest(b"crash clearance"),
            blocking: false,
        },
    ];
    let decision = policy
        .evaluate(&CompletionSnapshot {
            task_id: task_id.to_owned(),
            context_id: "restart-context".to_owned(),
            request_digest: content_digest(b"crash request"),
            artifacts: vec![artifact],
            evidence,
        })
        .unwrap();
    let PolicyDecision::Accepted(receipt) = decision else {
        panic!("crash completion fixture must be accepted");
    };
    receipt
}

fn attach_completion_receipt(task: &mut Task, receipt: &CompletionReceipt) {
    task.metadata.as_mut().unwrap().insert(
        "smesh.completionPolicy".to_owned(),
        serde_json::json!({"status": "accepted", "record": receipt}),
    );
}

fn database_path() -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "smesh-a2a-store-{}-{}",
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
        let candidate = PathBuf::from(format!("{}{suffix}", path.display()));
        let _ = std::fs::remove_file(candidate);
    }
    let _ = std::fs::remove_dir(path.parent().unwrap());
}

fn list_request(page_size: i32, page_token: Option<String>) -> ListTasksRequest {
    ListTasksRequest {
        context_id: None,
        status: None,
        page_size: Some(page_size),
        page_token,
        history_length: None,
        status_timestamp_after: None,
        include_artifacts: Some(true),
        tenant: None,
    }
}

#[tokio::test]
async fn terminal_and_nonterminal_tasks_survive_restart_without_terminal_regression() {
    let path = database_path();
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    store
        .create(task("working", TaskState::Working))
        .await
        .unwrap();
    store
        .create(task("completed", TaskState::Completed))
        .await
        .unwrap();
    drop(store);

    let reopened = SqliteTaskStore::open(&path, 8).await.unwrap();
    assert_eq!(
        reopened.get("working").await.unwrap().unwrap().status.state,
        TaskState::Failed
    );
    assert_eq!(
        reopened
            .get("completed")
            .await
            .unwrap()
            .unwrap()
            .status
            .state,
        TaskState::Completed
    );
    let error = reopened
        .update(task("completed", TaskState::Working))
        .await
        .unwrap_err();
    assert!(error.message.contains("terminal"));
    assert_eq!(
        reopened
            .get("completed")
            .await
            .unwrap()
            .unwrap()
            .status
            .state,
        TaskState::Completed
    );
    drop(reopened);
    cleanup(&path);
}

#[tokio::test]
async fn second_open_is_rejected_without_recovering_live_work() {
    let path = database_path();
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    store
        .create(task("live", TaskState::Working))
        .await
        .unwrap();

    let Err(error) = SqliteTaskStore::open(&path, 8).await else {
        panic!("second open unexpectedly succeeded");
    };
    assert!(error.to_string().contains("already open"));
    assert_eq!(
        store.get("live").await.unwrap().unwrap().status.state,
        TaskState::Working
    );
    drop(store);
    cleanup(&path);
}

#[tokio::test]
async fn page_tokens_and_capacity_survive_restart() {
    let path = database_path();
    let store = SqliteTaskStore::open(&path, 3).await.unwrap();
    let receipt_key = store.completion_receipt_key();
    for id in ["task-a", "task-b", "task-c"] {
        store.create(task(id, TaskState::Completed)).await.unwrap();
    }
    let first = store.list(&list_request(1, None)).await.unwrap();
    assert_eq!(first.total_size, 3);
    assert!(!first.next_page_token.is_empty());
    drop(store);

    let reopened = SqliteTaskStore::open(&path, 3).await.unwrap();
    assert_eq!(reopened.completion_receipt_key(), receipt_key);
    let second = reopened
        .list(&list_request(1, Some(first.next_page_token)))
        .await
        .unwrap();
    assert_eq!(second.tasks.len(), 1);
    assert!(
        reopened
            .create(task("task-d", TaskState::Submitted))
            .await
            .unwrap_err()
            .message
            .contains("capacity")
    );
    drop(reopened);
    cleanup(&path);
}

#[tokio::test]
async fn unknown_schema_and_capacity_downgrade_fail_without_rewriting_database() {
    let unknown_path = database_path();
    {
        let connection = rusqlite::Connection::open(&unknown_path).unwrap();
        connection.pragma_update(None, "user_version", 99).unwrap();
    }
    let before = std::fs::read(&unknown_path).unwrap();
    assert!(SqliteTaskStore::open(&unknown_path, 4).await.is_err());
    assert_eq!(std::fs::read(&unknown_path).unwrap(), before);
    cleanup(&unknown_path);

    let path = database_path();
    let store = SqliteTaskStore::open(&path, 2).await.unwrap();
    store.create(task("one", TaskState::Working)).await.unwrap();
    store
        .create(task("two", TaskState::Completed))
        .await
        .unwrap();
    drop(store);
    assert!(SqliteTaskStore::open(&path, 1).await.is_err());
    cleanup(&path);
}

#[tokio::test]
async fn terminal_same_state_update_requires_exact_full_task_idempotence() {
    let path = database_path();
    let store = SqliteTaskStore::open(&path, 4).await.unwrap();
    let original = task("terminal", TaskState::Completed);
    let revision = store.create(original.clone()).await.unwrap();
    assert_eq!(store.update(original.clone()).await.unwrap(), revision);
    let mut changed = original;
    changed.metadata =
        Some(serde_json::from_value(serde_json::json!({"different": true})).unwrap());
    assert!(
        store
            .update(changed)
            .await
            .unwrap_err()
            .message
            .contains("terminal")
    );
    assert!(
        store
            .get("terminal")
            .await
            .unwrap()
            .unwrap()
            .metadata
            .is_none()
    );
    drop(store);
    cleanup(&path);
}

#[tokio::test]
async fn altered_index_definition_fails_closed() {
    let path = database_path();
    drop(SqliteTaskStore::open(&path, 4).await.unwrap());
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "DROP INDEX tasks_context_state_time;
         CREATE INDEX tasks_context_state_time ON tasks(task_id);",
        )
        .unwrap();
    drop(connection);
    assert!(SqliteTaskStore::open(&path, 4).await.is_err());
    cleanup(&path);
}

#[tokio::test]
async fn altered_table_constraint_definition_fails_closed() {
    let path = database_path();
    drop(SqliteTaskStore::open(&path, 4).await.unwrap());
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute_batch(
        "PRAGMA writable_schema = ON;
         UPDATE sqlite_master SET sql = replace(sql, 'revision > 0', 'revision >= 0') WHERE name = 'tasks';
         PRAGMA writable_schema = OFF;",
    ).unwrap();
    drop(connection);
    assert!(SqliteTaskStore::open(&path, 4).await.is_err());
    cleanup(&path);
}

#[tokio::test]
async fn unexpected_schema_trigger_fails_closed() {
    let path = database_path();
    drop(SqliteTaskStore::open(&path, 4).await.unwrap());
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER unexpected_task_trigger
             AFTER UPDATE ON tasks
             BEGIN
                 SELECT 1;
             END;",
        )
        .unwrap();
    drop(connection);
    assert!(SqliteTaskStore::open(&path, 4).await.is_err());
    cleanup(&path);
}

#[tokio::test]
async fn database_and_sidecars_are_owner_only_and_untrusted_parent_is_rejected() {
    use std::os::unix::fs::PermissionsExt;
    let path = database_path();
    let store = SqliteTaskStore::open(&path, 4).await.unwrap();
    store.create(task("one", TaskState::Working)).await.unwrap();
    for suffix in ["", "-wal", "-shm"] {
        let candidate = PathBuf::from(format!("{}{suffix}", path.display()));
        if candidate.exists() {
            assert_eq!(
                std::fs::metadata(candidate).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    drop(store);
    cleanup(&path);

    let unsafe_path = database_path();
    std::fs::set_permissions(
        unsafe_path.parent().unwrap(),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(SqliteTaskStore::open(&unsafe_path, 4).await.is_err());
    cleanup(&unsafe_path);
}

#[tokio::test]
async fn every_lifecycle_state_recovers_fail_closed_or_remains_terminal() {
    let path = database_path();
    let store = SqliteTaskStore::open(&path, 16).await.unwrap();
    let states = [
        TaskState::Unspecified,
        TaskState::Submitted,
        TaskState::Working,
        TaskState::InputRequired,
        TaskState::AuthRequired,
        TaskState::Completed,
        TaskState::Failed,
        TaskState::Canceled,
        TaskState::Rejected,
    ];
    for (index, state) in states.iter().cloned().enumerate() {
        let mut value = task(&format!("state-{index}"), state);
        value.metadata =
            Some(serde_json::from_value(serde_json::json!({"payload": index})).unwrap());
        store.create(value).await.unwrap();
    }
    drop(store);
    let reopened = SqliteTaskStore::open(&path, 16).await.unwrap();
    for (index, original) in states.iter().enumerate() {
        let recovered = reopened
            .get(&format!("state-{index}"))
            .await
            .unwrap()
            .unwrap();
        let expected = if original.is_terminal() {
            original.clone()
        } else {
            TaskState::Failed
        };
        assert_eq!(recovered.status.state, expected);
        assert_eq!(
            recovered.metadata.unwrap().get("payload"),
            Some(&serde_json::json!(index))
        );
    }
    drop(reopened);
    cleanup(&path);
}

#[tokio::test]
async fn recovery_adds_fresh_diagnostic_status_and_preserves_task_payload() {
    let path = database_path();
    let store = SqliteTaskStore::open(&path, 4).await.unwrap();
    let mut original = rich_task("recover-rich", TaskState::Working);
    let old_timestamp = chrono::Utc::now() - chrono::Duration::days(1);
    original.status.timestamp = Some(old_timestamp);
    store.create(original.clone()).await.unwrap();
    drop(store);

    let reopened = SqliteTaskStore::open(&path, 4).await.unwrap();
    let recovered = reopened.get(&original.id).await.unwrap().unwrap();
    assert_eq!(recovered.status.state, TaskState::Failed);
    assert!(recovered.status.timestamp.unwrap() > old_timestamp);
    assert!(matches!(
        recovered
            .status
            .message
            .as_ref()
            .map(|message| message.parts.as_slice()),
        Some([Part { content: PartContent::Text(text), .. }])
            if text.contains("restart") && text.contains("orphaned")
    ));
    assert_eq!(recovered.history, original.history);
    assert_eq!(recovered.artifacts, original.artifacts);
    assert_eq!(recovered.metadata, original.metadata);
    drop(reopened);
    cleanup(&path);
}

#[tokio::test]
async fn recovery_refuses_to_expand_a_task_past_its_byte_limit() {
    let path = database_path();
    let store = SqliteTaskStore::open(&path, 4).await.unwrap();
    let mut value = task("near-limit-recovery", TaskState::Working);
    value.metadata = Some(serde_json::from_value(serde_json::json!({"padding": ""})).unwrap());
    let base_len = serde_json::to_string(&value).unwrap().len();
    let target_len = 1024 * 1024;
    value.metadata.as_mut().unwrap().insert(
        "padding".to_owned(),
        serde_json::json!("x".repeat(target_len - base_len)),
    );
    assert_eq!(serde_json::to_string(&value).unwrap().len(), target_len);
    store.create(value).await.unwrap();
    drop(store);

    assert!(SqliteTaskStore::open(&path, 4).await.is_err());
    let connection = rusqlite::Connection::open(&path).unwrap();
    let state: String = connection
        .query_row(
            "SELECT state FROM tasks WHERE task_id = 'near-limit-recovery'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "\"TASK_STATE_WORKING\"");
    drop(connection);
    cleanup(&path);
}

#[tokio::test]
async fn every_terminal_state_absorbs_all_nonidentical_updates() {
    let path = database_path();
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    let terminals = [
        TaskState::Completed,
        TaskState::Failed,
        TaskState::Canceled,
        TaskState::Rejected,
    ];
    let all = [
        TaskState::Unspecified,
        TaskState::Submitted,
        TaskState::Working,
        TaskState::Completed,
        TaskState::Failed,
        TaskState::Canceled,
        TaskState::InputRequired,
        TaskState::Rejected,
        TaskState::AuthRequired,
    ];
    for (index, terminal) in terminals.iter().cloned().enumerate() {
        let original = task(&format!("terminal-{index}"), terminal);
        store.create(original.clone()).await.unwrap();
        assert!(store.update(original.clone()).await.is_ok());
        for candidate in all.iter().cloned() {
            let mut changed = original.clone();
            changed.status.state = candidate;
            changed.metadata =
                Some(serde_json::from_value(serde_json::json!({"changed": true})).unwrap());
            assert!(store.update(changed).await.is_err());
        }
    }
    drop(store);
    cleanup(&path);
}

#[tokio::test]
async fn concurrent_creates_never_exceed_capacity() {
    let path = database_path();
    let store = SqliteTaskStore::open(&path, 4).await.unwrap();
    let mut joins = Vec::new();
    for index in 0..32 {
        let store = store.clone();
        joins.push(tokio::spawn(async move {
            store
                .create(task(&format!("concurrent-{index}"), TaskState::Completed))
                .await
        }));
    }
    let mut successes = 0;
    for join in joins {
        successes += usize::from(join.await.unwrap().is_ok());
    }
    assert_eq!(successes, 4);
    drop(store);
    let reopened = SqliteTaskStore::open(&path, 4).await.unwrap();
    assert_eq!(
        reopened
            .list(&list_request(100, None))
            .await
            .unwrap()
            .total_size,
        4
    );
    drop(reopened);
    cleanup(&path);
}

#[test]
fn crash_writer_helper() {
    let Some(path) = std::env::var_os("SMESH_TEST_CRASH_DB") else {
        return;
    };
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let store = SqliteTaskStore::open(path, 16).await.unwrap();
        let policy = VersionedCompletionPolicy::new_with_receipt_key(
            CompletionPolicySpec::development(),
            store.completion_receipt_key(),
        )
        .unwrap();
        let states = [
            TaskState::Unspecified,
            TaskState::Submitted,
            TaskState::Working,
            TaskState::InputRequired,
            TaskState::AuthRequired,
            TaskState::Completed,
            TaskState::Failed,
            TaskState::Canceled,
            TaskState::Rejected,
        ];
        let fixed = chrono::DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        for (index, target) in states.into_iter().enumerate() {
            let id = format!("crash-state-{index}");
            let initial = if target == TaskState::Unspecified {
                TaskState::Unspecified
            } else {
                TaskState::Submitted
            };
            let mut value = rich_task(&id, initial);
            value.status.timestamp = Some(fixed);
            store.create(value.clone()).await.unwrap();
            let transitions: &[TaskState] = match target {
                TaskState::Working => &[TaskState::Working],
                TaskState::InputRequired => &[TaskState::Working, TaskState::InputRequired],
                TaskState::AuthRequired => &[TaskState::Working, TaskState::AuthRequired],
                TaskState::Completed => &[TaskState::Working, TaskState::Completed],
                TaskState::Failed => &[TaskState::Working, TaskState::Failed],
                TaskState::Canceled => &[TaskState::Working, TaskState::Canceled],
                TaskState::Rejected => &[TaskState::Working, TaskState::Rejected],
                TaskState::Unspecified | TaskState::Submitted => &[],
            };
            for state in transitions {
                value.status.state = state.clone();
                if *state == TaskState::Completed {
                    attach_completion_receipt(&mut value, &completion_receipt(&policy, &id));
                }
                store.update(value.clone()).await.unwrap();
            }
        }
        std::process::abort();
    });
}

#[tokio::test]
async fn all_lifecycle_payloads_and_transitions_survive_process_abort() {
    let path = database_path();
    let child_status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_writer_helper", "--nocapture"])
        .env("SMESH_TEST_CRASH_DB", &path)
        .status()
        .unwrap();
    assert!(!child_status.success());
    let reopened = SqliteTaskStore::open(&path, 16).await.unwrap();
    let verifier = VersionedCompletionPolicy::new_with_receipt_key(
        CompletionPolicySpec::development(),
        reopened.completion_receipt_key(),
    )
    .unwrap();
    let states = [
        TaskState::Unspecified,
        TaskState::Submitted,
        TaskState::Working,
        TaskState::InputRequired,
        TaskState::AuthRequired,
        TaskState::Completed,
        TaskState::Failed,
        TaskState::Canceled,
        TaskState::Rejected,
    ];
    let fixed = chrono::DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    for (index, original_state) in states.into_iter().enumerate() {
        let id = format!("crash-state-{index}");
        let recovered = reopened.get(&id).await.unwrap().unwrap();
        let mut expected = rich_task(&id, original_state.clone());
        if original_state == TaskState::Completed {
            let receipt = completion_receipt(&verifier, &id);
            attach_completion_receipt(&mut expected, &receipt);
            let persisted: CompletionReceipt = serde_json::from_value(
                recovered.metadata.as_ref().unwrap()["smesh.completionPolicy"]["record"].clone(),
            )
            .unwrap();
            assert_eq!(persisted, receipt);
            assert!(verifier.verify_receipt(&persisted));
        }
        assert_eq!(recovered.history, expected.history, "history for {id}");
        assert_eq!(
            recovered.artifacts, expected.artifacts,
            "artifacts for {id}"
        );
        assert_eq!(recovered.metadata, expected.metadata, "metadata for {id}");
        if original_state.is_terminal() {
            assert_eq!(recovered.status.state, original_state);
            assert_eq!(recovered.status.timestamp, Some(fixed));
            assert!(recovered.status.message.is_none());
        } else {
            assert_eq!(recovered.status.state, TaskState::Failed);
            assert!(
                recovered
                    .status
                    .timestamp
                    .is_some_and(|value| value > fixed)
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
        }
    }
    drop(reopened);
    cleanup(&path);
}

#[tokio::test]
async fn aggregate_serialized_payload_is_bounded() {
    let path = database_path();
    let store = SqliteTaskStore::open(&path, 100).await.unwrap();
    let payload = "x".repeat(900_000);
    let mut accepted = 0;
    for index in 0..80 {
        let mut value = task(&format!("large-{index}"), TaskState::Completed);
        value.metadata =
            Some(serde_json::from_value(serde_json::json!({"payload": payload})).unwrap());
        if store.create(value).await.is_ok() {
            accepted += 1;
        } else {
            break;
        }
    }
    assert!(accepted < 80, "aggregate byte capacity was not enforced");
    drop(store);
    cleanup(&path);
}

#[tokio::test]
async fn aggregate_limit_counts_multibyte_utf8_bytes() {
    let path = database_path();
    let store = SqliteTaskStore::open(&path, 100).await.unwrap();
    let payload = "é".repeat(400_000);
    let mut accepted = 0;
    for index in 0..90 {
        let mut value = task(&format!("unicode-{index}"), TaskState::Completed);
        value.metadata =
            Some(serde_json::from_value(serde_json::json!({"payload": payload})).unwrap());
        if store.create(value).await.is_ok() {
            accepted += 1;
        } else {
            break;
        }
    }
    assert!(
        accepted < 90,
        "aggregate limit counted characters, not UTF-8 bytes"
    );
    drop(store);
    cleanup(&path);
}
