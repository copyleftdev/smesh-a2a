#![cfg(unix)]

use std::ffi::OsStr;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use a2a::{
    Artifact, ListTasksRequest, Message, Part, PartContent, Role, Task, TaskState, TaskStatus,
};
use a2a_server::TaskStore;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};
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

struct FixturePath(PathBuf);

impl Deref for FixturePath {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<Path> for FixturePath {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<OsStr> for FixturePath {
    fn as_ref(&self) -> &OsStr {
        self.0.as_os_str()
    }
}

impl Drop for FixturePath {
    fn drop(&mut self) {
        if let Some(directory) = self.0.parent()
            && directory.exists()
        {
            std::fs::remove_dir_all(directory).expect("RAII SQLite fixture cleanup must succeed");
        }
    }
}

fn database_path() -> FixturePath {
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
    FixturePath(directory.join("tasks.sqlite3"))
}

fn cleanup(path: &Path) {
    let directory = path.parent().expect("database fixture has parent");
    if directory.exists() {
        std::fs::remove_dir_all(directory).expect("SQLite fixture cleanup must succeed");
    }
    assert!(!directory.exists(), "SQLite fixture directory leaked");
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

#[test]
fn sqlite_fixture_raii_cleans_up_during_unwind() {
    let fixture = database_path();
    let directory = fixture.parent().unwrap().to_path_buf();
    let result = std::panic::catch_unwind(move || {
        let _fixture = fixture;
        panic!("exercise fixture unwind cleanup");
    });
    assert!(result.is_err());
    assert!(!directory.exists(), "RAII fixture leaked after panic");
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
async fn sqlite_pagination_freezes_total_membership_and_projection_across_restart() {
    let path = database_path();
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    for (id, second) in [("snap-a", 3), ("snap-b", 2), ("snap-c", 1)] {
        let mut value = rich_task(id, TaskState::Working);
        value.status.timestamp = Some(
            chrono::DateTime::parse_from_rfc3339(&format!("2026-01-01T00:00:0{second}Z"))
                .unwrap()
                .to_utc(),
        );
        store.create(value).await.unwrap();
    }
    let request = list_request(1, None);
    let first = store.list(&request).await.unwrap();
    assert_eq!(first.total_size, 3);
    assert_eq!(first.tasks[0].id, "snap-a");
    let token_raw = URL_SAFE_NO_PAD.decode(&first.next_page_token).unwrap();
    assert_eq!(token_raw.len(), 32, "token is one opaque random capability");
    let reader = rusqlite::Connection::open(&path).unwrap();
    let stored_hash: Vec<u8> = reader
        .query_row(
            "SELECT token_hash FROM list_page_tokens WHERE next_position=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored_hash.len(), 32);
    assert_eq!(stored_hash, Sha256::digest(&token_raw).as_slice());
    assert_ne!(stored_hash, token_raw, "only a token hash may be persisted");
    let raw_token = first.next_page_token.as_bytes();
    for suffix in ["", "-wal", "-shm"] {
        let candidate = PathBuf::from(format!("{}{suffix}", path.display()));
        if candidate.exists() {
            let bytes = std::fs::read(candidate).unwrap();
            assert!(
                !bytes
                    .windows(raw_token.len())
                    .any(|window| window == raw_token),
                "raw page capability leaked to SQLite file {suffix}"
            );
        }
    }
    let token_columns: String = reader
        .query_row(
            "SELECT group_concat(name, ',') FROM pragma_table_info('list_page_tokens')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!token_columns.contains("plaintext"));
    assert!(!token_columns.contains("token_value"));
    drop(reader);

    let mut changed = store.get("snap-b").await.unwrap().unwrap();
    changed.status.state = TaskState::Completed;
    changed.status.timestamp = Some(
        chrono::DateTime::parse_from_rfc3339("2026-01-02T00:00:00Z")
            .unwrap()
            .to_utc(),
    );
    changed
        .metadata
        .as_mut()
        .unwrap()
        .insert("snapshotMutation".to_owned(), serde_json::json!(true));
    store.update(changed).await.unwrap();
    store
        .create(task("snap-new", TaskState::Working))
        .await
        .unwrap();
    drop(store);

    let reopened = SqliteTaskStore::open(&path, 8).await.unwrap();
    let second_request = list_request(1, Some(first.next_page_token));
    let second = reopened.list(&second_request).await.unwrap();
    let replay = reopened.list(&second_request).await.unwrap();
    assert_eq!(second, replay);
    assert_eq!(second.total_size, 3);
    assert_eq!(second.tasks[0].id, "snap-b");
    assert_eq!(second.tasks[0].status.state, TaskState::Working);
    assert!(
        second.tasks[0]
            .metadata
            .as_ref()
            .unwrap()
            .get("snapshotMutation")
            .is_none()
    );
    let third = reopened
        .list(&list_request(1, Some(second.next_page_token)))
        .await
        .unwrap();
    assert_eq!(third.total_size, 3);
    assert_eq!(third.tasks[0].id, "snap-c");
    assert!(third.next_page_token.is_empty());
    drop(reopened);
    cleanup(&path);
}

#[tokio::test]
async fn reopen_rejects_every_snapshot_chain_corruption_class() {
    let corruptions = [
        "UPDATE list_snapshots SET total_size=total_size+1",
        "DELETE FROM list_snapshot_entries WHERE ordinal=1",
        "UPDATE list_snapshots SET frozen_bytes=0",
        "UPDATE list_snapshot_entries SET task_id='forged' WHERE ordinal=1",
        "UPDATE list_snapshot_entries SET task_digest='sha256:0000000000000000000000000000000000000000000000000000000000000000' WHERE ordinal=1",
        "UPDATE list_page_tokens SET scope_digest='forged'",
        "DELETE FROM list_page_tokens WHERE next_position=2",
        "UPDATE list_page_tokens SET token_hash=zeroblob(32) WHERE next_position=1",
        "INSERT INTO list_page_tokens(token_hash,snapshot_id,next_position,scope_digest,query_digest,token_version,key_generation,issued_at,expires_at) SELECT randomblob(32),snapshot_id,3,scope_digest,query_digest,token_version,key_generation,issued_at,expires_at FROM list_page_tokens LIMIT 1",
        "UPDATE list_snapshots SET scope_digest='forged'; UPDATE list_page_tokens SET scope_digest='forged'",
        "UPDATE list_snapshots SET query_digest='forged'; UPDATE list_page_tokens SET query_digest='forged'",
        "UPDATE list_snapshots SET issued_at=issued_at+9999999999,expires_at=expires_at+9999999999; UPDATE list_page_tokens SET issued_at=issued_at+9999999999,expires_at=expires_at+9999999999",
        "UPDATE list_snapshot_entries SET task_revision=task_revision+1000 WHERE ordinal=1",
        "UPDATE list_snapshot_entries SET ordinal=100 WHERE ordinal=0; UPDATE list_snapshot_entries SET ordinal=0 WHERE ordinal=1; UPDATE list_snapshot_entries SET ordinal=1 WHERE ordinal=100",
        "UPDATE list_snapshots SET metadata_digest=zeroblob(32)",
        "PRAGMA ignore_check_constraints=ON; UPDATE list_page_tokens SET key_generation=2",
    ];
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        for statement in corruptions {
            let path = database_path();
            let store = SqliteTaskStore::open(&path, 4).await.unwrap();
            for id in ["a", "b", "c"] {
                store.create(task(id, TaskState::Completed)).await.unwrap();
            }
            let first = store.list(&list_request(1, None)).await.unwrap();
            assert!(!first.next_page_token.is_empty());
            store.shutdown_shared().await.unwrap();
            let db = rusqlite::Connection::open(&path).unwrap();
            db.execute_batch(statement).unwrap();
            drop(db);
            assert!(
                SqliteTaskStore::open(&path, 4).await.is_err(),
                "reopen accepted corruption: {statement}"
            );
            cleanup(&path);
        }
    })
    .await
    .expect("snapshot corruption matrix watchdog expired");
}

#[tokio::test]
async fn followup_page_fails_generically_when_snapshot_metadata_is_tampered() {
    let path = database_path();
    let store = SqliteTaskStore::open(&path, 4).await.unwrap();
    for id in ["follow-a", "follow-b", "follow-c"] {
        store.create(task(id, TaskState::Completed)).await.unwrap();
    }
    let first = store.list(&list_request(1, None)).await.unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute(
        "UPDATE list_snapshot_entries SET task_revision=task_revision+1000 WHERE ordinal=1",
        [],
    )
    .unwrap();
    drop(db);
    let error = store
        .list(&list_request(1, Some(first.next_page_token)))
        .await
        .unwrap_err();
    assert_eq!(error.code, a2a::error_code::INVALID_PARAMS);
    assert_eq!(error.message, "invalid pageToken");
    store.shutdown_shared().await.unwrap();
    cleanup(&path);
}

#[tokio::test]
async fn failed_oversized_admission_cannot_roll_back_complete_expired_snapshot_gc() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let path = database_path();
        let store = SqliteTaskStore::open(&path, 100).await.unwrap();
        for id in ["small-a", "small-b"] {
            store.create(task(id, TaskState::Completed)).await.unwrap();
        }
        let db = rusqlite::Connection::open(&path).unwrap();
        for byte in 0_u8..128 {
            db.execute(
                "INSERT INTO list_snapshots(snapshot_id,scope_digest,query_digest,total_size,page_size,
                 issued_at,expires_at,projection_version,frozen_bytes,metadata_digest)
                 VALUES(?1,'scope','query',2,1,0,1,1,524288,zeroblob(32))",
                [vec![byte; 32]],
            )
            .unwrap();
        }
        let payload = "x".repeat(1_040_000);
        for index in 0..65 {
            let mut value = task(&format!("large-{index:02}"), TaskState::Completed);
            value.metadata =
                Some(serde_json::from_value(serde_json::json!({"payload": payload})).unwrap());
            let encoded = serde_json::to_string(&value).unwrap();
            assert!(encoded.len() <= 1024 * 1024);
            db.execute(
                "INSERT INTO tasks(task_id,context_id,state,status_timestamp,revision,task_json,
                 tenant_scope,owner_account_id) VALUES(?1,?2,?3,?4,1,?5,?6,?7)",
                rusqlite::params![value.id,value.context_id,"\"TASK_STATE_COMPLETED\"",
                    value.status.timestamp.map(|timestamp| timestamp.to_rfc3339()),encoded,
                    smesh_a2a::TRUSTED_SINGLE_TENANT_SCOPE,"smesh-dev-only-account"],
            )
            .unwrap();
        }
        assert!(store.list(&list_request(1, None)).await.unwrap_err().message.contains("capacity"));
        let expired: i64 = db.query_row("SELECT COUNT(*) FROM list_snapshots", [], |row| row.get(0)).unwrap();
        assert_eq!(expired, 0, "capacity rejection rolled back expired snapshot GC");
        db.execute("DELETE FROM tasks WHERE task_id LIKE 'large-%'", []).unwrap();
        let bounded = store.list(&list_request(1, None)).await.unwrap();
        assert_eq!(bounded.total_size, 2);
        store.shutdown_shared().await.unwrap();
        drop(db);
        cleanup(&path);
    }).await.expect("snapshot GC/capacity watchdog expired");
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
