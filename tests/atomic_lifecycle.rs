#![cfg(unix)]

use std::io::{BufRead, Write};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use a2a::{
    Message, Part, Role, SendMessageRequest, SendMessageResponse, Task, TaskState, TaskStatus,
};
use smesh_a2a::{
    AdmissionOutcome, AttemptDisposition, InputLimits, MeshRequest, SendMessageAdmission,
    SqliteTaskStore, TransitionOutcome, canonical_send_message_digest, content_digest,
};

trait TestAdmission {
    async fn admit_fixture(
        &self,
        task: Task,
        case_label: impl Into<String> + Send,
        original_result: SendMessageResponse,
        expected_dispatch: MeshRequest,
        now: i64,
        max_attempts: u32,
    ) -> Result<AdmissionOutcome, a2a::A2AError>;
}

impl TestAdmission for SqliteTaskStore {
    async fn admit_fixture(
        &self,
        task: Task,
        case_label: impl Into<String> + Send,
        original_result: SendMessageResponse,
        expected_dispatch: MeshRequest,
        now: i64,
        max_attempts: u32,
    ) -> Result<AdmissionOutcome, a2a::A2AError> {
        assert!(
            !case_label.into().is_empty(),
            "fixture case label is required"
        );
        let message = task
            .history
            .as_ref()
            .and_then(|history| history.last())
            .cloned()
            .expect("test task has a request message");
        let derived_dispatch = MeshRequest::from_a2a(
            task.id.clone(),
            task.context_id.clone(),
            &message,
            InputLimits::default(),
        )
        .expect("fixture request is valid");
        assert_eq!(
            expected_dispatch, derived_dispatch,
            "fixture expected dispatch must match canonical derivation"
        );
        self.admit_send_message(SendMessageAdmission {
            request: SendMessageRequest {
                message,
                configuration: None,
                metadata: None,
                tenant: None,
            },
            streaming: false,
            task,
            original_result,
            input_limits: InputLimits::default(),
            now,
            max_attempts,
        })
        .await
    }
}

struct TestDb(PathBuf);

impl AsRef<Path> for TestDb {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Deref for TestDb {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.0.as_path()
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        if let Some(parent) = self.0.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }
}

fn path() -> TestDb {
    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "smesh-atomic-{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    TestDb(dir.join("tasks.sqlite3"))
}

fn task(id: &str, state: TaskState) -> Task {
    let mut message = Message::new(Role::User, vec![Part::text("atomic work")]);
    message.message_id = format!("message-{id}");
    Task {
        id: id.to_owned(),
        context_id: "context-11".to_owned(),
        status: TaskStatus {
            state,
            message: None,
            timestamp: None,
        },
        artifacts: None,
        history: Some(vec![message]),
        metadata: None,
    }
}

fn request(task_id: &str) -> MeshRequest {
    MeshRequest {
        protocol: "a2a-v1".to_owned(),
        task_id: task_id.to_owned(),
        context_id: "context-11".to_owned(),
        text: "atomic work".to_owned(),
    }
}

fn digest(label: &str) -> String {
    content_digest(label.as_bytes())
}

#[tokio::test]
async fn admission_replay_conflict_and_outbox_are_atomic() {
    let path = path();
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    let submitted = task("task-11", TaskState::Submitted);
    let original = SendMessageResponse::Task(submitted.clone());

    let first = store
        .admit_fixture(
            submitted.clone(),
            "digest-a",
            original.clone(),
            request("task-11"),
            100,
            3,
        )
        .await
        .unwrap();
    let AdmissionOutcome::Admitted(record) = first else {
        panic!("expected admission")
    };
    assert_eq!(record.revision, 1);
    assert!(!record.dispatch_id.is_empty());

    let replay = store
        .admit_fixture(
            submitted.clone(),
            "digest-a",
            original.clone(),
            request("task-11"),
            101,
            3,
        )
        .await
        .unwrap();
    assert_eq!(replay, AdmissionOutcome::Replay(original));
    let mut altered_admission = submitted.clone();
    altered_admission.metadata =
        Some(serde_json::from_value(serde_json::json!({"forged": true})).unwrap());
    assert!(
        store
            .admit_fixture(
                altered_admission.clone(),
                "altered-admission",
                SendMessageResponse::Task(altered_admission),
                request("task-11"),
                102,
                3,
            )
            .await
            .unwrap_err()
            .message
            .contains("idempotency")
    );
    let mut conflicting = submitted;
    conflicting.history.as_mut().unwrap()[0].parts = vec![Part::text("different semantics")];
    let mut conflicting_dispatch = request("task-11");
    conflicting_dispatch.text = "different semantics".to_owned();
    assert!(
        store
            .admit_fixture(
                conflicting.clone(),
                "digest-b",
                SendMessageResponse::Task(conflicting),
                conflicting_dispatch,
                102,
                3
            )
            .await
            .unwrap_err()
            .message
            .contains("idempotency")
    );

    let counts = store.atomic_record_counts().await.unwrap();
    assert_eq!(counts.tasks, 1);
    assert_eq!(counts.events, 1);
    assert_eq!(counts.idempotency_records, 1);
    assert_eq!(counts.outbox, 1);
}

#[tokio::test]
async fn leases_are_fenced_retried_and_dead_lettered_with_injected_time() {
    let path = path();
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    let submitted = task("lease-task", TaskState::Submitted);
    store
        .admit_fixture(
            submitted.clone(),
            "lease-digest",
            SendMessageResponse::Task(submitted),
            request("lease-task"),
            1_000,
            2,
        )
        .await
        .unwrap();

    let first = store
        .claim_outbox("worker-a", 1_000, 50)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.attempt_no, 1);
    assert!(store.ack_outbox(&first, 1_001).await.unwrap());
    assert!(!store.ack_outbox(&first, 1_002).await.unwrap());

    // A second task exercises retry and dead-letter exhaustion.
    let submitted = task("retry-task", TaskState::Submitted);
    store
        .admit_fixture(
            submitted.clone(),
            "retry-digest",
            SendMessageResponse::Task(submitted),
            request("retry-task"),
            2_000,
            2,
        )
        .await
        .unwrap();
    let attempt1 = store
        .claim_outbox("worker-a", 2_000, 50)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .finish_outbox_attempt(
                &attempt1,
                AttemptDisposition::Retry {
                    available_at: 2_100,
                    error: "transient".to_owned()
                },
                2_001
            )
            .await
            .unwrap(),
        TransitionOutcome::Applied
    );
    assert!(
        store
            .claim_outbox("worker-b", 2_099, 50)
            .await
            .unwrap()
            .is_none()
    );
    let attempt2 = store
        .claim_outbox("worker-b", 2_100, 50)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(attempt1.dispatch_id, attempt2.dispatch_id);
    assert_eq!(
        store
            .finish_outbox_attempt(
                &attempt2,
                AttemptDisposition::Retry {
                    available_at: 2_200,
                    error: "again".to_owned()
                },
                2_101
            )
            .await
            .unwrap(),
        TransitionOutcome::DeadLettered
    );
    assert!(
        store
            .claim_outbox("worker-c", 9_999, 50)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn durable_cas_allows_exactly_one_terminal_winner_and_exact_replay() {
    let path = path();
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    let submitted = task("race-task", TaskState::Submitted);
    let AdmissionOutcome::Admitted(admitted) = store
        .admit_fixture(
            submitted.clone(),
            "race-digest",
            SendMessageResponse::Task(submitted),
            request("race-task"),
            10,
            3,
        )
        .await
        .unwrap()
    else {
        panic!()
    };

    let mut completed = task("race-task", TaskState::Completed);
    completed.status.timestamp = Some(chrono::Utc::now());
    let mut canceled = completed.clone();
    canceled.status.state = TaskState::Canceled;
    let canceled_result = SendMessageResponse::Task(canceled.clone());
    let a = store.clone();
    let b = store.clone();
    let (left, right) = tokio::join!(
        a.commit_transition(
            "race-task",
            admitted.revision,
            completed.clone(),
            "completed",
            Some(SendMessageResponse::Task(completed.clone())),
            11
        ),
        b.commit_transition(
            "race-task",
            admitted.revision,
            canceled,
            "canceled",
            Some(canceled_result),
            11
        ),
    );
    let outcomes = [left.unwrap(), right.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|value| **value == TransitionOutcome::Applied)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|value| **value == TransitionOutcome::Stale)
            .count(),
        1
    );
    let winner = a2a_server::TaskStore::get(&store, "race-task")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .commit_transition(
                "race-task",
                2,
                winner.clone(),
                "exact-replay",
                Some(SendMessageResponse::Task(winner.clone())),
                12,
            )
            .await
            .unwrap(),
        TransitionOutcome::Idempotent
    );
    let mut different_result = winner.clone();
    different_result.status.message =
        Some(Message::new(Role::Agent, vec![Part::text("different")]));
    assert!(
        store
            .commit_transition(
                "race-task",
                2,
                winner.clone(),
                "differing-replay",
                Some(SendMessageResponse::Task(different_result)),
                12,
            )
            .await
            .is_err()
    );
    assert_eq!(
        store
            .admit_fixture(
                task("race-task", TaskState::Submitted),
                "race-digest",
                SendMessageResponse::Task(task("race-task", TaskState::Submitted)),
                request("race-task"),
                12,
                3,
            )
            .await
            .unwrap(),
        AdmissionOutcome::Replay(SendMessageResponse::Task(winner.clone()))
    );
    drop(a);
    drop(b);
    drop(store);
    let reopened = SqliteTaskStore::open(&path, 8).await.unwrap();
    assert_eq!(
        reopened
            .admit_fixture(
                task("race-task", TaskState::Submitted),
                "race-digest",
                SendMessageResponse::Task(task("race-task", TaskState::Submitted)),
                request("race-task"),
                13,
                3,
            )
            .await
            .unwrap(),
        AdmissionOutcome::Replay(SendMessageResponse::Task(winner))
    );
}

#[tokio::test]
async fn terminal_transition_without_typed_result_is_rejected_without_mutation() {
    let path = path();
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    let submitted = task("terminal-result-required", TaskState::Submitted);
    store
        .admit_fixture(
            submitted.clone(),
            digest("terminal-result-required"),
            SendMessageResponse::Task(submitted),
            request("terminal-result-required"),
            10,
            3,
        )
        .await
        .unwrap();
    let completed = task("terminal-result-required", TaskState::Completed);
    let mut mismatched_result = completed.clone();
    mismatched_result.status.message = Some(Message::new(Role::Agent, vec![Part::text("other")]));
    assert!(
        store
            .commit_transition(
                "terminal-result-required",
                1,
                completed.clone(),
                "completed",
                Some(SendMessageResponse::Task(mismatched_result)),
                11,
            )
            .await
            .is_err()
    );
    assert!(
        store
            .commit_transition(
                "terminal-result-required",
                1,
                completed,
                "completed",
                None,
                11,
            )
            .await
            .unwrap_err()
            .message
            .contains("final result")
    );
    let durable = a2a_server::TaskStore::get(&store, "terminal-result-required")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(durable.status.state, TaskState::Submitted);
    let counts = store.atomic_record_counts().await.unwrap();
    assert_eq!(counts.events, 1);
}

#[tokio::test]
async fn simultaneous_claimers_produce_exactly_one_lease_and_attempt() {
    let path = path();
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    let submitted = task("simultaneous-claim", TaskState::Submitted);
    store
        .admit_fixture(
            submitted.clone(),
            digest("simultaneous-claim"),
            SendMessageResponse::Task(submitted),
            request("simultaneous-claim"),
            100,
            3,
        )
        .await
        .unwrap();
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));
    let claim = |owner: &'static str| {
        let store = store.clone();
        let barrier = barrier.clone();
        async move {
            barrier.wait().await;
            store.claim_outbox(owner, 100, 50).await.unwrap()
        }
    };
    let left = tokio::spawn(claim("worker-left"));
    let right = tokio::spawn(claim("worker-right"));
    barrier.wait().await;
    let outcomes = [left.await.unwrap(), right.await.unwrap()];
    assert_eq!(outcomes.iter().filter(|lease| lease.is_some()).count(), 1);
    drop(store);
    let connection = rusqlite::Connection::open(&path).unwrap();
    let attempts: i64 = connection
        .query_row("SELECT COUNT(*) FROM outbox_attempts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(attempts, 1);
}

#[tokio::test]
async fn expired_and_forged_outbox_leases_are_rejected_by_durable_fence() {
    let path = path();
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    let submitted = task("fenced-task", TaskState::Submitted);
    store
        .admit_fixture(
            submitted.clone(),
            "fenced-digest",
            SendMessageResponse::Task(submitted),
            request("fenced-task"),
            100,
            3,
        )
        .await
        .unwrap();
    let lease = store
        .claim_outbox("worker-a", 100, 50)
        .await
        .unwrap()
        .unwrap();
    assert!(!store.ack_outbox(&lease, 151).await.unwrap());

    let reclaimed = store
        .claim_outbox("worker-b", 151, 50)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .finish_outbox_attempt(
                &lease,
                AttemptDisposition::Retry {
                    available_at: 250,
                    error: "stale-worker-a".to_owned(),
                },
                152,
            )
            .await
            .unwrap(),
        TransitionOutcome::Stale
    );
    let mut forged = reclaimed.clone();
    forged.attempt_no = 99;
    forged.max_attempts = 1;
    assert_eq!(
        store
            .finish_outbox_attempt(
                &forged,
                AttemptDisposition::Retry {
                    available_at: 250,
                    error: "forged".to_owned(),
                },
                152,
            )
            .await
            .unwrap(),
        TransitionOutcome::Stale
    );
    let victim = task("fence-victim", TaskState::Submitted);
    store
        .admit_fixture(
            victim.clone(),
            "fence-victim-digest",
            SendMessageResponse::Task(victim),
            request("fence-victim"),
            152,
            3,
        )
        .await
        .unwrap();
    let mut forged_task = reclaimed.clone();
    forged_task.task_id = "fence-victim".to_owned();
    assert_eq!(
        store
            .finish_outbox_attempt(
                &forged_task,
                AttemptDisposition::Permanent {
                    error: "forged victim".to_owned(),
                },
                153,
            )
            .await
            .unwrap(),
        TransitionOutcome::Stale
    );
    assert_eq!(
        a2a_server::TaskStore::get(&store, "fence-victim")
            .await
            .unwrap()
            .unwrap()
            .status
            .state,
        TaskState::Submitted
    );
    assert!(store.ack_outbox(&reclaimed, 152).await.unwrap());
}

#[tokio::test]
async fn final_attempt_lease_expiry_atomically_dead_letters_task() {
    let path = path();
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    let submitted = task("expired-final", TaskState::Submitted);
    store
        .admit_fixture(
            submitted.clone(),
            "expired-final-digest",
            SendMessageResponse::Task(submitted),
            request("expired-final"),
            100,
            1,
        )
        .await
        .unwrap();
    let _lease = store
        .claim_outbox("crashed", 100, 10)
        .await
        .unwrap()
        .unwrap();
    assert!(
        store
            .claim_outbox("reaper", 111, 10)
            .await
            .unwrap()
            .is_none()
    );
    let failed = a2a_server::TaskStore::get(&store, "expired-final")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(failed.status.state, TaskState::Failed);
    assert!(matches!(
        store
            .admit_fixture(
                task("expired-final", TaskState::Submitted),
                "expired-final-digest",
                SendMessageResponse::Task(task("expired-final", TaskState::Submitted)),
                request("expired-final"),
                112,
                1,
            )
            .await
            .unwrap(),
        AdmissionOutcome::Replay(SendMessageResponse::Task(task)) if task.status.state == TaskState::Failed
    ));
    drop(store);
    let connection = rusqlite::Connection::open(&path).unwrap();
    let outbox: (String, String, i64, i64) = connection
        .query_row(
            "SELECT state, last_error, attempt_count, max_attempts FROM outbox",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(outbox.0, "dead");
    assert!(outbox.1.contains("lease expired"));
    assert_eq!((outbox.2, outbox.3), (1, 1));
    let attempt: (Option<i64>, Option<String>, Option<String>) = connection
        .query_row(
            "SELECT finished_at, outcome, error FROM outbox_attempts",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(attempt.0, Some(111));
    assert_eq!(attempt.1.as_deref(), Some("dead"));
    assert!(attempt.2.unwrap().contains("lease expired"));
    let event: (String, String) = connection
        .query_row(
            "SELECT event_kind, to_state FROM task_events ORDER BY event_seq DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        event,
        (
            "dead_lettered".to_owned(),
            serde_json::to_string(&TaskState::Failed).unwrap()
        )
    );
    let idempotency: (String, Option<String>) = connection
        .query_row(
            "SELECT state, final_result_json FROM idempotency_records",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(idempotency.0, "completed");
    assert!(idempotency.1.unwrap().contains("TASK_STATE_FAILED"));
}

#[tokio::test]
async fn final_leased_attempt_is_dead_lettered_during_restart_recovery() {
    let path = path();
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    let submitted = task("restart-final", TaskState::Submitted);
    store
        .admit_fixture(
            submitted.clone(),
            "restart-final-digest",
            SendMessageResponse::Task(submitted),
            request("restart-final"),
            100,
            1,
        )
        .await
        .unwrap();
    let lease = store
        .claim_outbox("crashed-final-worker", 100, 50)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lease.attempt_no, 1);
    drop(store);

    let reopened = SqliteTaskStore::open(&path, 8).await.unwrap();
    let failed = a2a_server::TaskStore::get(&reopened, "restart-final")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(failed.status.state, TaskState::Failed);
    assert!(matches!(
        reopened
            .admit_fixture(
                task("restart-final", TaskState::Submitted),
                "restart-final-digest",
                SendMessageResponse::Task(task("restart-final", TaskState::Submitted)),
                request("restart-final"),
                200,
                1,
            )
            .await
            .unwrap(),
        AdmissionOutcome::Replay(SendMessageResponse::Task(task))
            if task.status.state == TaskState::Failed
    ));
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One restart scenario proves both message replays and all intent states.
async fn delivered_nonterminal_intent_fails_closed_during_restart_recovery() {
    let path = path();
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    let submitted = task("delivered-orphan", TaskState::Submitted);
    store
        .admit_fixture(
            submitted.clone(),
            "delivered-orphan",
            SendMessageResponse::Task(submitted.clone()),
            request("delivered-orphan"),
            100,
            3,
        )
        .await
        .unwrap();
    let first_lease = store
        .claim_outbox("ack-before-interruption", 100, 50)
        .await
        .unwrap()
        .unwrap();
    assert!(store.ack_outbox(&first_lease, 101).await.unwrap());

    let interrupted = task("delivered-orphan", TaskState::InputRequired);
    assert_eq!(
        store
            .commit_transition(
                "delivered-orphan",
                1,
                interrupted.clone(),
                "input-required",
                Some(SendMessageResponse::Task(interrupted.clone())),
                102,
            )
            .await
            .unwrap(),
        TransitionOutcome::Applied
    );
    let continuation = || {
        let mut message = Message::new(Role::User, vec![Part::text("continued after input")]);
        message.message_id = "delivered-orphan-continuation".to_owned();
        message.task_id = Some("delivered-orphan".to_owned());
        message.context_id = Some("context-11".to_owned());
        SendMessageAdmission {
            request: SendMessageRequest {
                message,
                configuration: None,
                metadata: None,
                tenant: None,
            },
            streaming: false,
            task: interrupted.clone(),
            original_result: SendMessageResponse::Task(interrupted.clone()),
            input_limits: InputLimits::default(),
            now: 103,
            max_attempts: 3,
        }
    };
    assert!(matches!(
        store.admit_continuation(continuation()).await.unwrap(),
        AdmissionOutcome::Admitted(_)
    ));
    let second_lease = store
        .claim_outbox("ack-before-terminal", 103, 50)
        .await
        .unwrap()
        .unwrap();
    assert!(store.ack_outbox(&second_lease, 104).await.unwrap());
    drop(store);

    let reopened = SqliteTaskStore::open(&path, 8).await.unwrap();
    let failed = a2a_server::TaskStore::get(&reopened, "delivered-orphan")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(failed.status.state, TaskState::Failed);
    assert!(
        failed
            .status
            .message
            .as_ref()
            .is_some_and(|message| message.parts.iter().any(|part| {
                serde_json::to_string(part)
                    .is_ok_and(|encoded| encoded.contains("outcome is unknown"))
            }))
    );
    assert!(matches!(
        reopened
            .admit_fixture(
                submitted,
                "delivered-orphan-original-replay",
                SendMessageResponse::Task(task("delivered-orphan", TaskState::Submitted)),
                request("delivered-orphan"),
                200,
                3,
            )
            .await
            .unwrap(),
        AdmissionOutcome::Replay(SendMessageResponse::Task(task))
            if task.status.state == TaskState::InputRequired
    ));
    assert!(matches!(
        reopened.admit_continuation(continuation()).await.unwrap(),
        AdmissionOutcome::Replay(SendMessageResponse::Task(task))
            if task.status.state == TaskState::Failed
    ));
    drop(reopened);
    let connection = rusqlite::Connection::open(&path).unwrap();
    let superseded: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM outbox WHERE state = 'superseded'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(superseded, 2);
    let completed: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM idempotency_records WHERE state = 'completed'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(completed, 2);
}

#[tokio::test]
async fn lifecycle_rejects_regression_and_admission_rejects_reopen_poisoning_bounds() {
    let path = path();
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    let submitted = task("legal-task", TaskState::Submitted);
    store
        .admit_fixture(
            submitted.clone(),
            "legal-digest",
            SendMessageResponse::Task(submitted),
            request("legal-task"),
            100,
            3,
        )
        .await
        .unwrap();
    let working = task("legal-task", TaskState::Working);
    assert_eq!(
        store
            .commit_transition("legal-task", 1, working, "working", None, 101)
            .await
            .unwrap(),
        TransitionOutcome::Applied
    );
    assert_eq!(
        store
            .commit_transition(
                "legal-task",
                2,
                task("legal-task", TaskState::Submitted),
                "regression",
                None,
                102,
            )
            .await
            .unwrap(),
        TransitionOutcome::Stale
    );

    let mut oversized = task("oversized", TaskState::Submitted);
    oversized.history.as_mut().unwrap()[0].message_id = "m".repeat(4097);
    let error = store
        .admit_fixture(
            oversized.clone(),
            "digest",
            SendMessageResponse::Task(oversized),
            request("oversized"),
            103,
            3,
        )
        .await
        .unwrap_err();
    assert!(error.message.contains("messageId"));
}

#[tokio::test]
async fn continuation_atomically_enters_working_and_rejects_a_second_continuation() {
    let path = path();
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    let mut interrupted = task("continued-task", TaskState::InputRequired);
    interrupted.metadata =
        Some(serde_json::from_value(serde_json::json!({"preserve": "雪"})).unwrap());
    a2a_server::TaskStore::create(&store, interrupted.clone())
        .await
        .unwrap();

    let continuation = |message_id: &str| {
        let mut message = Message::new(Role::User, vec![Part::text("continued input")]);
        message.message_id = message_id.to_owned();
        SendMessageAdmission {
            request: SendMessageRequest {
                message,
                configuration: None,
                metadata: None,
                tenant: None,
            },
            streaming: false,
            task: interrupted.clone(),
            original_result: SendMessageResponse::Task(interrupted.clone()),
            input_limits: InputLimits::default(),
            now: 101,
            max_attempts: 3,
        }
    };
    let mut forged = continuation("forged-context");
    forged.task.context_id = "forged-context".to_owned();
    assert!(store.admit_continuation(forged).await.is_err());
    let mut forged_nested_identity = continuation("forged-nested-identity");
    forged_nested_identity.request.message.task_id = Some("different-task".to_owned());
    assert!(
        store
            .admit_continuation(forged_nested_identity)
            .await
            .is_err()
    );
    assert!(matches!(
        store
            .admit_continuation(continuation("continuation-one"))
            .await
            .unwrap(),
        AdmissionOutcome::Admitted(_)
    ));
    assert!(matches!(
        store
            .admit_continuation(continuation("continuation-one"))
            .await
            .unwrap(),
        AdmissionOutcome::Replay(SendMessageResponse::Task(task)) if task == interrupted
    ));
    let mut forged_replay = continuation("continuation-one");
    forged_replay.task.metadata =
        Some(serde_json::from_value(serde_json::json!({"forged": true})).unwrap());
    forged_replay.original_result = SendMessageResponse::Task(forged_replay.task.clone());
    assert!(
        store
            .admit_continuation(forged_replay)
            .await
            .unwrap_err()
            .message
            .contains("idempotency")
    );
    let durable = a2a_server::TaskStore::get(&store, "continued-task")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(durable.status.state, TaskState::Working);
    assert_eq!(
        durable.metadata,
        Some(serde_json::from_value(serde_json::json!({"preserve": "雪"})).unwrap())
    );
    assert_eq!(durable.history.unwrap().len(), 2);
    assert!(
        store
            .admit_continuation(continuation("continuation-two"))
            .await
            .unwrap_err()
            .message
            .contains("no longer accepts")
    );
    let counts = store.atomic_record_counts().await.unwrap();
    assert_eq!(
        (counts.events, counts.idempotency_records, counts.outbox),
        (2, 1, 1)
    );
}

#[tokio::test]
async fn admission_rejects_mismatched_result_before_any_write() {
    let path = path();
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    let submitted = task("semantic-task", TaskState::Submitted);
    assert!(
        store
            .admit_fixture(
                submitted,
                digest("semantic"),
                SendMessageResponse::Task(task("other-task", TaskState::Submitted)),
                request("semantic-task"),
                100,
                3,
            )
            .await
            .is_err()
    );
    let counts = store.atomic_record_counts().await.unwrap();
    assert_eq!(
        (
            counts.tasks,
            counts.events,
            counts.idempotency_records,
            counts.outbox
        ),
        (0, 0, 0, 0)
    );
}

#[tokio::test]
async fn canonical_admission_rejects_task_payload_that_differs_from_request() {
    let path = path();
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    let submitted = task("canonical-forged", TaskState::Submitted);
    let mut request_message = Message::new(Role::User, vec![Part::text("canonical request")]);
    request_message.message_id = "message-canonical-forged".to_owned();
    let request = SendMessageRequest {
        message: request_message,
        configuration: None,
        metadata: None,
        tenant: None,
    };
    assert_ne!(submitted.history.as_ref().unwrap()[0], request.message);
    let result = SendMessageResponse::Task(submitted.clone());
    assert!(
        store
            .admit_send_message(SendMessageAdmission {
                request,
                streaming: false,
                task: submitted,
                original_result: result,
                input_limits: InputLimits::default(),
                now: 100,
                max_attempts: 3,
            })
            .await
            .is_err()
    );
    let counts = store.atomic_record_counts().await.unwrap();
    assert_eq!(
        (
            counts.tasks,
            counts.events,
            counts.idempotency_records,
            counts.outbox
        ),
        (0, 0, 0, 0)
    );
}

#[tokio::test]
async fn exact_lease_expiry_is_stale_and_terminal_transition_closes_active_attempt() {
    let path = path();
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    let submitted = task("terminal-lease", TaskState::Submitted);
    store
        .admit_fixture(
            submitted.clone(),
            digest("terminal-lease"),
            SendMessageResponse::Task(submitted),
            request("terminal-lease"),
            100,
            3,
        )
        .await
        .unwrap();
    let expired = store
        .claim_outbox("worker-a", 100, 50)
        .await
        .unwrap()
        .unwrap();
    assert!(!store.ack_outbox(&expired, 150).await.unwrap());
    let active = store
        .claim_outbox("worker-b", 150, 50)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(active.attempt_no, 2);

    let completed = task("terminal-lease", TaskState::Completed);
    assert_eq!(
        store
            .commit_transition(
                "terminal-lease",
                1,
                completed.clone(),
                "completed",
                Some(SendMessageResponse::Task(completed)),
                151,
            )
            .await
            .unwrap(),
        TransitionOutcome::Applied
    );
    assert!(!store.ack_outbox(&active, 152).await.unwrap());
    drop(store);
    let connection = rusqlite::Connection::open(&path).unwrap();
    let row: (String, Option<i64>, Option<String>) = connection
        .query_row(
            "SELECT o.state, a.finished_at, a.outcome FROM outbox o
             JOIN outbox_attempts a ON a.outbox_id = o.outbox_id
             WHERE a.attempt_no = 2",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        row,
        (
            "superseded".to_owned(),
            Some(151),
            Some("superseded".to_owned())
        )
    );
}

#[tokio::test]
async fn unicode_event_kind_and_lease_owner_bounds_leave_rows_unchanged() {
    let path = path();
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    let submitted = task("bounded-text", TaskState::Submitted);
    store
        .admit_fixture(
            submitted.clone(),
            digest("bounded-text"),
            SendMessageResponse::Task(submitted),
            request("bounded-text"),
            1,
            3,
        )
        .await
        .unwrap();
    let before = store.atomic_record_counts().await.unwrap();
    let working = task("bounded-text", TaskState::Working);
    let oversized_unicode = "雪".repeat(1_366);
    assert!(
        store
            .commit_transition(
                "bounded-text",
                1,
                working,
                oversized_unicode.clone(),
                None,
                2,
            )
            .await
            .is_err()
    );
    assert!(store.claim_outbox(oversized_unicode, 2, 10).await.is_err());
    let after = store.atomic_record_counts().await.unwrap();
    assert_eq!(before, after);
    let durable = a2a_server::TaskStore::get(&store, "bounded-text")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(durable.status.state, TaskState::Submitted);
}

#[tokio::test]
async fn every_atomic_table_reopen_aggregate_counts_multibyte_bytes_without_mutation() {
    let oversized_unicode = "雪".repeat((64 * 1024 * 1024 / 3) + 1);
    for (table, column) in [
        ("task_events", "event_kind"),
        ("idempotency_records", "admission_result_json"),
        ("outbox", "payload_json"),
        ("outbox_attempts", "error"),
    ] {
        let path = path();
        let store = SqliteTaskStore::open(&path, 8).await.unwrap();
        let id = format!("unicode-aggregate-{table}");
        let submitted = task(&id, TaskState::Submitted);
        store
            .admit_fixture(
                submitted.clone(),
                digest(&id),
                SendMessageResponse::Task(submitted),
                request(&id),
                1,
                3,
            )
            .await
            .unwrap();
        if table == "outbox_attempts" {
            store.claim_outbox("worker", 1, 50).await.unwrap().unwrap();
        }
        drop(store);
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute(
                &format!("UPDATE {table} SET {column} = ?1"),
                [&oversized_unicode],
            )
            .unwrap();
        drop(connection);
        assert!(matches!(
            SqliteTaskStore::open(&path, 8).await,
            Err(smesh_a2a::SqliteStoreError::Capacity)
        ));
        let connection = rusqlite::Connection::open(&path).unwrap();
        let revision: i64 = connection
            .query_row("SELECT revision FROM tasks", [], |row| row.get(0))
            .unwrap();
        let rows: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!((revision, rows), (1, 1));
    }
}

#[tokio::test]
async fn event_aggregate_capacity_failure_rolls_back_and_database_reopens() {
    let path = path();
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    let submitted = task("bounded-events", TaskState::Submitted);
    store
        .admit_fixture(
            submitted.clone(),
            digest("bounded-events"),
            SendMessageResponse::Task(submitted),
            request("bounded-events"),
            1,
            3,
        )
        .await
        .unwrap();
    let payload = "x".repeat(950_000);
    let mut revision = 1;
    let mut rejected = false;
    for sequence in 0..80 {
        let mut next = task("bounded-events", TaskState::Working);
        next.history.as_mut().unwrap()[0].parts = vec![Part::text(format!("{sequence}:{payload}"))];
        match store
            .commit_transition("bounded-events", revision, next, "bounded", None, sequence)
            .await
        {
            Ok(TransitionOutcome::Applied) => revision += 1,
            Err(error) if error.message.contains("capacity") => {
                rejected = true;
                break;
            }
            other => panic!("unexpected transition result: {other:?}"),
        }
    }
    assert!(
        rejected,
        "event aggregate must reject before exceeding 64 MiB"
    );
    drop(store);
    SqliteTaskStore::open(&path, 8).await.unwrap();
}

#[tokio::test]
async fn reopen_rejects_corrupt_event_relation_sequence_and_state_semantics() {
    let path = path();
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    let submitted = task("corrupt-events", TaskState::Submitted);
    store
        .admit_fixture(
            submitted.clone(),
            digest("corrupt-events"),
            SendMessageResponse::Task(submitted),
            request("corrupt-events"),
            1,
            3,
        )
        .await
        .unwrap();
    store
        .commit_transition(
            "corrupt-events",
            1,
            task("corrupt-events", TaskState::Working),
            "working",
            None,
            2,
        )
        .await
        .unwrap();
    drop(store);
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute(
            "UPDATE task_events SET from_state = ?1, event_seq = 3 WHERE event_seq = 2",
            [serde_json::to_string(&TaskState::Completed).unwrap()],
        )
        .unwrap();
    drop(connection);
    assert!(SqliteTaskStore::open(&path, 8).await.is_err());
}

#[tokio::test]
async fn revision_exhaustion_is_rejected_before_recovery_mutates_state() {
    let path = path();
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    a2a_server::TaskStore::create(&store, task("revision-max", TaskState::Working))
        .await
        .unwrap();
    drop(store);
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute("UPDATE tasks SET revision = ?1", [i64::MAX])
        .unwrap();
    connection
        .execute("UPDATE task_events SET task_revision = ?1", [i64::MAX])
        .unwrap();
    drop(connection);
    assert!(SqliteTaskStore::open(&path, 8).await.is_err());
    let connection = rusqlite::Connection::open(&path).unwrap();
    let durable: (i64, String) = connection
        .query_row("SELECT revision, state FROM tasks", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    assert_eq!(
        durable,
        (
            i64::MAX,
            serde_json::to_string(&TaskState::Working).unwrap()
        )
    );
}

#[test]
fn canonical_digest_binds_semantics_not_caller_tenant_or_transport() {
    let mut message = Message::new(Role::User, vec![Part::text("one")]);
    message.message_id = "canonical-message".to_owned();
    let mut request = SendMessageRequest {
        message,
        configuration: None,
        metadata: None,
        tenant: None,
    };
    let unary = canonical_send_message_digest(&request, false).unwrap();
    request.tenant = Some("caller-controlled".to_owned());
    assert_eq!(
        canonical_send_message_digest(&request, false).unwrap(),
        unary
    );
    assert_ne!(
        canonical_send_message_digest(&request, true).unwrap(),
        unary
    );
    request.message.parts = vec![Part::text("two")];
    assert_ne!(
        canonical_send_message_digest(&request, false).unwrap(),
        unary
    );
}

#[tokio::test]
async fn exact_v1_schema_migrates_to_v2_preserving_keys_and_task() {
    const V1: &str = "CREATE TABLE store_metadata (
     singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
     schema_version INTEGER NOT NULL,
     migration_hash TEXT NOT NULL,
     cursor_key BLOB NOT NULL CHECK (length(cursor_key) = 32),
     receipt_key BLOB NOT NULL CHECK (length(receipt_key) = 32)
 );
 CREATE TABLE tasks (
     created_order INTEGER PRIMARY KEY AUTOINCREMENT,
     task_id TEXT NOT NULL UNIQUE,
     context_id TEXT NOT NULL,
     state TEXT NOT NULL,
     status_timestamp TEXT,
     revision INTEGER NOT NULL CHECK (revision > 0),
     task_json TEXT NOT NULL
 );
 CREATE INDEX tasks_context_state_time
     ON tasks(context_id, state, status_timestamp, task_id);";
    let path = path();
    let original = task("migrated-terminal", TaskState::Completed);
    let task_json = serde_json::to_string(&original).unwrap();
    let state = serde_json::to_string(&TaskState::Completed).unwrap();
    let cursor_key = [7_u8; 32];
    let receipt_key = [9_u8; 32];
    {
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection.execute_batch(V1).unwrap();
        connection
            .execute(
                "INSERT INTO store_metadata(singleton, schema_version, migration_hash, cursor_key, receipt_key)
                 VALUES (1, 1, ?1, ?2, ?3)",
                rusqlite::params![content_digest(V1.as_bytes()), cursor_key, receipt_key],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO tasks(task_id, context_id, state, revision, task_json)
                 VALUES (?1, ?2, ?3, 4, ?4)",
                rusqlite::params![original.id, original.context_id, state, task_json],
            )
            .unwrap();
        connection
            .pragma_update(None, "application_id", 0x534D_4132_i64)
            .unwrap();
        connection
            .pragma_update(None, "user_version", 1_i64)
            .unwrap();
    }
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    assert_eq!(store.completion_receipt_key(), receipt_key);
    assert_eq!(
        a2a_server::TaskStore::get(&store, "migrated-terminal")
            .await
            .unwrap(),
        Some(original.clone())
    );
    drop(store);
    let reopened = SqliteTaskStore::open(&path, 8).await.unwrap();
    assert_eq!(
        a2a_server::TaskStore::get(&reopened, "migrated-terminal")
            .await
            .unwrap(),
        Some(original)
    );
    drop(reopened);
    let connection = rusqlite::Connection::open(&path).unwrap();
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    let event_kind: String = connection
        .query_row(
            "SELECT event_kind FROM task_events WHERE task_id = 'migrated-terminal'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(version, 2);
    assert_eq!(event_kind, "migration_snapshot");
}

#[tokio::test]
async fn malformed_v1_record_rolls_back_migration_without_version_or_schema_change() {
    const V1: &str = "CREATE TABLE store_metadata (
     singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
     schema_version INTEGER NOT NULL,
     migration_hash TEXT NOT NULL,
     cursor_key BLOB NOT NULL CHECK (length(cursor_key) = 32),
     receipt_key BLOB NOT NULL CHECK (length(receipt_key) = 32)
 );
 CREATE TABLE tasks (
     created_order INTEGER PRIMARY KEY AUTOINCREMENT,
     task_id TEXT NOT NULL UNIQUE,
     context_id TEXT NOT NULL,
     state TEXT NOT NULL,
     status_timestamp TEXT,
     revision INTEGER NOT NULL CHECK (revision > 0),
     task_json TEXT NOT NULL
 );
 CREATE INDEX tasks_context_state_time
     ON tasks(context_id, state, status_timestamp, task_id);";
    let path = path();
    let malformed = task("encoded-id", TaskState::Completed);
    {
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection.execute_batch(V1).unwrap();
        connection
            .execute(
                "INSERT INTO store_metadata(singleton, schema_version, migration_hash, cursor_key, receipt_key)
                 VALUES (1, 1, ?1, ?2, ?3)",
                rusqlite::params![content_digest(V1.as_bytes()), [1_u8; 32], [2_u8; 32]],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO tasks(task_id, context_id, state, revision, task_json)
                 VALUES ('different-id', ?1, ?2, 1, ?3)",
                rusqlite::params![
                    malformed.context_id,
                    serde_json::to_string(&malformed.status.state).unwrap(),
                    serde_json::to_string(&malformed).unwrap()
                ],
            )
            .unwrap();
        connection
            .pragma_update(None, "application_id", 0x534D_4132_i64)
            .unwrap();
        connection
            .pragma_update(None, "user_version", 1_i64)
            .unwrap();
    }
    assert!(SqliteTaskStore::open(&path, 8).await.is_err());
    let connection = rusqlite::Connection::open(&path).unwrap();
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    let atomic_tables: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name IN
                 ('task_events', 'idempotency_records', 'outbox', 'outbox_attempts')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!((version, atomic_tables), (1, 0));
}

#[tokio::test]
async fn transaction_faults_on_task_event_idempotency_or_outbox_roll_back_all_admission_rows() {
    for (table, trigger) in [
        ("tasks", "reject_atomic_task"),
        ("task_events", "reject_atomic_event"),
        ("idempotency_records", "reject_atomic_idempotency"),
        ("outbox", "reject_atomic_outbox"),
    ] {
        let path = path();
        let store = SqliteTaskStore::open(&path, 8).await.unwrap();
        let injector = rusqlite::Connection::open(&path).unwrap();
        injector
            .execute_batch(&format!(
                "CREATE TRIGGER {trigger} BEFORE INSERT ON {table}
                 BEGIN SELECT RAISE(ABORT, 'injected atomic failure'); END;"
            ))
            .unwrap();
        let submitted = task(&format!("fault-{table}"), TaskState::Submitted);
        assert!(
            store
                .admit_fixture(
                    submitted.clone(),
                    format!("digest-{table}"),
                    SendMessageResponse::Task(submitted),
                    request(&format!("fault-{table}")),
                    10,
                    3,
                )
                .await
                .is_err()
        );
        let counts = store.atomic_record_counts().await.unwrap();
        assert_eq!(
            (
                counts.tasks,
                counts.events,
                counts.idempotency_records,
                counts.outbox
            ),
            (0, 0, 0, 0)
        );
        injector
            .execute_batch(&format!("DROP TRIGGER {trigger};"))
            .unwrap();
    }
}

#[tokio::test]
async fn claim_and_terminal_faults_roll_back_attempt_task_event_idempotency_and_outbox() {
    let path = path();
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    let submitted = task("fault-lifecycle", TaskState::Submitted);
    store
        .admit_fixture(
            submitted.clone(),
            digest("fault-lifecycle"),
            SendMessageResponse::Task(submitted.clone()),
            request("fault-lifecycle"),
            10,
            3,
        )
        .await
        .unwrap();
    let injector = rusqlite::Connection::open(&path).unwrap();
    injector
        .execute_batch(
            "CREATE TRIGGER reject_attempt BEFORE INSERT ON outbox_attempts
             BEGIN SELECT RAISE(ABORT, 'injected attempt failure'); END;",
        )
        .unwrap();
    assert!(store.claim_outbox("worker", 10, 50).await.is_err());
    injector
        .execute_batch("DROP TRIGGER reject_attempt;")
        .unwrap();

    injector
        .execute_batch(
            "CREATE TRIGGER reject_final_idempotency BEFORE UPDATE ON idempotency_records
             WHEN NEW.state = 'completed'
             BEGIN SELECT RAISE(ABORT, 'injected idempotency completion failure'); END;",
        )
        .unwrap();
    let completed = task("fault-lifecycle", TaskState::Completed);
    assert!(
        store
            .commit_transition(
                "fault-lifecycle",
                1,
                completed.clone(),
                "completed",
                Some(SendMessageResponse::Task(completed)),
                11,
            )
            .await
            .is_err()
    );
    injector
        .execute_batch("DROP TRIGGER reject_final_idempotency;")
        .unwrap();
    let durable = a2a_server::TaskStore::get(&store, "fault-lifecycle")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(durable.status.state, TaskState::Submitted);
    drop(store);
    let connection = rusqlite::Connection::open(&path).unwrap();
    let durable: (i64, i64, String, i64, String) = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM task_events),
                    (SELECT COUNT(*) FROM outbox_attempts), o.state, o.attempt_count, i.state
             FROM outbox o JOIN idempotency_records i ON i.task_id = o.task_id",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        durable,
        (1, 0, "pending".to_owned(), 0, "in_progress".to_owned())
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn retry_and_dead_letter_faults_roll_back_then_persist_exact_attempt_sequence() {
    let path = path();
    let store = SqliteTaskStore::open(&path, 8).await.unwrap();
    let submitted = task("fault-retry-dlq", TaskState::Submitted);
    store
        .admit_fixture(
            submitted.clone(),
            digest("fault-retry-dlq"),
            SendMessageResponse::Task(submitted),
            request("fault-retry-dlq"),
            10,
            2,
        )
        .await
        .unwrap();
    let first = store
        .claim_outbox("worker-a", 10, 50)
        .await
        .unwrap()
        .unwrap();
    let injector = rusqlite::Connection::open(&path).unwrap();
    injector
        .execute_batch(
            "CREATE TRIGGER reject_retry BEFORE UPDATE ON outbox
             WHEN NEW.state = 'pending' AND NEW.last_error IS NOT NULL
             BEGIN SELECT RAISE(ABORT, 'injected retry failure'); END;",
        )
        .unwrap();
    assert!(
        store
            .finish_outbox_attempt(
                &first,
                AttemptDisposition::Retry {
                    available_at: 100,
                    error: "transient".to_owned(),
                },
                11,
            )
            .await
            .is_err()
    );
    let unchanged: (String, i64, Option<i64>) = injector
        .query_row(
            "SELECT o.state, o.attempt_count, a.finished_at FROM outbox o
             JOIN outbox_attempts a ON a.outbox_id = o.outbox_id",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(unchanged, ("leased".to_owned(), 1, None));
    injector
        .execute_batch("DROP TRIGGER reject_retry;")
        .unwrap();
    assert_eq!(
        store
            .finish_outbox_attempt(
                &first,
                AttemptDisposition::Retry {
                    available_at: 100,
                    error: "transient".to_owned(),
                },
                11,
            )
            .await
            .unwrap(),
        TransitionOutcome::Applied
    );
    let second = store
        .claim_outbox("worker-b", 100, 50)
        .await
        .unwrap()
        .unwrap();
    injector
        .execute_batch(
            "CREATE TRIGGER reject_dead_event BEFORE INSERT ON task_events
             WHEN NEW.event_kind = 'dead_lettered'
             BEGIN SELECT RAISE(ABORT, 'injected dead-letter failure'); END;",
        )
        .unwrap();
    assert!(
        store
            .finish_outbox_attempt(
                &second,
                AttemptDisposition::Permanent {
                    error: "permanent".to_owned(),
                },
                101,
            )
            .await
            .is_err()
    );
    let unchanged: (String, String, Option<i64>, String) = injector
        .query_row(
            "SELECT o.state, t.state, a.finished_at, i.state FROM outbox o
             JOIN tasks t ON t.task_id = o.task_id
             JOIN idempotency_records i ON i.task_id = o.task_id
             JOIN outbox_attempts a ON a.outbox_id = o.outbox_id AND a.attempt_no = 2",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        unchanged,
        (
            "leased".to_owned(),
            serde_json::to_string(&TaskState::Submitted).unwrap(),
            None,
            "in_progress".to_owned(),
        )
    );
    injector
        .execute_batch("DROP TRIGGER reject_dead_event;")
        .unwrap();
    assert_eq!(
        store
            .finish_outbox_attempt(
                &second,
                AttemptDisposition::Permanent {
                    error: "permanent".to_owned(),
                },
                101,
            )
            .await
            .unwrap(),
        TransitionOutcome::DeadLettered
    );
    drop(store);
    let attempts: Vec<(i64, String, String)> = {
        let mut statement = injector
            .prepare("SELECT attempt_no, outcome, error FROM outbox_attempts ORDER BY attempt_no")
            .unwrap();
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    assert_eq!(
        attempts,
        vec![
            (1, "retry".to_owned(), "transient".to_owned()),
            (2, "dead".to_owned(), "permanent".to_owned()),
        ]
    );
    drop(injector);
    let reopened = SqliteTaskStore::open(&path, 8).await.unwrap();
    assert!(matches!(
        reopened
            .admit_fixture(
                task("fault-retry-dlq", TaskState::Submitted),
                digest("fault-retry-dlq"),
                SendMessageResponse::Task(task("fault-retry-dlq", TaskState::Submitted)),
                request("fault-retry-dlq"),
                102,
                2,
            )
            .await
            .unwrap(),
        AdmissionOutcome::Replay(SendMessageResponse::Task(task))
            if task.status.state == TaskState::Failed
    ));
}

#[test]
fn crash_barrier_helper() {
    let Ok(path) = std::env::var("SMESH_ATOMIC_CRASH_DB") else {
        return;
    };
    let mode = std::env::var("SMESH_ATOMIC_CRASH_MODE").unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let store = SqliteTaskStore::open(&path, 8).await.unwrap();
        if mode == "after_commit" {
            let submitted = task("crash-task", TaskState::Submitted);
            store
                .admit_fixture(
                    submitted.clone(),
                    "crash-digest",
                    SendMessageResponse::Task(submitted),
                    request("crash-task"),
                    100,
                    3,
                )
                .await
                .unwrap();
            println!("COMMIT_RETURNED");
        }
        std::io::stdout().flush().unwrap();
        let mut release = String::new();
        std::io::stdin().read_line(&mut release).unwrap();
    });
}

fn kill_at_barrier(path: &std::path::Path, mode: &str, barrier: &str) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_barrier_helper", "--nocapture"])
        .env("SMESH_ATOMIC_CRASH_DB", path)
        .env("SMESH_ATOMIC_CRASH_MODE", mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let output = child.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(output).lines() {
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    loop {
        let line = match receiver.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(line)) => line,
            Ok(Err(error)) => panic!("failed reading child output before {barrier}: {error}"),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("timed out waiting for child barrier {barrier}: {error}");
            }
        };
        if line.contains(barrier) {
            break;
        }
    }
    child.kill().unwrap();
    assert!(!child.wait().unwrap().success());
}

#[tokio::test]
async fn subprocess_crash_after_acknowledged_commit_preserves_all_rows() {
    let after = path();
    kill_at_barrier(&after, "after_commit", "COMMIT_RETURNED");
    let store = SqliteTaskStore::open(&after, 8).await.unwrap();
    let counts = store.atomic_record_counts().await.unwrap();
    assert_eq!(
        (
            counts.tasks,
            counts.events,
            counts.idempotency_records,
            counts.outbox
        ),
        (1, 1, 1, 1)
    );
    assert!(matches!(
        store
            .admit_fixture(
                task("crash-task", TaskState::Submitted),
                "crash-digest",
                SendMessageResponse::Task(task("crash-task", TaskState::Submitted)),
                request("crash-task"),
                101,
                3,
            )
            .await
            .unwrap(),
        AdmissionOutcome::Replay(_)
    ));
}
