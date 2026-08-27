use std::future::Future;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use a2a::{
    Message, Part, Role, SendMessageRequest, SendMessageResponse, Task, TaskState, TaskStatus,
};
use a2a_server::TaskStore;
use rusqlite::Connection;
use tokio::sync::Notify;

use crate::durable_handler::DurableRequestHandler;
use crate::durable_handler::project_send_response;
use crate::outbox_driver::{
    DriverTestGate, DriverTestHooks, DurableDriverControl, spawn_durable_driver_with_test_hooks,
};
use crate::{
    AdmissionOutcome, AdmissionRecord, AttemptDisposition, DurableDispatchEnvelope,
    DurableLoopbackEndpoint, GatewayConfig, InjectedClock, InputLimits, ReceiverAdmission,
    SendMessageAdmission, SqliteTaskStore, TRUSTED_SINGLE_TENANT_SCOPE, TransitionOutcome,
    build_durable_loopback_gateway, content_digest,
};

const WATCHDOG: Duration = Duration::from_secs(5);

#[test]
fn send_response_history_projection_is_non_mutating_and_keeps_latest_messages() {
    let mut first = Message::new(Role::User, vec![Part::text("first")]);
    first.message_id = "projection-first".to_owned();
    let mut second = Message::new(Role::User, vec![Part::text("second")]);
    second.message_id = "projection-second".to_owned();
    let canonical = Task {
        id: "projection-task".to_owned(),
        context_id: "projection-context".to_owned(),
        status: TaskStatus {
            state: TaskState::Working,
            message: None,
            timestamp: None,
        },
        artifacts: None,
        history: Some(vec![first, second.clone()]),
        metadata: None,
    };
    let response = SendMessageResponse::Task(canonical.clone());
    assert!(matches!(
        project_send_response(response.clone(), Some(0)),
        SendMessageResponse::Task(Task { history: None, .. })
    ));
    assert!(matches!(
        project_send_response(response.clone(), Some(1)),
        SendMessageResponse::Task(Task { history: Some(history), .. })
            if history == vec![second]
    ));
    assert_eq!(response, SendMessageResponse::Task(canonical));
}

async fn bounded<F: Future>(label: &str, future: F) -> F::Output {
    tokio::time::timeout(WATCHDOG, future)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {label}"))
}

async fn bounded_join<T>(label: &str, mut handle: tokio::task::JoinHandle<T>) -> T {
    if let Ok(result) = tokio::time::timeout(WATCHDOG, &mut handle).await {
        result.unwrap_or_else(|error| panic!("{label} task failed: {error}"))
    } else {
        handle.abort();
        let _ = handle.await;
        panic!("timed out waiting for {label}; task aborted and joined");
    }
}

async fn open_store(
    path: impl AsRef<Path>,
    max_tasks: usize,
) -> Result<SqliteTaskStore, crate::SqliteStoreError> {
    let path = path.as_ref().to_path_buf();
    tokio::time::timeout(WATCHDOG, SqliteTaskStore::open(&path, max_tasks))
        .await
        .unwrap_or_else(|_| panic!("timed out opening SQLite task store at {}", path.display()))
}

async fn shutdown_store(store: &SqliteTaskStore) -> Result<(), a2a::A2AError> {
    tokio::time::timeout(WATCHDOG, store.shutdown_shared())
        .await
        .unwrap_or_else(|_| panic!("timed out shutting down SQLite task store"))
}

fn database_path(label: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "smesh-driver-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_nanos()
    ));
    std::fs::create_dir(&directory).expect("create test directory");
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
        .expect("secure test directory");
    directory.join("tasks.sqlite3")
}

fn cleanup(path: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    let _ = std::fs::remove_file(format!("{}.lock", path.display()));
    let _ = std::fs::remove_dir(path.parent().expect("database parent"));
}

async fn admit(
    store: &SqliteTaskStore,
    message_id: &str,
    now: i64,
) -> (SendMessageRequest, AdmissionRecord) {
    admit_with_streaming(store, message_id, now, false).await
}

async fn admit_with_streaming(
    store: &SqliteTaskStore,
    message_id: &str,
    now: i64,
    streaming: bool,
) -> (SendMessageRequest, AdmissionRecord) {
    let mut message = Message::new(Role::User, vec![Part::text(message_id)]);
    message.message_id = message_id.to_owned();
    let task = Task {
        id: format!("task-{message_id}"),
        context_id: format!("context-{message_id}"),
        status: TaskStatus {
            state: TaskState::Submitted,
            message: None,
            timestamp: chrono::DateTime::from_timestamp_millis(now),
        },
        artifacts: None,
        history: Some(vec![message.clone()]),
        metadata: None,
    };
    let request = SendMessageRequest {
        message,
        configuration: None,
        metadata: None,
        tenant: None,
    };
    let outcome = store
        .admit_send_message(SendMessageAdmission {
            request: request.clone(),
            streaming,
            task: task.clone(),
            original_result: SendMessageResponse::Task(task),
            input_limits: InputLimits::default(),
            now,
            max_attempts: 8,
        })
        .await
        .expect("admit durable request");
    let AdmissionOutcome::Admitted(record) = outcome else {
        panic!("fresh request must be admitted");
    };
    (request, record)
}

#[tokio::test]
async fn unary_admission_has_an_atomic_subscription_revision_cursor() {
    let path = database_path("unary-subscription-cursor");
    let store = open_store(&path, 8).await.expect("open store");
    let (_, admission) = admit(&store, "unary-subscription-cursor", 100).await;
    let (snapshot, cursor) = store
        .subscription_snapshot(&admission.task_id)
        .await
        .expect("subscription snapshot")
        .expect("task exists");
    assert_eq!(snapshot.status.state, TaskState::Submitted);
    assert!(matches!(
        cursor,
        crate::sqlite_store::SubscriptionCursor::TaskRevision(1)
    ));
    shutdown_store(&store).await.expect("close store");
    cleanup(&path);
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Exact rollback and reopen evidence belongs in one fault trace.
async fn sender_commit_rejects_self_consistent_divergent_public_prefix_without_mutation() {
    let path = database_path("divergent-public-prefix");
    let now = 1_700_000_500_000;
    let store = open_store(&path, 32).await.expect("open store");
    let (_, admission) = admit_with_streaming(&store, "divergent-public-prefix", now, true).await;
    let receiver_started = Arc::new(Notify::new());
    let release_receiver = Arc::new(Notify::new());
    let driver = spawn_durable_driver_with_test_hooks(
        store.clone(),
        DurableLoopbackEndpoint::with_completion_barrier(
            Arc::clone(&receiver_started),
            Arc::clone(&release_receiver),
        ),
        InjectedClock::new(now),
        DriverTestHooks::default(),
    );
    let mut driver_state = driver.control().subscribe();
    bounded(
        "public-prefix receiver barrier",
        receiver_started.notified(),
    )
    .await;

    let connection = Connection::open(&path).expect("open prefix fault injector");
    let message_id: String = connection
        .query_row(
            "SELECT message_id FROM stream_transcripts WHERE task_id = ?1",
            [&admission.task_id],
            |row| row.get(0),
        )
        .expect("stream message identity");
    let mut frames: Vec<a2a::StreamResponse> = {
        let mut statement = connection
            .prepare(
                "SELECT frame_json FROM stream_frames WHERE message_id = ?1 ORDER BY frame_seq",
            )
            .expect("prepare public-prefix read");
        statement
            .query_map([&message_id], |row| row.get::<_, String>(0))
            .expect("read public prefix")
            .map(|row| serde_json::from_str(&row.expect("public frame row")).expect("public frame"))
            .collect()
    };
    assert_eq!(frames.len(), 2, "initial and working frames are durable");
    let a2a::StreamResponse::Task(initial) = &mut frames[0] else {
        panic!("first public frame must be a task");
    };
    initial.status.timestamp = chrono::DateTime::from_timestamp_millis(now + 1);
    let divergent_frame = serde_json::to_string(&frames[0]).expect("encode divergent frame");
    let divergent_digest = content_digest(divergent_frame.as_bytes());
    let transcript_digest =
        content_digest(&serde_json::to_vec(&frames).expect("encode divergent public transcript"));
    connection
        .execute(
            "UPDATE stream_frames SET frame_json = ?2, frame_digest = ?3
             WHERE message_id = ?1 AND frame_seq = 1",
            rusqlite::params![message_id, divergent_frame, divergent_digest],
        )
        .expect("install self-consistent divergent frame");
    connection
        .execute(
            "UPDATE stream_transcripts SET transcript_digest = ?2 WHERE message_id = ?1",
            rusqlite::params![message_id, transcript_digest],
        )
        .expect("install self-consistent divergent transcript digest");
    drop(connection);

    release_receiver.notify_one();
    bounded("driver rejects divergent public prefix", async {
        loop {
            if driver_state.borrow().failure.is_some() {
                break;
            }
            driver_state
                .changed()
                .await
                .expect("driver state remains open");
        }
    })
    .await;
    assert!(
        driver_state
            .borrow()
            .failure
            .as_deref()
            .is_some_and(|failure| failure.contains("public stream prefix"))
    );

    let connection = Connection::open(&path).expect("read rollback state");
    let durable: (
        String,
        i64,
        String,
        String,
        Option<i64>,
        String,
        i64,
        Option<i64>,
    ) = connection
        .query_row(
            "SELECT task.state, task.revision, identity.state, outbox.state,
                    attempt.finished_at, stream.state, stream.frame_count, stream.terminal_seq
             FROM tasks task
             JOIN idempotency_records identity ON identity.task_id = task.task_id
             JOIN outbox ON outbox.task_id = task.task_id
             JOIN outbox_attempts attempt ON attempt.outbox_id = outbox.outbox_id
             JOIN stream_transcripts stream ON stream.task_id = task.task_id",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .expect("read exact rollback state");
    assert_eq!(
        durable,
        (
            "\"TASK_STATE_SUBMITTED\"".to_owned(),
            1,
            "in_progress".to_owned(),
            "leased".to_owned(),
            None,
            "open".to_owned(),
            2,
            None,
        )
    );
    drop(connection);
    bounded("failed prefix driver shutdown", driver.shutdown())
        .await
        .expect_err("failed driver reports the prefix divergence");
    bounded("divergent-prefix store shutdown", shutdown_store(&store))
        .await
        .expect("close divergent-prefix store");
    let reopened = bounded(
        "reopen after rejected self-consistent prefix",
        open_store(&path, 32),
    )
    .await
    .expect("self-consistent open prefix remains reopenable");
    shutdown_store(&reopened)
        .await
        .expect("close reopened prefix store");
    cleanup(&path);
}

async fn wait_for_waiters(control: &Arc<DurableDriverControl>, count: usize) {
    let mut state = control.subscribe();
    bounded("attached durable waiter", async {
        loop {
            if state.borrow().waiters >= count {
                return;
            }
            state.changed().await.expect("driver state remains open");
        }
    })
    .await;
}

#[tokio::test]
async fn completion_published_after_empty_read_before_changed_wakes_waiter() {
    let path = database_path("retained-generation");
    let now = 1_700_001_000_000;
    let store = open_store(&path, 32).await.expect("open store");
    let (request, _) = admit(&store, "retained-generation", now).await;
    let before_claim = DriverTestGate::new();
    let after_commit = DriverTestGate::new();
    let driver = spawn_durable_driver_with_test_hooks(
        store.clone(),
        DurableLoopbackEndpoint::new(),
        InjectedClock::new(now),
        DriverTestHooks {
            before_claim: Some(before_claim.clone()),
            after_commit_before_publish: Some(after_commit.clone()),
            idle: None,
        },
    );
    let control = driver.control();
    bounded("driver pre-claim gate", before_claim.reached.notified()).await;

    let empty_read = Arc::new(Notify::new());
    let release_read = Arc::new(Notify::new());
    let handler = Arc::new(
        DurableRequestHandler::new(
            store.clone(),
            Arc::clone(&control),
            InjectedClock::new(now),
            InputLimits::default(),
        )
        .with_after_empty_read_gate(Arc::clone(&empty_read), Arc::clone(&release_read)),
    );
    let message_id = request.message.message_id.clone();
    let waiter = tokio::spawn(async move { handler.wait_for_result(&message_id).await });
    bounded("handler empty final-result read", empty_read.notified()).await;
    before_claim.release.notify_one();
    bounded(
        "sender commit before generation publish",
        after_commit.reached.notified(),
    )
    .await;
    after_commit.release.notify_one();
    release_read.notify_one();

    let result = bounded_join("waiter retained-generation completion", waiter)
        .await
        .expect("waiter result");
    assert!(
        matches!(result, SendMessageResponse::Task(task) if task.status.state == TaskState::Completed)
    );
    bounded("retained-generation driver shutdown", driver.shutdown())
        .await
        .expect("driver shutdown");
    bounded("retained-generation store shutdown", shutdown_store(&store))
        .await
        .expect("store shutdown");
    cleanup(&path);
}

#[tokio::test]
async fn fatal_claim_error_publishes_failure_wakes_waiter_and_shutdown_releases_sqlite() {
    let path = database_path("claim-failure");
    let now = 1_700_002_000_000;
    let store = open_store(&path, 32).await.expect("open store");
    let (request, _) = admit(&store, "claim-failure", now).await;
    store
        .execute_test_batch(
            "CREATE TRIGGER inject_claim_failure BEFORE UPDATE OF state ON outbox
             WHEN NEW.state = 'leased' BEGIN SELECT RAISE(ABORT, 'injected claim failure'); END;",
        )
        .await
        .expect("install claim fault");
    let before_claim = DriverTestGate::new();
    let driver = spawn_durable_driver_with_test_hooks(
        store.clone(),
        DurableLoopbackEndpoint::new(),
        InjectedClock::new(now),
        DriverTestHooks {
            before_claim: Some(before_claim.clone()),
            ..DriverTestHooks::default()
        },
    );
    let control = driver.control();
    bounded(
        "fatal claim pre-claim gate",
        before_claim.reached.notified(),
    )
    .await;
    let handler = Arc::new(DurableRequestHandler::new(
        store.clone(),
        Arc::clone(&control),
        InjectedClock::new(now),
        InputLimits::default(),
    ));
    let message_id = request.message.message_id.clone();
    let waiter = tokio::spawn(async move { handler.wait_for_result(&message_id).await });
    wait_for_waiters(&control, 1).await;
    before_claim.release.notify_one();

    let waiter_error = bounded_join("claim failure waiter wake", waiter)
        .await
        .expect_err("claim failure must reach waiter");
    assert!(
        waiter_error
            .to_string()
            .contains("outbox claim update failed")
    );
    assert!(
        control
            .subscribe()
            .borrow()
            .failure
            .as_deref()
            .is_some_and(|value| value.contains("outbox claim update failed"))
    );
    let shutdown_error = bounded("already-failed driver shutdown", driver.shutdown())
        .await
        .expect_err("failed driver shutdown must report failure");
    assert!(
        shutdown_error
            .to_string()
            .contains("outbox claim update failed")
    );
    store
        .execute_test_batch("DROP TRIGGER inject_claim_failure;")
        .await
        .expect("remove claim fault");
    bounded("failed-driver store shutdown", shutdown_store(&store))
        .await
        .expect("store shutdown");

    let connection = Connection::open(&path).expect("read released database");
    let state: (String, i64, i64, i64) = connection
        .query_row(
            "SELECT state, attempt_count,
                (SELECT COUNT(*) FROM receiver_inbox),
                (SELECT COUNT(*) FROM loopback_effects) FROM outbox",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("claim failure durable state");
    assert_eq!(state, ("pending".to_owned(), 0, 0, 0));
    drop(connection);
    let reopened = bounded(
        "SQLite reacquisition after failed driver",
        open_store(&path, 32),
    )
    .await
    .expect("reopen released store");
    shutdown_store(&reopened)
        .await
        .expect("close reopened store");
    cleanup(&path);
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Full durable rollback state is asserted in one fault trace.
async fn fatal_sender_commit_error_publishes_failure_and_wakes_attached_waiter() {
    let path = database_path("commit-failure");
    let now = 1_700_003_000_000;
    let store = open_store(&path, 32).await.expect("open store");
    let (request, _) = admit(&store, "commit-failure", now).await;
    store
        .execute_test_batch(
            "CREATE TRIGGER inject_commit_failure BEFORE UPDATE OF state ON tasks
             WHEN NEW.state = '\"TASK_STATE_COMPLETED\"'
             BEGIN SELECT RAISE(ABORT, 'injected sender commit failure'); END;",
        )
        .await
        .expect("install commit fault");
    let receiver_started = Arc::new(Notify::new());
    let release_receiver = Arc::new(Notify::new());
    let driver = spawn_durable_driver_with_test_hooks(
        store.clone(),
        DurableLoopbackEndpoint::with_completion_barrier(
            Arc::clone(&receiver_started),
            Arc::clone(&release_receiver),
        ),
        InjectedClock::new(now),
        DriverTestHooks::default(),
    );
    let control = driver.control();
    bounded(
        "commit failure receiver barrier",
        receiver_started.notified(),
    )
    .await;
    let handler = Arc::new(DurableRequestHandler::new(
        store.clone(),
        Arc::clone(&control),
        InjectedClock::new(now),
        InputLimits::default(),
    ));
    let message_id = request.message.message_id.clone();
    let waiter = tokio::spawn(async move { handler.wait_for_result(&message_id).await });
    wait_for_waiters(&control, 1).await;
    release_receiver.notify_one();

    let waiter_error = bounded_join("sender commit failure waiter wake", waiter)
        .await
        .expect_err("commit failure must reach waiter");
    assert!(
        waiter_error
            .to_string()
            .contains("durable delivery task commit failed")
    );
    assert!(
        control
            .subscribe()
            .borrow()
            .failure
            .as_deref()
            .is_some_and(|value| value.contains("durable delivery task commit failed"))
    );
    let shutdown_error = bounded("commit-failed driver shutdown", driver.shutdown())
        .await
        .expect_err("failed driver shutdown must report commit failure");
    assert!(
        shutdown_error
            .to_string()
            .contains("durable delivery task commit failed")
    );
    store
        .execute_test_batch("DROP TRIGGER inject_commit_failure;")
        .await
        .expect("remove commit fault");
    bounded("commit-failure store shutdown", shutdown_store(&store))
        .await
        .expect("store shutdown");

    let connection = Connection::open(&path).expect("read commit failure state");
    let state: (String, i64, String, String, i64, i64) = connection
        .query_row(
            "SELECT o.state, o.attempt_count, t.state, r.state,
                (SELECT COUNT(*) FROM loopback_effects),
                (SELECT COUNT(*) FROM receiver_frames)
             FROM outbox o JOIN tasks t ON t.task_id = o.task_id
             JOIN receiver_inbox r ON r.dispatch_id = o.dispatch_id",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .expect("commit failure durable state");
    assert_eq!(
        state,
        (
            "leased".to_owned(),
            1,
            "\"TASK_STATE_SUBMITTED\"".to_owned(),
            "completed".to_owned(),
            1,
            3
        )
    );
    drop(connection);
    cleanup(&path);
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One end-to-end clock/lease/dispatch trace.
async fn busy_retry_idles_until_injected_clock_reclaims_receiver_with_stable_dispatch_id() {
    let path = database_path("clock-retry");
    let now = 1_700_004_000_000;
    let clock = InjectedClock::new(now);
    let store = open_store(&path, 32).await.expect("open store");
    let (request, admission) = admit(&store, "clock-retry", now).await;
    let seed_lease = store
        .claim_outbox("seed-sender", now, 60_000)
        .await
        .expect("seed claim")
        .expect("seed lease");
    assert_eq!(seed_lease.dispatch_id, admission.dispatch_id);
    let payload = serde_json::to_string(&seed_lease.request).expect("encode envelope");
    let envelope = DurableDispatchEnvelope {
        tenant_scope: TRUSTED_SINGLE_TENANT_SCOPE.to_owned(),
        dispatch_id: seed_lease.dispatch_id.clone(),
        payload_digest: content_digest(payload.as_bytes()),
        request: seed_lease.request.clone(),
    };
    let ReceiverAdmission::Execute(receiver_lease) = store
        .begin_receive(envelope, "blocked-receiver", now, 1_000)
        .await
        .expect("seed receiver")
    else {
        panic!("seed receiver must execute");
    };
    assert_eq!(receiver_lease.lease_epoch, 1);
    assert_eq!(
        store
            .finish_outbox_attempt(
                &seed_lease,
                AttemptDisposition::Retry {
                    available_at: now,
                    error: "seed sender released for busy proof".to_owned(),
                },
                now,
            )
            .await
            .expect("seed retry"),
        TransitionOutcome::Applied
    );

    let idle = Arc::new(Notify::new());
    let driver = spawn_durable_driver_with_test_hooks(
        store.clone(),
        DurableLoopbackEndpoint::new(),
        clock.clone(),
        DriverTestHooks {
            idle: Some(Arc::clone(&idle)),
            ..DriverTestHooks::default()
        },
    );
    let control = driver.control();
    let handler = Arc::new(DurableRequestHandler::new(
        store.clone(),
        Arc::clone(&control),
        clock.clone(),
        InputLimits::default(),
    ));
    let message_id = request.message.message_id.clone();
    let waiter = tokio::spawn(async move { handler.wait_for_result(&message_id).await });
    wait_for_waiters(&control, 1).await;
    bounded("driver idle after receiver Busy", idle.notified()).await;
    assert!(
        store
            .final_result_for_message(&request.message.message_id)
            .await
            .expect("read pending result")
            .is_none()
    );
    assert_eq!(
        store
            .durable_effect_count()
            .await
            .expect("effect count before retry"),
        0
    );

    clock.advance_to(now + 1_000);
    let result = bounded_join("clock-woken retry completion", waiter)
        .await
        .expect("retry result");
    assert!(
        matches!(result, SendMessageResponse::Task(task) if task.status.state == TaskState::Completed)
    );
    bounded("clock retry driver shutdown", driver.shutdown())
        .await
        .expect("driver shutdown");
    bounded("clock retry store shutdown", shutdown_store(&store))
        .await
        .expect("store shutdown");

    let connection = Connection::open(&path).expect("read retry durable state");
    let state: (String, String, i64, String, i64, i64, i64) = connection
        .query_row(
            "SELECT o.dispatch_id, o.state, o.attempt_count, r.state, r.lease_epoch,
                (SELECT COUNT(*) FROM loopback_effects),
                (SELECT COUNT(*) FROM outbox_attempts WHERE outcome = 'retry')
             FROM outbox o JOIN receiver_inbox r ON r.dispatch_id = o.dispatch_id",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .expect("retry durable state");
    assert_eq!(
        state,
        (
            admission.dispatch_id,
            "delivered".to_owned(),
            3,
            "completed".to_owned(),
            2,
            1,
            2
        )
    );
    drop(connection);
    cleanup(&path);
}

#[tokio::test]
async fn pending_unclaimed_cancel_is_atomic_effect_free_and_reopens_exactly() {
    let path = database_path("pending-cancel");
    let now = 1_700_006_000_000;
    let store = open_store(&path, 32).await.expect("open store");
    let (request, admission) = admit_with_streaming(&store, "pending-cancel", now, true).await;
    let outcome = store
        .request_cancellation(&admission.task_id, now + 1)
        .await
        .expect("cancel pending intent");
    let crate::CancellationOutcome::Canceled(canceled) = outcome else {
        panic!("unclaimed intent must cancel in one transaction");
    };
    assert_eq!(canceled.status.state, TaskState::Canceled);
    assert_eq!(store.durable_effect_count().await.unwrap(), 0);
    let replay = store
        .final_result_for_message(&request.message.message_id)
        .await
        .unwrap()
        .expect("canonical cancellation replay");
    assert_eq!(replay, SendMessageResponse::Task(canceled.clone()));
    let transcript = store
        .stream_frames_after(&request.message.message_id, 0)
        .await
        .unwrap();
    assert!(transcript.closed);
    assert_eq!(transcript.frames.len(), 2);
    assert!(
        matches!(transcript.frames.last(), Some(a2a::StreamResponse::StatusUpdate(update))
        if update.status.state == TaskState::Canceled)
    );
    shutdown_store(&store).await.unwrap();

    let reopened = open_store(&path, 32).await.expect("reopen canceled store");
    assert_eq!(
        reopened
            .final_result_for_message(&request.message.message_id)
            .await
            .unwrap(),
        Some(replay)
    );
    assert_eq!(reopened.durable_effect_count().await.unwrap(), 0);
    shutdown_store(&reopened).await.unwrap();
    cleanup(&path);
}

#[tokio::test]
async fn recovered_processing_cancel_finishes_from_sqlite_without_live_control() {
    let path = database_path("recovered-cancel");
    let now = chrono::Utc::now().timestamp_millis();
    let store = open_store(&path, 32).await.expect("open store");
    let (request, admission) = admit(&store, "recovered-cancel", now).await;
    let sender = store
        .claim_outbox("crashed-sender", now, 60_000)
        .await
        .unwrap()
        .unwrap();
    let payload = serde_json::to_string(&sender.request).unwrap();
    let envelope = DurableDispatchEnvelope {
        tenant_scope: TRUSTED_SINGLE_TENANT_SCOPE.to_owned(),
        dispatch_id: sender.dispatch_id.clone(),
        payload_digest: content_digest(payload.as_bytes()),
        request: sender.request.clone(),
    };
    let ReceiverAdmission::Execute(_abandoned_receiver) = store
        .begin_receive(envelope, "crashed-receiver", now, 60_000)
        .await
        .unwrap()
    else {
        panic!("receiver must be processing before crash");
    };
    assert!(matches!(
        store
            .request_cancellation(&admission.task_id, now + 1)
            .await
            .unwrap(),
        crate::CancellationOutcome::AwaitReceiver { .. }
    ));
    shutdown_store(&store).await.unwrap();

    let reopened = open_store(&path, 32)
        .await
        .expect("recover processing cancellation");
    let clock = InjectedClock::new(chrono::Utc::now().timestamp_millis() + 10_000);
    let driver = spawn_durable_driver_with_test_hooks(
        reopened.clone(),
        DurableLoopbackEndpoint::new(),
        clock.clone(),
        DriverTestHooks::default(),
    );
    let handler = DurableRequestHandler::new(
        reopened.clone(),
        driver.control(),
        clock,
        InputLimits::default(),
    );
    let result = bounded(
        "recovered cancellation result",
        handler.wait_for_result(&request.message.message_id),
    )
    .await
    .unwrap();
    assert!(matches!(result, SendMessageResponse::Task(task)
        if task.status.state == TaskState::Canceled));
    assert_eq!(reopened.durable_effect_count().await.unwrap(), 0);
    bounded("recovered cancellation driver shutdown", driver.shutdown())
        .await
        .unwrap();
    shutdown_store(&reopened).await.unwrap();
    cleanup(&path);
}

#[tokio::test]
async fn receiver_cancel_fence_rejects_stale_worker_completion_without_effect() {
    let path = database_path("stale-cancel-worker");
    let now = 1_700_006_500_000;
    let store = open_store(&path, 32).await.unwrap();
    let (_, admission) = admit(&store, "stale-cancel-worker", now).await;
    let sender = store
        .claim_outbox("sender", now, 60_000)
        .await
        .unwrap()
        .unwrap();
    let payload = serde_json::to_string(&sender.request).unwrap();
    let ReceiverAdmission::Execute(receiver) = store
        .begin_receive(
            DurableDispatchEnvelope {
                tenant_scope: TRUSTED_SINGLE_TENANT_SCOPE.to_owned(),
                dispatch_id: sender.dispatch_id.clone(),
                payload_digest: content_digest(payload.as_bytes()),
                request: sender.request,
            },
            "receiver",
            now,
            60_000,
        )
        .await
        .unwrap()
    else {
        panic!("receiver lease");
    };
    assert!(matches!(
        store
            .request_cancellation(&admission.task_id, now + 1)
            .await
            .unwrap(),
        crate::CancellationOutcome::AwaitReceiver { .. }
    ));
    let canceled_events = vec![
        crate::MeshEvent::Progress("SMESH swarm is processing the durable dispatch".to_owned()),
        crate::MeshEvent::Completed {
            summary: crate::durable_dispatch::DURABLE_CANCELED_SUMMARY.to_owned(),
        },
    ];
    store
        .complete_canceled_receive(&receiver, &canceled_events, now + 2)
        .await
        .unwrap();
    let stale = store
        .complete_loopback_receive(
            &receiver,
            &[crate::MeshEvent::Completed {
                summary: "late completion".to_owned(),
            }],
            now + 3,
        )
        .await
        .unwrap_err();
    assert!(
        stale
            .to_string()
            .contains("stale receiver completion lease")
    );
    assert_eq!(store.durable_effect_count().await.unwrap(), 0);
    shutdown_store(&store).await.unwrap();
    cleanup(&path);
}

#[tokio::test]
async fn input_and_auth_required_tasks_cancel_without_live_receiver_control() {
    let path = database_path("waiting-state-cancel");
    let now = 1_700_006_750_000;
    let store = open_store(&path, 32).await.unwrap();
    for (index, state) in [TaskState::InputRequired, TaskState::AuthRequired]
        .into_iter()
        .enumerate()
    {
        let message_id = format!("waiting-cancel-{index}");
        let (_, admission) = admit(&store, &message_id, now + i64::try_from(index).unwrap()).await;
        let mut waiting = store.get(&admission.task_id).await.unwrap().unwrap();
        waiting.status.state = state;
        assert_eq!(
            store
                .commit_transition(
                    &admission.task_id,
                    admission.revision,
                    waiting,
                    "waiting_for_input",
                    None,
                    now + 10
                )
                .await
                .unwrap(),
            TransitionOutcome::Applied
        );
        let crate::CancellationOutcome::Canceled(canceled) = store
            .request_cancellation(&admission.task_id, now + 20)
            .await
            .unwrap()
        else {
            panic!("waiting task cancellation must not require memory");
        };
        assert_eq!(canceled.status.state, TaskState::Canceled);
    }
    assert_eq!(store.durable_effect_count().await.unwrap(), 0);
    shutdown_store(&store).await.unwrap();
    cleanup(&path);
}

#[tokio::test]
async fn idle_gateway_shutdown_is_bounded_and_releases_sqlite() {
    let path = database_path("idle-shutdown");
    let store = open_store(&path, 32).await.expect("open store");
    let gateway = build_durable_loopback_gateway(
        GatewayConfig::new("http://127.0.0.1:1", "durable-loopback"),
        store,
        DurableLoopbackEndpoint::new(),
        InjectedClock::new(1_700_005_000_000),
    )
    .expect("build gateway");
    bounded("idle gateway shutdown", gateway.shutdown())
        .await
        .expect("idle shutdown");
    let reopened = bounded("idle shutdown SQLite reacquisition", open_store(&path, 32))
        .await
        .expect("reopen released SQLite");
    assert_eq!(
        reopened
            .durable_effect_count()
            .await
            .expect("empty effects"),
        0
    );
    shutdown_store(&reopened)
        .await
        .expect("close reopened store");
    cleanup(&path);
}
