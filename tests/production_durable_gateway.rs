#![cfg(unix)]

use std::future::Future;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use a2a::{
    Message, Part, Role, SendMessageRequest, SendMessageResponse, StreamResponse,
    TRANSPORT_PROTOCOL_JSONRPC, Task, TaskState, TaskStatus,
};
use a2a_client::agent_card::AgentCardResolver;
use a2a_client::{A2AClient, A2AClientFactory, Transport};
use futures::StreamExt;
use smesh_a2a::{
    AttemptDisposition, DurableDispatchEnvelope, DurableLoopbackEndpoint, GatewayConfig,
    InjectedClock, InputLimits, ReceiverAdmission, SendMessageAdmission, SqliteTaskStore,
    SystemClockTicker, TRUSTED_SINGLE_TENANT_SCOPE, build_durable_loopback_gateway, content_digest,
};
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};

const WATCHDOG: Duration = Duration::from_secs(10);

async fn bounded<F: Future>(label: &str, future: F) -> F::Output {
    tokio::time::timeout(WATCHDOG, future)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {label}"))
}

async fn bounded_join<T>(label: &str, mut handle: tokio::task::JoinHandle<T>) -> T {
    if let Ok(result) = tokio::time::timeout(WATCHDOG, &mut handle).await {
        result.unwrap_or_else(|error| panic!("{label} failed: {error}"))
    } else {
        handle.abort();
        let _ = tokio::time::timeout(WATCHDOG, &mut handle)
            .await
            .unwrap_or_else(|_| panic!("timed out aborting {label}"));
        panic!("timed out waiting for {label}");
    }
}

async fn kill_and_reap_child(label: &str, child: &mut Child) {
    if child.try_wait().unwrap().is_none() {
        child
            .start_kill()
            .unwrap_or_else(|error| panic!("failed to kill {label}: {error}"));
    }
    tokio::time::timeout(WATCHDOG, child.wait())
        .await
        .unwrap_or_else(|_| panic!("timed out reaping killed {label}"))
        .unwrap_or_else(|error| panic!("failed to reap killed {label}: {error}"));
}

async fn bounded_child_wait(label: &str, child: &mut Child) -> std::process::ExitStatus {
    if let Ok(result) = tokio::time::timeout(WATCHDOG, child.wait()).await {
        result.unwrap_or_else(|error| panic!("failed waiting for {label}: {error}"))
    } else {
        kill_and_reap_child(label, child).await;
        panic!("timed out waiting for {label}");
    }
}

async fn bounded_child_status(label: &str, command: &mut Command) -> std::process::ExitStatus {
    command.kill_on_drop(true);
    let mut child = command
        .spawn()
        .unwrap_or_else(|error| panic!("failed spawning {label}: {error}"));
    bounded_child_wait(label, &mut child).await
}

async fn bounded_child_output(label: &str, command: &mut Command) -> Output {
    command.kill_on_drop(true);
    let mut child = command
        .spawn()
        .unwrap_or_else(|error| panic!("failed spawning {label}: {error}"));
    let mut stdout = child.stdout.take().expect("piped child stdout");
    let mut stderr = child.stderr.take().expect("piped child stderr");
    let stdout_reader = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).await.unwrap();
        bytes
    });
    let stderr_reader = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).await.unwrap();
        bytes
    });
    let status = bounded_child_wait(label, &mut child).await;
    let stdout = bounded_join("child stdout reader", stdout_reader).await;
    let stderr = bounded_join("child stderr reader", stderr_reader).await;
    Output {
        status,
        stdout,
        stderr,
    }
}

fn test_directory(label: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "smesh-a2a-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn cleanup_database(path: &Path) {
    for suffix in ["", "-wal", "-shm", ".lock"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    let _ = std::fs::remove_dir(path.parent().unwrap());
}

fn gateway_address() -> std::net::SocketAddr {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = probe.local_addr().unwrap();
    drop(probe);
    address
}

fn spawn_durable_gateway(address: std::net::SocketAddr, database: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_smesh-a2a-gateway"))
        .env_clear()
        .env("SMESH_A2A_MODE", "loopback")
        .env("SMESH_A2A_BIND", address.to_string())
        .env("SMESH_A2A_PUBLIC_URL", format!("http://{address}"))
        .env("SMESH_A2A_SQLITE_PATH", database)
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

async fn wait_for_official_client(
    child: &mut Child,
    base_url: &str,
) -> A2AClient<Box<dyn Transport>> {
    let deadline = tokio::time::Instant::now() + WATCHDOG;
    let mut retry = tokio::time::interval(Duration::from_millis(25));
    retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        if tokio::time::timeout_at(deadline, retry.tick())
            .await
            .is_err()
        {
            kill_and_reap_child("gateway awaiting official client readiness", child).await;
            panic!("timed out waiting for official client readiness");
        }
        let resolution =
            tokio::time::timeout_at(deadline, AgentCardResolver::new(None).resolve(base_url)).await;
        match resolution {
            Ok(Ok(card)) => {
                if let Ok(client) = tokio::time::timeout_at(
                    deadline,
                    A2AClientFactory::builder()
                        .preferred_bindings(vec![TRANSPORT_PROTOCOL_JSONRPC.to_owned()])
                        .build()
                        .create_from_card(&card),
                )
                .await
                {
                    return client.unwrap();
                }
                kill_and_reap_child("gateway during official client creation", child).await;
                panic!("timed out creating official client after gateway readiness");
            }
            Ok(Err(_)) => {}
            Err(_) => {
                kill_and_reap_child("gateway awaiting agent-card resolution", child).await;
                panic!("timed out waiting for agent-card resolution");
            }
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("durable gateway exited before agent-card readiness: {status}");
        }
    }
}

async fn stop_with_sigint(mut child: Child) {
    let process_id = child.id().expect("running gateway process");
    let signal = bounded_child_status(
        "SIGINT delivery",
        Command::new("/usr/bin/kill")
            .arg("-INT")
            .arg(process_id.to_string()),
    )
    .await;
    assert!(signal.success());
    let status = bounded_child_wait("gateway process join", &mut child).await;
    assert!(status.success(), "gateway did not stop cleanly: {status}");
}

fn send_request(message_id: &str, text: &str) -> SendMessageRequest {
    let mut message = Message::new(Role::User, vec![Part::text(text)]);
    message_id.clone_into(&mut message.message_id);
    SendMessageRequest {
        message,
        configuration: None,
        metadata: None,
        tenant: None,
    }
}

async fn collect_stream(
    client: &A2AClient<Box<dyn Transport>>,
    request: &SendMessageRequest,
) -> Vec<StreamResponse> {
    bounded("stream open and completion", async {
        client
            .send_streaming_message(request)
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    })
    .await
}

#[tokio::test]
async fn production_loopback_sqlite_replays_unary_and_stream_after_sigint_restart() {
    let directory = test_directory("production-durable-loopback");
    let database = directory.join("tasks.sqlite3");
    let address = gateway_address();
    let base_url = format!("http://{address}");
    let unary_request = send_request("production-durable-unary", "durable unary");
    let stream_request = send_request("production-durable-stream", "durable stream");

    let mut first_process = spawn_durable_gateway(address, &database);
    let first_client = wait_for_official_client(&mut first_process, &base_url).await;
    let first_unary = bounded(
        "initial unary completion",
        first_client.send_message(&unary_request),
    )
    .await
    .unwrap();
    assert!(matches!(
        &first_unary,
        SendMessageResponse::Task(task) if task.status.state == TaskState::Completed
    ));
    let first_stream = collect_stream(&first_client, &stream_request).await;
    assert!(first_stream.iter().any(|frame| match frame {
        StreamResponse::Task(task) => task.status.state == TaskState::Completed,
        StreamResponse::StatusUpdate(update) => update.status.state == TaskState::Completed,
        StreamResponse::ArtifactUpdate(_) | StreamResponse::Message(_) => false,
    }));
    stop_with_sigint(first_process).await;

    let first_reopen = bounded("first store reopen", SqliteTaskStore::open(&database, 1024))
        .await
        .unwrap();
    assert_eq!(
        bounded(
            "first reopened store effect count",
            first_reopen.durable_effect_count()
        )
        .await
        .unwrap(),
        2
    );
    bounded(
        "first reopened store shutdown",
        first_reopen.shutdown_shared(),
    )
    .await
    .unwrap();

    let mut restarted_process = spawn_durable_gateway(address, &database);
    let restarted_client = wait_for_official_client(&mut restarted_process, &base_url).await;
    let replayed_unary = bounded(
        "restarted unary replay",
        restarted_client.send_message(&unary_request),
    )
    .await
    .unwrap();
    let replayed_stream = collect_stream(&restarted_client, &stream_request).await;
    assert_eq!(replayed_unary, first_unary);
    assert_eq!(replayed_stream, first_stream);
    stop_with_sigint(restarted_process).await;

    let independently_reacquired = bounded(
        "independent store reacquisition",
        SqliteTaskStore::open(&database, 1024),
    )
    .await
    .unwrap();
    assert_eq!(
        bounded(
            "independently reacquired store effect count",
            independently_reacquired.durable_effect_count()
        )
        .await
        .unwrap(),
        2
    );
    bounded(
        "independently reacquired store shutdown",
        independently_reacquired.shutdown_shared(),
    )
    .await
    .unwrap();
    cleanup_database(&database);
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One production retry tracer owns its durable Busy fixture and cleanup.
async fn production_system_clock_wakes_busy_receiver_backoff_without_manual_advance() {
    let directory = test_directory("production-system-clock-retry");
    let database = directory.join("tasks.sqlite3");
    let address = gateway_address();
    let base_url = format!("http://{address}");
    let request = send_request("production-busy-retry", "retry after busy receiver");
    let identity = content_digest(request.message.message_id.as_bytes());
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let task = Task {
        id: format!("task-{}", &identity[..32]),
        context_id: format!("context-{}", &identity[32..]),
        status: TaskStatus {
            state: TaskState::Submitted,
            message: None,
            timestamp: chrono::DateTime::from_timestamp_millis(now),
        },
        artifacts: None,
        history: Some(vec![request.message.clone()]),
        metadata: None,
    };
    let store = bounded(
        "busy fixture store open",
        SqliteTaskStore::open(&database, 1024),
    )
    .await
    .unwrap();
    bounded(
        "busy fixture message admission",
        store.admit_send_message(SendMessageAdmission {
            request: request.clone(),
            streaming: false,
            task: task.clone(),
            original_result: SendMessageResponse::Task(task),
            input_limits: InputLimits::default(),
            now,
            max_attempts: 8,
        }),
    )
    .await
    .unwrap();
    let sender_lease = bounded(
        "busy fixture outbox claim",
        store.claim_outbox("busy-retry-fixture", now, 60_000),
    )
    .await
    .unwrap()
    .unwrap();
    let payload = serde_json::to_string(&sender_lease.request).unwrap();
    let envelope = DurableDispatchEnvelope {
        tenant_scope: TRUSTED_SINGLE_TENANT_SCOPE.to_owned(),
        dispatch_id: sender_lease.dispatch_id.clone(),
        payload_digest: content_digest(payload.as_bytes()),
        request: sender_lease.request.clone(),
    };
    assert!(matches!(
        bounded(
            "busy fixture receiver admission",
            store.begin_receive(envelope, "busy-retry-fixture", now, 2_500),
        )
        .await
        .unwrap(),
        ReceiverAdmission::Execute(_)
    ));
    bounded(
        "busy fixture outbox retry",
        store.finish_outbox_attempt(
            &sender_lease,
            AttemptDisposition::Retry {
                available_at: now,
                error: "fixture releases sender while receiver stays busy".to_owned(),
            },
            now,
        ),
    )
    .await
    .unwrap();
    let clock = InjectedClock::new(now);
    let gateway = build_durable_loopback_gateway(
        GatewayConfig::new(&base_url, "production-clock-test"),
        store,
        DurableLoopbackEndpoint::new(),
        clock.clone(),
    )
    .unwrap();
    let ticker = SystemClockTicker::spawn(clock);
    let listener = bounded(
        "clock-test listener bind",
        tokio::net::TcpListener::bind(address),
    )
    .await
    .unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let app = gateway.router();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    let client = bounded("clock-test official client creation", async {
        let card = AgentCardResolver::new(None)
            .resolve(&base_url)
            .await
            .unwrap();
        A2AClientFactory::builder()
            .preferred_bindings(vec![TRANSPORT_PROTOCOL_JSONRPC.to_owned()])
            .build()
            .create_from_card(&card)
            .await
            .unwrap()
    })
    .await;
    let response = bounded(
        "real-time busy/backoff retry",
        client.send_message(&request),
    )
    .await
    .unwrap();
    assert!(matches!(
        response,
        SendMessageResponse::Task(task) if task.status.state == TaskState::Completed
    ));
    shutdown_tx.send(()).unwrap();
    bounded_join("clock-test server join", server).await;
    bounded("system clock ticker shutdown", ticker.shutdown())
        .await
        .unwrap();
    bounded("clock-test gateway shutdown", gateway.shutdown())
        .await
        .unwrap();

    let reopened = bounded(
        "clock-test store reopen",
        SqliteTaskStore::open(&database, 1024),
    )
    .await
    .unwrap();
    assert_eq!(
        bounded(
            "reopened store effect count",
            reopened.durable_effect_count()
        )
        .await
        .unwrap(),
        1
    );
    bounded(
        "clock-test reopened store shutdown",
        reopened.shutdown_shared(),
    )
    .await
    .unwrap();
    cleanup_database(&database);
}

#[tokio::test]
async fn dropped_gateway_aborts_worker_and_releases_sqlite_with_router_clone_alive() {
    let directory = test_directory("drop-release");
    let database = directory.join("tasks.sqlite3");
    let now = 1_700_003_000_000;
    let request = send_request("drop-release-message", "drop must abort blocked work");
    let identity = content_digest(request.message.message_id.as_bytes());
    let task = Task {
        id: format!("task-{}", &identity[..32]),
        context_id: format!("context-{}", &identity[32..]),
        status: TaskStatus {
            state: TaskState::Submitted,
            message: None,
            timestamp: chrono::DateTime::from_timestamp_millis(now),
        },
        artifacts: None,
        history: Some(vec![request.message.clone()]),
        metadata: None,
    };
    let store = bounded(
        "drop-release store open",
        SqliteTaskStore::open(&database, 16),
    )
    .await
    .unwrap();
    bounded(
        "drop-release message admission",
        store.admit_send_message(SendMessageAdmission {
            request,
            streaming: false,
            task: task.clone(),
            original_result: SendMessageResponse::Task(task),
            input_limits: InputLimits::default(),
            now,
            max_attempts: 1,
        }),
    )
    .await
    .unwrap();
    let started = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let gateway = build_durable_loopback_gateway(
        GatewayConfig::new("http://127.0.0.1:1", "drop-release"),
        store,
        DurableLoopbackEndpoint::with_completion_barrier(
            std::sync::Arc::clone(&started),
            std::sync::Arc::clone(&release),
        ),
        InjectedClock::new(now),
    )
    .unwrap();
    let router_clone = gateway.router();
    bounded("blocked receiver start", started.notified()).await;
    bounded_join(
        "gateway drop worker",
        tokio::task::spawn_blocking(move || drop(gateway)),
    )
    .await;
    release.notify_waiters();

    let reopened = bounded(
        "drop-path SQLite reacquisition",
        SqliteTaskStore::open(&database, 16),
    )
    .await
    .expect("drop must release ownership despite router clone");
    assert_eq!(
        bounded(
            "reopened store effect count",
            reopened.durable_effect_count()
        )
        .await
        .unwrap(),
        0
    );
    bounded(
        "drop-release reopened store shutdown",
        reopened.shutdown_shared(),
    )
    .await
    .unwrap();
    drop(router_clone);
    cleanup_database(&database);
}

#[tokio::test]
async fn runtime_with_sqlite_fails_before_acquiring_any_resource() {
    let directory = test_directory("runtime-sqlite-rejection");
    let database = directory.join("must-not-exist.sqlite3");
    let trace = directory.join("must-not-exist.trace.json");
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mesh_addr = probe.local_addr().unwrap();
    drop(probe);

    let output = bounded_child_output(
        "runtime plus SQLite rejection process",
        Command::new(env!("CARGO_BIN_EXE_smesh-a2a-gateway"))
            .env_clear()
            .env("SMESH_A2A_MODE", "runtime")
            .env("SMESH_A2A_MESH_BIND", mesh_addr.to_string())
            .env("SMESH_A2A_SQLITE_PATH", &database)
            .env("SMESH_RUNTIME_TRACE_PATH", &trace)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    )
    .await;

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("durable runtime receiver/effect replay is unsupported"),
        "unexpected stderr: {stderr}"
    );
    assert!(!database.exists(), "rejection must not create SQLite");
    assert!(!trace.exists(), "rejection must not start the trace drain");
    let rebound = std::net::TcpListener::bind(mesh_addr)
        .expect("rejection must leave the candidate mesh port free");
    drop(rebound);

    cleanup_database(&database);
    let _ = std::fs::remove_dir(directory);
}
