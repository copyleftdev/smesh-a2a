#![cfg(unix)]

use std::future::Future;
use std::io::{BufRead, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use a2a::{
    CancelTaskRequest, GetTaskRequest, Message, Part, Role, SendMessageConfiguration,
    SendMessageRequest, SendMessageResponse, StreamResponse, SubscribeToTaskRequest,
    TRANSPORT_PROTOCOL_HTTP_JSON, TRANSPORT_PROTOCOL_JSONRPC, Task, TaskState, TaskStatus,
    error_code,
};
use a2a_client::agent_card::AgentCardResolver;
use a2a_client::{A2AClient, A2AClientFactory, Transport};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use futures::StreamExt;
use http_body_util::BodyExt;
use smesh_a2a::{
    DurableDispatchEnvelope, DurableInterruptionKind, DurableLoopbackEndpoint, GatewayConfig,
    InjectedClock, InputLimits, MeshEvent, ReceiverAdmission, SendMessageAdmission,
    SqliteTaskStore, TRUSTED_SINGLE_TENANT_SCOPE, build_durable_loopback_gateway, content_digest,
};
use tokio::sync::Notify;
use tower::ServiceExt;

const WATCHDOG: Duration = Duration::from_secs(5);

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

async fn bounded_join_pair<T, U>(
    label: &str,
    mut left: tokio::task::JoinHandle<T>,
    mut right: tokio::task::JoinHandle<U>,
) -> (T, U) {
    if let Ok((left_result, right_result)) =
        tokio::time::timeout(WATCHDOG, async { tokio::join!(&mut left, &mut right) }).await
    {
        (
            left_result.unwrap_or_else(|error| panic!("{label} left task failed: {error}")),
            right_result.unwrap_or_else(|error| panic!("{label} right task failed: {error}")),
        )
    } else {
        left.abort();
        right.abort();
        let _ = tokio::time::timeout(WATCHDOG, async { tokio::join!(&mut left, &mut right) })
            .await
            .unwrap_or_else(|_| panic!("timed out aborting {label}"));
        panic!("timed out waiting for {label}");
    }
}

fn wait_for_child_until(child: &mut Child, deadline: Instant) -> Option<ExitStatus> {
    let mutex = std::sync::Mutex::new(());
    let wake = std::sync::Condvar::new();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        let remaining = deadline.checked_duration_since(Instant::now())?;
        let guard = mutex.lock().unwrap();
        let _ = wake
            .wait_timeout(guard, remaining.min(Duration::from_millis(10)))
            .unwrap();
    }
}

fn kill_and_reap_child(label: &str, child: &mut Child) -> ExitStatus {
    if child.try_wait().unwrap().is_none() {
        child
            .kill()
            .unwrap_or_else(|error| panic!("failed to kill {label}: {error}"));
    }
    wait_for_child_until(child, Instant::now() + WATCHDOG)
        .unwrap_or_else(|| panic!("timed out reaping killed {label}"))
}

fn bounded_child_wait(label: &str, child: &mut Child) -> ExitStatus {
    if let Some(status) = wait_for_child_until(child, Instant::now() + WATCHDOG) {
        return status;
    }
    let _ = kill_and_reap_child(label, child);
    panic!("timed out waiting for {label}");
}

fn database_path() -> PathBuf {
    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
    let directory = std::env::temp_dir().join(format!(
        "smesh-a2a-durable-vertical-{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    directory.join("tasks.sqlite3")
}

fn cleanup(path: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    let _ = std::fs::remove_file(format!("{}.lock", path.display()));
    let _ = std::fs::remove_dir(path.parent().unwrap());
}

async fn client(base_url: &str) -> A2AClient<Box<dyn Transport>> {
    binding_client(base_url, TRANSPORT_PROTOCOL_JSONRPC).await
}

async fn rest_client(base_url: &str) -> A2AClient<Box<dyn Transport>> {
    binding_client(base_url, TRANSPORT_PROTOCOL_HTTP_JSON).await
}

async fn binding_client(base_url: &str, protocol: &str) -> A2AClient<Box<dyn Transport>> {
    bounded("official client creation", async {
        let mut card = AgentCardResolver::new(None)
            .resolve(base_url)
            .await
            .unwrap();
        card.supported_interfaces
            .retain(|interface| interface.protocol_binding == protocol);
        assert_eq!(
            card.supported_interfaces.len(),
            1,
            "binding-specific client card must fail closed"
        );
        A2AClientFactory::builder()
            .preferred_bindings(vec![protocol.to_owned()])
            .build()
            .create_from_card(&card)
            .await
            .unwrap()
    })
    .await
}

async fn raw_rest(
    gateway: &smesh_a2a::DurableGateway,
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, axum::http::HeaderMap, serde_json::Value) {
    bounded("raw REST request", async {
        let mut builder = Request::builder().method(method).uri(path);
        let request_body = if let Some(body) = body {
            builder = builder.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&body).unwrap())
        } else {
            Body::empty()
        };
        let response = gateway
            .router()
            .oneshot(builder.body(request_body).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body = serde_json::from_slice(&bytes).unwrap_or_else(|error| {
            panic!(
                "raw REST response was not JSON: {error}; body={}",
                String::from_utf8_lossy(&bytes)
            )
        });
        (status, headers, body)
    })
    .await
}

async fn collect_stream(
    client: &A2AClient<Box<dyn Transport>>,
    request: &SendMessageRequest,
) -> Vec<StreamResponse> {
    bounded("open durable stream", async {
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

async fn collect_rest_stream(base_url: &str, request: &SendMessageRequest) -> Vec<StreamResponse> {
    collect_stream(&rest_client(base_url).await, request).await
}

fn continuation_request(
    message_id: &str,
    text: &str,
    task: Option<(&str, &str)>,
) -> SendMessageRequest {
    let mut message = Message::new(Role::User, vec![Part::text(text)]);
    message_id.clone_into(&mut message.message_id);
    if let Some((task_id, context_id)) = task {
        message.task_id = Some(task_id.to_owned());
        message.context_id = Some(context_id.to_owned());
    }
    SendMessageRequest {
        message,
        configuration: None,
        metadata: None,
        tenant: None,
    }
}

#[tokio::test]
async fn raw_rest_omitted_defaults_replay_through_jsonrpc_explicit_defaults() {
    let path = database_path();
    let (base_url, server, shutdown_tx, gateway) = start(
        &path,
        DurableLoopbackEndpoint::new(),
        InjectedClock::new(1_700_000_390_000),
    )
    .await;
    let request = continuation_request(
        "raw-cross-client-defaults",
        "canonical omitted defaults",
        None,
    );
    let mut omitted = serde_json::to_value(&request).unwrap();
    omitted.as_object_mut().unwrap().remove("configuration");
    let (rest_status, _, rest_body) =
        raw_rest(&gateway, "POST", "/rest/message:send", Some(omitted)).await;
    assert_eq!(rest_status, StatusCode::OK, "REST response: {rest_body}");
    let SendMessageResponse::Task(rest_task) =
        serde_json::from_value::<SendMessageResponse>(rest_body).unwrap()
    else {
        panic!("REST unary response must be a task")
    };
    assert_eq!(rest_task.status.state, TaskState::Completed);
    assert!(
        !serde_json::to_string(&rest_task)
            .unwrap()
            .contains("dispatchId"),
        "private sender correlation must not leak into public artifacts"
    );

    let mut explicit = serde_json::to_value(&request).unwrap();
    explicit["configuration"] = serde_json::json!({
        "acceptedOutputModes": ["application/json"],
        "historyLength": 0,
        "returnImmediately": false
    });
    let (rpc_status, _, rpc_body) = raw_rest(
        &gateway,
        "POST",
        "/jsonrpc",
        Some(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "explicit-default-retry",
            "method": a2a::jsonrpc::methods::SEND_MESSAGE,
            "params": explicit
        })),
    )
    .await;
    assert_eq!(rpc_status, StatusCode::OK, "JSON-RPC response: {rpc_body}");
    assert!(
        rpc_body.get("error").is_none(),
        "JSON-RPC response: {rpc_body}"
    );
    let SendMessageResponse::Task(rpc_task) =
        serde_json::from_value::<SendMessageResponse>(rpc_body["result"].clone()).unwrap()
    else {
        panic!("JSON-RPC unary response must be a task")
    };
    assert_eq!(rpc_task.id, rest_task.id);
    assert_eq!(rpc_task.status.state, TaskState::Completed);
    assert!(
        rpc_task.history.is_none(),
        "current history projection must apply"
    );
    assert_eq!(
        bounded(
            "gateway durable effect count",
            gateway.durable_effect_count()
        )
        .await
        .unwrap(),
        1
    );

    shutdown_tx.send(()).unwrap();
    bounded_join("raw default server join", server).await;
    bounded("raw default gateway shutdown", gateway.shutdown())
        .await
        .unwrap();
    cleanup(&path);
    drop(base_url);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn durable_rest_unary_parity_and_cross_binding_replay_are_exact() {
    let path = database_path();
    let clock = InjectedClock::new(1_700_000_400_000);
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let endpoint = DurableLoopbackEndpoint::with_completion_barrier(
        Arc::clone(&started),
        Arc::clone(&release),
    );
    let (base_url, server, shutdown_tx, gateway) = start(&path, endpoint, clock).await;
    let card = bounded(
        "REST agent card",
        AgentCardResolver::new(None).resolve(&base_url),
    )
    .await
    .unwrap();
    assert!(card.supported_interfaces.iter().any(|interface| {
        interface.protocol_binding == TRANSPORT_PROTOCOL_HTTP_JSON
            && interface.url == format!("{base_url}/rest")
    }));
    assert_eq!(card.default_output_modes, ["application/json"]);
    assert!(
        card.skills.iter().all(|skill| {
            skill.output_modes.as_deref() == Some(&["application/json".to_owned()])
        })
    );

    let mut message = Message::new(Role::User, vec![Part::text("REST unary parity")]);
    message.message_id = "rest-unary-parity".to_owned();
    let request = SendMessageRequest {
        message,
        configuration: Some(SendMessageConfiguration {
            accepted_output_modes: None,
            task_push_notification_config: None,
            history_length: Some(0),
            return_immediately: Some(true),
        }),
        metadata: None,
        tenant: None,
    };
    let admitted = bounded(
        "REST immediate admission",
        rest_client(&base_url).await.send_message(&request),
    )
    .await
    .unwrap();
    let SendMessageResponse::Task(admitted_task) = &admitted else {
        panic!("REST admission task")
    };
    assert_eq!(admitted_task.status.state, TaskState::Submitted);
    assert!(admitted_task.history.is_none());
    bounded("REST receiver barrier", started.notified()).await;
    assert_eq!(
        bounded(
            "JSON-RPC replay of REST admission",
            client(&base_url).await.send_message(&request),
        )
        .await
        .unwrap(),
        admitted
    );
    let mut conflict = request.clone();
    conflict.message.parts = vec![Part::text("different semantics")];
    assert_eq!(
        bounded(
            "REST idempotency conflict",
            rest_client(&base_url).await.send_message(&conflict),
        )
        .await
        .unwrap_err()
        .code,
        error_code::INVALID_REQUEST
    );
    let subscription_client = rest_client(&base_url).await;
    let mut completion = bounded(
        "REST unary subscription establishment",
        subscription_client.subscribe_to_task(&SubscribeToTaskRequest {
            id: admitted_task.id.clone(),
            tenant: None,
        }),
    )
    .await
    .unwrap();
    assert!(matches!(
        bounded("REST unary active snapshot", completion.next())
            .await
            .unwrap()
            .unwrap(),
        StreamResponse::Task(task) if task.status.state == TaskState::Submitted
    ));
    release.notify_one();
    let completion_tail = bounded(
        "REST unary completion barrier",
        completion.collect::<Vec<_>>(),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    assert!(
        completion_tail
            .iter()
            .all(|frame| !matches!(frame, StreamResponse::Task(_)))
    );
    assert!(matches!(
        completion_tail.last(),
        Some(StreamResponse::StatusUpdate(update))
            if update.status.state == TaskState::Completed
    ));
    let replay = bounded(
        "REST completed unary replay",
        rest_client(&base_url).await.send_message(&request),
    )
    .await
    .unwrap();
    assert!(matches!(&replay, SendMessageResponse::Task(task)
        if task.status.state == TaskState::Completed && task.history.is_none()));
    assert_eq!(
        serde_json::to_vec(
            &bounded(
                "JSON-RPC replay after REST completion",
                client(&base_url).await.send_message(&request),
            )
            .await
            .unwrap()
        )
        .unwrap(),
        serde_json::to_vec(&replay).unwrap()
    );
    assert_eq!(
        bounded(
            "gateway durable effect count",
            gateway.durable_effect_count()
        )
        .await
        .unwrap(),
        1
    );

    let hidden = bounded(
        "REST get task without history",
        rest_client(&base_url).await.get_task(&GetTaskRequest {
            id: admitted_task.id.clone(),
            history_length: Some(0),
            tenant: None,
        }),
    )
    .await
    .unwrap();
    assert!(hidden.history.is_none());
    let projected = bounded(
        "REST get task projected history",
        rest_client(&base_url).await.get_task(&GetTaskRequest {
            id: admitted_task.id.clone(),
            history_length: Some(1),
            tenant: None,
        }),
    )
    .await
    .unwrap();
    assert_eq!(projected.history.as_ref().unwrap().len(), 1);
    assert_eq!(
        bounded(
            "REST missing task lookup",
            rest_client(&base_url).await.get_task(&GetTaskRequest {
                id: "missing-rest-task".to_owned(),
                history_length: None,
                tenant: None,
            }),
        )
        .await
        .unwrap_err()
        .code,
        error_code::TASK_NOT_FOUND
    );
    let mut tenant = request.clone();
    tenant.message.message_id = "rest-tenant-rejected".to_owned();
    tenant.tenant = Some("caller-controlled".to_owned());
    assert_eq!(
        bounded(
            "REST tenant rejection",
            rest_client(&base_url).await.send_message(&tenant),
        )
        .await
        .unwrap_err()
        .code,
        error_code::INVALID_PARAMS
    );

    shutdown_tx.send(()).unwrap();
    bounded_join("REST unary server join", server).await;
    bounded("REST unary gateway shutdown", gateway.shutdown())
        .await
        .unwrap();
    cleanup(&path);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn durable_rest_preflight_errors_use_http_status_envelopes_before_sse() {
    let path = database_path();
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let endpoint = DurableLoopbackEndpoint::with_completion_barrier(
        Arc::clone(&started),
        Arc::clone(&release),
    );
    let (base_url, server, shutdown_tx, gateway) =
        start(&path, endpoint, InjectedClock::new(1_700_000_425_000)).await;

    let mut invalid = continuation_request("raw-rest-invalid", "invalid", None);
    invalid.configuration = Some(SendMessageConfiguration {
        accepted_output_modes: Some(vec!["text/plain".to_owned()]),
        task_push_notification_config: None,
        history_length: None,
        return_immediately: None,
    });
    let (status, headers, body) = raw_rest(
        &gateway,
        "POST",
        "/rest/message:stream",
        Some(serde_json::to_value(&invalid).unwrap()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_ne!(
        headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream")
    );
    assert_eq!(body["error"]["code"], 400);
    assert_eq!(body["error"]["status"], "INVALID_ARGUMENT");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("acceptedOutputModes")
    );

    let (status, headers, body) = raw_rest(
        &gateway,
        "GET",
        "/rest/tasks/raw-rest-missing:subscribe",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_ne!(
        headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream")
    );
    assert_eq!(body["error"]["code"], 404);
    assert_eq!(body["error"]["status"], "NOT_FOUND");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("raw-rest-missing")
    );

    let mut admitted = continuation_request("raw-rest-conflict", "original", None);
    admitted.configuration = Some(SendMessageConfiguration {
        accepted_output_modes: None,
        task_push_notification_config: None,
        history_length: None,
        return_immediately: Some(true),
    });
    let conflict_setup_stream = bounded(
        "raw REST conflict setup admission",
        rest_client(&base_url)
            .await
            .send_streaming_message(&admitted),
    )
    .await
    .unwrap();
    drop(conflict_setup_stream);
    bounded("raw REST conflict receiver barrier", started.notified()).await;
    let mut conflict = admitted;
    conflict.message.parts = vec![Part::text("different")];
    let (status, headers, body) = raw_rest(
        &gateway,
        "POST",
        "/rest/message:stream",
        Some(serde_json::to_value(&conflict).unwrap()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_ne!(
        headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream")
    );
    assert_eq!(body["error"]["code"], 400);
    assert_eq!(body["error"]["status"], "INVALID_ARGUMENT");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("different request semantics")
    );

    release.notify_one();
    shutdown_tx.send(()).unwrap();
    bounded_join("raw REST preflight server join", server).await;
    bounded("raw REST preflight gateway shutdown", gateway.shutdown())
        .await
        .unwrap();
    cleanup(&path);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn durable_rest_sse_parity_reconnect_subscription_and_cross_binding_are_exact() {
    let path = database_path();
    let clock = InjectedClock::new(1_700_000_450_000);
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let endpoint = DurableLoopbackEndpoint::with_completion_barrier(
        Arc::clone(&started),
        Arc::clone(&release),
    );
    let effects = endpoint.diagnostic_effect_counter();
    let (base_url, server, shutdown_tx, gateway) = start(&path, endpoint, clock.clone()).await;
    let mut message = Message::new(Role::User, vec![Part::text("REST SSE parity")]);
    message.message_id = "rest-sse-parity".to_owned();
    let request = SendMessageRequest {
        message,
        configuration: None,
        metadata: None,
        tenant: None,
    };

    // Admit through JSON-RPC, then attach through REST: binding is excluded,
    // while the streaming invocation kind remains part of semantic identity.
    let json_client = client(&base_url).await;
    let mut original = bounded(
        "JSON-RPC stream admission",
        json_client.send_streaming_message(&request),
    )
    .await
    .unwrap();
    bounded("REST SSE receiver barrier", started.notified()).await;
    let initial = bounded("immediate Task frame", original.next())
        .await
        .unwrap()
        .unwrap();
    let task_id = match &initial {
        StreamResponse::Task(task) if task.status.state == TaskState::Submitted => task.id.clone(),
        other => panic!("unexpected REST initial frame: {other:?}"),
    };
    let progress = bounded("REST progress frame", original.next())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(&progress, StreamResponse::StatusUpdate(update)
        if update.status.state == TaskState::Working));

    let rest = rest_client(&base_url).await;
    let mut disconnected = bounded(
        "open active REST stream to disconnect",
        rest.send_streaming_message(&request),
    )
    .await
    .unwrap();
    assert_eq!(
        bounded("REST disconnected initial frame", disconnected.next())
            .await
            .unwrap()
            .unwrap(),
        initial
    );
    drop(disconnected);

    let reattach_client = rest_client(&base_url).await;
    let mut reattached = bounded(
        "second active REST streaming attachment",
        reattach_client.send_streaming_message(&request),
    )
    .await
    .unwrap();
    let reattached_initial = bounded("reattached REST initial frame", reattached.next())
        .await
        .unwrap()
        .unwrap();
    let reattached_progress = bounded("reattached REST progress frame", reattached.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reattached_initial, initial);
    assert_eq!(reattached_progress, progress);

    let subscription_client = rest_client(&base_url).await;
    let mut subscription = bounded(
        "REST active subscription establishment",
        subscription_client.subscribe_to_task(&SubscribeToTaskRequest {
            id: task_id,
            tenant: None,
        }),
    )
    .await
    .unwrap();
    let snapshot = bounded("REST active subscription snapshot", subscription.next())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(snapshot, StreamResponse::Task(task)
        if task.status.state == TaskState::Working));
    release.notify_one();
    let mut transcript = vec![initial, progress];
    transcript.extend(
        bounded("REST original terminal tail", original.collect::<Vec<_>>())
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
    );
    let reattached_tail = bounded(
        "second active REST attachment exact tail",
        reattached.collect::<Vec<_>>(),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    assert_eq!(reattached_tail, transcript[2..]);
    let tail = bounded(
        "REST subscription exact tail",
        subscription.collect::<Vec<_>>(),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    assert_eq!(tail, transcript[2..]);
    assert!(
        transcript
            .iter()
            .any(|frame| matches!(frame, StreamResponse::ArtifactUpdate(_)))
    );
    assert!(
        matches!(transcript.last(), Some(StreamResponse::StatusUpdate(update))
        if update.status.state == TaskState::Completed)
    );
    assert_eq!(
        transcript
            .iter()
            .filter(|frame| matches!(frame, StreamResponse::StatusUpdate(update)
                if update.status.state.is_terminal()))
            .count(),
        1
    );
    let rest_reconnect = collect_rest_stream(&base_url, &request).await;
    assert_eq!(
        serde_json::to_vec(&rest_reconnect).unwrap(),
        serde_json::to_vec(&transcript).unwrap()
    );
    assert_eq!(effects.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        bounded(
            "gateway durable effect count",
            gateway.durable_effect_count()
        )
        .await
        .unwrap(),
        1
    );

    let unary_error_client = rest_client(&base_url).await;
    assert_eq!(
        bounded(
            "REST unary rejection for streaming identity",
            unary_error_client.send_message(&request),
        )
        .await
        .unwrap_err()
        .code,
        error_code::INVALID_REQUEST
    );
    let mut invalid = request.clone();
    invalid.message.message_id = "rest-sse-invalid".to_owned();
    invalid.configuration = Some(SendMessageConfiguration {
        accepted_output_modes: Some(vec!["text/plain".to_owned()]),
        task_push_notification_config: None,
        history_length: None,
        return_immediately: None,
    });
    let invalid_client = rest_client(&base_url).await;
    let Err(invalid_error) = bounded(
        "REST invalid preflight rejection",
        invalid_client.send_streaming_message(&invalid),
    )
    .await
    else {
        panic!("invalid REST request opened SSE")
    };
    assert_eq!(invalid_error.code, error_code::INVALID_PARAMS);
    assert!(invalid_error.to_string().contains("acceptedOutputModes"));
    let missing_client = rest_client(&base_url).await;
    let Err(missing_error) = bounded(
        "REST missing subscription preflight rejection",
        missing_client.subscribe_to_task(&SubscribeToTaskRequest {
            id: "missing-rest-subscription".to_owned(),
            tenant: None,
        }),
    )
    .await
    else {
        panic!("missing REST subscription opened SSE")
    };
    assert_eq!(missing_error.code, error_code::TASK_NOT_FOUND);
    assert!(
        missing_error
            .to_string()
            .contains("missing-rest-subscription")
    );

    shutdown_tx.send(()).unwrap();
    bounded_join("REST SSE server join", server).await;
    bounded("REST SSE gateway shutdown", gateway.shutdown())
        .await
        .unwrap();
    let endpoint = DurableLoopbackEndpoint::from_diagnostic_counter(Arc::clone(&effects));
    let (base_url, server, shutdown_tx, gateway) = start(&path, endpoint, clock).await;
    let restarted = collect_rest_stream(&base_url, &request).await;
    assert_eq!(
        serde_json::to_vec(&restarted).unwrap(),
        serde_json::to_vec(&transcript).unwrap()
    );
    assert_eq!(
        bounded(
            "gateway durable effect count",
            gateway.durable_effect_count()
        )
        .await
        .unwrap(),
        1
    );
    shutdown_tx.send(()).unwrap();
    bounded_join("restarted REST SSE server join", server).await;
    bounded("restarted REST SSE gateway shutdown", gateway.shutdown())
        .await
        .unwrap();
    cleanup(&path);
}

#[tokio::test]
async fn durable_rest_sse_never_serializes_transport_errors_as_data() {
    let path = database_path();
    let (_base_url, server, shutdown_tx, gateway) = start(
        &path,
        DurableLoopbackEndpoint::new(),
        InjectedClock::new(1_700_000_474_000),
    )
    .await;
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER inject_rest_sse_claim_failure BEFORE UPDATE OF state ON outbox
             WHEN NEW.state = 'leased'
             BEGIN SELECT RAISE(ABORT, 'injected REST SSE claim failure'); END;",
        )
        .unwrap();
    let request = continuation_request("rest-sse-no-errors", "REST SSE data typing", None);
    let response = bounded("raw REST SSE fatal stream", async {
        gateway
            .router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/rest/message:stream")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::to_value(&request).unwrap()).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
    })
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream")
    );
    let bytes = bounded(
        "collect raw REST SSE fatal stream",
        response.into_body().collect(),
    )
    .await
    .unwrap()
    .to_bytes();
    let wire = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(wire.contains("rest-sse-no-errors"));
    assert!(
        !wire.contains("\"code\":"),
        "REST SSE leaked an error: {wire}"
    );

    shutdown_tx.send(()).unwrap();
    bounded_join("REST typed SSE server join", server).await;
    assert!(
        bounded("REST typed SSE gateway shutdown", gateway.shutdown())
            .await
            .unwrap_err()
            .to_string()
            .contains("outbox claim update failed")
    );
    cleanup(&path);
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Fatal-stream and post-failure unary mutation share one fault trace.
async fn durable_fatal_driver_is_jsonrpc_observable_and_rest_fails_before_sse() {
    let path = database_path();
    let (base_url, server, shutdown_tx, gateway) = start(
        &path,
        DurableLoopbackEndpoint::new(),
        InjectedClock::new(1_700_000_475_000),
    )
    .await;
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER inject_rest_claim_failure BEFORE UPDATE OF state ON outbox
             WHEN NEW.state = 'leased'
             BEGIN SELECT RAISE(ABORT, 'injected REST claim failure'); END;",
        )
        .unwrap();
    let request = continuation_request("rest-fatal-driver", "fatal REST SSE", None);
    let fatal_client = client(&base_url).await;
    let mut stream = bounded(
        "JSON-RPC fatal stream establishment",
        fatal_client.send_streaming_message(&request),
    )
    .await
    .unwrap();
    assert!(matches!(
        bounded("JSON-RPC fatal initial Task", stream.next())
            .await
            .unwrap()
            .unwrap(),
        StreamResponse::Task(task) if task.status.state == TaskState::Submitted
    ));
    let fatal = bounded("JSON-RPC fatal one-shot error", stream.next())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(fatal.code, error_code::INTERNAL_ERROR);
    assert!(fatal.to_string().contains("outbox claim update failed"));
    assert!(
        bounded("JSON-RPC fatal closure", stream.next())
            .await
            .is_none()
    );

    let rest_request = continuation_request(
        "rest-fatal-preestablishment",
        "REST must fail before opening SSE",
        None,
    );
    let (status, headers, body) = raw_rest(
        &gateway,
        "POST",
        "/rest/message:stream",
        Some(serde_json::to_value(&rest_request).unwrap()),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_ne!(
        headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream")
    );
    assert_eq!(body["error"]["code"], 500);
    assert_eq!(body["error"]["status"], "INTERNAL");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("outbox claim update failed")
    );

    let Err(official_error) = bounded(
        "official REST fatal preflight error",
        rest_client(&base_url)
            .await
            .send_streaming_message(&rest_request),
    )
    .await
    else {
        panic!("failed REST driver opened SSE")
    };
    assert_eq!(official_error.code, error_code::INTERNAL_ERROR);
    assert!(
        official_error
            .to_string()
            .contains("outbox claim update failed")
    );

    let rows_before: i64 = rusqlite::Connection::open(&path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM tasks", [], |row| row.get(0))
        .unwrap();
    let unary_after_failure = continuation_request(
        "unary-after-fatal-driver",
        "health preflight must precede admission",
        None,
    );
    let (unary_status, _, unary_body) = raw_rest(
        &gateway,
        "POST",
        "/rest/message:send",
        Some(serde_json::to_value(unary_after_failure).unwrap()),
    )
    .await;
    assert_eq!(unary_status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        unary_body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("outbox claim update failed")
    );
    let rows_after: i64 = rusqlite::Connection::open(&path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM tasks", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        rows_after, rows_before,
        "failed unary preflight created rows"
    );

    shutdown_tx.send(()).unwrap();
    bounded_join("REST fatal server join", server).await;
    assert!(
        bounded("REST fatal gateway shutdown", gateway.shutdown())
            .await
            .unwrap_err()
            .to_string()
            .contains("outbox claim update failed")
    );
    cleanup(&path);
}

#[tokio::test]
async fn durable_rest_input_and_auth_continuations_replay_previous_and_current_exactly() {
    for (index, kind) in [
        DurableInterruptionKind::InputRequired,
        DurableInterruptionKind::AuthRequired,
    ]
    .into_iter()
    .enumerate()
    {
        let path = database_path();
        let trigger = format!("rest-continuation-trigger-{index}");
        let endpoint = DurableLoopbackEndpoint::with_interruption_for_text(
            trigger.clone(),
            kind,
            "REST continuation required",
        );
        let (base_url, server, shutdown_tx, gateway) = start(
            &path,
            endpoint,
            InjectedClock::new(1_700_000_500_000 + i64::try_from(index).unwrap()),
        )
        .await;
        let original_request = continuation_request(
            &format!("rest-continuation-original-{index}"),
            &trigger,
            None,
        );
        let original = bounded(
            "REST interrupted original send",
            rest_client(&base_url).await.send_message(&original_request),
        )
        .await
        .unwrap();
        let SendMessageResponse::Task(interrupted) = &original else {
            panic!("REST interrupted task")
        };
        assert!(matches!(
            interrupted.status.state,
            TaskState::InputRequired | TaskState::AuthRequired
        ));
        let current_request = continuation_request(
            &format!("rest-continuation-current-{index}"),
            "REST continuation proof",
            Some((&interrupted.id, &interrupted.context_id)),
        );
        let current = bounded(
            "REST continuation send",
            rest_client(&base_url).await.send_message(&current_request),
        )
        .await
        .unwrap();
        assert!(matches!(&current, SendMessageResponse::Task(task)
            if task.status.state == TaskState::Completed
                && task.history.as_ref().is_some_and(|history| history.len() == 2)));
        assert_eq!(
            serde_json::to_vec(
                &bounded(
                    "REST interrupted original replay",
                    rest_client(&base_url).await.send_message(&original_request),
                )
                .await
                .unwrap()
            )
            .unwrap(),
            serde_json::to_vec(&original).unwrap()
        );
        assert_eq!(
            serde_json::to_vec(
                &bounded(
                    "JSON-RPC continuation replay",
                    client(&base_url).await.send_message(&current_request),
                )
                .await
                .unwrap()
            )
            .unwrap(),
            serde_json::to_vec(&current).unwrap()
        );
        assert_eq!(
            bounded(
                "gateway durable effect count",
                gateway.durable_effect_count()
            )
            .await
            .unwrap(),
            2
        );
        shutdown_tx.send(()).unwrap();
        bounded_join("REST continuation server join", server).await;
        bounded("REST continuation gateway shutdown", gateway.shutdown())
            .await
            .unwrap();
        cleanup(&path);
    }
}

#[tokio::test]
async fn durable_rest_active_cancellation_reaches_stream_and_subscription_once() {
    let path = database_path();
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let endpoint = DurableLoopbackEndpoint::with_completion_barrier(Arc::clone(&started), release);
    let (base_url, server, shutdown_tx, gateway) =
        start(&path, endpoint, InjectedClock::new(1_700_000_550_000)).await;
    let request = continuation_request("rest-active-cancel", "cancel REST activity", None);
    let stream_client = rest_client(&base_url).await;
    let mut stream = bounded(
        "open REST cancellation stream",
        stream_client.send_streaming_message(&request),
    )
    .await
    .unwrap();
    bounded("REST cancel receiver barrier", started.notified()).await;
    let initial = bounded("REST cancellation initial frame", stream.next())
        .await
        .unwrap()
        .unwrap();
    let task_id = match initial {
        StreamResponse::Task(task) => task.id,
        other => panic!("unexpected REST cancellation initial frame: {other:?}"),
    };
    assert!(matches!(
        bounded("REST cancellation working frame", stream.next())
            .await
            .unwrap()
            .unwrap(),
        StreamResponse::StatusUpdate(update) if update.status.state == TaskState::Working
    ));
    let subscription_client = rest_client(&base_url).await;
    let mut subscription = bounded(
        "open REST cancellation subscription",
        subscription_client.subscribe_to_task(&SubscribeToTaskRequest {
            id: task_id.clone(),
            tenant: None,
        }),
    )
    .await
    .unwrap();
    assert!(matches!(
        bounded("REST cancellation subscription snapshot", subscription.next())
            .await
            .unwrap()
            .unwrap(),
        StreamResponse::Task(task) if task.status.state == TaskState::Working
    ));
    let canceled = bounded(
        "REST active cancellation request",
        rest_client(&base_url)
            .await
            .cancel_task(&CancelTaskRequest {
                id: task_id,
                metadata: None,
                tenant: None,
            }),
    )
    .await
    .unwrap();
    assert_eq!(canceled.status.state, TaskState::Canceled);
    let stream_tail = bounded("REST canceled stream close", stream.collect::<Vec<_>>())
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let subscription_tail = bounded(
        "REST canceled subscription close",
        subscription.collect::<Vec<_>>(),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    assert_eq!(stream_tail, subscription_tail);
    assert_eq!(stream_tail.len(), 1);
    assert!(
        matches!(&stream_tail[0], StreamResponse::StatusUpdate(update)
        if update.status.state == TaskState::Canceled)
    );
    assert_eq!(
        bounded(
            "gateway durable effect count",
            gateway.durable_effect_count()
        )
        .await
        .unwrap(),
        0
    );
    shutdown_tx.send(()).unwrap();
    bounded_join("REST cancellation server join", server).await;
    bounded("REST cancellation gateway shutdown", gateway.shutdown())
        .await
        .unwrap();
    cleanup(&path);
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One exact per-message replay and restart tracer.
async fn durable_unary_input_required_continuation_replays_each_message_exactly() {
    let path = database_path();
    let clock = InjectedClock::new(1_700_000_025_000);
    let endpoint = DurableLoopbackEndpoint::with_interruption_for_text(
        "require-input",
        DurableInterruptionKind::InputRequired,
        "Provide the durable approval code",
    );
    let (base_url, server, shutdown_tx, gateway) = start(&path, endpoint, clock.clone()).await;
    let first_request = continuation_request("interrupt-input-1", "require-input", None);
    let first = bounded(
        "input-required interruption",
        client(&base_url).await.send_message(&first_request),
    )
    .await
    .unwrap();
    let SendMessageResponse::Task(interrupted) = &first else {
        panic!("task result")
    };
    assert_eq!(interrupted.status.state, TaskState::InputRequired);
    assert_eq!(interrupted.history.as_ref().unwrap().len(), 1);
    let subscription_client =
        bounded("input-required subscription client", client(&base_url)).await;
    let mut subscription = bounded(
        "open input-required unary subscription",
        subscription_client.subscribe_to_task(&SubscribeToTaskRequest {
            id: interrupted.id.clone(),
            tenant: None,
        }),
    )
    .await
    .unwrap();
    let subscription_snapshot =
        bounded("input-required subscription snapshot", subscription.next())
            .await
            .unwrap()
            .unwrap();
    assert!(
        matches!(subscription_snapshot, StreamResponse::Task(task) if task.status.state == TaskState::InputRequired)
    );
    let mismatched = continuation_request(
        "interrupt-input-context-mismatch",
        "must reject",
        Some((&interrupted.id, "wrong-context")),
    );
    let mismatch_client = bounded("context mismatch client", client(&base_url)).await;
    let mismatch = bounded(
        "explicit continuation context mismatch",
        mismatch_client.send_message(&mismatched),
    )
    .await
    .expect_err("mismatched context must be rejected");
    assert_eq!(mismatch.code, error_code::INVALID_PARAMS);
    assert_eq!(
        bounded(
            "gateway durable effect count",
            gateway.durable_effect_count()
        )
        .await
        .unwrap(),
        1
    );

    let replay_client = bounded("input replay client", client(&base_url)).await;
    let replay = bounded(
        "input replay request",
        replay_client.send_message(&first_request),
    )
    .await
    .unwrap();
    assert_eq!(
        serde_json::to_vec(&replay).unwrap(),
        serde_json::to_vec(&first).unwrap()
    );
    let mut continuation = continuation_request(
        "interrupt-input-2",
        "approval-code-42",
        Some((&interrupted.id, &interrupted.context_id)),
    );
    continuation.message.context_id = None;
    continuation.configuration = Some(SendMessageConfiguration {
        accepted_output_modes: None,
        task_push_notification_config: None,
        history_length: Some(1),
        return_immediately: None,
    });
    let left_client = bounded("left continuation client", client(&base_url)).await;
    let right_client = bounded("right continuation client", client(&base_url)).await;
    let simultaneous = Arc::new(tokio::sync::Barrier::new(3));
    let left_gate = Arc::clone(&simultaneous);
    let right_gate = Arc::clone(&simultaneous);
    let left_request = continuation.clone();
    let right_request = continuation.clone();
    let left = tokio::spawn(async move {
        left_gate.wait().await;
        bounded(
            "spawned left continuation send",
            left_client.send_message(&left_request),
        )
        .await
    });
    let right = tokio::spawn(async move {
        right_gate.wait().await;
        bounded(
            "spawned right continuation send",
            right_client.send_message(&right_request),
        )
        .await
    });
    bounded("three continuation contenders ready", simultaneous.wait()).await;
    let (left, right) = bounded_join_pair("simultaneous identical continuation", left, right).await;
    let completed = left.unwrap();
    assert_eq!(right.unwrap(), completed);
    let SendMessageResponse::Task(completed_task) = &completed else {
        panic!("task result")
    };
    assert_eq!(completed_task.status.state, TaskState::Completed);
    assert_eq!(completed_task.history.as_ref().unwrap().len(), 1);
    assert_eq!(
        completed_task.history.as_ref().unwrap()[0].message_id,
        "interrupt-input-2"
    );
    assert_eq!(
        bounded(
            "gateway durable effect count",
            gateway.durable_effect_count()
        )
        .await
        .unwrap(),
        2
    );
    let subscription_tail = bounded("input-required subscription tail", async {
        subscription
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
    })
    .await
    .unwrap();
    assert!(
        subscription_tail
            .iter()
            .all(|frame| !matches!(frame, StreamResponse::Task(_)))
    );
    assert!(matches!(
        subscription_tail.last(),
        Some(StreamResponse::StatusUpdate(update))
            if update.status.state == TaskState::Completed
    ));
    let final_client = bounded("input final replay client", client(&base_url)).await;
    assert_eq!(
        bounded(
            "input first final replay",
            final_client.send_message(&first_request),
        )
        .await
        .unwrap(),
        first
    );
    assert_eq!(
        bounded(
            "input continuation final replay",
            final_client.send_message(&continuation),
        )
        .await
        .unwrap(),
        completed
    );

    shutdown_tx.send(()).unwrap();
    bounded_join("input continuation server join", server).await;
    bounded("input continuation gateway shutdown", gateway.shutdown())
        .await
        .unwrap();
    let (base_url, server, shutdown_tx, gateway) = start(
        &path,
        DurableLoopbackEndpoint::with_interruption_for_text(
            "require-input",
            DurableInterruptionKind::InputRequired,
            "Provide the durable approval code",
        ),
        clock,
    )
    .await;
    let restart_client = bounded("restarted input replay client", client(&base_url)).await;
    assert_eq!(
        bounded(
            "restarted input first replay",
            restart_client.send_message(&first_request),
        )
        .await
        .unwrap(),
        first
    );
    assert_eq!(
        bounded(
            "restarted input continuation replay",
            restart_client.send_message(&continuation),
        )
        .await
        .unwrap(),
        completed
    );
    assert_eq!(
        bounded(
            "gateway durable effect count",
            gateway.durable_effect_count()
        )
        .await
        .unwrap(),
        2
    );
    shutdown_tx.send(()).unwrap();
    bounded_join("restarted input continuation server join", server).await;
    bounded(
        "restarted input continuation gateway shutdown",
        gateway.shutdown(),
    )
    .await
    .unwrap();
    cleanup(&path);
}

#[tokio::test]
async fn return_immediately_continuation_replays_authoritative_working_snapshot() {
    let path = database_path();
    let clock = InjectedClock::new(1_700_000_030_000);
    let reached = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let endpoint = DurableLoopbackEndpoint::with_interruption_for_text(
        "pause-for-input",
        DurableInterruptionKind::InputRequired,
        "continue",
    )
    .with_barrier(Arc::clone(&reached), Arc::clone(&release));
    let (base_url, server, shutdown_tx, gateway) = start(&path, endpoint, clock).await;
    let first_client = bounded("return-immediately first client", client(&base_url)).await;
    let first_request = continuation_request("return-first", "pause-for-input", None);
    let initial_gate = tokio::spawn({
        let reached = Arc::clone(&reached);
        let release = Arc::clone(&release);
        async move {
            reached.notified().await;
            release.notify_one();
        }
    });
    let first = bounded(
        "return-immediately interruption",
        first_client.send_message(&first_request),
    )
    .await
    .unwrap();
    bounded_join("initial barrier join", initial_gate).await;
    let SendMessageResponse::Task(interrupted) = first else {
        panic!("task response")
    };
    assert_eq!(interrupted.status.state, TaskState::InputRequired);

    let mut continuation = continuation_request(
        "return-continuation",
        "resume",
        Some((&interrupted.id, &interrupted.context_id)),
    );
    continuation.message.context_id = None;
    continuation.configuration = Some(SendMessageConfiguration {
        accepted_output_modes: None,
        task_push_notification_config: None,
        history_length: Some(1),
        return_immediately: Some(true),
    });
    let continuation_client =
        bounded("return-immediately continuation client", client(&base_url)).await;
    let admitted = bounded(
        "return-immediately admission",
        continuation_client.send_message(&continuation),
    )
    .await
    .unwrap();
    bounded("continuation reached receiver barrier", reached.notified()).await;
    let replay_client = bounded("return-immediately replay client", client(&base_url)).await;
    let replay = bounded(
        "return-immediately working replay",
        replay_client.send_message(&continuation),
    )
    .await
    .unwrap();
    assert_eq!(replay, admitted);
    assert!(matches!(
        admitted,
        SendMessageResponse::Task(Task { status: TaskStatus { state: TaskState::Working, .. }, history: Some(history), .. })
            if history.len() == 1 && history[0].message_id == "return-continuation"
    ));
    release.notify_one();
    bounded("return continuation terminal commit", async {
        loop {
            if bounded(
                "gateway durable effect count",
                gateway.durable_effect_count(),
            )
            .await
            .unwrap()
                == 2
            {
                break;
            }
            gateway.wait_for_waiter_count(0).await.unwrap();
        }
    })
    .await;
    shutdown_tx.send(()).unwrap();
    bounded_join("return-immediately server join", server).await;
    bounded("return-immediately gateway shutdown", gateway.shutdown())
        .await
        .unwrap();
    cleanup(&path);
}

#[tokio::test]
async fn durable_stream_auth_required_continuation_has_independent_exact_transcripts() {
    let path = database_path();
    let clock = InjectedClock::new(1_700_000_035_000);
    let endpoint = DurableLoopbackEndpoint::with_interruption_for_text(
        "require-auth",
        DurableInterruptionKind::AuthRequired,
        "Authenticate the durable request",
    );
    let (base_url, server, shutdown_tx, gateway) = start(&path, endpoint, clock.clone()).await;
    let first_request = continuation_request("interrupt-auth-1", "require-auth", None);
    let first = collect_stream(&client(&base_url).await, &first_request).await;
    assert!(matches!(first.first(), Some(StreamResponse::Task(_))));
    assert!(
        matches!(first.last(), Some(StreamResponse::StatusUpdate(update))
        if update.status.state == TaskState::AuthRequired)
    );
    let task_id = match first.first().unwrap() {
        StreamResponse::Task(task) => task.id.clone(),
        _ => unreachable!(),
    };
    let task = bounded(
        "auth-required task lookup",
        client(&base_url).await.get_task(&GetTaskRequest {
            id: task_id,
            history_length: None,
            tenant: None,
        }),
    )
    .await
    .unwrap();
    let continuation = continuation_request(
        "interrupt-auth-2",
        "bearer-proof",
        Some((&task.id, &task.context_id)),
    );
    let second = collect_stream(&client(&base_url).await, &continuation).await;
    assert!(matches!(second.first(), Some(StreamResponse::Task(task))
        if task.status.state == TaskState::Working && task.history.as_ref().unwrap().len() == 2));
    assert!(
        matches!(second.last(), Some(StreamResponse::StatusUpdate(update))
        if update.status.state == TaskState::Completed)
    );
    assert_eq!(
        collect_stream(&client(&base_url).await, &first_request).await,
        first
    );
    assert_eq!(
        collect_stream(&client(&base_url).await, &continuation).await,
        second
    );
    assert_eq!(
        bounded(
            "gateway durable effect count",
            gateway.durable_effect_count()
        )
        .await
        .unwrap(),
        2
    );
    shutdown_tx.send(()).unwrap();
    bounded_join("auth continuation server join", server).await;
    bounded("auth continuation gateway shutdown", gateway.shutdown())
        .await
        .unwrap();
    let (base_url, server, shutdown_tx, gateway) = start(
        &path,
        DurableLoopbackEndpoint::with_interruption_for_text(
            "require-auth",
            DurableInterruptionKind::AuthRequired,
            "Authenticate the durable request",
        ),
        clock,
    )
    .await;
    assert_eq!(
        collect_stream(&client(&base_url).await, &first_request).await,
        first
    );
    assert_eq!(
        collect_stream(&client(&base_url).await, &continuation).await,
        second
    );
    assert_eq!(
        bounded(
            "gateway durable effect count",
            gateway.durable_effect_count()
        )
        .await
        .unwrap(),
        2
    );
    shutdown_tx.send(()).unwrap();
    bounded_join("restarted auth continuation server join", server).await;
    bounded(
        "restarted auth continuation gateway shutdown",
        gateway.shutdown(),
    )
    .await
    .unwrap();
    cleanup(&path);
}

#[tokio::test]
async fn durable_stream_rejects_unsupported_output_mode_once_without_mutation() {
    let path = database_path();
    let clock = InjectedClock::new(1_700_000_040_000);
    let (base_url, server, shutdown_tx, gateway) =
        start(&path, DurableLoopbackEndpoint::new(), clock).await;
    let mut message = Message::new(Role::User, vec![Part::text("unsupported output")]);
    message.message_id = "durable-stream-output-mode".to_owned();
    let request = SendMessageRequest {
        message,
        configuration: Some(SendMessageConfiguration {
            accepted_output_modes: Some(vec!["text/plain".to_owned()]),
            task_push_notification_config: None,
            history_length: None,
            return_immediately: None,
        }),
        metadata: None,
        tenant: None,
    };
    let mut stream = bounded(
        "open rejected output stream",
        client(&base_url).await.send_streaming_message(&request),
    )
    .await
    .expect("stream errors are represented inside SSE");
    let error = bounded("one output-mode error", stream.next())
        .await
        .expect("one error item")
        .expect_err("unsupported output mode must fail");
    assert_eq!(error.code, error_code::INVALID_PARAMS);
    assert!(
        bounded("error stream closure", stream.next())
            .await
            .is_none()
    );
    assert_eq!(
        bounded(
            "gateway durable effect count",
            gateway.durable_effect_count()
        )
        .await
        .unwrap(),
        0
    );

    let missing_client = client(&base_url).await;
    let mut missing = bounded(
        "open missing task subscription error envelope",
        missing_client.subscribe_to_task(&SubscribeToTaskRequest {
            id: "missing-durable-subscription".to_owned(),
            tenant: None,
        }),
    )
    .await
    .expect("official client accepts the pre-SSE JSON-RPC error response");
    assert!(
        bounded("missing preflight produces no SSE event", missing.next())
            .await
            .is_none()
    );

    shutdown_tx.send(()).unwrap();
    bounded_join("output mode server join", server).await;
    bounded("output mode gateway shutdown", gateway.shutdown())
        .await
        .unwrap();
    let reopened = bounded("output-mode store reopen", SqliteTaskStore::open(&path, 32))
        .await
        .unwrap();
    assert_eq!(
        bounded(
            "reopened store atomic record counts",
            reopened.atomic_record_counts()
        )
        .await
        .unwrap()
        .tasks,
        0
    );
    bounded("output-mode store shutdown", reopened.shutdown_shared())
        .await
        .unwrap();
    cleanup(&path);
}

#[tokio::test]
async fn production_stream_emits_fatal_driver_error_once_then_closes() {
    let path = database_path();
    let clock = InjectedClock::new(1_700_000_045_000);
    let (base_url, server, shutdown_tx, gateway) =
        start(&path, DurableLoopbackEndpoint::new(), clock).await;
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER inject_production_claim_failure BEFORE UPDATE OF state ON outbox
             WHEN NEW.state = 'leased'
             BEGIN SELECT RAISE(ABORT, 'injected production claim failure'); END;",
        )
        .unwrap();
    let mut message = Message::new(Role::User, vec![Part::text("fatal driver stream")]);
    message.message_id = "fatal-production-driver-stream".to_owned();
    let request = SendMessageRequest {
        message,
        configuration: None,
        metadata: None,
        tenant: None,
    };
    let mut stream = bounded(
        "open fatal-driver production stream",
        client(&base_url).await.send_streaming_message(&request),
    )
    .await
    .unwrap();
    let initial = bounded("fatal-driver initial frame", stream.next())
        .await
        .expect("initial frame before driver claim")
        .expect("initial frame remains valid");
    assert!(matches!(initial, StreamResponse::Task(task)
        if task.status.state == TaskState::Submitted));
    let fatal = bounded("one fatal-driver stream error", stream.next())
        .await
        .expect("one fatal-driver error")
        .expect_err("fatal driver failure reaches the stream");
    assert!(fatal.to_string().contains("outbox claim update failed"));
    assert!(
        bounded("fatal-driver stream closure", stream.next())
            .await
            .is_none()
    );

    shutdown_tx.send(()).unwrap();
    bounded_join("fatal-driver server join", server).await;
    let shutdown_error = bounded("fatal-driver gateway shutdown", gateway.shutdown())
        .await
        .expect_err("failed production driver is reported at shutdown");
    assert!(
        shutdown_error
            .to_string()
            .contains("outbox claim update failed")
    );
    cleanup(&path);
}

async fn start(
    path: &Path,
    endpoint: DurableLoopbackEndpoint,
    clock: InjectedClock,
) -> (
    String,
    tokio::task::JoinHandle<()>,
    tokio::sync::oneshot::Sender<()>,
    smesh_a2a::DurableGateway,
) {
    let listener = bounded(
        "durable gateway listener bind",
        tokio::net::TcpListener::bind("127.0.0.1:0"),
    )
    .await
    .unwrap();
    let address = listener.local_addr().unwrap();
    let base_url = format!("http://{address}");
    let store = bounded(
        "durable gateway store open",
        SqliteTaskStore::open(path, 32),
    )
    .await
    .unwrap();
    let gateway = build_durable_loopback_gateway(
        GatewayConfig::new(&base_url, "durable-loopback"),
        store,
        endpoint,
        clock,
    )
    .unwrap();
    let app = gateway.router();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    (base_url, server, shutdown_tx, gateway)
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One restart/reacquisition tracer owns all bounded cleanup.
async fn durable_jsonrpc_unary_commits_one_atomic_loopback_marker_and_replays_after_restart() {
    let path = database_path();
    let clock = InjectedClock::new(1_700_000_000_000);
    let effect_started = Arc::new(Notify::new());
    let release_completion = Arc::new(Notify::new());
    let endpoint = DurableLoopbackEndpoint::with_completion_barrier(
        Arc::clone(&effect_started),
        Arc::clone(&release_completion),
    );
    let effects = endpoint.diagnostic_effect_counter();
    let (base_url, server, shutdown_tx, gateway) = start(&path, endpoint, clock.clone()).await;

    let mut message = Message::new(Role::User, vec![Part::text("execute exactly once")]);
    message.message_id = "durable-unary-message-1".to_owned();
    let request = SendMessageRequest {
        message,
        configuration: Some(SendMessageConfiguration {
            accepted_output_modes: None,
            task_push_notification_config: None,
            history_length: Some(0),
            return_immediately: None,
        }),
        metadata: None,
        tenant: None,
    };

    let first_client = bounded("history-zero first client", client(&base_url)).await;
    let first_request = request.clone();
    let first = tokio::spawn(async move {
        bounded(
            "spawned original durable send",
            first_client.send_message(&first_request),
        )
        .await
        .unwrap()
    });
    bounded("receiver effect barrier", effect_started.notified()).await;
    assert_eq!(effects.load(std::sync::atomic::Ordering::SeqCst), 0);

    let retry_client = client(&base_url).await;
    let retry_request = request.clone();
    let during = tokio::spawn(async move {
        bounded(
            "spawned attached durable replay",
            retry_client.send_message(&retry_request),
        )
        .await
        .unwrap()
    });
    // A retained driver-state barrier proves the duplicate is attached to the
    // in-progress admission before receiver completion is released.
    bounded(
        "two attached durable waiters",
        gateway.wait_for_waiter_count(2),
    )
    .await
    .unwrap();
    assert_eq!(effects.load(std::sync::atomic::Ordering::SeqCst), 0);
    release_completion.notify_one();

    let (original, during_replay) =
        bounded_join_pair("concurrent durable send completion", first, during).await;
    assert_eq!(during_replay, original);
    assert!(matches!(&original, SendMessageResponse::Task(task)
            if task.status.state == TaskState::Completed && task.history.is_none()));
    assert_eq!(effects.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        bounded(
            "gateway durable effect count",
            gateway.durable_effect_count()
        )
        .await
        .unwrap(),
        1
    );

    let after = bounded(
        "completed durable send replay",
        client(&base_url).await.send_message(&request),
    )
    .await
    .unwrap();
    assert_eq!(after, original);
    assert_eq!(effects.load(std::sync::atomic::Ordering::SeqCst), 1);

    shutdown_tx.send(()).unwrap();
    bounded_join("first server join", server).await;
    bounded("first gateway shutdown", gateway.shutdown())
        .await
        .unwrap();

    let endpoint = DurableLoopbackEndpoint::from_diagnostic_counter(Arc::clone(&effects));
    let (base_url, server, shutdown_tx, gateway) = start(&path, endpoint, clock).await;
    let restarted = bounded(
        "restarted durable send replay",
        client(&base_url).await.send_message(&request),
    )
    .await
    .unwrap();
    assert_eq!(restarted, original);
    assert_eq!(effects.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        bounded(
            "gateway durable effect count",
            gateway.durable_effect_count()
        )
        .await
        .unwrap(),
        1
    );

    shutdown_tx.send(()).unwrap();
    bounded_join("restarted server join", server).await;
    let retained_router = gateway.router();
    bounded("retained-router gateway shutdown", gateway.shutdown())
        .await
        .unwrap();

    // Explicit shutdown relinquishes shared SQLite state even while an Axum
    // router clone still retains the durable handler.
    let reacquired = bounded(
        "shared-store lock reacquisition",
        SqliteTaskStore::open(&path, 32),
    )
    .await
    .unwrap();
    drop(reacquired);
    drop(retained_router);
    cleanup(&path);
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One real-time duplicate/subscription/restart tracer.
async fn durable_jsonrpc_stream_replays_exact_ordered_transcript_after_restart() {
    let path = database_path();
    let clock = InjectedClock::new(1_700_000_050_000);
    let effect_started = Arc::new(Notify::new());
    let release_completion = Arc::new(Notify::new());
    let endpoint = DurableLoopbackEndpoint::with_completion_barrier(
        Arc::clone(&effect_started),
        Arc::clone(&release_completion),
    );
    let effects = endpoint.diagnostic_effect_counter();
    let (base_url, server, shutdown_tx, gateway) = start(&path, endpoint, clock.clone()).await;
    let card = bounded(
        "streaming agent-card resolution",
        AgentCardResolver::new(None).resolve(&base_url),
    )
    .await
    .unwrap();
    assert_eq!(card.capabilities.streaming, Some(true));

    let mut message = Message::new(Role::User, vec![Part::text("durable streaming transcript")]);
    message.message_id = "durable-stream-message-1".to_owned();
    let request = SendMessageRequest {
        message,
        configuration: None,
        metadata: None,
        tenant: None,
    };
    let first_client = client(&base_url).await;
    let mut first_stream = bounded(
        "open original durable stream",
        first_client.send_streaming_message(&request),
    )
    .await
    .unwrap();
    bounded("stream receiver effect barrier", effect_started.notified()).await;
    let initial = bounded("initial task before receiver release", first_stream.next())
        .await
        .expect("initial frame")
        .expect("initial frame is valid");
    let task_id = match &initial {
        StreamResponse::Task(task) if task.status.state == TaskState::Submitted => task.id.clone(),
        other => panic!("unexpected initial frame: {other:?}"),
    };
    let progress = bounded(
        "working status before receiver release",
        first_stream.next(),
    )
    .await
    .expect("working frame")
    .expect("working frame is valid");
    assert!(matches!(&progress, StreamResponse::StatusUpdate(update)
        if update.status.state == TaskState::Working));
    let duplicate_client = client(&base_url).await;
    let mut disconnected_active = bounded(
        "attach active duplicate stream",
        duplicate_client.send_streaming_message(&request),
    )
    .await
    .unwrap();
    let duplicate_initial = bounded("active duplicate initial", disconnected_active.next())
        .await
        .expect("duplicate initial")
        .expect("valid duplicate initial");
    let duplicate_progress = bounded("active duplicate progress", disconnected_active.next())
        .await
        .expect("duplicate progress")
        .expect("valid duplicate progress");
    assert_eq!(duplicate_initial, initial);
    assert_eq!(duplicate_progress, progress);
    drop(disconnected_active);
    let subscribe_client = client(&base_url).await;
    let mut subscription = bounded(
        "subscribe to active durable task",
        subscribe_client.subscribe_to_task(&SubscribeToTaskRequest {
            id: task_id.clone(),
            tenant: None,
        }),
    )
    .await
    .unwrap();
    let snapshot = bounded("active subscription snapshot", subscription.next())
        .await
        .expect("subscription snapshot")
        .expect("valid subscription snapshot");
    assert!(matches!(&snapshot, StreamResponse::Task(task)
        if task.status.state == TaskState::Working));
    let snapshot_cursor: usize = rusqlite::Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT frame_count FROM stream_transcripts WHERE task_id = ?1",
            [&task_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        snapshot_cursor, 2,
        "snapshot cursor follows initial and working frames"
    );
    assert_eq!(effects.load(std::sync::atomic::Ordering::SeqCst), 0);
    release_completion.notify_one();
    let mut original = vec![initial, progress];
    original.extend(
        bounded("original durable stream", first_stream.collect::<Vec<_>>())
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
    );
    let subscription_tail = bounded("active subscription tail", subscription.collect::<Vec<_>>())
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(subscription_tail.len(), original.len() - snapshot_cursor);
    assert_eq!(subscription_tail.as_slice(), &original[snapshot_cursor..]);
    assert!(
        subscription_tail
            .iter()
            .any(|frame| matches!(frame, StreamResponse::ArtifactUpdate(_)))
    );
    assert!(matches!(subscription_tail.last(),
        Some(StreamResponse::StatusUpdate(update)) if update.status.state == TaskState::Completed));

    assert!(matches!(
        original.first(),
        Some(StreamResponse::Task(task)) if task.status.state == TaskState::Submitted
    ));
    assert!(original.iter().any(|frame| matches!(
        frame,
        StreamResponse::StatusUpdate(update) if update.status.state == TaskState::Working
    )));
    assert!(
        original
            .iter()
            .any(|frame| matches!(frame, StreamResponse::ArtifactUpdate(_)))
    );
    assert!(matches!(
        original.last(),
        Some(StreamResponse::StatusUpdate(update)) if update.status.state == TaskState::Completed
    ));
    assert_eq!(
        original
            .iter()
            .filter(|frame| {
                matches!(frame, StreamResponse::Task(task) if task.status.state.is_terminal())
                    || matches!(frame, StreamResponse::StatusUpdate(update) if update.status.state.is_terminal())
            })
            .count(),
        1
    );
    assert_eq!(effects.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        bounded(
            "gateway durable effect count",
            gateway.durable_effect_count()
        )
        .await
        .unwrap(),
        1
    );

    // Disconnect after one committed frame. Work and replay remain independent
    // of this transport stream's lifetime.
    let disconnect_client = client(&base_url).await;
    let mut disconnected = bounded(
        "open disconnecting duplicate stream",
        disconnect_client.send_streaming_message(&request),
    )
    .await
    .unwrap();
    assert_eq!(
        bounded("completed duplicate first frame", disconnected.next())
            .await
            .unwrap()
            .unwrap(),
        original[0]
    );
    drop(disconnected);
    let duplicate = collect_stream(&client(&base_url).await, &request).await;
    assert_eq!(
        serde_json::to_vec(&duplicate).unwrap(),
        serde_json::to_vec(&original).unwrap()
    );
    assert_eq!(effects.load(std::sync::atomic::Ordering::SeqCst), 1);

    shutdown_tx.send(()).unwrap();
    bounded_join("stream server join", server).await;
    bounded("stream gateway shutdown", gateway.shutdown())
        .await
        .unwrap();

    let endpoint = DurableLoopbackEndpoint::from_diagnostic_counter(Arc::clone(&effects));
    let (base_url, server, shutdown_tx, gateway) = start(&path, endpoint, clock).await;
    let restarted = collect_stream(&client(&base_url).await, &request).await;
    assert_eq!(
        serde_json::to_vec(&restarted).unwrap(),
        serde_json::to_vec(&original).unwrap()
    );
    assert_eq!(effects.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        bounded(
            "gateway durable effect count",
            gateway.durable_effect_count()
        )
        .await
        .unwrap(),
        1
    );

    shutdown_tx.send(()).unwrap();
    bounded_join("restarted stream server join", server).await;
    bounded("restarted stream gateway shutdown", gateway.shutdown())
        .await
        .unwrap();
    cleanup(&path);
}

#[tokio::test]
async fn durable_stream_and_subscription_receive_one_canceled_terminal_then_close() {
    let path = database_path();
    let clock = InjectedClock::new(1_700_000_075_000);
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let endpoint = DurableLoopbackEndpoint::with_completion_barrier(Arc::clone(&started), release);
    let (base_url, server, shutdown_tx, gateway) = start(&path, endpoint, clock).await;
    let mut message = Message::new(Role::User, vec![Part::text("cancel durable stream")]);
    message.message_id = "durable-stream-cancel-1".to_owned();
    let request = SendMessageRequest {
        message,
        configuration: None,
        metadata: None,
        tenant: None,
    };
    let stream_client = client(&base_url).await;
    let mut stream = bounded(
        "open JSON-RPC cancellation stream",
        stream_client.send_streaming_message(&request),
    )
    .await
    .unwrap();
    bounded("stream cancellation receiver barrier", started.notified()).await;
    let initial = bounded("cancellation initial frame", stream.next())
        .await
        .unwrap()
        .unwrap();
    let task_id = match initial {
        StreamResponse::Task(task) => task.id,
        other => panic!("unexpected initial cancellation frame: {other:?}"),
    };
    let working = bounded("cancellation working frame", stream.next())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(working, StreamResponse::StatusUpdate(update)
        if update.status.state == TaskState::Working));

    let subscription_client = client(&base_url).await;
    let mut subscription = bounded(
        "open JSON-RPC cancellation subscription",
        subscription_client.subscribe_to_task(&SubscribeToTaskRequest {
            id: task_id.clone(),
            tenant: None,
        }),
    )
    .await
    .unwrap();
    let snapshot = bounded("cancellation subscription snapshot", subscription.next())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(snapshot, StreamResponse::Task(task)
        if task.status.state == TaskState::Working));
    let canceled = bounded(
        "JSON-RPC stream cancellation request",
        client(&base_url).await.cancel_task(&CancelTaskRequest {
            id: task_id,
            metadata: None,
            tenant: None,
        }),
    )
    .await
    .unwrap();
    assert_eq!(canceled.status.state, TaskState::Canceled);
    let tail = bounded("cancellation stream tail", stream.collect::<Vec<_>>())
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(tail.len(), 1);
    assert!(
        matches!(tail.first(), Some(StreamResponse::StatusUpdate(update))
        if update.status.state == TaskState::Canceled)
    );
    let subscription_tail = bounded(
        "cancellation subscription tail",
        subscription.collect::<Vec<_>>(),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    assert_eq!(subscription_tail, tail);
    assert_eq!(
        bounded(
            "gateway durable effect count",
            gateway.durable_effect_count()
        )
        .await
        .unwrap(),
        0
    );

    shutdown_tx.send(()).unwrap();
    bounded_join("cancellation stream server join", server).await;
    bounded("cancellation stream gateway shutdown", gateway.shutdown())
        .await
        .unwrap();
    cleanup(&path);
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One official-client active cancellation/replay tracer.
async fn durable_protocol_active_loopback_cancel_is_durable_and_cooperative() {
    let path = database_path();
    let clock = InjectedClock::new(1_700_000_000_000);
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let endpoint = DurableLoopbackEndpoint::with_completion_barrier(
        Arc::clone(&started),
        Arc::clone(&release),
    );
    let (base_url, server, shutdown_tx, gateway) = start(&path, endpoint, clock.clone()).await;

    let card = bounded(
        "protocol agent-card resolution",
        AgentCardResolver::new(None).resolve(&base_url),
    )
    .await
    .unwrap();
    assert_eq!(card.capabilities.streaming, Some(true));
    let client = client(&base_url).await;
    let mut message = Message::new(Role::User, vec![Part::text("return admitted snapshot")]);
    message.message_id = "durable-protocol-options-1".to_owned();
    let request = SendMessageRequest {
        message,
        configuration: Some(SendMessageConfiguration {
            accepted_output_modes: None,
            task_push_notification_config: None,
            history_length: None,
            return_immediately: Some(true),
        }),
        metadata: None,
        tenant: None,
    };
    let response = bounded(
        "immediate protocol admission",
        client.send_message(&request),
    )
    .await
    .unwrap();
    let SendMessageResponse::Task(admitted) = response else {
        panic!("durable admission must return a task");
    };
    assert_eq!(admitted.status.state, TaskState::Submitted);
    bounded("immediate request receiver barrier", started.notified()).await;

    let hidden = bounded(
        "protocol hidden-history lookup",
        client.get_task(&GetTaskRequest {
            id: admitted.id.clone(),
            history_length: Some(0),
            tenant: None,
        }),
    )
    .await
    .unwrap();
    assert!(hidden.history.is_none());
    let invalid = bounded(
        "protocol invalid-history lookup",
        client.get_task(&GetTaskRequest {
            id: admitted.id.clone(),
            history_length: Some(-1),
            tenant: None,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(invalid.code, error_code::INVALID_PARAMS);
    let tenant = bounded(
        "protocol tenant cancellation rejection",
        client.cancel_task(&CancelTaskRequest {
            id: admitted.id.clone(),
            metadata: None,
            tenant: Some("caller-controlled".to_owned()),
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(tenant.code, error_code::INVALID_PARAMS);
    let missing = bounded(
        "protocol missing-task cancellation",
        client.cancel_task(&CancelTaskRequest {
            id: "missing-durable-task".to_owned(),
            metadata: None,
            tenant: None,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(missing.code, error_code::TASK_NOT_FOUND);
    let active = bounded(
        "protocol active cancellation",
        client.cancel_task(&CancelTaskRequest {
            id: admitted.id.clone(),
            metadata: None,
            tenant: None,
        }),
    )
    .await
    .unwrap();
    assert_eq!(active.status.state, TaskState::Canceled);
    assert_eq!(
        bounded(
            "gateway durable effect count",
            gateway.durable_effect_count()
        )
        .await
        .unwrap(),
        0
    );
    let replay = bounded(
        "protocol canceled send replay",
        client.send_message(&request),
    )
    .await
    .unwrap();
    assert_eq!(replay, SendMessageResponse::Task(active.clone()));
    let late = bounded(
        "protocol late cancellation rejection",
        client.cancel_task(&CancelTaskRequest {
            id: admitted.id,
            metadata: None,
            tenant: None,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(late.code, error_code::TASK_NOT_CANCELABLE);

    shutdown_tx.send(()).unwrap();
    bounded_join("protocol server join", server).await;
    bounded("protocol gateway shutdown", gateway.shutdown())
        .await
        .unwrap();

    let (base_url, server, shutdown_tx, gateway) =
        start(&path, DurableLoopbackEndpoint::new(), clock).await;
    let restarted = bounded(
        "restarted canceled send replay",
        crate::client(&base_url).await.send_message(&request),
    )
    .await
    .unwrap();
    assert_eq!(restarted, replay);
    assert_eq!(
        bounded(
            "gateway durable effect count",
            gateway.durable_effect_count()
        )
        .await
        .unwrap(),
        0
    );
    shutdown_tx.send(()).unwrap();
    bounded_join("canceled replay server join", server).await;
    bounded("canceled replay gateway shutdown", gateway.shutdown())
        .await
        .unwrap();
    cleanup(&path);
}

#[tokio::test]
async fn receiver_completion_wins_cancel_race_and_cancel_replays_winner() {
    let path = database_path();
    let clock = InjectedClock::new(1_700_000_080_000);
    let started = Arc::new(Notify::new());
    let release_effect = Arc::new(Notify::new());
    let receiver_completed = Arc::new(Notify::new());
    let release_publish = Arc::new(Notify::new());
    let endpoint = DurableLoopbackEndpoint::with_completion_race_barrier(
        Arc::clone(&started),
        Arc::clone(&release_effect),
        Arc::clone(&receiver_completed),
        Arc::clone(&release_publish),
    );
    let (base_url, server, shutdown_tx, gateway) = start(&path, endpoint, clock).await;
    let mut message = Message::new(Role::User, vec![Part::text("completion wins cancel race")]);
    message.message_id = "completion-wins-cancel-race".to_owned();
    let request = SendMessageRequest {
        message,
        configuration: Some(SendMessageConfiguration {
            accepted_output_modes: None,
            task_push_notification_config: None,
            history_length: None,
            return_immediately: Some(true),
        }),
        metadata: None,
        tenant: None,
    };
    let admitted = bounded(
        "completion-race immediate admission",
        client(&base_url).await.send_message(&request),
    )
    .await
    .unwrap();
    let SendMessageResponse::Task(admitted) = admitted else {
        panic!("task admission");
    };
    bounded("completion race receiver start", started.notified()).await;
    release_effect.notify_one();
    bounded(
        "receiver completion winner commit",
        receiver_completed.notified(),
    )
    .await;
    let cancel_client = client(&base_url).await;
    let task_id = admitted.id;
    let cancel = tokio::spawn(async move {
        bounded(
            "spawned completion-race cancellation",
            cancel_client.cancel_task(&CancelTaskRequest {
                id: task_id,
                metadata: None,
                tenant: None,
            }),
        )
        .await
        .unwrap()
    });
    bounded(
        "completion-winner cancel attached",
        gateway.wait_for_waiter_count(1),
    )
    .await
    .unwrap();
    release_publish.notify_one();
    let winner = bounded_join("completion winner returned to cancel", cancel).await;
    assert_eq!(winner.status.state, TaskState::Completed);
    assert_eq!(
        bounded(
            "gateway durable effect count",
            gateway.durable_effect_count()
        )
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        bounded(
            "completion-winner send replay",
            client(&base_url).await.send_message(&request),
        )
        .await
        .unwrap(),
        SendMessageResponse::Task(winner)
    );

    shutdown_tx.send(()).unwrap();
    bounded_join("completion race server join", server).await;
    bounded("completion race gateway shutdown", gateway.shutdown())
        .await
        .unwrap();
    cleanup(&path);
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One end-to-end final-attempt crash reconciliation trace.
async fn max_attempts_one_crash_after_receiver_complete_is_committed_by_driver() {
    let path = database_path();
    let store = bounded("final-attempt store open", SqliteTaskStore::open(&path, 32))
        .await
        .unwrap();
    let mut message = Message::new(Role::User, vec![Part::text("final attempt crash")]);
    message.message_id = "final-attempt-driver-message".to_owned();
    message.task_id = Some("final-attempt-driver-task".to_owned());
    message.context_id = Some("final-attempt-driver-context".to_owned());
    let task = Task {
        id: "final-attempt-driver-task".to_owned(),
        context_id: "final-attempt-driver-context".to_owned(),
        status: TaskStatus {
            state: TaskState::Submitted,
            message: None,
            timestamp: chrono::DateTime::from_timestamp_millis(111),
        },
        artifacts: None,
        history: Some(vec![message.clone()]),
        metadata: None,
    };
    let send_request = SendMessageRequest {
        message,
        configuration: None,
        metadata: None,
        tenant: None,
    };
    bounded(
        "final-attempt message admission",
        Box::pin(store.admit_send_message(SendMessageAdmission {
            request: send_request.clone(),
            streaming: false,
            task: task.clone(),
            original_result: SendMessageResponse::Task(task),
            input_limits: InputLimits::default(),
            now: 100,
            max_attempts: 8,
        })),
    )
    .await
    .unwrap();
    // Preserve the handler's admission semantics while forcing this durable
    // sender row onto its final attempt for the crash-reconciliation probe.
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute("UPDATE outbox SET max_attempts = 1", [])
        .unwrap();
    let crashed_sender = bounded(
        "final-attempt outbox claim",
        store.claim_outbox("crashed-sender", 100, 10),
    )
    .await
    .unwrap()
    .unwrap();
    let payload = serde_json::to_vec(&crashed_sender.request).unwrap();
    let envelope = DurableDispatchEnvelope {
        tenant_scope: TRUSTED_SINGLE_TENANT_SCOPE.to_owned(),
        dispatch_id: crashed_sender.dispatch_id.clone(),
        payload_digest: content_digest(&payload),
        request: crashed_sender.request.clone(),
    };
    let ReceiverAdmission::Execute(receiver) = bounded(
        "final-attempt receiver admission",
        store.begin_receive(envelope, "receiver-before-crash", 100, 10),
    )
    .await
    .unwrap() else {
        panic!("receiver must accept the final sender attempt");
    };
    let events = vec![smesh_a2a::MeshEvent::Completed {
        summary: "receiver completed before sender crash".to_owned(),
    }];
    bounded(
        "final-attempt receiver completion",
        store.complete_loopback_receive(&receiver, &events, 101),
    )
    .await
    .unwrap();

    let listener = bounded(
        "final-attempt listener bind",
        tokio::net::TcpListener::bind("127.0.0.1:0"),
    )
    .await
    .unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let gateway = build_durable_loopback_gateway(
        GatewayConfig::new(&base_url, "durable-loopback"),
        store.clone(),
        DurableLoopbackEndpoint::new(),
        InjectedClock::new(111),
    )
    .unwrap();
    let app = gateway.router();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    let result = bounded(
        "driver final-attempt reconciliation",
        client(&base_url).await.send_message(&send_request),
    )
    .await
    .unwrap();
    assert!(matches!(
        result,
        SendMessageResponse::Task(task) if task.status.state == TaskState::Completed
    ));
    assert_eq!(
        bounded("store durable effect count", store.durable_effect_count())
            .await
            .unwrap(),
        1
    );
    shutdown_tx.send(()).unwrap();
    bounded_join("final-attempt server join", server).await;
    bounded("final-attempt gateway shutdown", gateway.shutdown())
        .await
        .unwrap();
    cleanup(&path);
}

#[tokio::test]
async fn active_blocked_dispatch_shutdown_requeues_fenced_attempt_and_stops_claiming() {
    let path = database_path();
    let clock = InjectedClock::new(1_700_000_100_000);
    let started = Arc::new(Notify::new());
    let never_release = Arc::new(Notify::new());
    let endpoint = DurableLoopbackEndpoint::with_completion_barrier(
        Arc::clone(&started),
        Arc::clone(&never_release),
    );
    let effects = endpoint.diagnostic_effect_counter();
    let (base_url, server, shutdown_tx, gateway) = start(&path, endpoint, clock.clone()).await;
    let mut message = Message::new(Role::User, vec![Part::text("blocked shutdown")]);
    message.message_id = "blocked-shutdown-message".to_owned();
    let response = bounded(
        "blocked-shutdown immediate admission",
        client(&base_url).await.send_message(&SendMessageRequest {
            message,
            configuration: Some(SendMessageConfiguration {
                accepted_output_modes: None,
                task_push_notification_config: None,
                history_length: None,
                return_immediately: Some(true),
            }),
            metadata: None,
            tenant: None,
        }),
    )
    .await
    .unwrap();
    assert!(
        matches!(response, SendMessageResponse::Task(task) if task.status.state == TaskState::Submitted)
    );
    bounded("blocked receiver dispatch barrier", started.notified()).await;

    bounded("active blocked gateway shutdown", gateway.shutdown())
        .await
        .unwrap();
    clock.advance_to(1_700_000_200_000);
    assert_eq!(effects.load(std::sync::atomic::Ordering::SeqCst), 0);
    shutdown_tx.send(()).unwrap();
    bounded_join("blocked dispatch server join", server).await;

    let connection = rusqlite::Connection::open(&path).unwrap();
    let durable: (
        String,
        i64,
        Option<String>,
        Option<String>,
        String,
        i64,
        i64,
    ) = connection
        .query_row(
            "SELECT o.state, o.attempt_count, a.outcome, a.error, r.state,
                    (SELECT COUNT(*) FROM loopback_effects),
                    (SELECT COUNT(*) FROM receiver_frames)
             FROM outbox o JOIN outbox_attempts a ON a.outbox_id = o.outbox_id
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
                    row.get(6)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(durable.1, 1);
    match (durable.0.as_str(), durable.2.as_deref(), durable.4.as_str()) {
        ("pending", Some("retry"), "processing") => {
            assert!(
                durable
                    .3
                    .as_deref()
                    .is_some_and(|error| error.contains("shutdown interrupted"))
            );
        }
        // If receiver cancellation wins the shutdown race, the accepted receiver row
        // remains the authoritative restart boundary. The attempt may be unfinished,
        // but it must remain leased/reconcilable rather than dead-lettered or retried
        // under a new effect identity.
        ("leased", None, "processing" | "completed") => assert!(durable.3.is_none()),
        ("delivered", Some("delivered"), "completed") => {}
        state => panic!("unexpected durable shutdown arbitration state: {state:?}"),
    }
    assert_eq!(durable.5, 0);
    if durable.0 != "delivered" {
        assert_eq!(durable.6, 0);
    }
    cleanup(&path);
}

const CONTINUATION_RESTART_NOW: i64 = 1_700_000_300_000;

fn restart_fixture_requests() -> (SendMessageRequest, SendMessageRequest) {
    let original = continuation_request(
        "continuation-restart-original",
        "continuation-restart-interrupt",
        None,
    );
    let identity = content_digest(original.message.message_id.as_bytes());
    let task_id = format!("task-{}", &identity[..32]);
    let context_id = format!("context-{}", &identity[32..]);
    let continuation = continuation_request(
        "continuation-restart-current",
        "continuation-restart-resume",
        Some((&task_id, &context_id)),
    );
    (original, continuation)
}

#[test]
#[allow(clippy::too_many_lines)] // The child checkpoint fixture keeps each durable phase explicit.
fn continuation_restart_checkpoint_helper() {
    let Ok(path) = std::env::var("SMESH_CONTINUATION_RESTART_DB") else {
        return;
    };
    let checkpoint = std::env::var("SMESH_CONTINUATION_RESTART_CHECKPOINT").unwrap();
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let (original, continuation) = restart_fixture_requests();
        let endpoint = DurableLoopbackEndpoint::with_interruption_for_text(
            "continuation-restart-interrupt",
            DurableInterruptionKind::InputRequired,
            "continuation restart approval required",
        );
        let clock = InjectedClock::new(CONTINUATION_RESTART_NOW);
        let (base_url, server, shutdown_tx, gateway) =
            start(Path::new(&path), endpoint, clock).await;
        let interrupted = bounded(
            "child initial interruption",
            client(&base_url).await.send_message(&original),
        )
        .await
        .unwrap();
        assert!(matches!(&interrupted, SendMessageResponse::Task(task)
            if task.status.state == TaskState::InputRequired));
        shutdown_tx.send(()).unwrap();
        bounded_join("child initial server join", server).await;
        bounded("child initial gateway shutdown", gateway.shutdown())
            .await
            .unwrap();

        let store = bounded(
            "continuation checkpoint store open",
            SqliteTaskStore::open(&path, 32),
        )
        .await
        .unwrap();
        let SendMessageResponse::Task(interrupted_task) = interrupted else {
            unreachable!()
        };
        bounded(
            "continuation checkpoint admission",
            store.admit_continuation(SendMessageAdmission {
                request: continuation,
                streaming: false,
                task: interrupted_task.clone(),
                original_result: SendMessageResponse::Task(interrupted_task),
                input_limits: InputLimits::default(),
                now: CONTINUATION_RESTART_NOW,
                max_attempts: 8,
            }),
        )
        .await
        .unwrap();

        if checkpoint != "before_driver_claim" {
            let sender = bounded(
                "continuation checkpoint outbox claim",
                store.claim_outbox(
                    "continuation-restart-child-sender",
                    CONTINUATION_RESTART_NOW,
                    60_000,
                ),
            )
            .await
            .unwrap()
            .unwrap();
            let payload = serde_json::to_string(&sender.request).unwrap();
            let envelope = DurableDispatchEnvelope {
                tenant_scope: TRUSTED_SINGLE_TENANT_SCOPE.to_owned(),
                dispatch_id: sender.dispatch_id,
                payload_digest: content_digest(payload.as_bytes()),
                request: sender.request,
            };
            let ReceiverAdmission::Execute(receiver) = bounded(
                "continuation checkpoint receiver admission",
                store.begin_receive(
                    envelope,
                    "continuation-restart-child-receiver",
                    CONTINUATION_RESTART_NOW,
                    60_000,
                ),
            )
            .await
            .unwrap() else {
                panic!("continuation receiver must accept exactly once in child");
            };
            if checkpoint == "receiver_completed_before_sender_commit" {
                bounded(
                    "continuation checkpoint receiver completion",
                    store.complete_loopback_receive(
                        &receiver,
                        &[
                            MeshEvent::Progress("continuation resumed after restart".to_owned()),
                            MeshEvent::Completed {
                                summary: "continuation receiver completed before crash".to_owned(),
                            },
                        ],
                        CONTINUATION_RESTART_NOW,
                    ),
                )
                .await
                .unwrap();
            }
        }

        println!("{}", serde_json::json!({ "checkpoint": checkpoint }));
        std::io::stdout().flush().unwrap();
        let mut release = String::new();
        std::io::stdin().read_line(&mut release).unwrap();
        drop(store);
    });
}

fn terminate_continuation_helper_at(path: &Path, checkpoint: &str) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "continuation_restart_checkpoint_helper",
            "--nocapture",
        ])
        .env("SMESH_CONTINUATION_RESTART_DB", path)
        .env("SMESH_CONTINUATION_RESTART_CHECKPOINT", checkpoint)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let output = child.stdout.take().unwrap();
    let (line_tx, line_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(output).lines() {
            if line_tx.send(line).is_err() {
                break;
            }
        }
    });
    loop {
        let line = match line_rx.recv_timeout(WATCHDOG) {
            Ok(Ok(line)) => line,
            Ok(Err(error)) => {
                let _ = kill_and_reap_child("continuation checkpoint helper", &mut child);
                panic!("failed reading continuation helper: {error}");
            }
            Err(error) => {
                let _ = kill_and_reap_child("continuation checkpoint helper", &mut child);
                panic!("timed out waiting for continuation checkpoint {checkpoint}: {error}");
            }
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        if value.get("checkpoint").and_then(serde_json::Value::as_str) == Some(checkpoint) {
            break;
        }
    }
    child.kill().unwrap();
    let status = bounded_child_wait("terminated continuation helper", &mut child);
    assert!(!status.success());
}

async fn assert_continuation_restart(checkpoint: &str, expected_attempts: i64) {
    let path = database_path();
    terminate_continuation_helper_at(&path, checkpoint);
    let (original_request, continuation) = restart_fixture_requests();
    let clock = InjectedClock::new(CONTINUATION_RESTART_NOW);
    let (base_url, server, shutdown_tx, gateway) =
        start(&path, DurableLoopbackEndpoint::new(), clock).await;

    let original = bounded(
        "restarted original interruption replay",
        client(&base_url).await.send_message(&original_request),
    )
    .await
    .unwrap();
    assert!(matches!(&original, SendMessageResponse::Task(task)
        if task.status.state == TaskState::InputRequired
            && task.history.as_ref().is_some_and(|history| history.len() == 1)));
    let current = bounded(
        "restarted continuation completion",
        client(&base_url).await.send_message(&continuation),
    )
    .await
    .unwrap();
    assert!(matches!(&current, SendMessageResponse::Task(task)
        if task.status.state == TaskState::Completed
            && task.history.as_ref().is_some_and(|history| history.len() == 2)));
    assert_eq!(
        serde_json::to_vec(
            &bounded(
                "exact original replay after continuation",
                client(&base_url).await.send_message(&original_request),
            )
            .await
            .unwrap(),
        )
        .unwrap(),
        serde_json::to_vec(&original).unwrap()
    );
    assert_eq!(
        serde_json::to_vec(
            &bounded(
                "exact current continuation replay",
                client(&base_url).await.send_message(&continuation),
            )
            .await
            .unwrap(),
        )
        .unwrap(),
        serde_json::to_vec(&current).unwrap()
    );
    assert_eq!(
        bounded(
            "gateway durable effect count",
            gateway.durable_effect_count()
        )
        .await
        .unwrap(),
        2
    );

    shutdown_tx.send(()).unwrap();
    bounded_join("continuation restart server join", server).await;
    bounded("continuation restart gateway shutdown", gateway.shutdown())
        .await
        .unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    let durable: (i64, i64, i64, i64) = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM loopback_effects effects JOIN outbox sender
                 ON sender.dispatch_id = effects.dispatch_id
                 WHERE sender.message_id = 'continuation-restart-current'),
                (SELECT COUNT(*) FROM receiver_frames frames JOIN outbox sender
                 ON sender.dispatch_id = frames.dispatch_id
                 WHERE sender.message_id = 'continuation-restart-current'),
                (SELECT COUNT(*) FROM outbox_attempts attempts JOIN outbox sender
                 ON sender.outbox_id = attempts.outbox_id
                 WHERE sender.message_id = 'continuation-restart-current'),
                (SELECT COUNT(*) FROM idempotency_records
                 WHERE message_id IN ('continuation-restart-original', 'continuation-restart-current')
                   AND final_result_json IS NOT NULL)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(durable.0, 1, "one continuation loopback effect marker");
    assert!(
        durable.1 >= 2,
        "continuation receiver transcript is durable"
    );
    assert_eq!(durable.2, expected_attempts);
    assert_eq!(durable.3, 2, "both message results are durable");
    drop(connection);
    cleanup(&path);
}

#[tokio::test]
async fn continuation_restart_after_admission_before_driver_claim_replays_both_messages_exactly() {
    assert_continuation_restart("before_driver_claim", 1).await;
}

#[tokio::test]
async fn continuation_restart_after_receiver_acceptance_reclaims_one_effect_and_transcript() {
    assert_continuation_restart("receiver_accepted_before_result", 1).await;
}

#[tokio::test]
async fn continuation_restart_after_receiver_completion_reconciles_without_second_attempt() {
    assert_continuation_restart("receiver_completed_before_sender_commit", 1).await;
}

#[tokio::test]
async fn active_continuation_cancel_and_barrier_blocked_shutdown_are_bounded_and_reopenable() {
    let path = database_path();
    let clock = InjectedClock::new(CONTINUATION_RESTART_NOW);
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let endpoint = DurableLoopbackEndpoint::with_interruption_for_text(
        "continuation-restart-interrupt",
        DurableInterruptionKind::AuthRequired,
        "continuation restart authentication required",
    )
    .with_barrier(Arc::clone(&started), Arc::clone(&release));
    let (base_url, server, shutdown_tx, gateway) = start(&path, endpoint, clock).await;
    let (original_request, mut continuation) = restart_fixture_requests();
    let initial_release = tokio::spawn({
        let started = Arc::clone(&started);
        let release = Arc::clone(&release);
        async move {
            started.notified().await;
            release.notify_one();
        }
    });
    let interrupted = bounded(
        "auth-required setup",
        client(&base_url).await.send_message(&original_request),
    )
    .await
    .unwrap();
    bounded_join("auth-required setup barrier", initial_release).await;
    let SendMessageResponse::Task(interrupted) = interrupted else {
        panic!("interrupted task")
    };
    assert_eq!(interrupted.status.state, TaskState::AuthRequired);
    continuation.configuration = Some(SendMessageConfiguration {
        accepted_output_modes: None,
        task_push_notification_config: None,
        history_length: None,
        return_immediately: Some(true),
    });
    let admitted = bounded(
        "barrier-blocked continuation admission",
        client(&base_url).await.send_message(&continuation),
    )
    .await
    .unwrap();
    bounded("active continuation receiver barrier", started.notified()).await;
    let canceled = bounded(
        "active continuation cancellation",
        client(&base_url).await.cancel_task(&CancelTaskRequest {
            id: interrupted.id,
            metadata: None,
            tenant: None,
        }),
    )
    .await
    .unwrap();
    assert_eq!(canceled.status.state, TaskState::Canceled);
    assert_ne!(admitted, SendMessageResponse::Task(canceled.clone()));
    bounded(
        "barrier-blocked continuation gateway shutdown",
        gateway.shutdown(),
    )
    .await
    .unwrap();
    shutdown_tx.send(()).unwrap();
    bounded_join("barrier-blocked continuation server join", server).await;

    let reopened = bounded(
        "continuation database reopen after cancellation shutdown",
        SqliteTaskStore::open(&path, 32),
    )
    .await
    .unwrap();
    assert_eq!(
        bounded(
            "reopened continuation final result lookup",
            reopened.final_result_for_message("continuation-restart-current"),
        )
        .await
        .unwrap(),
        Some(SendMessageResponse::Task(canceled))
    );
    bounded(
        "reopened continuation store shutdown",
        reopened.shutdown_shared(),
    )
    .await
    .unwrap();
    cleanup(&path);
}
