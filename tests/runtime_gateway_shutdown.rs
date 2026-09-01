#![cfg(unix)]

use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use smesh_a2a::RuntimeEventCapture;
use tokio::process::Command;

#[tokio::test]
async fn sigint_gracefully_persists_a_replayable_runtime_trace() {
    let trace_path = std::env::temp_dir().join(format!(
        "smesh-runtime-shutdown-{}-{}.json",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let gateway_addr = probe.local_addr().unwrap();
    drop(probe);
    let mut child = Command::new(env!("CARGO_BIN_EXE_smesh-a2a-gateway"))
        .env_clear()
        .env("SMESH_A2A_AUTH_MODE", "disabled")
        .env("SMESH_A2A_MODE", "runtime")
        .env("SMESH_A2A_BIND", gateway_addr.to_string())
        .env("SMESH_A2A_MESH_BIND", "127.0.0.1:0")
        .env("SMESH_RUNTIME_TRACE_PATH", &trace_path)
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if tokio::net::TcpStream::connect(gateway_addr).await.is_ok() {
                break;
            }
            if let Some(status) = child.try_wait().unwrap() {
                panic!("runtime gateway exited before readiness: {status}");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();

    let process_id = child.id().unwrap();
    let signal = Command::new("/usr/bin/kill")
        .arg("-INT")
        .arg(process_id.to_string())
        .status()
        .await
        .unwrap();
    assert!(signal.success());
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(status.success());

    let bytes = std::fs::read(&trace_path).unwrap();
    RuntimeEventCapture::replay(&bytes).unwrap();
    std::fs::remove_file(trace_path).unwrap();
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One process saturation, canary, shutdown, and replay proof.
async fn saturated_runtime_trace_keeps_gateway_alive_and_healthy_work_bounded() {
    let trace_path = std::env::temp_dir().join(format!(
        "smesh-runtime-saturation-{}-{}.json",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let gateway_addr = probe.local_addr().unwrap();
    drop(probe);
    let mut child = Command::new(env!("CARGO_BIN_EXE_smesh-a2a-gateway"))
        .env_clear()
        .env("SMESH_A2A_AUTH_MODE", "disabled")
        .env("SMESH_A2A_MODE", "runtime")
        .env("SMESH_A2A_BIND", gateway_addr.to_string())
        .env("SMESH_A2A_MESH_BIND", "127.0.0.1:0")
        .env("SMESH_A2A_RUNTIME_TRACE_REQUIRED_CAPACITY", "8")
        .env("SMESH_A2A_RUNTIME_TRACE_OPTIONAL_CAPACITY", "1")
        .env("SMESH_A2A_RUNTIME_TRACE_PER_WORKLOAD_CAPACITY", "2")
        .env("SMESH_RUNTIME_TRACE_PATH", &trace_path)
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if tokio::net::TcpStream::connect(gateway_addr).await.is_ok() {
                break;
            }
            if let Some(status) = child.try_wait().unwrap() {
                panic!("runtime gateway exited before readiness: {status}");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();

    let client = reqwest::Client::new();
    let endpoint = format!("http://{gateway_addr}/jsonrpc");
    let send = |message_id: String| {
        let client = client.clone();
        let endpoint = endpoint.clone();
        async move {
            tokio::time::timeout(
                Duration::from_secs(2),
                client
                    .post(endpoint)
                    .json(&serde_json::json!({
                        "jsonrpc":"2.0",
                        "id":message_id,
                        "method":a2a::jsonrpc::methods::SEND_MESSAGE,
                        "params":{
                            "message":{
                                "messageId":message_id,
                                "role":"ROLE_USER",
                                "parts":[{"text":"bounded trace qualification"}]
                            },
                            "configuration":{"returnImmediately":false}
                        }
                    }))
                    .send(),
            )
            .await
            .unwrap()
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap()
        }
    };
    for offender in 0..24 {
        let response = send(format!("offender-{offender}")).await;
        assert!(response.get("result").is_some(), "{response}");
    }
    let started = std::time::Instant::now();
    let healthy = send("healthy-canary".to_owned()).await;
    assert!(started.elapsed() < Duration::from_secs(1));
    let healthy_task = healthy["result"]["task"]["id"]
        .as_str()
        .expect("healthy task id")
        .to_owned();
    assert!(
        child.try_wait().unwrap().is_none(),
        "gateway exited under saturation"
    );

    let signal = Command::new("/usr/bin/kill")
        .arg("-INT")
        .arg(child.id().unwrap().to_string())
        .status()
        .await
        .unwrap();
    assert!(signal.success());
    assert!(
        tokio::time::timeout(Duration::from_secs(10), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    let trace = RuntimeEventCapture::replay(&std::fs::read(&trace_path).unwrap()).unwrap();
    assert!(
        trace
            .events
            .iter()
            .filter(|event| event.kind != smesh_a2a::RuntimeTraceKind::TickCompleted)
            .count()
            <= 8
    );
    assert!(trace.events.iter().any(|event| {
        event.task_id.as_deref() == Some(&healthy_task)
            && event.kind == smesh_a2a::RuntimeTraceKind::TerminalOutput
    }));
    assert!(trace.events.iter().any(|event| {
        event.task_id.as_deref() == Some(&healthy_task)
            && event.kind == smesh_a2a::RuntimeTraceKind::SignalEmitted
    }));
    std::fs::remove_file(trace_path).unwrap();
}

#[tokio::test]
async fn invalid_runtime_trace_windows_fail_before_serving() {
    for overrides in [
        vec![("SMESH_A2A_RUNTIME_TRACE_REQUIRED_CAPACITY", "1")],
        vec![("SMESH_A2A_RUNTIME_TRACE_PER_WORKLOAD_CAPACITY", "1")],
        vec![
            ("SMESH_A2A_RUNTIME_TRACE_REQUIRED_CAPACITY", "800"),
            ("SMESH_A2A_RUNTIME_TRACE_OPTIONAL_CAPACITY", "300"),
        ],
    ] {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let gateway_addr = probe.local_addr().unwrap();
        drop(probe);
        let mut command = Command::new(env!("CARGO_BIN_EXE_smesh-a2a-gateway"));
        command
            .env_clear()
            .env("SMESH_A2A_AUTH_MODE", "disabled")
            .env("SMESH_A2A_MODE", "runtime")
            .env("SMESH_A2A_BIND", gateway_addr.to_string())
            .env("SMESH_A2A_MESH_BIND", "127.0.0.1:0")
            .kill_on_drop(true)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (name, value) in overrides {
            command.env(name, value);
        }
        let mut child = command.spawn().unwrap();
        let status = tokio::time::timeout(Duration::from_secs(3), child.wait())
            .await
            .unwrap()
            .unwrap();
        assert!(!status.success());
        let rebound = std::net::TcpListener::bind(gateway_addr).unwrap();
        drop(rebound);
    }
}
