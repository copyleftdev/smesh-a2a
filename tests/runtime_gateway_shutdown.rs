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
