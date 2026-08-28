use std::{
    io::{BufRead as _, BufReader, Read as _},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use wait_timeout::ChildExt as _;

struct TempDir(PathBuf);
impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "smesh-a2a-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct ChildGuard(Option<Child>);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait_timeout(Duration::from_secs(2));
        }
    }
}

fn policy_json() -> &'static [u8] {
    br#"{
      "schemaVersion":"smesh-authz-policy/v1",
      "policyId":"gateway-main",
      "revision":1,
      "tenants":[{"id":"tenant-a","enabled":true}],
      "accounts":[{"id":"operator","kind":"human","memberships":[{"tenantId":"tenant-a","roles":["taskOperator"]}]}],
      "principalBindings":[{"principal":{"issuer":"https://issuer.example","subject":"operator"},"accountId":"operator"}]
    }"#
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
    if let Some(status) = child.wait_timeout(timeout).unwrap() {
        return Some(status);
    }
    child.kill().expect("kill timed-out child");
    child
        .wait_timeout(timeout)
        .expect("wait for killed child")
        .expect("killed child exits within deadline");
    None
}

#[test]
fn absent_auth_mode_fails_before_listener_and_sqlite_initialization() {
    let root = TempDir::new("required-auth");
    let database = root.0.join("must-not-exist.sqlite");
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = probe.local_addr().unwrap();
    drop(probe);

    let child = Command::new(env!("CARGO_BIN_EXE_smesh-a2a-gateway"))
        .env_clear()
        .env("SMESH_A2A_MODE", "loopback")
        .env("SMESH_A2A_BIND", address.to_string())
        .env("SMESH_A2A_DURABLE_BACKEND", "sqlite")
        .env("SMESH_A2A_SQLITE_PATH", &database)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = ChildGuard(Some(child));
    let status = wait_for_exit(child.0.as_mut().unwrap(), Duration::from_secs(2))
        .expect("missing required OIDC configuration must fail promptly");

    assert!(!status.success());
    let mut stderr = String::new();
    child
        .0
        .as_mut()
        .unwrap()
        .stderr
        .as_mut()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(
        stderr.contains("SMESH_A2A_OIDC_ISSUER"),
        "failure must specifically be missing required OIDC configuration: {stderr}"
    );
    assert!(
        !database.exists(),
        "authentication must fail before SQLite opens"
    );
    let rebound = std::net::TcpListener::bind(address)
        .expect("authentication must fail before binding the listener");
    drop(rebound);
}

#[test]
fn explicit_disabled_auth_starts_only_on_loopback_for_local_development() {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = probe.local_addr().unwrap();
    drop(probe);

    let mut child = Command::new(env!("CARGO_BIN_EXE_smesh-a2a-gateway"))
        .env_clear()
        .env("SMESH_A2A_AUTH_MODE", "disabled")
        .env("SMESH_A2A_MODE", "loopback")
        .env("SMESH_A2A_BIND", address.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let output = child.stderr.take().expect("capture gateway stderr");
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let output_reader = std::thread::spawn(move || {
        let mut captured = String::new();
        for line in BufReader::new(output).lines() {
            match line {
                Ok(line) => {
                    captured.push_str(&line);
                    captured.push('\n');
                    if line.contains("gateway listening") {
                        let _ = ready_tx.send(Ok(captured));
                        let _ = done_tx.send(());
                        return;
                    }
                }
                Err(error) => {
                    let _ = ready_tx.send(Err(format!(
                        "failed reading gateway output: {error}; output: {captured}"
                    )));
                    let _ = done_tx.send(());
                    return;
                }
            }
        }
        let _ = ready_tx.send(Err(format!(
            "gateway output closed before readiness; output: {captured}"
        )));
        let _ = done_tx.send(());
    });
    let mut child = ChildGuard(Some(child));
    let readiness = match ready_rx.recv_timeout(Duration::from_secs(2)) {
        Ok(result) => result,
        Err(error) => {
            let child = child.0.as_mut().unwrap();
            let _ = child.kill();
            let _ = child.wait_timeout(Duration::from_secs(2));
            panic!("explicit local-development opt-out readiness timed out: {error}");
        }
    };
    readiness.unwrap_or_else(|error| panic!("explicit local-development opt-out failed: {error}"));
    child.0.as_mut().unwrap().kill().unwrap();
    wait_for_exit(child.0.as_mut().unwrap(), Duration::from_secs(2))
        .expect("disabled development gateway must stop within deadline");
    done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("gateway output reader completion deadline");
    output_reader.join().expect("gateway output reader thread");
}

#[test]
fn bind_conflicts_fail_before_durable_or_runtime_resources() {
    let root = TempDir::new("bind-conflict");
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let public_address = occupied.local_addr().unwrap();

    let database = root.0.join("must-not-exist.sqlite");
    let child = Command::new(env!("CARGO_BIN_EXE_smesh-a2a-gateway"))
        .env_clear()
        .env("SMESH_A2A_AUTH_MODE", "disabled")
        .env("SMESH_A2A_MODE", "loopback")
        .env("SMESH_A2A_BIND", public_address.to_string())
        .env("SMESH_A2A_DURABLE_BACKEND", "sqlite")
        .env("SMESH_A2A_SQLITE_PATH", &database)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = ChildGuard(Some(child));
    let status = wait_for_exit(child.0.as_mut().unwrap(), Duration::from_secs(2))
        .expect("durable bind conflict must fail promptly");
    assert!(!status.success());
    assert!(!database.exists(), "bind conflict must precede SQLite open");

    let mesh_probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mesh_address = mesh_probe.local_addr().unwrap();
    drop(mesh_probe);
    let trace = root.0.join("must-not-exist.trace.json");
    let child = Command::new(env!("CARGO_BIN_EXE_smesh-a2a-gateway"))
        .env_clear()
        .env("SMESH_A2A_AUTH_MODE", "disabled")
        .env("SMESH_A2A_MODE", "runtime")
        .env("SMESH_A2A_BIND", public_address.to_string())
        .env("SMESH_A2A_MESH_BIND", mesh_address.to_string())
        .env("SMESH_RUNTIME_TRACE_PATH", &trace)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = ChildGuard(Some(child));
    let status = wait_for_exit(child.0.as_mut().unwrap(), Duration::from_secs(2))
        .expect("runtime bind conflict must fail promptly");
    assert!(!status.success());
    assert!(!trace.exists(), "bind conflict must precede trace startup");
    let rebound =
        std::net::TcpListener::bind(mesh_address).expect("bind conflict must leave mesh port free");
    drop(rebound);
}

#[test]
fn mismatched_tls_public_host_fails_before_listener_and_sqlite() {
    let root = TempDir::new("tls-host-mismatch");
    let database = root.0.join("must-not-exist.sqlite");
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = probe.local_addr().unwrap();
    drop(probe);
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls");

    let child = Command::new(env!("CARGO_BIN_EXE_smesh-a2a-gateway"))
        .env_clear()
        .env("SMESH_A2A_AUTH_MODE", "disabled")
        .env("SMESH_A2A_MODE", "loopback")
        .env("SMESH_A2A_BIND", address.to_string())
        .env("SMESH_A2A_PUBLIC_URL", "https://gateway.example")
        .env("SMESH_A2A_TRANSPORT_MODE", "direct-tls")
        .env("SMESH_A2A_CLIENT_AUTH_MODE", "required")
        .env("SMESH_A2A_TLS_CERT_PATH", fixtures.join("server.pem"))
        .env("SMESH_A2A_TLS_KEY_PATH", fixtures.join("server.key"))
        .env(
            "SMESH_A2A_TLS_CLIENT_CA_PATH",
            fixtures.join("client-ca.pem"),
        )
        .env(
            "SMESH_A2A_TLS_PRINCIPAL_MAP_PATH",
            fixtures.join("principals.json"),
        )
        .env("SMESH_A2A_DURABLE_BACKEND", "sqlite")
        .env("SMESH_A2A_SQLITE_PATH", &database)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = ChildGuard(Some(child));
    let status = wait_for_exit(child.0.as_mut().unwrap(), Duration::from_secs(2))
        .expect("TLS hostname mismatch must fail promptly");
    assert!(!status.success());
    assert!(
        !database.exists(),
        "hostname mismatch must precede SQLite open"
    );
    let rebound =
        std::net::TcpListener::bind(address).expect("hostname mismatch must precede listener bind");
    drop(rebound);
}

#[test]
fn authentication_and_policy_startup_matrix_fails_closed_before_resources() {
    for client_auth in ["required", "optional"] {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = probe.local_addr().unwrap();
        drop(probe);
        let child = Command::new(env!("CARGO_BIN_EXE_smesh-a2a-gateway"))
            .env_clear()
            .env("SMESH_A2A_AUTH_MODE", "disabled")
            .env("SMESH_A2A_CLIENT_AUTH_MODE", client_auth)
            .env("SMESH_A2A_MODE", "loopback")
            .env("SMESH_A2A_BIND", address.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut child = ChildGuard(Some(child));
        let status = wait_for_exit(child.0.as_mut().unwrap(), Duration::from_secs(2))
            .expect("mTLS without policy must fail promptly");
        assert!(!status.success());
        drop(std::net::TcpListener::bind(address).expect("failure precedes listener bind"));
    }

    let root = TempDir::new("policy-without-auth");
    let policy = root.0.join("policy.json");
    let database = root.0.join("must-not-exist.sqlite");
    std::fs::write(&policy, policy_json()).unwrap();
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = probe.local_addr().unwrap();
    drop(probe);
    let child = Command::new(env!("CARGO_BIN_EXE_smesh-a2a-gateway"))
        .env_clear()
        .env("SMESH_A2A_AUTH_MODE", "disabled")
        .env("SMESH_A2A_AUTHORIZATION_POLICY_PATH", &policy)
        .env("SMESH_A2A_DURABLE_BACKEND", "sqlite")
        .env("SMESH_A2A_SQLITE_PATH", &database)
        .env("SMESH_A2A_MODE", "loopback")
        .env("SMESH_A2A_BIND", address.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = ChildGuard(Some(child));
    let status = wait_for_exit(child.0.as_mut().unwrap(), Duration::from_secs(2))
        .expect("policy without authentication must fail promptly");
    assert!(!status.success());
    assert!(!database.exists());
    drop(std::net::TcpListener::bind(address).expect("failure precedes listener bind"));

    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = probe.local_addr().unwrap();
    drop(probe);
    let child = Command::new(env!("CARGO_BIN_EXE_smesh-a2a-gateway"))
        .env_clear()
        .env("SMESH_A2A_AUTH_MODE", "oidc")
        .env("SMESH_A2A_OIDC_ISSUER", "https://issuer.example")
        .env("SMESH_A2A_MODE", "loopback")
        .env("SMESH_A2A_BIND", address.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = ChildGuard(Some(child));
    let status = wait_for_exit(child.0.as_mut().unwrap(), Duration::from_secs(2))
        .expect("OIDC without policy must fail promptly");
    assert!(!status.success());
    drop(std::net::TcpListener::bind(address).expect("failure precedes listener bind"));
}

#[test]
fn process_watchdogs_are_event_driven() {
    let source = include_str!("production_auth_defaults.rs");
    let blocking_pause = String::from_utf8(vec![115, 108, 101, 101, 112]).unwrap();
    let cooperative_pause = String::from_utf8(vec![121, 105, 101, 108, 100]).unwrap();
    for forbidden in [
        format!("thread::{blocking_pause}"),
        format!("thread::{cooperative_pause}"),
        format!("tokio::time::{blocking_pause}"),
    ] {
        assert!(
            !source.contains(&forbidden),
            "process readiness/exit tests must not use polling pauses"
        );
    }
}
