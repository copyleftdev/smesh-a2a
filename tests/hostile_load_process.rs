#![cfg(target_os = "linux")]
#![allow(clippy::too_many_lines)]

#[path = "support/fault_proxy.rs"]
mod fault_proxy;
#[path = "support/load_metrics.rs"]
mod load_metrics;

use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fault_proxy::{FaultMode, FaultProxy};
use load_metrics::{
    nearest_rank_percentile, process_fd_count, process_rss_bytes, sqlite_file_set_bytes,
};
use tokio::io::AsyncWriteExt as _;
use tokio::process::{Child, Command};
use tokio::sync::Barrier;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

const REQUEST_DEADLINE: Duration = Duration::from_secs(2);
const PROCESS_WATCHDOG: Duration = Duration::from_secs(10);
const MIB: u64 = 1024 * 1024;

struct Fixture {
    path: Option<PathBuf>,
}

impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "smesh-hostile-load-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self { path: Some(path) }
    }

    fn path(&self) -> &Path {
        self.path.as_deref().expect("live hostile-load fixture")
    }

    fn cleanup(&mut self) {
        let path = self.path.take().expect("live hostile-load fixture");
        std::fs::remove_dir_all(&path).unwrap();
        assert!(!path.exists(), "hostile-load fixture root leaked");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

fn free_address() -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    address
}

fn spawn_gateway(address: std::net::SocketAddr, database: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_smesh-a2a-gateway"))
        .env_clear()
        .env("SMESH_A2A_AUTH_MODE", "disabled")
        .env("SMESH_A2A_MODE", "loopback")
        .env("SMESH_A2A_BIND", address.to_string())
        .env("SMESH_A2A_PUBLIC_URL", format!("http://{address}"))
        .env("SMESH_A2A_DURABLE_BACKEND", "sqlite")
        .env("SMESH_A2A_SQLITE_PATH", database)
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

async fn wait_ready(child: &mut Child, address: std::net::SocketAddr) {
    let deadline = tokio::time::Instant::now() + PROCESS_WATCHDOG;
    let mut interval = tokio::time::interval(Duration::from_millis(20));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        assert!(
            tokio::time::timeout_at(deadline, interval.tick())
                .await
                .is_ok(),
            "gateway readiness exceeded watchdog"
        );
        if tokio::net::TcpStream::connect(address).await.is_ok() {
            return;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("gateway exited before readiness: {status}");
        }
    }
}

fn send_body(message_id: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc":"2.0",
        "id":message_id,
        "method":a2a::jsonrpc::methods::SEND_MESSAGE,
        "params":{
            "message":{
                "messageId":message_id,
                "role":"ROLE_USER",
                "parts":[{"text":"hostile-load-canary"}]
            },
            "configuration":{"returnImmediately":false}
        }
    })
}

async fn send_canary(client: &reqwest::Client, endpoint: &str, message_id: &str) -> (u64, bool) {
    let started = Instant::now();
    let response = tokio::time::timeout(REQUEST_DEADLINE, async {
        let response = client
            .post(endpoint)
            .json(&send_body(message_id))
            .send()
            .await?;
        response.json::<serde_json::Value>().await
    })
    .await;
    let elapsed = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    (
        elapsed,
        matches!(response, Ok(Ok(body)) if body.get("result").is_some()),
    )
}

async fn stop_gateway(child: &mut Child) {
    let status = Command::new("/usr/bin/kill")
        .arg("-TERM")
        .arg(child.id().unwrap().to_string())
        .status()
        .await
        .unwrap();
    assert!(status.success());
    assert!(
        tokio::time::timeout(PROCESS_WATCHDOG, child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
}

fn write_evidence(value: &serde_json::Value) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/hostile-load");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.join("sqlite-process.json");
    let temporary = root.join(format!(".sqlite-process-{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&temporary);
    let file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .unwrap();
    serde_json::to_writer_pretty(&file, value).unwrap();
    file.sync_all().unwrap();
    std::fs::rename(&temporary, path).unwrap();
    std::fs::File::open(root).unwrap().sync_all().unwrap();
}

struct EpochMetrics {
    canary_latencies: Vec<u64>,
    offender_completed: usize,
    peak_fds: usize,
    peak_rss: u64,
}

async fn run_epoch(
    client: &reqwest::Client,
    endpoint: &str,
    pid: u32,
    epoch: usize,
    offender_count: usize,
    canary_count: usize,
) -> EpochMetrics {
    let barrier = Arc::new(Barrier::new(offender_count + canary_count + 1));
    let mut tasks = JoinSet::new();
    for offender in 0..offender_count {
        let barrier = Arc::clone(&barrier);
        let client = client.clone();
        let endpoint = endpoint.to_owned();
        tasks.spawn(async move {
            barrier.wait().await;
            let result = tokio::time::timeout(
                REQUEST_DEADLINE,
                client
                    .post(endpoint)
                    .header("content-type", "application/json")
                    .body(format!("{{not-json-{epoch}-{offender}"))
                    .send(),
            )
            .await;
            (false, 0_u64, matches!(result, Ok(Ok(_))))
        });
    }
    for canary in 0..canary_count {
        let barrier = Arc::clone(&barrier);
        let client = client.clone();
        let endpoint = endpoint.to_owned();
        tasks.spawn(async move {
            barrier.wait().await;
            let (elapsed, ok) =
                send_canary(&client, &endpoint, &format!("load-canary-{epoch}-{canary}")).await;
            (true, elapsed, ok)
        });
    }
    let sampler_stop = CancellationToken::new();
    let sampler_owner = sampler_stop.clone();
    let sampler = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(2));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut peak_fds = process_fd_count(pid);
        let mut peak_rss = process_rss_bytes(pid);
        loop {
            tokio::select! {
                () = sampler_owner.cancelled() => return (peak_fds, peak_rss),
                _ = interval.tick() => {
                    peak_fds = peak_fds.max(process_fd_count(pid));
                    peak_rss = peak_rss.max(process_rss_bytes(pid));
                }
            }
        }
    });
    barrier.wait().await;
    let mut peak_fds = process_fd_count(pid);
    let mut peak_rss = process_rss_bytes(pid);
    let mut canary_latencies = Vec::new();
    let mut offender_completed = 0;
    while let Some(result) = tokio::time::timeout(Duration::from_secs(8), tasks.join_next())
        .await
        .expect("load join watchdog")
    {
        let (canary, elapsed, ok) = result.unwrap();
        assert!(ok, "bounded load request failed");
        if canary {
            canary_latencies.push(elapsed);
        } else {
            offender_completed += 1;
        }
    }
    sampler_stop.cancel();
    let (sampled_fds, sampled_rss) = tokio::time::timeout(Duration::from_secs(2), sampler)
        .await
        .expect("metric sampler join watchdog")
        .unwrap();
    peak_fds = peak_fds.max(sampled_fds).max(process_fd_count(pid));
    peak_rss = peak_rss.max(sampled_rss).max(process_rss_bytes(pid));
    EpochMetrics {
        canary_latencies,
        offender_completed,
        peak_fds,
        peak_rss,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hostile_load_network_faults_and_slow_consumers_remain_bounded() {
    let mut fixture = Fixture::new();
    let database = fixture.path().join("authority.sqlite3");
    let address = free_address();
    let endpoint = format!("http://{address}/jsonrpc");
    let mut child = spawn_gateway(address, &database);
    wait_ready(&mut child, address).await;
    let pid = child.id().unwrap();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();

    let (warm_ms, warm_ok) = send_canary(&client, &endpoint, "warm-canary").await;
    assert!(warm_ok && warm_ms <= 1_000);
    let baseline_rss = process_rss_bytes(pid);
    let baseline_fds = process_fd_count(pid);
    let baseline_db = sqlite_file_set_bytes(&database);

    let proxy = FaultProxy::start(address).await;
    let proxy_address = proxy.address();
    let proxy_endpoint = format!("http://{proxy_address}/jsonrpc");
    let (_, proxy_ok) = send_canary(&reqwest::Client::new(), &proxy_endpoint, "proxy-pass").await;
    assert!(proxy_ok);
    proxy.set_mode(FaultMode::Blackhole);
    let blocked = tokio::time::timeout(
        Duration::from_millis(300),
        reqwest::Client::new()
            .post(&proxy_endpoint)
            .json(&send_body("proxy-blackhole"))
            .send(),
    )
    .await;
    assert!(
        blocked.is_err(),
        "blackholed request unexpectedly completed"
    );
    let direct_started = Instant::now();
    let (_, direct_ok) = send_canary(&client, &endpoint, "direct-during-blackhole").await;
    assert!(direct_ok && direct_started.elapsed() <= Duration::from_secs(1));
    proxy.set_mode(FaultMode::Reset);
    let reset = tokio::time::timeout(
        Duration::from_secs(1),
        reqwest::Client::new()
            .post(&proxy_endpoint)
            .json(&send_body("proxy-reset"))
            .send(),
    )
    .await;
    assert!(
        matches!(reset, Ok(Err(_))),
        "reset request did not fail closed"
    );
    proxy.set_mode(FaultMode::Pass);
    let recovery_started = Instant::now();
    let (_, recovered) =
        send_canary(&reqwest::Client::new(), &proxy_endpoint, "proxy-recovered").await;
    assert!(recovered && recovery_started.elapsed() <= Duration::from_secs(2));

    let mut slow_consumers = Vec::new();
    for _ in 0..16 {
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream
            .write_all(b"POST /jsonrpc HTTP/1.1\r\nHost: localhost\r\nContent-Length: 999\r\n")
            .await
            .unwrap();
        slow_consumers.push(stream);
    }

    let offender_count = 128;
    let canary_count = 8;
    let mut epochs = Vec::new();
    for epoch in 0..3 {
        epochs.push(run_epoch(&client, &endpoint, pid, epoch, offender_count, canary_count).await);
    }
    assert!(
        epochs
            .iter()
            .all(|epoch| epoch.offender_completed == offender_count)
    );
    let canary_latencies = epochs
        .iter()
        .flat_map(|epoch| epoch.canary_latencies.iter().copied())
        .collect::<Vec<_>>();
    assert_eq!(canary_latencies.len(), canary_count * epochs.len());
    let mut peak_fds = epochs.iter().map(|epoch| epoch.peak_fds).max().unwrap();
    let mut peak_rss = epochs.iter().map(|epoch| epoch.peak_rss).max().unwrap();
    assert!(
        epochs[2].peak_rss <= epochs[1].peak_rss.saturating_add(16 * MIB),
        "late-epoch RSS growth exceeded 16MiB"
    );
    let p95 = nearest_rank_percentile(&canary_latencies, 95);
    let max_latency = *canary_latencies.iter().max().unwrap();
    assert!(p95 <= 500, "canary p95 {p95}ms exceeded 500ms");
    assert!(
        max_latency <= 1_000,
        "canary max {max_latency}ms exceeded 1s"
    );
    assert!(peak_rss <= 256 * MIB, "peak RSS {peak_rss} exceeded 256MiB");
    assert!(
        peak_rss <= baseline_rss.saturating_add(64 * MIB),
        "RSS growth exceeded 64MiB"
    );
    assert!(
        peak_fds <= baseline_fds + offender_count + canary_count + 16 + 16,
        "FD peak exceeded synchronized workload bound"
    );

    let acknowledged = tokio::time::timeout(
        REQUEST_DEADLINE,
        client
            .post(&endpoint)
            .json(&send_body("rpo-ledger-acknowledged"))
            .send(),
    )
    .await
    .unwrap()
    .unwrap()
    .json::<serde_json::Value>()
    .await
    .unwrap();
    let acknowledged_task_id = acknowledged["result"]["task"]["id"]
        .as_str()
        .expect("acknowledged task id")
        .to_owned();

    drop(slow_consumers);
    drop(client);
    proxy.shutdown().await;
    drop(std::net::TcpListener::bind(proxy_address).unwrap());
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut interval = tokio::time::interval(Duration::from_millis(20));
        loop {
            interval.tick().await;
            if process_fd_count(pid) <= baseline_fds + 8 {
                break;
            }
        }
    })
    .await
    .expect("FD recovery watchdog");
    let final_fds = process_fd_count(pid);
    let final_rss = process_rss_bytes(pid);
    peak_fds = peak_fds.max(final_fds);
    peak_rss = peak_rss.max(final_rss);
    assert!(final_fds <= baseline_fds + 8);
    assert!(final_rss <= baseline_rss.saturating_add(64 * MIB));
    assert!(peak_rss <= 256 * MIB);
    assert!(peak_rss <= baseline_rss.saturating_add(64 * MIB));

    child.start_kill().unwrap();
    let killed = tokio::time::timeout(PROCESS_WATCHDOG, child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(!killed.success());
    assert!(!Path::new(&format!("/proc/{pid}")).exists());

    let restart_started = Instant::now();
    child = spawn_gateway(address, &database);
    wait_ready(&mut child, address).await;
    let restarted_pid = child.id().unwrap();
    let readiness_millis = u64::try_from(restart_started.elapsed().as_millis()).unwrap_or(u64::MAX);
    assert!(
        readiness_millis <= 5_000,
        "restart RTO exceeded five seconds"
    );
    let recovered_client = reqwest::Client::builder().no_proxy().build().unwrap();
    let recovered = tokio::time::timeout(
        REQUEST_DEADLINE,
        recovered_client
            .post(&endpoint)
            .json(&serde_json::json!({
                "jsonrpc":"2.0","id":"recover-ledger","method":a2a::jsonrpc::methods::GET_TASK,
                "params":{"id":acknowledged_task_id}
            }))
            .send(),
    )
    .await
    .unwrap()
    .unwrap()
    .json::<serde_json::Value>()
    .await
    .unwrap();
    assert_eq!(recovered["result"]["id"], acknowledged_task_id);
    let canary_started = Instant::now();
    let (_, recovery_canary_ok) =
        send_canary(&recovered_client, &endpoint, "post-restart-canary").await;
    let first_canary_millis =
        u64::try_from(canary_started.elapsed().as_millis()).unwrap_or(u64::MAX);
    assert!(recovery_canary_ok && first_canary_millis <= 2_000);
    drop(recovered_client);
    stop_gateway(&mut child).await;
    assert!(!Path::new(&format!("/proc/{restarted_pid}")).exists());
    drop(std::net::TcpListener::bind(address).unwrap());

    let connection = rusqlite::Connection::open(&database).unwrap();
    let quick_check: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(quick_check, "ok");
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    drop(connection);
    let final_db = sqlite_file_set_bytes(&database);
    assert!(
        final_db <= baseline_db.saturating_add(2 * MIB),
        "retained SQLite growth exceeded 2MiB: baseline={baseline_db}, final={final_db}"
    );
    let epoch_evidence = epochs
        .iter()
        .enumerate()
        .map(|(index, epoch)| {
            let rss_growth = if index == 0 {
                0
            } else {
                epoch.peak_rss.saturating_sub(epochs[index - 1].peak_rss)
            };
            serde_json::json!({
                "index":index,
                "rssPeak":epoch.peak_rss,
                "rssGrowthFromPrevious":rss_growth,
                "fdPeak":epoch.peak_fds,
                "canaryP95Millis":nearest_rank_percentile(&epoch.canary_latencies, 95),
                "canaryMaxMillis":epoch.canary_latencies.iter().max().copied().unwrap_or(0)
            })
        })
        .collect::<Vec<_>>();
    fixture.cleanup();

    write_evidence(&serde_json::json!({
        "schemaVersion":"smesh.hostile-load-evidence/1",
        "backend":"sqlite",
        "profile":"stable",
        "workload":{"offenders":offender_count * epochs.len(),"canaries":canary_count * epochs.len(),"slowConsumers":16},
        "epochs":epoch_evidence,
        "latencyMillis":{"p95":p95,"max":max_latency},
        "rssBytes":{"baseline":baseline_rss,"peak":peak_rss,"final":final_rss},
        "fileDescriptors":{"baseline":baseline_fds,"peak":peak_fds,"final":final_fds},
        "databaseBytes":{"baseline":baseline_db,"final":final_db},
        "network":{"blackholeObserved":true,"healthyDuringFault":true,"recovered":true},
        "recovery":{"signal":"SIGKILL","acknowledged":1,"recovered":1,"rpoLost":0,"readinessMillis":readiness_millis,"firstCanaryMillis":first_canary_millis},
        "cleanup":{"processes":0,"boundPorts":0,"temporaryArtifacts":0,"sqliteQuickCheck":"ok"},
        "verdict":"pass",
        "limitations":["Linux /proc metrics are qualification evidence, not capacity planning"]
    }));
}
