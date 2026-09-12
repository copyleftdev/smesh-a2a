use smesh_a2a::owned_temp::OwnedTempDir;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[path = "support/process.rs"]
mod process;

static CANDIDATE_TREE_ARCHIVE_LOCK: Mutex<()> = Mutex::new(());
static OPERATIONAL_HARNESS_TEST_LOCK: Mutex<()> = Mutex::new(());

struct OperationalHarnessTestGuard {
    _guard: std::sync::MutexGuard<'static, ()>,
}

fn acquire_operational_harness_test_lock() -> OperationalHarnessTestGuard {
    OperationalHarnessTestGuard {
        _guard: OPERATIONAL_HARNESS_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    }
}

#[test]
fn operational_harness_test_lock_excludes_parallel_heavy_tests() {
    use std::sync::TryLockError;

    let owner = acquire_operational_harness_test_lock();
    assert!(matches!(
        OPERATIONAL_HARNESS_TEST_LOCK.try_lock(),
        Err(TryLockError::WouldBlock)
    ));
    drop(owner);

    let _successor = OPERATIONAL_HARNESS_TEST_LOCK
        .try_lock()
        .unwrap_or_else(|error| match error {
            TryLockError::Poisoned(error) => error.into_inner(),
            TryLockError::WouldBlock => panic!("released operational harness lock remained held"),
        });
}

#[test]
fn documented_outer_acceptance_timeout_exceeds_every_inner_watchdog_and_cleanup_budget() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let harness =
        std::fs::read_to_string(repo.join("scripts/run-operational-acceptance.sh")).unwrap();
    let acceptance =
        std::fs::read_to_string(repo.join("src/bin/operational-lifeline-acceptance.rs")).unwrap();
    let qualification =
        std::fs::read_to_string(repo.join("src/bin/operational-lifeline-qualification.rs"))
            .unwrap();

    let outer = numeric_constant(&harness, "ACCEPTANCE_OUTER_TIMEOUT_SECS=");
    let inner = numeric_constant(&acceptance, "QUALIFICATION_TIMEOUT_SECS: u64 = ");
    let browser = numeric_constant(&qualification, "BROWSER_TIMEOUT_SECS: u64 = ");
    let cleanup = numeric_constant(&acceptance, "QUALIFICATION_CLEANUP_BUDGET_SECS: u64 = ");
    assert!(
        browser < inner,
        "browser watchdog must expire inside qualification"
    );
    assert_eq!(browser, 90, "production browser timeout changed");
    assert!(
        outer > inner + cleanup,
        "outer={outer}, inner={inner}, cleanup={cleanup}"
    );

    let assignment = harness.find("ACCEPTANCE_OUTER_TIMEOUT_SECS=").unwrap();
    let invocation = harness
        .find("operational-lifeline-acceptance\" \\")
        .unwrap();
    assert!(
        assignment < invocation,
        "outer timeout must be defined before use"
    );
    assert!(
        harness.contains("${ACCEPTANCE_OUTER_TIMEOUT_SECS}s"),
        "acceptance invocation must use the documented outer budget"
    );
}

fn numeric_constant(source: &str, prefix: &str) -> u64 {
    source
        .split_once(prefix)
        .unwrap_or_else(|| panic!("missing numeric constant {prefix}"))
        .1
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .unwrap()
}

#[cfg(unix)]
#[test]
fn bounded_process_watchdog_delivers_term_before_forced_cleanup() {
    let root = TempRoot::new();
    let marker = root.path().join("term-marker");
    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            "trap 'printf term > \"$1\"; exit 0' TERM; while :; do sleep 1; done",
            "term-trap-regression",
        ])
        .arg(&marker);

    let error = process::bounded_status(
        &mut command,
        Duration::from_millis(100),
        "TERM-trap process-group regression",
    )
    .unwrap_err();

    assert!(error.contains("timed out"), "{error}");
    assert_eq!(std::fs::read(marker).unwrap(), b"term");
}

#[cfg(unix)]
#[test]
fn bounded_process_watchdog_kills_term_ignoring_descendant_but_not_unrelated_process() {
    let root = TempRoot::new();
    let marker = root.path().join("term-ignore-pids");
    let mut unrelated = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    let unrelated_pid = unrelated.id();
    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            "trap '' TERM; sleep 30 & printf '%s %s' \"$$\" \"$!\" > \"$1\"; wait",
            "term-ignore-regression",
        ])
        .arg(&marker);

    let error = process::bounded_status(
        &mut command,
        Duration::from_millis(100),
        "TERM-ignore process-group regression",
    )
    .unwrap_err();
    assert!(error.contains("timed out"), "{error}");
    for pid in std::fs::read_to_string(marker).unwrap().split_whitespace() {
        assert!(
            !Path::new("/proc").join(pid).exists(),
            "unreaped owned pid {pid}"
        );
    }
    assert!(Path::new("/proc").join(unrelated_pid.to_string()).exists());
    unrelated.kill().unwrap();
    unrelated.wait().unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn injected_term_operation_failure_is_reported_and_kill_reaps_the_group() {
    let root = TempRoot::new();
    let marker = root.path().join("term-injection-pids");
    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            "trap '' TERM; sleep 30 & printf '%s %s' \"$$\" \"$!\" > \"$1\"; wait",
            "injected-term-regression",
        ])
        .arg(&marker);
    let error = process::bounded_status_with_injected_term_signal_failure(
        &mut command,
        Duration::from_millis(100),
        "injected TERM cleanup regression",
    )
    .unwrap_err();
    assert!(error.contains("injected TERM signal failure"), "{error}");
    assert_owned_pids_absent(&marker);
}

#[cfg(target_os = "linux")]
#[test]
fn injected_kill_operation_failure_uses_total_fallback_and_reaps_the_group() {
    let root = TempRoot::new();
    let marker = root.path().join("kill-injection-pids");
    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            "trap '' TERM; sleep 30 & printf '%s %s' \"$$\" \"$!\" > \"$1\"; wait",
            "injected-kill-regression",
        ])
        .arg(&marker);
    let error = process::bounded_status_with_injected_kill_signal_failure(
        &mut command,
        Duration::from_millis(100),
        "injected KILL cleanup regression",
    )
    .unwrap_err();
    assert!(error.contains("injected KILL signal failure"), "{error}");
    assert_owned_pids_absent(&marker);
}

#[cfg(target_os = "linux")]
#[test]
fn bounded_output_returns_after_injected_kill_failure_with_pipe_holding_group() {
    let root = TempRoot::new();
    let marker = root.path().join("output-kill-injection-pids");
    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            "trap '' TERM; sleep 30 & printf '%s %s' \"$$\" \"$!\" > \"$1\"; printf diagnostic; wait",
            "output-injected-kill-regression",
        ])
        .arg(&marker);

    let started = Instant::now();
    let error = process::bounded_output_with_injected_kill_signal_failure(
        &mut command,
        Duration::from_millis(100),
        "injected KILL output cleanup regression",
    )
    .unwrap_err();

    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(error.contains("injected KILL signal failure"), "{error}");
    assert_owned_pids_absent(&marker);
}

#[cfg(target_os = "linux")]
#[test]
fn bounded_output_returns_when_escaped_descendant_holds_pipes() {
    let root = TempRoot::new();
    let marker = root.path().join("escaped-pipe-holder");
    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            "setsid sleep 30 & printf '%s' \"$!\" > \"$1\"; exit 0",
            "escaped-output-regression",
        ])
        .arg(&marker);

    let started = Instant::now();
    let result = process::bounded_output(
        &mut command,
        Duration::from_secs(1),
        "escaped output pipe regression",
    );
    let pid = std::fs::read_to_string(marker).unwrap();
    let _ = Command::new("/bin/kill")
        .args(["-KILL", pid.trim()])
        .status();
    let error = result.unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(
        error.contains("pipe remained open after cleanup"),
        "{error}"
    );
}

#[cfg(target_os = "linux")]
fn assert_owned_pids_absent(marker: &Path) {
    for pid in std::fs::read_to_string(marker).unwrap().split_whitespace() {
        assert!(
            !Path::new("/proc").join(pid).exists(),
            "owned pid {pid} survived"
        );
    }
}

#[cfg(unix)]
#[test]
fn bounded_process_watchdog_reaps_its_group_and_distinguishes_command_failure() {
    let root = TempRoot::new();
    let marker = root.path().join("pids");
    let mut hung = Command::new("/bin/sh");
    hung.args([
        "-c",
        "sleep 30 & printf '%s %s' \"$$\" \"$!\" > \"$1\"; wait",
        "bounded-process-regression",
    ])
    .arg(&marker);

    let started = Instant::now();
    let error = process::bounded_status(
        &mut hung,
        Duration::from_millis(100),
        "hung process-group regression",
    )
    .unwrap_err();
    assert!(error.contains("timed out"), "{error}");
    assert!(started.elapsed() < Duration::from_secs(2));

    let pids = std::fs::read_to_string(marker).unwrap();
    for pid in pids.split_whitespace() {
        let proc_entry = Path::new("/proc").join(pid);
        let deadline = Instant::now() + Duration::from_secs(1);
        while proc_entry.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!proc_entry.exists(), "unreaped process {pid}");
    }

    let status = process::bounded_status(
        Command::new("/bin/sh").args(["-c", "exit 7"]),
        Duration::from_secs(1),
        "expected command failure",
    )
    .unwrap();
    assert_eq!(status.code(), Some(7));
}

#[cfg(target_os = "linux")]
#[test]
fn bounded_status_cleans_descendant_after_normal_group_leader_exit() {
    let root = TempRoot::new();
    let marker = root.path().join("descendant-pid");
    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            "sleep 30 & printf '%s' \"$!\" > \"$1\"; exit 0",
            "normal-exit",
        ])
        .arg(&marker);

    let started = Instant::now();
    let status = process::bounded_status(
        &mut command,
        Duration::from_millis(100),
        "normal-exit status descendant regression",
    )
    .unwrap();

    assert!(status.success());
    assert!(started.elapsed() < Duration::from_secs(2));
    let pid = std::fs::read_to_string(marker).unwrap();
    assert!(
        !Path::new("/proc").join(pid).exists(),
        "owned descendant survived"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn bounded_output_cleans_pipe_holding_descendant_after_normal_group_leader_exit() {
    let root = TempRoot::new();
    let marker = root.path().join("descendant-pid");
    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            "sleep 30 & printf '%s' \"$!\" > \"$1\"; exit 0",
            "normal-exit",
        ])
        .arg(&marker);

    let started = Instant::now();
    let output = process::bounded_output(
        &mut command,
        Duration::from_millis(100),
        "normal-exit output descendant regression",
    )
    .unwrap();

    assert!(output.status.success());
    assert!(started.elapsed() < Duration::from_secs(2));
    let pid = std::fs::read_to_string(marker).unwrap();
    assert!(
        !Path::new("/proc").join(pid).exists(),
        "owned descendant survived"
    );
}

#[test]
fn harness_failure_never_deletes_report_collision_created_after_initial_check() {
    use std::os::unix::fs::PermissionsExt as _;

    let operational_harness_test_guard = acquire_operational_harness_test_lock();
    let checkout = IsolatedCheckout::new(&operational_harness_test_guard);
    let report = checkout.root().join("attacker-report");
    let fake_bin = checkout.root().join("fake-bin");
    std::fs::create_dir(&fake_bin).unwrap();
    let fake_npm = fake_bin.join("npm");
    std::fs::write(
        &fake_npm,
        "#!/bin/sh\nmkdir \"$PLANTED_REPORT\"\nprintf preserve > \"$PLANTED_REPORT/sentinel\"\nexit 1\n",
    )
    .unwrap();
    std::fs::set_permissions(&fake_npm, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut path = fake_bin.into_os_string();
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap());

    let status = process::bounded_status(
        Command::new(
            checkout
                .path()
                .join("scripts/run-operational-acceptance.sh"),
        )
        .arg(&report)
        .current_dir(checkout.path())
        .env("PATH", path)
        .env("PLANTED_REPORT", &report),
        Duration::from_secs(30),
        "report collision provenance regression",
    )
    .unwrap();

    assert!(!status.success());
    assert_eq!(std::fs::read(report.join("sentinel")).unwrap(), b"preserve");
}

#[cfg(target_os = "linux")]
#[test]
fn documented_harness_allows_default_browser_watchdog_to_finish_owned_cleanup() {
    let operational_harness_test_guard = acquire_operational_harness_test_lock();
    let checkout = IsolatedCheckout::new(&operational_harness_test_guard);
    let qualification_report = checkout.root().join("qualification-report");
    let report = checkout.root().join("forced-hang-report");
    let marker = checkout.root().join("forced-hang-lifecycle.json");

    assert!(!checkout.path().join("target").exists());
    assert!(!checkout.path().join("node_modules").exists());
    run_documented_harness(checkout.path(), &qualification_report);
    assert_exact_40_of_40_report(&qualification_report);

    let process_started = Instant::now();
    let outcome = process::bounded_status_after_marker(
        Command::new(
            checkout
                .path()
                .join("scripts/run-operational-acceptance.sh"),
        )
        .arg(&report)
        .current_dir(checkout.path())
        .env("SMESH_QUALIFICATION_FORCE_FRESH_BROWSER_HANG", "1")
        .env("SMESH_QUALIFICATION_FRESH_LIFECYCLE_MARKER", &marker),
        &marker,
        Duration::from_secs(3 * 60),
        Duration::from_secs(90 + 8),
        "default 90s browser-hang operational harness",
    )
    .unwrap();
    let process_elapsed = process_started.elapsed();

    assert!(!outcome.status.success());
    assert!(
        outcome.marker_observed(),
        "authentic lifecycle marker was not observed"
    );
    assert!(
        process_elapsed >= Duration::from_secs(90),
        "inner watchdog exited too early after process invocation: {process_elapsed:?}"
    );
    assert!(
        process_elapsed < Duration::from_secs(3 * 60),
        "operational harness exceeded its pre-marker watchdog: {process_elapsed:?}"
    );
    assert!(
        outcome.post_marker_process_elapsed.unwrap() < Duration::from_secs(98),
        "inner cleanup did not return promptly after marker: {:?}",
        outcome.post_marker_process_elapsed
    );
    assert!(!report.exists());
    let lifecycle: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&marker).unwrap()).unwrap();
    for field in ["nodePid", "browserPid"] {
        let pid = lifecycle[field].as_u64().unwrap();
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "{field} {pid} survived"
        );
    }
    let profile_argument = lifecycle["profileArgument"].as_str().unwrap();
    let profile = profile_argument.strip_prefix("--user-data-dir=").unwrap();
    assert!(!Path::new(profile).exists(), "browser profile survived");
    let owned_roots = lifecycle["ownedRoots"].as_array().unwrap();
    assert_eq!(owned_roots.len(), 2, "incomplete owned-root provenance");
    let owned_roots = owned_roots
        .iter()
        .map(|root| root.as_str().unwrap())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(owned_roots.len(), 2, "owned-root provenance was duplicated");
    assert!(owned_roots.contains(profile));
    assert!(owned_roots.iter().any(|root| {
        Path::new(root).file_name().is_some_and(|name| {
            name.to_string_lossy()
                .starts_with("smesh-acceptance-owned-probe-")
        })
    }));
    for root in owned_roots {
        assert!(!Path::new(root).exists(), "owned root survived: {root}");
    }
    assert_no_process_cmdline_contains(checkout.path().as_os_str().as_encoded_bytes());
    assert_no_process_cmdline_contains(profile_argument.as_bytes());
}

#[cfg(target_os = "linux")]
#[test]
fn marker_relative_watchdog_rejects_stale_marker_without_launching() {
    let root = TempRoot::new();
    let marker = root.path().join("marker");
    let launched = root.path().join("launched");
    std::fs::write(&marker, b"stale").unwrap();
    let error = process::bounded_status_after_marker(
        Command::new("/bin/sh")
            .args(["-c", ": > \"$1\"", "stale-marker"])
            .arg(&launched),
        &marker,
        Duration::from_secs(1),
        Duration::from_secs(1),
        "stale marker",
    )
    .unwrap_err();
    assert!(error.contains("existed before process launch"), "{error}");
    assert!(!launched.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn marker_relative_status_records_absent_marker() {
    let root = TempRoot::new();
    let marker = root.path().join("marker");
    let outcome = process::bounded_status_after_marker(
        Command::new("/bin/sh").args(["-c", "exit 6"]),
        &marker,
        Duration::from_secs(1),
        Duration::from_secs(1),
        "absent marker",
    )
    .unwrap();
    assert_eq!(outcome.status.code(), Some(6));
    assert!(!outcome.marker_observed());
    assert!(outcome.post_marker_process_elapsed.is_none());
}

#[cfg(target_os = "linux")]
#[test]
fn marker_relative_status_exposes_slow_setup_then_early_exit() {
    let root = TempRoot::new();
    let marker = root.path().join("marker");
    let outcome = process::bounded_status_after_marker(
        Command::new("/bin/sh")
            .args(["-c", "sleep 0.15; : > \"$1\"; exit 7", "phase"])
            .arg(&marker),
        &marker,
        Duration::from_secs(1),
        Duration::from_millis(100),
        "slow setup early exit",
    )
    .unwrap();
    assert_eq!(outcome.status.code(), Some(7));
    assert!(outcome.pre_marker_elapsed >= Duration::from_millis(100));
    assert!(outcome.marker_observed());
    assert!(outcome.post_marker_process_elapsed.unwrap() < Duration::from_millis(100));
}

#[cfg(target_os = "linux")]
#[test]
fn marker_observation_wins_same_poll_as_exit() {
    let root = TempRoot::new();
    let marker = root.path().join("marker");
    let outcome = process::bounded_status_after_marker(
        Command::new("/bin/sh")
            .args(["-c", ": > \"$1\"; exit 9", "phase"])
            .arg(&marker),
        &marker,
        Duration::from_secs(1),
        Duration::from_secs(1),
        "same poll marker and exit",
    )
    .unwrap();
    assert_eq!(outcome.status.code(), Some(9));
    assert!(outcome.marker_observed());
}

#[cfg(target_os = "linux")]
#[test]
fn marker_first_observed_after_pre_marker_deadline_fails_closed() {
    let root = TempRoot::new();
    let marker = root.path().join("marker");
    let error = process::bounded_status_after_marker_with_injected_observers(
        Command::new("/bin/sh").args(["-c", "exec sleep 30"]),
        &marker,
        Duration::from_millis(50),
        Duration::from_secs(1),
        "marker observation crossing deadline",
        move |deadline| {
            assert!(
                Instant::now() < deadline,
                "marker observer must enter before the helper's exact deadline"
            );
            while Instant::now() <= deadline {
                std::hint::spin_loop();
            }
            assert!(Instant::now() > deadline);
            Ok(true)
        },
        |child, _| process::observe_child_exit_for_test(child),
    )
    .unwrap_err();
    assert!(error.contains("pre-marker phase timed out"), "{error}");
}

#[cfg(target_os = "linux")]
#[test]
fn exit_first_observed_after_pre_marker_deadline_fails_closed() {
    let root = TempRoot::new();
    let marker = root.path().join("marker");
    let error = process::bounded_status_after_marker_with_injected_observers(
        Command::new("/bin/sh").args(["-c", "exit 0"]),
        &marker,
        Duration::from_millis(50),
        Duration::from_secs(1),
        "exit observation crossing pre-marker deadline",
        |_| Ok(false),
        move |child, deadline| {
            assert!(
                Instant::now() < deadline,
                "exit observer must enter before the exact pre-marker deadline"
            );
            while Instant::now() <= deadline {
                std::hint::spin_loop();
            }
            assert!(Instant::now() > deadline);
            loop {
                if process::observe_child_exit_for_test(child)? {
                    return Ok(true);
                }
            }
        },
    )
    .unwrap_err();
    assert!(error.contains("pre-marker phase timed out"), "{error}");
}

#[cfg(target_os = "linux")]
#[test]
fn exit_first_observed_after_post_marker_deadline_fails_closed() {
    let root = TempRoot::new();
    let marker = root.path().join("marker");
    let error = process::bounded_status_after_marker_with_injected_observers(
        Command::new("/bin/sh").args(["-c", "exit 0"]),
        &marker,
        Duration::from_secs(1),
        Duration::from_millis(50),
        "exit observation crossing deadline",
        |_| Ok(true),
        move |child, deadline| {
            assert!(
                Instant::now() < deadline,
                "exit observer must enter before the exact post-marker deadline"
            );
            while Instant::now() <= deadline {
                std::hint::spin_loop();
            }
            assert!(Instant::now() > deadline);
            loop {
                if process::observe_child_exit_for_test(child)? {
                    return Ok(true);
                }
            }
        },
    )
    .unwrap_err();
    assert!(error.contains("post-marker phase timed out"), "{error}");
}

#[cfg(target_os = "linux")]
#[test]
fn marker_relative_watchdog_times_out_post_marker_phase() {
    let root = TempRoot::new();
    let marker = root.path().join("marker");
    let pid_marker = root.path().join("pid");
    let error = process::bounded_status_after_marker(
        Command::new("/bin/sh")
            .args([
                "-c",
                ": > \"$1\"; printf %s $$ > \"$2\"; exec sleep 30",
                "phase",
            ])
            .arg(&marker)
            .arg(&pid_marker),
        &marker,
        Duration::from_secs(1),
        Duration::from_millis(100),
        "post-marker timeout",
    )
    .unwrap_err();
    assert!(error.contains("post-marker phase timed out"), "{error}");
    assert_owned_pids_absent(&pid_marker);
}

#[cfg(target_os = "linux")]
fn assert_no_process_cmdline_contains(needle: &[u8]) {
    for entry in std::fs::read_dir("/proc").unwrap() {
        let entry = entry.unwrap();
        if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
            continue;
        }
        let cmdline = std::fs::read(entry.path().join("cmdline")).unwrap_or_default();
        assert!(
            !cmdline.windows(needle.len()).any(|window| window == needle),
            "owned process survived: {}",
            String::from_utf8_lossy(&cmdline)
        );
    }
}

#[test]
fn documented_harness_holds_dependency_lock_during_mutation_and_releases_it_on_exit() {
    use rustix::fs::{FlockOperation, flock};
    use std::os::unix::fs::PermissionsExt as _;

    let operational_harness_test_guard = acquire_operational_harness_test_lock();
    let checkout = IsolatedCheckout::new(&operational_harness_test_guard);
    let report = checkout.root().join("report");
    let mutation_started = checkout.root().join("mutation-started");
    let mutation_release = checkout.root().join("mutation-release");
    let cargo_mutation_started = checkout.root().join("cargo-mutation-started");
    let fake_bin = checkout.root().join("fake-bin");
    std::fs::create_dir(&fake_bin).unwrap();
    for (name, script) in [
        (
            "npm",
            "#!/bin/sh\n: > \"$MUTATION_STARTED\"\nwhile [ ! -e \"$MUTATION_RELEASE\" ]; do sleep 0.01; done\nexit 76\n",
        ),
        (
            "cargo",
            "#!/bin/sh\n: > \"$CARGO_MUTATION_STARTED\"\nexit 77\n",
        ),
    ] {
        let command = fake_bin.join(name);
        std::fs::write(&command, script).unwrap();
        std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut path = fake_bin.into_os_string();
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap());

    std::thread::scope(|scope| {
        let harness = scope.spawn(|| {
            process::bounded_status(
                Command::new(
                    checkout
                        .path()
                        .join("scripts/run-operational-acceptance.sh"),
                )
                .arg(&report)
                .current_dir(checkout.path())
                .env("PATH", path)
                .env("MUTATION_STARTED", &mutation_started)
                .env("MUTATION_RELEASE", &mutation_release)
                .env("CARGO_MUTATION_STARTED", &cargo_mutation_started),
                Duration::from_secs(10),
                "dependency lifecycle lock regression",
            )
        });

        let marker_deadline = Instant::now() + Duration::from_secs(5);
        while !mutation_started.exists() && Instant::now() < marker_deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            mutation_started.exists(),
            "fake npm did not reach dependency mutation before its watchdog"
        );

        let lock_path = checkout
            .path()
            .join("target/.operational-acceptance-dependencies.lock");
        let lock_probe = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
            .unwrap();
        assert_eq!(
            flock(&lock_probe, FlockOperation::NonBlockingLockExclusive),
            Err(rustix::io::Errno::WOULDBLOCK),
            "dependency mutation ran without the shell holding the lifecycle lock"
        );

        std::fs::write(&mutation_release, b"release").unwrap();
        let status = harness.join().unwrap().unwrap();
        assert!(!status.success());
        assert!(!report.exists());
        assert!(!cargo_mutation_started.exists());
        #[cfg(target_os = "linux")]
        assert_no_process_cmdline_contains(checkout.path().as_os_str().as_encoded_bytes());
        flock(&lock_probe, FlockOperation::NonBlockingLockExclusive)
            .expect("dependency lifecycle lock remained held after harness termination");
    });
}

#[test]
fn two_cold_git_archives_emit_byte_identical_40_of_40_reports() {
    let operational_harness_test_guard = acquire_operational_harness_test_lock();
    let first_checkout = IsolatedCheckout::new(&operational_harness_test_guard);
    let second_checkout = IsolatedCheckout::new(&operational_harness_test_guard);
    let first = first_checkout.root().join("report");
    let second = second_checkout.root().join("report");
    for (checkout, report) in [
        (first_checkout.path(), &first),
        (second_checkout.path(), &second),
    ] {
        run_documented_harness(checkout, report);
        smesh_a2a::lifeline_acceptance::verify_acceptance_report(report).unwrap();
        let scorecard: serde_json::Value = serde_json::from_slice(
            &std::fs::read(report.join("acceptance-scorecard.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(scorecard["summary"]["passed"], "40");
        assert_eq!(scorecard["summary"]["failed"], "0");
    }
    for name in ["acceptance-scorecard.json", "acceptance-receipt.json"] {
        let left = std::fs::read(first.join(name)).unwrap();
        let right = std::fs::read(second.join(name)).unwrap();
        assert_eq!(left, right, "{name}");
        assert!(left.len() <= 128 * 1024);
    }
    let total = std::fs::metadata(first.join("acceptance-scorecard.json"))
        .unwrap()
        .len()
        + std::fs::metadata(first.join("acceptance-receipt.json"))
            .unwrap()
            .len();
    assert!(total <= 256 * 1024);
}

#[test]
fn clean_git_archive_runs_documented_command_without_a_preexisting_target() {
    let operational_harness_test_guard = acquire_operational_harness_test_lock();
    let checkout = IsolatedCheckout::new(&operational_harness_test_guard);
    let report = checkout.root().join("report");
    assert!(!checkout.path().join("target").exists());
    run_documented_harness(checkout.path(), &report);
    let verifier = checkout
        .path()
        .join("target/debug/operational-lifeline-acceptance");
    assert!(
        verify_report_status(&verifier, &report, Duration::from_secs(60))
            .unwrap()
            .success()
    );
}

#[test]
fn verify_report_watchdog_terminates_a_hung_verifier() {
    use std::os::unix::fs::PermissionsExt;

    let root = TempRoot::new();
    let verifier = root.path().join("hung-verifier");
    std::fs::write(&verifier, "#!/bin/sh\nsleep 30\n").unwrap();
    std::fs::set_permissions(&verifier, std::fs::Permissions::from_mode(0o755)).unwrap();
    let started = Instant::now();
    let error =
        verify_report_status(&verifier, root.path(), Duration::from_millis(100)).unwrap_err();
    assert!(error.contains("timed out"), "{error}");
    assert!(started.elapsed() < Duration::from_secs(2));
}

fn verify_report_status(
    verifier: &Path,
    report: &Path,
    watchdog: Duration,
) -> Result<std::process::ExitStatus, String> {
    process::bounded_status(
        Command::new(verifier).arg("verify-report").arg(report),
        watchdog,
        "acceptance report verifier",
    )
}

fn run_documented_harness(checkout: &Path, report: &Path) {
    let status = run_documented_harness_result(checkout, report).unwrap();
    assert!(status.success());
}

fn run_documented_harness_result(
    checkout: &Path,
    report: &Path,
) -> Result<std::process::ExitStatus, String> {
    process::bounded_status(
        Command::new(checkout.join("scripts/run-operational-acceptance.sh"))
            .arg(report)
            .current_dir(checkout),
        Duration::from_secs(8 * 60),
        "documented operational acceptance harness",
    )
}

fn assert_exact_40_of_40_report(report: &Path) {
    smesh_a2a::lifeline_acceptance::verify_acceptance_report(report).unwrap();
    let mut files = std::fs::read_dir(report)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    files.sort();
    assert_eq!(
        files,
        ["acceptance-receipt.json", "acceptance-scorecard.json"]
    );
    let scorecard: serde_json::Value =
        serde_json::from_slice(&std::fs::read(report.join("acceptance-scorecard.json")).unwrap())
            .unwrap();
    assert_eq!(scorecard["summary"]["passed"], "40");
    assert_eq!(scorecard["summary"]["failed"], "0");
}

struct IsolatedCheckout<'guard> {
    root: TempRoot,
    checkout: PathBuf,
    _operational_harness_test_guard: &'guard OperationalHarnessTestGuard,
}

impl<'guard> IsolatedCheckout<'guard> {
    fn new(operational_harness_test_guard: &'guard OperationalHarnessTestGuard) -> Self {
        let root = TempRoot::new();
        let archive = root.path().join("candidate.tar");
        let checkout = root.path().join("checkout");
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
        let candidate_tree_archive_guard = CANDIDATE_TREE_ARCHIVE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tree = process::bounded_output(
            Command::new("git").arg("write-tree").current_dir(repo),
            Duration::from_secs(10),
            "git write-tree",
        )
        .unwrap();
        assert!(
            tree.status.success(),
            "git write-tree failed: {}",
            String::from_utf8_lossy(&tree.stderr)
        );
        let tree = String::from_utf8(tree.stdout).unwrap();
        assert!(
            process::bounded_status(
                Command::new("git")
                    .args(["archive", "--format=tar", "-o"])
                    .arg(&archive)
                    .arg(tree.trim())
                    .current_dir(repo),
                Duration::from_secs(30),
                "git archive",
            )
            .unwrap()
            .success()
        );
        drop(candidate_tree_archive_guard);
        std::fs::create_dir(&checkout).unwrap();
        assert!(
            process::bounded_status(
                Command::new("tar")
                    .arg("-xf")
                    .arg(&archive)
                    .arg("-C")
                    .arg(&checkout),
                Duration::from_secs(30),
                "candidate archive extraction",
            )
            .unwrap()
            .success()
        );
        assert!(!checkout.join("target").exists());
        Self {
            root,
            checkout,
            _operational_harness_test_guard: operational_harness_test_guard,
        }
    }

    fn root(&self) -> &Path {
        self.root.path()
    }

    fn path(&self) -> &Path {
        &self.checkout
    }
}

struct TempRoot(OwnedTempDir);
impl TempRoot {
    fn new() -> Self {
        OwnedTempDir::create("smesh-operational-acceptance-test-")
            .map(Self)
            .unwrap()
    }
    fn path(&self) -> &Path {
        self.0.path()
    }
}
