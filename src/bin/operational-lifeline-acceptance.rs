use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};
use smesh_a2a::lifeline_acceptance::{
    AcceptanceStatus, evaluate_operational_lifeline, verify_acceptance_report,
};
use smesh_a2a::owned_temp::OwnedTempDir;

const QUALIFICATION_TIMEOUT_SECS: u64 = 120;
// TERM grace + direct reap + descendant TERM/KILL + final group absence is < 8s.
#[allow(dead_code)] // Source-checked timeout hierarchy contract shared with the shell harness.
const QUALIFICATION_CLEANUP_BUDGET_SECS: u64 = 8;

fn main() -> ExitCode {
    match run() {
        Ok(status) => status,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(70)
        }
    }
}

fn run() -> Result<ExitCode, &'static str> {
    let mut args = std::env::args_os();
    let _binary = args.next();
    let Some(package) = args.next() else {
        usage();
        return Ok(ExitCode::from(64));
    };
    if package == "verify-report" {
        let Some(report) = args.next() else {
            usage();
            return Ok(ExitCode::from(64));
        };
        if args.next().is_some() {
            usage();
            return Ok(ExitCode::from(64));
        }
        verify_acceptance_report(Path::new(&report))
            .map_err(|_| "acceptance report verification failed")?;
        return Ok(ExitCode::SUCCESS);
    }
    let Some(qualification) = args.next() else {
        usage();
        return Ok(ExitCode::from(64));
    };
    let Some(output) = args.next() else {
        usage();
        return Ok(ExitCode::from(64));
    };
    if args.next().is_some() {
        usage();
        return Ok(ExitCode::from(64));
    }
    let qualification =
        std::fs::read(&qualification).map_err(|_| "qualification evidence read failed")?;
    verify_fresh_repository_probe_execution(Path::new(&package), &qualification)?;
    let artifacts = evaluate_operational_lifeline(Path::new(&package), &qualification)
        .map_err(|_| "operational acceptance evaluation failed")?;
    let output = Path::new(&output);
    let parent = output.parent().ok_or("report output parent unavailable")?;
    let name = output
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("report output name invalid")?;
    let staging = OwnedTempDir::create_in(parent, &format!(".{name}.staging-"))
        .map_err(|_| "report staging directory creation failed")?;
    let publication = (|| {
        write_private(
            &staging.path().join("acceptance-scorecard.json"),
            &artifacts.scorecard_json,
        )?;
        write_private(
            &staging.path().join("acceptance-receipt.json"),
            &artifacts.receipt_json,
        )?;
        verify_acceptance_report(staging.path())
            .map_err(|_| "written acceptance report failed verification")?;
        #[cfg(unix)]
        if std::env::var_os("SMESH_TEST_REPORT_STAGING_CLEANUP_FAILURE").is_some() {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(staging.path(), std::fs::Permissions::from_mode(0o500))
                .map_err(|_| "report staging failure injection failed")?;
        }
        publish_report(staging.path(), output)
    })();
    match publication {
        Ok(()) => staging.relinquish(),
        Err(primary) => {
            return Err(if staging.close().is_ok() {
                primary
            } else {
                "report creation failed and staging cleanup failed"
            });
        }
    }
    Ok(if artifacts.receipt.status == AcceptanceStatus::Pass {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn verify_fresh_repository_probe_execution(
    package: &Path,
    supplied: &[u8],
) -> Result<(), &'static str> {
    let root = OwnedProbeRoot::new()?;
    let output = root.path().join("qualification.json");
    let executable = std::env::current_exe()
        .map_err(|_| "acceptance executable path unavailable")?
        .parent()
        .ok_or("acceptance executable directory unavailable")?
        .join("operational-lifeline-qualification");
    let result = (|| {
        let status = run_owned_qualification(
            Command::new(executable)
                .arg(env!("CARGO_MANIFEST_DIR"))
                .arg(package)
                .arg(package)
                .arg(&output)
                .env("SMESH_QUALIFICATION_OWNED_PROBE_ROOT", root.path()),
        )?;
        if !status.success() {
            return Err("repository qualification probes failed");
        }
        let executed =
            std::fs::read(output).map_err(|_| "repository qualification output missing")?;
        if executed != supplied {
            return Err("qualification evidence does not match fresh repository probe execution");
        }
        Ok(())
    })();
    match (result, root.close()) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(_)) => Err("owned probe directory cleanup failed"),
        (Err(_), Err(_)) => Err("repository qualification failed and probe cleanup failed"),
    }
}

#[cfg(target_os = "linux")]
fn run_owned_qualification(
    command: &mut Command,
) -> Result<std::process::ExitStatus, &'static str> {
    use std::os::unix::process::CommandExt as _;
    let mut containment = QualificationContainment::enable()?;
    command.process_group(0);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|_| "repository qualification probe launch failed")?;
    if containment.retain_leader_identity(child.id()).is_err() {
        return Err(
            if terminate_owned_qualification(&mut child, &mut containment).is_ok() {
                "qualification leader identity unavailable"
            } else {
                "qualification leader identity unavailable and cleanup failed"
            },
        );
    }
    let Some(stderr) = child.stderr.take() else {
        return Err(
            if terminate_owned_qualification(&mut child, &mut containment).is_ok() {
                "qualification stderr unavailable"
            } else {
                "qualification stderr unavailable and cleanup failed"
            },
        );
    };
    let Ok(mut stderr) = BoundedPipe::new(stderr, 32 * 1024) else {
        return Err(
            if terminate_owned_qualification(&mut child, &mut containment).is_ok() {
                "qualification stderr nonblocking setup failed"
            } else {
                "qualification stderr nonblocking setup and cleanup failed"
            },
        );
    };
    let deadline = Instant::now() + Duration::from_secs(QUALIFICATION_TIMEOUT_SECS);
    let result = loop {
        if stderr.drain().is_err() {
            let cleanup = terminate_owned_qualification(&mut child, &mut containment);
            break if cleanup.is_ok() {
                Err("qualification stderr read failed")
            } else {
                Err("qualification stderr read and cleanup failed")
            };
        }
        match qualification_child_exited(&mut child) {
            Ok(true) => break finish_exited_qualification_group(&mut child, &mut containment),
            Ok(false) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Ok(false) => {
                let cleanup = terminate_owned_qualification(&mut child, &mut containment);
                break if cleanup.is_ok() {
                    Err("repository qualification probe timeout")
                } else {
                    Err("repository qualification probe timeout and cleanup failed")
                };
            }
            Err(()) => {
                let cleanup = terminate_owned_qualification(&mut child, &mut containment);
                break if cleanup.is_ok() {
                    Err("repository qualification probe wait failed")
                } else {
                    Err("repository qualification probe wait and cleanup failed")
                };
            }
        }
    };
    let drain_deadline = Instant::now() + Duration::from_millis(250);
    while !stderr.eof && Instant::now() < drain_deadline {
        stderr
            .drain()
            .map_err(|_| "qualification stderr read failed")?;
        if !stderr.eof {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    if result.is_err() || result.as_ref().is_ok_and(|status| !status.success()) {
        print_qualification_stderr_summary(&stderr.retained);
    }
    if !stderr.eof {
        return Err("repository qualification stderr pipe cleanup failed");
    }
    containment.write_emergency_evidence()?;
    result
}

#[cfg(not(target_os = "linux"))]
fn run_owned_qualification(
    _command: &mut Command,
) -> Result<std::process::ExitStatus, &'static str> {
    Err("operational qualification requires Linux; no child was launched")
}

#[cfg(target_os = "linux")]
struct BoundedPipe<R> {
    pipe: R,
    retained: Vec<u8>,
    limit: usize,
    eof: bool,
}

#[cfg(target_os = "linux")]
impl<R: std::io::Read + std::os::fd::AsFd> BoundedPipe<R> {
    fn new(pipe: R, limit: usize) -> std::io::Result<Self> {
        let flags = rustix::fs::fcntl_getfl(pipe.as_fd())?;
        rustix::fs::fcntl_setfl(pipe.as_fd(), flags | rustix::fs::OFlags::NONBLOCK)?;
        Ok(Self {
            pipe,
            retained: Vec::new(),
            limit,
            eof: false,
        })
    }

    fn drain(&mut self) -> std::io::Result<()> {
        let mut buffer = [0_u8; 4096];
        loop {
            match self.pipe.read(&mut buffer) {
                Ok(0) => {
                    self.eof = true;
                    return Ok(());
                }
                Ok(count) => {
                    let available = self.limit.saturating_sub(self.retained.len());
                    self.retained
                        .extend_from_slice(&buffer[..count.min(available)]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
}

fn print_qualification_stderr_summary(stderr: &[u8]) {
    if stderr.is_empty() {
        return;
    }
    let mut digest = Sha256::new();
    digest.update(b"smesh-operational-qualification-stderr-v1\0");
    digest.update(stderr);
    eprintln!(
        "repository qualification stderr captured: class=qualificationFailure bytes={} digest=sha256:{:x}",
        stderr.len(),
        digest.finalize()
    );
}

#[cfg(target_os = "linux")]
fn qualification_child_exited(child: &mut std::process::Child) -> Result<bool, ()> {
    if std::env::var_os("SMESH_TEST_QUALIFICATION_INITIAL_WAIT_FAILURE").is_some() {
        return Err(());
    }
    let pid = rustix::process::Pid::from_raw(child.id().cast_signed()).ok_or(())?;
    let options = rustix::process::WaitIdOptions::EXITED
        | rustix::process::WaitIdOptions::NOHANG
        | rustix::process::WaitIdOptions::NOWAIT;
    rustix::process::waitid(rustix::process::WaitId::Pid(pid), options)
        .map(|status| status.is_some())
        .map_err(|_| ())
}

#[cfg(target_os = "linux")]
struct QualificationContainment {
    owner: u32,
    leader: Option<ProcessIdentity>,
    emergency_fd: Option<std::os::fd::OwnedFd>,
    emergency_evidence: EmergencyRetryEvidence,
    fd_exhaustion_triggered: bool,
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct EmergencyRetryEvidence {
    fixture_exhaustion_emfile: u32,
    pidfd_open_emfile: u32,
    reserve_release: u32,
    pidfd_retry_success: u32,
}

#[cfg(target_os = "linux")]
impl QualificationContainment {
    fn enable() -> Result<Self, &'static str> {
        nix::sys::prctl::set_child_subreaper(true)
            .map_err(|_| "qualification descendant containment setup failed")?;
        let emergency_fd = rustix::fs::open(
            "/dev/null",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| "qualification emergency descriptor reservation failed")?;
        Ok(Self {
            owner: std::process::id(),
            leader: None,
            emergency_fd: Some(emergency_fd),
            emergency_evidence: EmergencyRetryEvidence::default(),
            fd_exhaustion_triggered: false,
        })
    }

    fn retain_leader_identity(&mut self, pid: u32) -> Result<(), ()> {
        let Some((parent, start_time)) = read_process_identity(pid)? else {
            return Err(());
        };
        if parent != self.owner {
            return Err(());
        }
        self.leader = Some(ProcessIdentity { pid, start_time });
        Ok(())
    }

    fn cleanup_reparented_descendants(&mut self, leader_unreaped: bool) -> Result<(), ()> {
        let owned_leader = if leader_unreaped { self.leader } else { None };
        let mut term_signalled = std::collections::HashSet::new();
        let mut failed = false;
        let term_deadline = Instant::now() + Duration::from_millis(500);
        loop {
            let children = direct_reparented_children(self.owner, owned_leader)?;
            if children.is_empty() {
                return if failed { Err(()) } else { Ok(()) };
            }
            let mut fd_exhaustion = self.exhaust_fds_before_pidfd()?;
            for child in children {
                let signal = term_signalled
                    .insert(child)
                    .then_some(rustix::process::Signal::TERM);
                failed |= process_reparented_child(
                    self.owner,
                    child,
                    signal,
                    &mut self.emergency_fd,
                    &mut self.emergency_evidence,
                    &mut fd_exhaustion,
                )
                .is_err();
            }
            if Instant::now() >= term_deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        let kill_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let children = direct_reparented_children(self.owner, owned_leader)?;
            if children.is_empty() {
                return if failed { Err(()) } else { Ok(()) };
            }
            let mut no_fd_exhaustion = Vec::new();
            for child in children {
                failed |= process_reparented_child(
                    self.owner,
                    child,
                    Some(rustix::process::Signal::KILL),
                    &mut self.emergency_fd,
                    &mut self.emergency_evidence,
                    &mut no_fd_exhaustion,
                )
                .is_err();
            }
            if Instant::now() >= kill_deadline {
                return Err(());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn exhaust_fds_before_pidfd(&mut self) -> Result<Vec<std::os::fd::OwnedFd>, ()> {
        if self.fd_exhaustion_triggered
            || std::env::var("SMESH_TEST_QUALIFICATION_EXHAUST_FDS_BEFORE_PIDFD").as_deref()
                != Ok("1")
        {
            return Ok(Vec::new());
        }
        self.fd_exhaustion_triggered = true;
        let mut held = Vec::new();
        loop {
            match rustix::fs::open(
                "/dev/null",
                rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            ) {
                Ok(fd) => held.push(fd),
                Err(rustix::io::Errno::MFILE) => {
                    self.emergency_evidence.fixture_exhaustion_emfile += 1;
                    return Ok(held);
                }
                Err(_) => return Err(()),
            }
        }
    }

    fn write_emergency_evidence(&self) -> Result<(), &'static str> {
        use std::io::Write as _;
        let Some(path) = std::env::var_os("SMESH_TEST_QUALIFICATION_EMERGENCY_EVIDENCE") else {
            return Ok(());
        };
        let body = format!(
            "{{\"fixtureExhaustionEmfileCount\":{},\"pidfdOpenEmfileCount\":{},\"reserveReleaseCount\":{},\"pidfdRetrySuccessCount\":{}}}",
            self.emergency_evidence.fixture_exhaustion_emfile,
            self.emergency_evidence.pidfd_open_emfile,
            self.emergency_evidence.reserve_release,
            self.emergency_evidence.pidfd_retry_success,
        );
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options
            .open(path)
            .map_err(|_| "qualification emergency evidence create failed")?;
        file.write_all(body.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|_| "qualification emergency evidence write failed")
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ProcessIdentity {
    pid: u32,
    start_time: u64,
}

#[cfg(target_os = "linux")]
fn should_process_reparented_identity(
    candidate: ProcessIdentity,
    owned_unreaped_leader: Option<ProcessIdentity>,
) -> bool {
    Some(candidate) != owned_unreaped_leader
}

#[cfg(target_os = "linux")]
fn direct_reparented_children(
    parent: u32,
    owned_unreaped_leader: Option<ProcessIdentity>,
) -> Result<Vec<ProcessIdentity>, ()> {
    let direct_children =
        std::fs::read_to_string(format!("/proc/self/task/{parent}/children")).map_err(|_| ())?;
    let mut children = Vec::new();
    for raw_pid in direct_children.split_whitespace() {
        let raw_pid = raw_pid.parse::<u32>().map_err(|_| ())?;
        let Some(before) = read_process_identity(raw_pid)? else {
            continue;
        };
        if before.0 != parent {
            continue;
        }
        let identity = ProcessIdentity {
            pid: raw_pid,
            start_time: before.1,
        };
        if !should_process_reparented_identity(identity, owned_unreaped_leader) {
            continue;
        }
        let Some(after) = read_process_identity(raw_pid)? else {
            continue;
        };
        if after == before && after.0 == parent {
            children.push(identity);
        }
    }
    Ok(children)
}

#[cfg(target_os = "linux")]
fn read_process_identity(pid: u32) -> Result<Option<(u32, u64)>, ()> {
    let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
    };
    let Some(fields) = stat.rsplit_once(") ").map(|(_, fields)| fields) else {
        return Err(());
    };
    let mut fields = fields.split_whitespace();
    let _state = fields.next().ok_or(())?;
    let parent = fields.next().ok_or(())?.parse::<u32>().map_err(|_| ())?;
    let start_time = fields.nth(17).ok_or(())?.parse::<u64>().map_err(|_| ())?;
    Ok(Some((parent, start_time)))
}

#[cfg(target_os = "linux")]
fn process_reparented_child(
    parent: u32,
    identity: ProcessIdentity,
    signal: Option<rustix::process::Signal>,
    emergency_fd: &mut Option<std::os::fd::OwnedFd>,
    emergency_evidence: &mut EmergencyRetryEvidence,
    fd_exhaustion: &mut Vec<std::os::fd::OwnedFd>,
) -> Result<(), ()> {
    let pid = rustix::process::Pid::from_raw(identity.pid.cast_signed()).ok_or(())?;
    let pidfd = match open_with_emergency_reserve(emergency_fd, emergency_evidence, || {
        rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())
    }) {
        Ok(pidfd) => pidfd,
        Err(rustix::io::Errno::SRCH) => return Ok(()),
        Err(_) => return Err(()),
    };
    fd_exhaustion.clear();
    let Some(after) = read_process_identity(identity.pid)? else {
        return Ok(());
    };
    if after.0 != parent || after.1 != identity.start_time {
        return Ok(());
    }
    if reaped_if_exited(pid)? {
        return Ok(());
    }
    let Some(signal) = signal else {
        return Ok(());
    };
    match rustix::process::pidfd_send_signal(&pidfd, signal) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        Err(_) => Err(()),
    }
}

#[cfg(target_os = "linux")]
fn open_with_emergency_reserve<T>(
    emergency_fd: &mut Option<std::os::fd::OwnedFd>,
    evidence: &mut EmergencyRetryEvidence,
    mut open: impl FnMut() -> Result<T, rustix::io::Errno>,
) -> Result<T, rustix::io::Errno> {
    match open() {
        Err(rustix::io::Errno::MFILE) if emergency_fd.is_some() => {
            evidence.pidfd_open_emfile += 1;
            drop(emergency_fd.take());
            evidence.reserve_release += 1;
            let result = open();
            if result.is_ok() {
                evidence.pidfd_retry_success += 1;
            }
            result
        }
        result => result,
    }
}

#[cfg(target_os = "linux")]
fn reaped_if_exited(pid: rustix::process::Pid) -> Result<bool, ()> {
    let observe = rustix::process::WaitIdOptions::EXITED
        | rustix::process::WaitIdOptions::NOHANG
        | rustix::process::WaitIdOptions::NOWAIT;
    if rustix::process::waitid(rustix::process::WaitId::Pid(pid), observe)
        .map_err(|_| ())?
        .is_none()
    {
        return Ok(false);
    }
    let reap = rustix::process::WaitIdOptions::EXITED | rustix::process::WaitIdOptions::NOHANG;
    rustix::process::waitid(rustix::process::WaitId::Pid(pid), reap)
        .map(|status| status.is_some())
        .map_err(|_| ())
}

#[cfg(target_os = "linux")]
fn finish_exited_qualification_group(
    child: &mut std::process::Child,
    containment: &mut QualificationContainment,
) -> Result<std::process::ExitStatus, &'static str> {
    let group = match qualification_group(child.id()) {
        Ok(group) => group,
        Err(error) => {
            let killed = child.kill().is_ok();
            let reaped = bounded_qualification_reap(child).is_ok();
            let descendants = containment.cleanup_reparented_descendants(!reaped).is_ok();
            return Err(if !killed || !reaped || !descendants {
                "repository qualification normal-exit cleanup failed"
            } else {
                error
            });
        }
    };
    let mut failed = false;
    match qualification_group_has_descendant(group, child.id()) {
        Ok(true) => failed |= signal_and_wait_for_qualification_descendants(group, child.id()),
        Ok(false) => {}
        Err(()) => {
            failed = true;
            failed |= signal_and_wait_for_qualification_descendants(group, child.id());
        }
    }
    let status = bounded_qualification_reap(child);
    failed |= containment
        .cleanup_reparented_descendants(status.is_err())
        .is_err();
    failed |= !qualification_group_absent(group);
    if failed || status.is_err() {
        Err("repository qualification normal-exit cleanup failed")
    } else {
        status
    }
}

#[cfg(target_os = "linux")]
fn qualification_group(id: u32) -> Result<rustix::process::Pid, &'static str> {
    rustix::process::Pid::from_raw(id.cast_signed())
        .ok_or("repository qualification process-group id invalid")
}

#[cfg(target_os = "linux")]
fn qualification_group_has_descendant(
    group: rustix::process::Pid,
    leader: u32,
) -> Result<bool, ()> {
    let group = group.as_raw_nonzero().get();
    for entry in std::fs::read_dir("/proc").map_err(|_| ())? {
        let entry = entry.map_err(|_| ())?;
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if pid == leader {
            continue;
        }
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        let Some(after_name) = stat.rsplit_once(") ").map(|(_, rest)| rest) else {
            continue;
        };
        if after_name
            .split_whitespace()
            .nth(2)
            .and_then(|value| value.parse::<i32>().ok())
            == Some(group)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(target_os = "linux")]
fn signal_and_wait_for_qualification_descendants(group: rustix::process::Pid, leader: u32) -> bool {
    let mut failed = signal_qualification_group(group, rustix::process::Signal::TERM).is_err();
    let grace = Instant::now() + Duration::from_millis(500);
    while Instant::now() < grace {
        match qualification_group_has_descendant(group, leader) {
            Ok(false) => return failed,
            Ok(true) => std::thread::sleep(Duration::from_millis(20)),
            Err(()) => {
                failed = true;
                break;
            }
        }
    }
    if signal_qualification_group(group, rustix::process::Signal::KILL).is_err() {
        failed = true;
        failed |=
            signal_qualification_group_fallback(group, rustix::process::Signal::KILL).is_err();
    }
    failed
}

#[cfg(target_os = "linux")]
fn signal_qualification_group(
    group: rustix::process::Pid,
    signal: rustix::process::Signal,
) -> Result<(), ()> {
    if std::env::var("SMESH_TEST_QUALIFICATION_SIGNAL_FAILURE").is_ok_and(|value| {
        (value == "TERM" && signal == rustix::process::Signal::TERM)
            || (value == "KILL" && signal == rustix::process::Signal::KILL)
    }) {
        return Err(());
    }
    signal_qualification_group_fallback(group, signal)
}

#[cfg(target_os = "linux")]
fn signal_qualification_group_fallback(
    group: rustix::process::Pid,
    signal: rustix::process::Signal,
) -> Result<(), ()> {
    match rustix::process::kill_process_group(group, signal) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        Err(_) => Err(()),
    }
}

#[cfg(target_os = "linux")]
fn qualification_group_alive(group: rustix::process::Pid) -> Result<bool, ()> {
    match rustix::process::test_kill_process_group(group) {
        Ok(()) => Ok(true),
        Err(rustix::io::Errno::SRCH) => Ok(false),
        Err(_) => Err(()),
    }
}

#[cfg(target_os = "linux")]
fn qualification_group_absent(group: rustix::process::Pid) -> bool {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match qualification_group_alive(group) {
            Ok(false) => return true,
            Ok(true) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(true) | Err(()) => return false,
        }
    }
}

#[cfg(target_os = "linux")]
fn terminate_owned_qualification(
    child: &mut std::process::Child,
    containment: &mut QualificationContainment,
) -> Result<(), ()> {
    let Ok(group) = qualification_group(child.id()) else {
        let killed = child.kill().is_ok();
        let reaped = bounded_qualification_reap(child).is_ok();
        let descendants = containment.cleanup_reparented_descendants(!reaped).is_ok();
        return if killed && reaped && descendants {
            Ok(())
        } else {
            Err(())
        };
    };
    let mut failed = signal_qualification_group(group, rustix::process::Signal::TERM).is_err();
    let grace = Instant::now() + Duration::from_millis(500);
    while Instant::now() < grace {
        match qualification_group_alive(group) {
            Ok(false) => break,
            Ok(true) => std::thread::sleep(Duration::from_millis(20)),
            Err(()) => {
                failed = true;
                break;
            }
        }
    }
    if qualification_group_alive(group).unwrap_or(true)
        && signal_qualification_group(group, rustix::process::Signal::KILL).is_err()
    {
        failed = true;
        failed |= child.kill().is_err();
        failed |=
            signal_qualification_group_fallback(group, rustix::process::Signal::KILL).is_err();
    }
    let reaped = bounded_qualification_reap(child).is_ok();
    failed |= !reaped;
    failed |= containment.cleanup_reparented_descendants(!reaped).is_err();
    failed |= !qualification_group_absent(group);
    if failed { Err(()) } else { Ok(()) }
}

struct OwnedProbeRoot(OwnedTempDir);

impl OwnedProbeRoot {
    fn new() -> Result<Self, &'static str> {
        OwnedTempDir::create("smesh-acceptance-owned-probe-")
            .map(Self)
            .map_err(|_| "owned probe directory creation failed")
    }

    fn path(&self) -> &Path {
        self.0.path()
    }

    fn close(self) -> std::io::Result<()> {
        self.0.close()
    }
}

#[cfg(target_os = "linux")]
fn bounded_qualification_reap(
    child: &mut std::process::Child,
) -> Result<std::process::ExitStatus, &'static str> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => return Err("repository qualification reap timeout"),
            Err(_) => return Err("repository qualification reap failed"),
        }
    }
}

fn usage() {
    eprintln!(
        "usage: operational-lifeline-acceptance <operational-package> <qualification-probes.json> <new-report-directory>\n       operational-lifeline-acceptance verify-report <report-directory>"
    );
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), &'static str> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "report file creation failed")?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| "report file write failed")
}

fn publish_report(staging: &Path, output: &Path) -> Result<(), &'static str> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        staging,
        rustix::fs::CWD,
        output,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|_| "new report directory publication failed")
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{
        EmergencyRetryEvidence, ProcessIdentity, open_with_emergency_reserve,
        should_process_reparented_identity,
    };

    #[test]
    fn reused_leader_pid_with_a_new_start_identity_is_selected_for_cleanup() {
        let leader = ProcessIdentity {
            pid: 41,
            start_time: 1_000,
        };
        let reused = ProcessIdentity {
            pid: 41,
            start_time: 1_001,
        };

        assert!(!should_process_reparented_identity(leader, Some(leader)));
        assert!(should_process_reparented_identity(reused, Some(leader)));
        assert!(should_process_reparented_identity(leader, None));
    }

    #[test]
    fn emfile_consumes_the_pre_spawn_reserve_and_retries_once() {
        let reserve = rustix::fs::open(
            "/dev/null",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let mut reserve = Some(reserve);
        let mut evidence = EmergencyRetryEvidence::default();
        let mut attempts = 0;
        let result = open_with_emergency_reserve(&mut reserve, &mut evidence, || {
            attempts += 1;
            if attempts == 1 {
                Err(rustix::io::Errno::MFILE)
            } else {
                Ok(())
            }
        });

        assert_eq!(result, Ok(()));
        assert_eq!(attempts, 2);
        assert!(reserve.is_none());
        assert_eq!(evidence.pidfd_open_emfile, 1);
        assert_eq!(evidence.reserve_release, 1);
        assert_eq!(evidence.pidfd_retry_success, 1);
    }
}
