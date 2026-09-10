use std::io::Read;
use std::process::{Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};
use wait_timeout::ChildExt as _;

const TERM_GRACE: Duration = Duration::from_millis(500);
const REAP_WATCHDOG: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const PIPE_DRAIN_WATCHDOG: Duration = Duration::from_millis(250);
const PIPE_CAPTURE_LIMIT: usize = 256 * 1024;

#[derive(Clone, Copy, Default)]
struct InjectedErrors {
    initial_wait: bool,
    term_signal: bool,
    kill_signal: bool,
}

pub fn bounded_status(
    command: &mut Command,
    watchdog: Duration,
    label: &str,
) -> Result<ExitStatus, String> {
    let mut child = spawn_owned(command, label)?;
    wait_and_reap(&mut child, watchdog, label, InjectedErrors::default())
}

pub fn bounded_output(
    command: &mut Command,
    watchdog: Duration,
    label: &str,
) -> Result<Output, String> {
    bounded_output_with_errors(command, watchdog, label, InjectedErrors::default())
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_lines)] // Lifecycle and both owned pipe drains form one state machine.
fn bounded_output_with_errors(
    command: &mut Command,
    watchdog: Duration,
    label: &str,
    injected: InjectedErrors,
) -> Result<Output, String> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = spawn_owned(command, label)?;
    let mut stdout = match PipeCapture::new(
        child.stdout.take().expect("configured child stdout pipe"),
        PIPE_CAPTURE_LIMIT,
    ) {
        Ok(pipe) => pipe,
        Err(error) => {
            let cleanup = cleanup_owned_group(&mut child, label, injected);
            return Err(format!(
                "{label} stdout nonblocking setup failed: {error}; cleanup errors: {}",
                cleanup.join("; ")
            ));
        }
    };
    let mut stderr = match PipeCapture::new(
        child.stderr.take().expect("configured child stderr pipe"),
        PIPE_CAPTURE_LIMIT,
    ) {
        Ok(pipe) => pipe,
        Err(error) => {
            let cleanup = cleanup_owned_group(&mut child, label, injected);
            return Err(format!(
                "{label} stderr nonblocking setup failed: {error}; cleanup errors: {}",
                cleanup.join("; ")
            ));
        }
    };
    let deadline = Instant::now() + watchdog;
    let status = loop {
        let stdout_result = stdout.drain();
        let stderr_result = stderr.drain();
        if let Err(error) = stdout_result {
            let primary = format!("{label} stdout read failed: {error}");
            let cleanup = cleanup_owned_group(&mut child, label, injected);
            break if cleanup.is_empty() {
                Err(primary)
            } else {
                Err(format!("{primary}; cleanup errors: {}", cleanup.join("; ")))
            };
        }
        if let Err(error) = stderr_result {
            let primary = format!("{label} stderr read failed: {error}");
            let cleanup = cleanup_owned_group(&mut child, label, injected);
            break if cleanup.is_empty() {
                Err(primary)
            } else {
                Err(format!("{primary}; cleanup errors: {}", cleanup.join("; ")))
            };
        }
        match observe_child_exit(&mut child, Duration::ZERO) {
            Ok(true) => break finish_normally_exited_group(&mut child, label),
            Ok(false) if Instant::now() < deadline => std::thread::sleep(POLL_INTERVAL),
            Ok(false) => {
                let primary = format!("{label} timed out after {watchdog:?}");
                let cleanup = cleanup_owned_group(&mut child, label, injected);
                break if cleanup.is_empty() {
                    Err(primary)
                } else {
                    Err(format!("{primary}; cleanup errors: {}", cleanup.join("; ")))
                };
            }
            Err(error) => {
                let primary = format!("{label} wait failed: {error}");
                let cleanup = cleanup_owned_group(&mut child, label, injected);
                break if cleanup.is_empty() {
                    Err(primary)
                } else {
                    Err(format!("{primary}; cleanup errors: {}", cleanup.join("; ")))
                };
            }
        }
    };

    let drain_deadline = Instant::now() + PIPE_DRAIN_WATCHDOG;
    while (!stdout.eof || !stderr.eof) && Instant::now() < drain_deadline {
        let _ = stdout.drain();
        let _ = stderr.drain();
        if !stdout.eof || !stderr.eof {
            std::thread::sleep(POLL_INTERVAL);
        }
    }
    let mut errors = Vec::new();
    let status = match status {
        Ok(status) => Some(status),
        Err(error) => {
            errors.push(error);
            None
        }
    };
    if !stdout.eof {
        errors.push(format!("{label} stdout pipe remained open after cleanup"));
    }
    if !stderr.eof {
        errors.push(format!("{label} stderr pipe remained open after cleanup"));
    }
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    Ok(Output {
        status: status.expect("status present without errors"),
        stdout: stdout.retained,
        stderr: stderr.retained,
    })
}

#[cfg(not(target_os = "linux"))]
fn bounded_output_with_errors(
    _command: &mut Command,
    _watchdog: Duration,
    label: &str,
    _injected: InjectedErrors,
) -> Result<Output, String> {
    Err(format!(
        "{label} requires Linux process groups; no child was launched"
    ))
}

#[cfg(target_os = "linux")]
struct PipeCapture<R> {
    pipe: R,
    retained: Vec<u8>,
    limit: usize,
    eof: bool,
}

#[cfg(target_os = "linux")]
impl<R: Read + std::os::fd::AsFd> PipeCapture<R> {
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

#[cfg(target_os = "linux")]
fn spawn_owned(command: &mut Command, label: &str) -> Result<std::process::Child, String> {
    use std::os::unix::process::CommandExt as _;
    command.process_group(0);
    let retry_deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match command.spawn() {
            Ok(child) => return Ok(child),
            Err(error) if error.raw_os_error() == Some(26) && Instant::now() < retry_deadline => {
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(error) => return Err(format!("{label} spawn failed: {error}")),
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn spawn_owned(_command: &mut Command, label: &str) -> Result<std::process::Child, String> {
    Err(format!(
        "{label} requires Linux process groups; no child was launched"
    ))
}

fn wait_and_reap(
    child: &mut std::process::Child,
    watchdog: Duration,
    label: &str,
    injected: InjectedErrors,
) -> Result<ExitStatus, String> {
    let initial = if injected.initial_wait {
        Err(std::io::Error::other("injected initial wait failure"))
    } else {
        observe_child_exit(child, watchdog)
    };
    let primary = match initial {
        Ok(true) => return finish_normally_exited_group(child, label),
        Ok(false) => format!("{label} timed out after {watchdog:?}"),
        Err(error) => format!("{label} wait failed: {error}"),
    };

    let cleanup = cleanup_owned_group(child, label, injected);
    if cleanup.is_empty() {
        Err(primary)
    } else {
        Err(format!("{primary}; cleanup errors: {}", cleanup.join("; ")))
    }
}

#[cfg(target_os = "linux")]
fn observe_child_exit(
    child: &mut std::process::Child,
    watchdog: Duration,
) -> std::io::Result<bool> {
    let pid = rustix::process::Pid::from_raw(child.id().cast_signed())
        .ok_or_else(|| std::io::Error::other("invalid child pid"))?;
    let options = rustix::process::WaitIdOptions::EXITED
        | rustix::process::WaitIdOptions::NOHANG
        | rustix::process::WaitIdOptions::NOWAIT;
    let deadline = Instant::now() + watchdog;
    loop {
        if rustix::process::waitid(rustix::process::WaitId::Pid(pid), options)
            .map_err(std::io::Error::from)?
            .is_some()
        {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(not(target_os = "linux"))]
fn observe_child_exit(
    _child: &mut std::process::Child,
    _watchdog: Duration,
) -> std::io::Result<bool> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Linux waitid WNOWAIT is required",
    ))
}

#[cfg(unix)]
fn finish_normally_exited_group(
    child: &mut std::process::Child,
    label: &str,
) -> Result<ExitStatus, String> {
    let mut errors = Vec::new();
    let group = rustix::process::Pid::from_raw(child.id().cast_signed())
        .ok_or_else(|| format!("{label} had invalid pid {}", child.id()))?;
    match owned_group_has_descendant(group, child.id()) {
        Ok(true) => terminate_group_before_reap(group, child.id(), label, &mut errors),
        Ok(false) => signal_group(
            group,
            rustix::process::Signal::KILL,
            label,
            "final KILL",
            &mut errors,
        ),
        Err(error) => {
            errors.push(format!("{label} descendant check failed: {error}"));
            terminate_group_before_reap(group, child.id(), label, &mut errors);
        }
    }
    let status = bounded_reap(child, label);
    verify_group_absent(group, label, &mut errors);
    match (status, errors.is_empty()) {
        (Ok(status), true) => Ok(status),
        (Ok(_), false) => Err(format!("{label} cleanup errors: {}", errors.join("; "))),
        (Err(primary), true) => Err(primary),
        (Err(primary), false) => Err(format!("{primary}; cleanup errors: {}", errors.join("; "))),
    }
}

#[cfg(not(unix))]
fn finish_normally_exited_group(
    child: &mut std::process::Child,
    label: &str,
) -> Result<ExitStatus, String> {
    bounded_reap(child, label)
}

#[cfg(target_os = "linux")]
fn owned_group_has_descendant(
    group: rustix::process::Pid,
    leader: u32,
) -> Result<bool, std::io::Error> {
    let group = group.as_raw_nonzero().get();
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
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

#[cfg(all(unix, not(target_os = "linux")))]
fn owned_group_has_descendant(
    group: rustix::process::Pid,
    _leader: u32,
) -> Result<bool, std::io::Error> {
    group_alive(group).map_err(std::io::Error::from)
}

#[cfg(unix)]
fn terminate_group_before_reap(
    group: rustix::process::Pid,
    leader: u32,
    label: &str,
    errors: &mut Vec<String>,
) {
    signal_group(group, rustix::process::Signal::TERM, label, "TERM", errors);
    let grace_deadline = Instant::now() + TERM_GRACE;
    while Instant::now() < grace_deadline {
        match owned_group_has_descendant(group, leader) {
            Ok(false) => return,
            Ok(true) => std::thread::sleep(POLL_INTERVAL),
            Err(error) => {
                errors.push(format!("{label} TERM grace check failed: {error}"));
                break;
            }
        }
    }
    signal_group(group, rustix::process::Signal::KILL, label, "KILL", errors);
}

#[cfg(unix)]
fn cleanup_owned_group(
    child: &mut std::process::Child,
    label: &str,
    injected: InjectedErrors,
) -> Vec<String> {
    let mut errors = Vec::new();
    let Some(group) = rustix::process::Pid::from_raw(child.id().cast_signed()) else {
        errors.push(format!("{label} had invalid pid {}", child.id()));
        reap_direct_child(child, label, &mut errors);
        return errors;
    };

    signal_group_with_injection(
        group,
        rustix::process::Signal::TERM,
        label,
        "TERM",
        injected.term_signal,
        &mut errors,
    );

    let grace_deadline = Instant::now() + TERM_GRACE;
    while Instant::now() < grace_deadline {
        match group_alive(group) {
            Ok(false) => break,
            Ok(true) => std::thread::sleep(POLL_INTERVAL),
            Err(error) => {
                errors.push(format!("{label} TERM grace check failed: {error}"));
                break;
            }
        }
    }

    match group_alive(group) {
        Ok(true) => {
            let kill_failed = signal_group_with_injection(
                group,
                rustix::process::Signal::KILL,
                label,
                "KILL",
                injected.kill_signal,
                &mut errors,
            );
            if kill_failed {
                if let Err(error) = child.kill() {
                    errors.push(format!(
                        "{label} direct child kill fallback failed: {error}"
                    ));
                }
                signal_group(
                    group,
                    rustix::process::Signal::KILL,
                    label,
                    "fallback KILL",
                    &mut errors,
                );
            }
        }
        Ok(false) => {}
        Err(error) => {
            errors.push(format!("{label} pre-KILL group check failed: {error}"));
            if let Err(error) = child.kill() {
                errors.push(format!(
                    "{label} direct child kill fallback failed: {error}"
                ));
            }
            signal_group(
                group,
                rustix::process::Signal::KILL,
                label,
                "fallback KILL",
                &mut errors,
            );
        }
    }

    reap_direct_child(child, label, &mut errors);
    verify_group_absent(group, label, &mut errors);
    errors
}

#[cfg(unix)]
fn signal_group(
    group: rustix::process::Pid,
    signal: rustix::process::Signal,
    label: &str,
    name: &str,
    errors: &mut Vec<String>,
) {
    match rustix::process::kill_process_group(group, signal) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => {}
        Err(error) => errors.push(format!("{label} process-group {name} failed: {error}")),
    }
}

#[cfg(unix)]
fn signal_group_with_injection(
    group: rustix::process::Pid,
    signal: rustix::process::Signal,
    label: &str,
    name: &str,
    injected_failure: bool,
    errors: &mut Vec<String>,
) -> bool {
    if injected_failure {
        errors.push(format!("{label} injected {name} signal failure"));
        return true;
    }
    let before = errors.len();
    signal_group(group, signal, label, name, errors);
    errors.len() != before
}

#[cfg(unix)]
fn group_alive(group: rustix::process::Pid) -> Result<bool, rustix::io::Errno> {
    match rustix::process::test_kill_process_group(group) {
        Ok(()) => Ok(true),
        Err(rustix::io::Errno::SRCH) => Ok(false),
        Err(error) => Err(error),
    }
}

fn reap_direct_child(child: &mut std::process::Child, label: &str, errors: &mut Vec<String>) {
    match bounded_reap(child, label) {
        Ok(_) => return,
        Err(error) => errors.push(error),
    }
    if let Err(error) = child.kill() {
        errors.push(format!(
            "{label} direct child kill fallback failed: {error}"
        ));
    }
    if let Err(error) = bounded_reap(child, label) {
        errors.push(format!("{label} post-kill {error}"));
    }
}

fn bounded_reap(child: &mut std::process::Child, label: &str) -> Result<ExitStatus, String> {
    match child.wait_timeout(REAP_WATCHDOG) {
        Ok(Some(status)) => Ok(status),
        Ok(None) => Err(format!(
            "{label} direct child did not exit within the reap watchdog"
        )),
        Err(error) => Err(format!("{label} reap wait failed: {error}")),
    }
}

#[cfg(unix)]
fn verify_group_absent(group: rustix::process::Pid, label: &str, errors: &mut Vec<String>) {
    let deadline = Instant::now() + REAP_WATCHDOG;
    loop {
        match group_alive(group) {
            Ok(false) => return,
            Ok(true) if Instant::now() < deadline => std::thread::sleep(POLL_INTERVAL),
            Ok(true) => {
                errors.push(format!(
                    "{label} process group remained after KILL and reap"
                ));
                return;
            }
            Err(error) => {
                errors.push(format!("{label} group absence check failed: {error}"));
                return;
            }
        }
    }
}

#[cfg(not(unix))]
fn cleanup_owned_group(
    child: &mut std::process::Child,
    label: &str,
    _injected: InjectedErrors,
) -> Vec<String> {
    let mut errors = Vec::new();
    if let Err(error) = child.kill() {
        errors.push(format!("{label} direct child kill failed: {error}"));
    }
    reap_direct_child(child, label, &mut errors);
    errors
}

#[cfg(all(test, unix))]
pub fn bounded_status_with_injected_term_signal_failure(
    command: &mut Command,
    watchdog: Duration,
    label: &str,
) -> Result<ExitStatus, String> {
    let mut child = spawn_owned(command, label)?;
    wait_and_reap(
        &mut child,
        watchdog,
        label,
        InjectedErrors {
            initial_wait: false,
            term_signal: true,
            kill_signal: false,
        },
    )
}

#[cfg(all(test, target_os = "linux"))]
pub fn bounded_output_with_injected_kill_signal_failure(
    command: &mut Command,
    watchdog: Duration,
    label: &str,
) -> Result<Output, String> {
    bounded_output_with_errors(
        command,
        watchdog,
        label,
        InjectedErrors {
            initial_wait: false,
            term_signal: false,
            kill_signal: true,
        },
    )
}

#[cfg(all(test, unix))]
pub fn bounded_status_with_injected_kill_signal_failure(
    command: &mut Command,
    watchdog: Duration,
    label: &str,
) -> Result<ExitStatus, String> {
    let mut child = spawn_owned(command, label)?;
    wait_and_reap(
        &mut child,
        watchdog,
        label,
        InjectedErrors {
            initial_wait: false,
            term_signal: false,
            kill_signal: true,
        },
    )
}
