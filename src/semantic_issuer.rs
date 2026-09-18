use std::collections::BTreeSet;
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use thiserror::Error;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::Command;
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::{
    IssuerRoleV1, SignedIssuerEvidenceV1, TextConcordanceCandidatePacketV1,
    validate_text_concordance_candidate,
};

const MAX_PACKET_BYTES: usize = 2_000_000;
const MAX_STDOUT_BYTES: u64 = 65_536;
const MAX_STDERR_BYTES: u64 = 4_096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextConcordanceIssuerProcess {
    pub role: IssuerRoleV1,
    pub identity: String,
    pub program: PathBuf,
    pub key_file: PathBuf,
}

#[derive(Debug, Clone)]
pub struct TextConcordanceIssuerSet {
    issuers: [TextConcordanceIssuerProcess; 3],
}

#[derive(Debug, Error)]
pub enum TextConcordanceIssuerError {
    #[error("semantic issuer configuration is invalid")]
    InvalidConfiguration,
    #[error("semantic candidate packet is invalid")]
    InvalidCandidate,
    #[error("semantic issuer process failed")]
    ProcessFailed,
    #[error("semantic issuer process timed out")]
    TimedOut,
    #[error("semantic issuer output is invalid")]
    InvalidOutput,
}

impl TextConcordanceIssuerSet {
    /// Construct the closed three-role independent issuer set.
    ///
    /// # Errors
    /// Returns an error unless roles, identities, key files, and absolute programs are distinct.
    pub fn new(
        issuers: [TextConcordanceIssuerProcess; 3],
    ) -> Result<Self, TextConcordanceIssuerError> {
        let mut roles = BTreeSet::new();
        let mut identities = BTreeSet::new();
        let mut key_files = BTreeSet::new();
        let mut public_keys = BTreeSet::new();
        for issuer in &issuers {
            let seed = crate::private_file::read_owner_private_exact::<32>(&issuer.key_file)
                .map_err(|_| TextConcordanceIssuerError::InvalidConfiguration)?;
            let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
            if issuer.identity.is_empty()
                || issuer.identity.len() > 512
                || !issuer.program.is_absolute()
                || !issuer.key_file.is_absolute()
                || !roles.insert(role_arg(issuer.role))
                || !identities.insert(issuer.identity.as_str())
                || !key_files.insert(issuer.key_file.as_path())
                || !public_keys.insert(public_key)
            {
                return Err(TextConcordanceIssuerError::InvalidConfiguration);
            }
        }
        if roles.len() != 3 {
            return Err(TextConcordanceIssuerError::InvalidConfiguration);
        }
        Ok(Self { issuers })
    }

    /// Run all three role-separated issuer processes concurrently with bounded I/O and lifetime.
    ///
    /// # Errors
    /// Returns a redacted error when any process fails, times out, or emits a mismatched record.
    pub async fn issue_all(
        &self,
        packet: &TextConcordanceCandidatePacketV1,
        timeout: Duration,
    ) -> Result<Vec<SignedIssuerEvidenceV1>, TextConcordanceIssuerError> {
        validate_text_concordance_candidate(packet)
            .map_err(|_| TextConcordanceIssuerError::InvalidCandidate)?;
        let packet_json =
            serde_json::to_vec(packet).map_err(|_| TextConcordanceIssuerError::InvalidCandidate)?;
        if packet_json.len() > MAX_PACKET_BYTES || timeout.is_zero() {
            return Err(TextConcordanceIssuerError::InvalidCandidate);
        }

        let mut tasks = JoinSet::new();
        for issuer in self.issuers.clone() {
            let packet_json = packet_json.clone();
            let candidate = packet.candidate.clone();
            tasks.spawn(async move { run_issuer(issuer, packet_json, candidate, timeout).await });
        }
        let mut evidence = Vec::with_capacity(3);
        let mut failure = None;
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok(signed)) => evidence.push(signed),
                Ok(Err(error)) => {
                    failure.get_or_insert(error);
                }
                Err(_) => {
                    failure.get_or_insert(TextConcordanceIssuerError::ProcessFailed);
                }
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        evidence.sort_by_key(|signed| role_order(signed.evidence.issuer_role));
        if evidence.len() != 3 {
            return Err(TextConcordanceIssuerError::ProcessFailed);
        }
        Ok(evidence)
    }
}

fn spawn_issuer(
    issuer: &TextConcordanceIssuerProcess,
) -> Result<tokio::process::Child, TextConcordanceIssuerError> {
    let mut command = Command::new(&issuer.program);
    command
        .args([
            "--role",
            role_arg(issuer.role),
            "--identity",
            &issuer.identity,
            "--key-file",
        ])
        .arg(&issuer.key_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.as_std_mut().process_group(0);
    command
        .spawn()
        .map_err(|_| TextConcordanceIssuerError::ProcessFailed)
}

async fn run_issuer(
    issuer: TextConcordanceIssuerProcess,
    packet_json: Vec<u8>,
    candidate: crate::CandidateGenerationV1,
    timeout: Duration,
) -> Result<SignedIssuerEvidenceV1, TextConcordanceIssuerError> {
    let deadline = Instant::now() + timeout;
    let mut child = spawn_issuer(&issuer)?;
    let mut process_group = ProcessGroupGuard::new(&child)?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or(TextConcordanceIssuerError::ProcessFailed)?;
    let stdout = child
        .stdout
        .take()
        .ok_or(TextConcordanceIssuerError::ProcessFailed)?;
    let stderr = child
        .stderr
        .take()
        .ok_or(TextConcordanceIssuerError::ProcessFailed)?;
    match tokio::time::timeout_at(deadline, async {
        stdin.write_all(&packet_json).await?;
        stdin.shutdown().await
    })
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            terminate_child(&mut child, &mut process_group).await;
            return Err(TextConcordanceIssuerError::ProcessFailed);
        }
        Err(_) => {
            terminate_child(&mut child, &mut process_group).await;
            return Err(TextConcordanceIssuerError::TimedOut);
        }
    }
    drop(stdin);
    let execution = async {
        let read_stdout = async {
            let mut bytes = Vec::new();
            stdout
                .take(MAX_STDOUT_BYTES + 1)
                .read_to_end(&mut bytes)
                .await?;
            Ok::<_, std::io::Error>(bytes)
        };
        let read_stderr = async {
            let mut bytes = Vec::new();
            stderr
                .take(MAX_STDERR_BYTES + 1)
                .read_to_end(&mut bytes)
                .await?;
            Ok::<_, std::io::Error>(bytes)
        };
        let (stdout, stderr, status) = tokio::try_join!(read_stdout, read_stderr, child.wait())?;
        Ok::<_, std::io::Error>((status, stdout, stderr))
    };
    let (status, stdout, stderr) = match tokio::time::timeout_at(deadline, execution).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => {
            terminate_child(&mut child, &mut process_group).await;
            return Err(TextConcordanceIssuerError::ProcessFailed);
        }
        Err(_) => {
            terminate_child(&mut child, &mut process_group).await;
            return Err(TextConcordanceIssuerError::TimedOut);
        }
    };
    process_group.terminate();
    if !status.success()
        || !stderr.is_empty()
        || stdout.len() > usize::try_from(MAX_STDOUT_BYTES).unwrap_or(usize::MAX)
        || stderr.len() > usize::try_from(MAX_STDERR_BYTES).unwrap_or(usize::MAX)
    {
        return Err(TextConcordanceIssuerError::ProcessFailed);
    }
    let signed: SignedIssuerEvidenceV1 =
        serde_json::from_slice(&stdout).map_err(|_| TextConcordanceIssuerError::InvalidOutput)?;
    signed
        .evidence
        .validate_candidate(&candidate)
        .map_err(|_| TextConcordanceIssuerError::InvalidOutput)?;
    if signed.evidence.issuer_role != issuer.role
        || signed.evidence.issuer_identity != issuer.identity
    {
        return Err(TextConcordanceIssuerError::InvalidOutput);
    }
    Ok(signed)
}

#[cfg(unix)]
struct ProcessGroupGuard {
    pgid: Option<nix::unistd::Pid>,
}

#[cfg(unix)]
impl ProcessGroupGuard {
    fn new(child: &tokio::process::Child) -> Result<Self, TextConcordanceIssuerError> {
        let pgid = child
            .id()
            .and_then(|pid| i32::try_from(pid).ok())
            .map(nix::unistd::Pid::from_raw)
            .ok_or(TextConcordanceIssuerError::ProcessFailed)?;
        Ok(Self { pgid: Some(pgid) })
    }

    fn terminate(&mut self) {
        if let Some(pgid) = self.pgid.take() {
            let _ = nix::sys::signal::killpg(pgid, nix::sys::signal::Signal::SIGKILL);
        }
    }
}

#[cfg(unix)]
impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        self.terminate();
    }
}

#[cfg(not(unix))]
struct ProcessGroupGuard;

#[cfg(not(unix))]
impl ProcessGroupGuard {
    fn new(_child: &tokio::process::Child) -> Result<Self, TextConcordanceIssuerError> {
        Ok(Self)
    }

    fn terminate(&mut self) {}
}

async fn terminate_child(child: &mut tokio::process::Child, process_group: &mut ProcessGroupGuard) {
    process_group.terminate();
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        let _ = child.kill().await;
        let _ = child.wait().await;
    })
    .await;
}

const fn role_arg(role: IssuerRoleV1) -> &'static str {
    match role {
        IssuerRoleV1::Review => "review",
        IssuerRoleV1::Test => "test",
        IssuerRoleV1::Contradiction => "contradiction",
    }
}

const fn role_order(role: IssuerRoleV1) -> u8 {
    match role {
        IssuerRoleV1::Review => 0,
        IssuerRoleV1::Test => 1,
        IssuerRoleV1::Contradiction => 2,
    }
}
