#![cfg(unix)]

use std::collections::BTreeSet;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use smesh_a2a::{
    CandidateGenerationV1, IssuerEnrollmentV1, IssuerRoleV1, SignedIssuerEvidenceV1,
    TEXT_CONCORDANCE_COMPLETION_POLICY_REVISION_V1, TEXT_CONCORDANCE_COMPLETION_POLICY_V1,
    TextConcordanceCandidatePacketV1, TextConcordanceIssuerProcess, TextConcordanceIssuerSet,
    TextConcordanceLimits, process_text_concordance,
};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "smesh-semantic-issuer-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn key(&self, name: &str, seed: [u8; 32]) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, seed).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    fn program(&self, name: &str, body: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct PublishedDescendant {
    group: i32,
    pid: u32,
    start_ticks: u64,
}

#[cfg(target_os = "linux")]
struct UnrelatedProcess(std::process::Child);

#[cfg(target_os = "linux")]
impl UnrelatedProcess {
    fn new() -> Self {
        Self(Command::new("sleep").arg("30").spawn().unwrap())
    }

    fn assert_alive(&mut self) {
        assert!(
            self.0.try_wait().unwrap().is_none(),
            "unrelated process was terminated"
        );
    }
}

#[cfg(target_os = "linux")]
impl Drop for UnrelatedProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(target_os = "linux")]
impl PublishedDescendant {
    fn read(path: &std::path::Path) -> Option<Self> {
        let value = std::fs::read_to_string(path).ok()?;
        let mut fields = value.split_whitespace();
        Some(Self {
            group: fields.next()?.parse().ok()?,
            pid: fields.next()?.parse().ok()?,
            start_ticks: fields.next()?.parse().ok()?,
        })
    }

    fn is_same_process(self) -> bool {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", self.pid)) else {
            return false;
        };
        stat.rsplit_once(") ")
            .and_then(|(_, tail)| tail.split_whitespace().nth(19))
            .and_then(|value| value.parse::<u64>().ok())
            == Some(self.start_ticks)
    }

    fn cleanup(self) {
        let _ = nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(self.group),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
}

#[cfg(target_os = "linux")]
async fn wait_for_descendants(
    fixture: &Fixture,
    identities: [&str; 3],
) -> Vec<PublishedDescendant> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let descendants = identities.map(|identity| {
            PublishedDescendant::read(&fixture.0.join(format!("{identity}.descendant")))
        });
        if descendants.iter().all(Option::is_some) {
            return descendants.into_iter().flatten().collect();
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "issuer descendants did not publish bounded readiness"
        );
        tokio::task::yield_now().await;
    }
}

#[cfg(target_os = "linux")]
async fn descendants_still_alive(descendants: &[PublishedDescendant]) -> Vec<PublishedDescendant> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let alive: Vec<_> = descendants
            .iter()
            .copied()
            .filter(|descendant| descendant.is_same_process())
            .collect();
        if alive.is_empty() || tokio::time::Instant::now() >= deadline {
            return alive;
        }
        tokio::task::yield_now().await;
    }
}

fn packet() -> TextConcordanceCandidatePacketV1 {
    let output = process_text_concordance(
        "separate process evidence",
        TextConcordanceLimits::default(),
    )
    .unwrap();
    TextConcordanceCandidatePacketV1 {
        candidate: CandidateGenerationV1 {
            tenant_scope: "tenant-a".to_owned(),
            task_id: "task-a".to_owned(),
            context_id: "context-a".to_owned(),
            request_digest: output.request_digest,
            artifact_set_digest: output.artifact_set_digest,
            dispatch_id: "dispatch-a".to_owned(),
            attempt: 1,
            fence: 2,
            completion_policy: TEXT_CONCORDANCE_COMPLETION_POLICY_V1.to_owned(),
            completion_policy_revision: TEXT_CONCORDANCE_COMPLETION_POLICY_REVISION_V1,
        },
        input: "separate process evidence".to_owned(),
        artifact: URL_SAFE_NO_PAD.encode(output.artifact_bytes),
        observed_conflict_digests: Vec::new(),
    }
}

#[test]
fn three_distinct_issuer_processes_produce_verifiable_role_bound_evidence() {
    let fixture = Fixture::new();
    let packet = packet();
    let packet_json = serde_json::to_vec(&packet).unwrap();
    let cases = [
        ("review", IssuerRoleV1::Review, "review-key-1", 1_u8),
        ("test", IssuerRoleV1::Test, "test-key-1", 2_u8),
        (
            "contradiction",
            IssuerRoleV1::Contradiction,
            "contradiction-key-1",
            3_u8,
        ),
    ];
    let mut pids = BTreeSet::new();

    for (role_arg, role, identity, seed) in cases {
        let key_path = fixture.key(identity, [seed; 32]);
        let mut child = Command::new(env!("CARGO_BIN_EXE_smesh-text-concordance-issuer"))
            .args([
                "--role",
                role_arg,
                "--identity",
                identity,
                "--key-file",
                key_path.to_str().unwrap(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        assert!(pids.insert(child.id()));
        child.stdin.take().unwrap().write_all(&packet_json).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        let signed: SignedIssuerEvidenceV1 = serde_json::from_slice(&output.stdout).unwrap();
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let enrollment = IssuerEnrollmentV1 {
            tenant_scope: "tenant-a".to_owned(),
            issuer_role: role,
            issuer_identity: identity.to_owned(),
            public_key: URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
            valid_from: 1,
            expires_at: 1_000,
            revoked_at: None,
        };
        signed.verify(&packet.candidate, &enrollment, 100).unwrap();
    }
    assert_eq!(pids.len(), 3);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn timeout_kills_descendants_after_leader_exits_with_inherited_pipes() {
    let fixture = Fixture::new();
    let mut unrelated = UnrelatedProcess::new();
    let program = fixture.program(
        "leader-exits.sh",
        &format!(
            "#!/bin/sh\nsleep 30 & child=$!\nstart=$(awk '{{print $22}}' /proc/$child/stat)\necho \"$$ $child $start\" > {}/$4.descendant\nexit 0\n",
            fixture.0.display()
        ),
    );
    let cases = [
        (IssuerRoleV1::Review, "review-key-1", 1_u8),
        (IssuerRoleV1::Test, "test-key-1", 2_u8),
        (IssuerRoleV1::Contradiction, "contradiction-key-1", 3_u8),
    ];
    let configs = cases.map(|(role, identity, seed)| TextConcordanceIssuerProcess {
        role,
        identity: identity.to_owned(),
        program: program.clone(),
        key_file: fixture.key(identity, [seed; 32]),
    });
    let issuers = TextConcordanceIssuerSet::new(configs).unwrap();
    assert!(
        issuers
            .issue_all(&packet(), Duration::from_millis(100))
            .await
            .is_err()
    );
    let descendants = wait_for_descendants(
        &fixture,
        ["review-key-1", "test-key-1", "contradiction-key-1"],
    )
    .await;
    let alive = descendants_still_alive(&descendants).await;
    unrelated.assert_alive();
    for descendant in &alive {
        descendant.cleanup();
    }
    assert!(
        alive.is_empty(),
        "descendants survived leader-exit timeout: {}",
        alive.len()
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn dropping_issue_all_kills_every_published_descendant() {
    let fixture = Fixture::new();
    let mut unrelated = UnrelatedProcess::new();
    let program = fixture.program(
        "cancel.sh",
        &format!(
            "#!/bin/sh\nsleep 30 & child=$!\nstart=$(awk '{{print $22}}' /proc/$child/stat)\necho \"$$ $child $start\" > {}/$4.descendant\nwait\n",
            fixture.0.display()
        ),
    );
    let cases = [
        (IssuerRoleV1::Review, "review-key-1", 1_u8),
        (IssuerRoleV1::Test, "test-key-1", 2_u8),
        (IssuerRoleV1::Contradiction, "contradiction-key-1", 3_u8),
    ];
    let configs = cases.map(|(role, identity, seed)| TextConcordanceIssuerProcess {
        role,
        identity: identity.to_owned(),
        program: program.clone(),
        key_file: fixture.key(identity, [seed; 32]),
    });
    let issuers = TextConcordanceIssuerSet::new(configs).unwrap();
    let task =
        tokio::spawn(async move { issuers.issue_all(&packet(), Duration::from_secs(20)).await });
    let descendants = wait_for_descendants(
        &fixture,
        ["review-key-1", "test-key-1", "contradiction-key-1"],
    )
    .await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let alive = descendants_still_alive(&descendants).await;
    unrelated.assert_alive();
    for descendant in &alive {
        descendant.cleanup();
    }
    assert!(
        alive.is_empty(),
        "descendants survived issue_all cancellation: {}",
        alive.len()
    );
}

#[tokio::test]
async fn production_supervisor_rejects_duplicate_key_material_before_spawn() {
    let fixture = Fixture::new();
    let program = PathBuf::from(env!("CARGO_BIN_EXE_smesh-text-concordance-issuer"));
    let configs = [
        (IssuerRoleV1::Review, "review-key-1"),
        (IssuerRoleV1::Test, "test-key-1"),
        (IssuerRoleV1::Contradiction, "contradiction-key-1"),
    ]
    .map(|(role, identity)| TextConcordanceIssuerProcess {
        role,
        identity: identity.to_owned(),
        program: program.clone(),
        key_file: fixture.key(identity, [7_u8; 32]),
    });
    assert!(TextConcordanceIssuerSet::new(configs).is_err());
}

#[tokio::test]
async fn production_supervisor_timeout_kills_and_reaps_every_process_group() {
    let fixture = Fixture::new();
    let program = fixture.program(
        "hang.sh",
        &format!(
            "#!/bin/sh\necho $$ > {}/$4.pid\nsleep 30\n",
            fixture.0.display()
        ),
    );
    let cases = [
        (IssuerRoleV1::Review, "review-key-1", 1_u8),
        (IssuerRoleV1::Test, "test-key-1", 2_u8),
        (IssuerRoleV1::Contradiction, "contradiction-key-1", 3_u8),
    ];
    let configs = cases.map(|(role, identity, seed)| TextConcordanceIssuerProcess {
        role,
        identity: identity.to_owned(),
        program: program.clone(),
        key_file: fixture.key(identity, [seed; 32]),
    });
    let issuers = TextConcordanceIssuerSet::new(configs).unwrap();
    let started = std::time::Instant::now();
    assert!(
        issuers
            .issue_all(&packet(), Duration::from_millis(100))
            .await
            .is_err()
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    for (_, identity, _) in cases {
        let pid = std::fs::read_to_string(fixture.0.join(format!("{identity}.pid"))).unwrap();
        assert!(
            !PathBuf::from(format!("/proc/{}", pid.trim())).exists(),
            "issuer process {pid} survived supervisor timeout"
        );
    }
}

#[tokio::test]
async fn production_supervisor_runs_closed_issuer_set_and_verifies_outputs() {
    let fixture = Fixture::new();
    let program = PathBuf::from(env!("CARGO_BIN_EXE_smesh-text-concordance-issuer"));
    let cases = [
        (IssuerRoleV1::Review, "review-key-1", 1_u8),
        (IssuerRoleV1::Test, "test-key-1", 2_u8),
        (IssuerRoleV1::Contradiction, "contradiction-key-1", 3_u8),
    ];
    let configs = cases.map(|(role, identity, seed)| TextConcordanceIssuerProcess {
        role,
        identity: identity.to_owned(),
        program: program.clone(),
        key_file: fixture.key(identity, [seed; 32]),
    });
    let issuers = TextConcordanceIssuerSet::new(configs).unwrap();
    let packet = packet();
    let signed = issuers
        .issue_all(&packet, Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(signed.len(), 3);
    for ((role, identity, seed), evidence) in cases.into_iter().zip(signed) {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        evidence
            .verify(
                &packet.candidate,
                &IssuerEnrollmentV1 {
                    tenant_scope: "tenant-a".to_owned(),
                    issuer_role: role,
                    issuer_identity: identity.to_owned(),
                    public_key: URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
                    valid_from: 1,
                    expires_at: 1_000,
                    revoked_at: None,
                },
                100,
            )
            .unwrap();
    }
}
