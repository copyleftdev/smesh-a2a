use std::io::Write;
use std::process::{Command, Stdio};

use smesh_a2a::{ArtifactManifest, artifact_set_digest, content_digest};

#[test]
fn specialist_process_returns_bounded_role_specific_decision() {
    let program = env!("CARGO_BIN_EXE_smesh-e2e-specialist");
    let content = serde_json::json!({
        "analysis": "independent runtime result",
        "checks": ["binding", "policy"],
        "contradictions": [],
    })
    .to_string();
    let subject_digest = artifact_set_digest(&[ArtifactManifest {
        name: "analysis.json".to_owned(),
        media_type: "application/json".to_owned(),
        digest: content_digest(content.as_bytes()),
    }])
    .unwrap();
    let input = serde_json::json!({
        "schema": "smesh-a2a/specialist-input/v1",
        "taskId": "task-specialist",
        "contextId": "context-specialist",
        "subjectDigest": subject_digest,
        "artifactName": "analysis.json",
        "mediaType": "application/json",
        "content": content,
    });
    let mut child = Command::new(program)
        .arg("review")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(&input).unwrap().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.len() <= 4096);
    let decision: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(decision["schema"], "smesh-a2a/specialist-output/v1");
    assert_eq!(decision["role"], "review");
    assert_eq!(decision["issuer"], "review-authority");
    assert_eq!(decision["approved"], true);
    assert_eq!(decision["taskId"], "task-specialist");
    assert_eq!(decision["contextId"], "context-specialist");
    assert_eq!(decision["subjectDigest"], input["subjectDigest"]);
}
