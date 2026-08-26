use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use smesh_a2a::{ArtifactManifest, artifact_set_digest, content_digest};

const MAX_INPUT_BYTES: u64 = 64 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SpecialistInput {
    schema: String,
    task_id: String,
    context_id: String,
    subject_digest: String,
    artifact_name: String,
    media_type: String,
    content: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SpecialistOutput {
    schema: &'static str,
    role: String,
    issuer: &'static str,
    approved: bool,
    assurance_bps: u16,
    evidence: String,
    task_id: String,
    context_id: String,
    subject_digest: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let role = std::env::args().nth(1).ok_or("missing specialist role")?;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > usize::try_from(MAX_INPUT_BYTES)? {
        return Err("specialist input exceeds 64 KiB".into());
    }
    let input: SpecialistInput = serde_json::from_slice(&bytes)?;
    validate_input(&input)?;
    let computed_subject = artifact_set_digest(&[ArtifactManifest {
        name: input.artifact_name.clone(),
        media_type: input.media_type.clone(),
        digest: content_digest(input.content.as_bytes()),
    }])?;
    if computed_subject != input.subject_digest {
        return Err("specialist subject digest does not match artifact bytes".into());
    }
    let content: serde_json::Value = serde_json::from_str(&input.content)?;
    let (issuer, approved, evidence) = match role.as_str() {
        "review" => (
            "review-authority",
            content
                .get("analysis")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| !value.is_empty()),
            "reviewed non-empty semantic analysis",
        ),
        "test" => (
            "test-authority",
            content
                .get("checks")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|checks| checks.len() >= 2),
            "verified at least two declared checks",
        ),
        "contradiction" => (
            "contradiction-monitor",
            content
                .get("contradictions")
                .and_then(serde_json::Value::as_array)
                .is_some_and(Vec::is_empty),
            "checked declared contradiction set",
        ),
        _ => return Err("unsupported specialist role".into()),
    };
    let output = SpecialistOutput {
        schema: "smesh-a2a/specialist-output/v1",
        role,
        issuer,
        approved,
        assurance_bps: 10_000,
        evidence: evidence.to_owned(),
        task_id: input.task_id,
        context_id: input.context_id,
        subject_digest: input.subject_digest,
    };
    let encoded = serde_json::to_vec(&output)?;
    std::io::stdout().write_all(&encoded)?;
    Ok(())
}

fn validate_input(input: &SpecialistInput) -> Result<(), Box<dyn std::error::Error>> {
    if input.schema != "smesh-a2a/specialist-input/v1" {
        return Err("unsupported specialist input schema".into());
    }
    for value in [
        &input.task_id,
        &input.context_id,
        &input.artifact_name,
        &input.media_type,
    ] {
        if value.is_empty() || value.len() > 512 {
            return Err("invalid specialist binding field".into());
        }
    }
    let digest = input
        .subject_digest
        .strip_prefix("sha256:")
        .ok_or("invalid subject digest prefix")?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("invalid subject digest".into());
    }
    Ok(())
}
