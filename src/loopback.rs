use async_trait::async_trait;
use futures::stream::{self, BoxStream};

use crate::{
    ArtifactManifest, CompletionEvidence, DispatchError, MeshDispatcher, MeshEvent, MeshRequest,
    artifact_set_digest, content_digest,
};

/// Deterministic local worker used by tests and the standalone demo.
#[derive(Debug, Clone, Default)]
pub struct LoopbackDispatcher;

#[async_trait]
impl MeshDispatcher for LoopbackDispatcher {
    fn dispatch(
        &self,
        request: MeshRequest,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        let signal = request.to_signal("loopback-worker");
        let content = serde_json::json!({
            "taskId": request.task_id,
            "contextId": request.context_id,
            "result": format!("SMESH accepted: {}", request.text),
            "signalHash": signal.origin_hash,
        })
        .to_string();
        let subject_digest = match artifact_set_digest(&[ArtifactManifest {
            name: "smesh-result.json".to_owned(),
            media_type: "application/json".to_owned(),
            digest: content_digest(content.as_bytes()),
        }]) {
            Ok(digest) => digest,
            Err(error) => {
                return Box::pin(stream::iter([Err(DispatchError::Message(format!(
                    "loopback completion manifest failed: {error}"
                )))]));
            }
        };

        Box::pin(stream::iter([
            Ok(MeshEvent::Progress(
                "task claimed by the loopback SMESH worker".to_owned(),
            )),
            Ok(MeshEvent::Evidence(CompletionEvidence::Review {
                id: "loopback-review".to_owned(),
                issuer: "review-authority".to_owned(),
                subject_digest: subject_digest.clone(),
                evidence: b"loopback deterministic review fixture".to_vec(),
                evidence_digest: content_digest(b"loopback deterministic review fixture"),
                approved: true,
                assurance_bps: 10_000,
            })),
            Ok(MeshEvent::Evidence(CompletionEvidence::Test {
                id: "loopback-test".to_owned(),
                issuer: "test-authority".to_owned(),
                subject_digest: subject_digest.clone(),
                evidence: b"loopback deterministic test fixture".to_vec(),
                evidence_digest: content_digest(b"loopback deterministic test fixture"),
                passed: true,
                assurance_bps: 10_000,
            })),
            Ok(MeshEvent::Evidence(CompletionEvidence::Contradiction {
                id: "loopback-contradiction-clearance".to_owned(),
                issuer: "contradiction-monitor".to_owned(),
                subject_digest,
                evidence: b"loopback deterministic contradiction clearance".to_vec(),
                evidence_digest: content_digest(b"loopback deterministic contradiction clearance"),
                blocking: false,
            })),
            Ok(MeshEvent::Artifact {
                name: "smesh-result.json".to_owned(),
                media_type: "application/json".to_owned(),
                content,
            }),
            Ok(MeshEvent::Completed {
                summary: "SMESH swarm completed the task".to_owned(),
            }),
        ]))
    }

    async fn cancel(&self, _task_id: &str) -> Result<(), DispatchError> {
        Ok(())
    }
}
