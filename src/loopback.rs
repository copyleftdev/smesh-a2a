use async_trait::async_trait;
use futures::stream::{self, BoxStream};

use crate::{DispatchError, MeshDispatcher, MeshEvent, MeshRequest};

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

        Box::pin(stream::iter([
            Ok(MeshEvent::Progress(
                "task claimed by the loopback SMESH worker".to_owned(),
            )),
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
