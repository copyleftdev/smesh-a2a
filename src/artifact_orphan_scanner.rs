use std::{sync::Arc, time::Duration};

use a2a::A2AError;
use tokio::{sync::watch, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::DurableAuthority;

const MAX_CONSECUTIVE_FAILURES: u32 = 3;
fn retry_backoff(failures: u32) -> Duration {
    Duration::from_millis(25 * u64::from(failures))
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ArtifactOrphanScannerState {
    pub fatal: Option<String>,
    pub deleted: u64,
    pub refunded_bytes: u64,
}

pub struct ArtifactOrphanScannerHandle {
    cancel: CancellationToken,
    state: watch::Receiver<ArtifactOrphanScannerState>,
    join: Option<JoinHandle<()>>,
}

impl ArtifactOrphanScannerHandle {
    #[must_use]
    pub fn state(&self) -> ArtifactOrphanScannerState {
        self.state.borrow().clone()
    }

    /// Stop and join the scanner.
    ///
    /// # Errors
    /// Returns an internal error if the worker panics or misses its shutdown watchdog.
    pub async fn shutdown(mut self) -> Result<(), A2AError> {
        self.cancel.cancel();
        let Some(mut join) = self.join.take() else {
            return Ok(());
        };
        match tokio::time::timeout(Duration::from_secs(5), &mut join).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(A2AError::internal("artifact orphan scanner join failed")),
            Err(_) => {
                join.abort();
                let _ = join.await;
                Err(A2AError::internal(
                    "artifact orphan scanner shutdown timed out",
                ))
            }
        }
    }
}

impl Drop for ArtifactOrphanScannerHandle {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

#[must_use]
pub fn spawn_artifact_orphan_scanner(
    authority: Arc<dyn DurableAuthority>,
) -> Option<ArtifactOrphanScannerHandle> {
    let artifact = authority.artifact_authority()?;
    if !artifact.artifact_capabilities().promotion {
        return None;
    }
    let cancel = CancellationToken::new();
    let worker_cancel = cancel.clone();
    let (state_tx, state) = watch::channel(ArtifactOrphanScannerState::default());
    let batch = artifact.artifact_runtime_limits().worker_batch;
    let join = tokio::spawn(async move {
        let mut current = ArtifactOrphanScannerState::default();
        let mut consecutive_failures = 0_u32;
        while let Some(artifact) = authority.artifact_authority() {
            let scan = tokio::select! { ()=worker_cancel.cancelled()=>break, scan=artifact.scan_artifact_stage_orphans(300_000,batch)=>scan };
            if let Ok(report) = scan {
                consecutive_failures = 0;
                current.deleted = current.deleted.saturating_add(report.deleted as u64);
                current.refunded_bytes =
                    current.refunded_bytes.saturating_add(report.refunded_bytes);
                let _ = state_tx.send(current.clone());
            } else {
                consecutive_failures = consecutive_failures.saturating_add(1);
                if consecutive_failures < MAX_CONSECUTIVE_FAILURES {
                    tokio::select! {()=worker_cancel.cancelled()=>break,()=tokio::time::sleep(retry_backoff(consecutive_failures))=>{}}
                    continue;
                }
                current.fatal = Some("artifact orphan scanner authority failure".into());
                let _ = state_tx.send(current);
                break;
            }
            tokio::select! { ()=worker_cancel.cancelled()=>break, ()=tokio::time::sleep(Duration::from_secs(30))=>{} }
        }
    });
    Some(ArtifactOrphanScannerHandle {
        cancel,
        state,
        join: Some(join),
    })
}
