use std::{sync::Arc, time::Duration};

use a2a::A2AError;
use tokio::{sync::watch, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{DurableAuthority, content_digest};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ArtifactGcState {
    pub fatal: Option<String>,
    pub deleted: u64,
}

/// Joinable owner for the production artifact garbage collector.
pub struct ArtifactGcHandle {
    cancel: CancellationToken,
    state: watch::Receiver<ArtifactGcState>,
    join: Option<JoinHandle<()>>,
}

impl ArtifactGcHandle {
    #[must_use]
    pub fn state(&self) -> ArtifactGcState {
        self.state.borrow().clone()
    }

    /// Stop and join the collector.
    ///
    /// # Errors
    /// Returns an internal error when the worker panics or misses its watchdog.
    pub async fn shutdown(mut self) -> Result<(), A2AError> {
        self.cancel.cancel();
        let Some(mut join) = self.join.take() else {
            return Ok(());
        };
        match tokio::time::timeout(Duration::from_secs(5), &mut join).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(A2AError::internal("artifact gc join failed")),
            Err(_) => {
                join.abort();
                let _ = join.await;
                Err(A2AError::internal("artifact gc shutdown timed out"))
            }
        }
    }
}
impl Drop for ArtifactGcHandle {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

#[must_use]
pub fn spawn_artifact_gc(authority: Arc<dyn DurableAuthority>) -> Option<ArtifactGcHandle> {
    let artifact = authority.artifact_authority()?;
    if !artifact.artifact_capabilities().retention_gc {
        return None;
    }
    let cancel = CancellationToken::new();
    let worker_cancel = cancel.clone();
    let (state_tx, state) = watch::channel(ArtifactGcState::default());
    let batch = artifact.artifact_runtime_limits().worker_batch;
    let join = tokio::spawn(async move {
        let owner = content_digest(&rand::random::<[u8; 32]>());
        let mut deleted = 0_u64;
        while let Some(artifact) = authority.artifact_authority() {
            let claim = tokio::select! { ()=worker_cancel.cancelled()=>break, claim=artifact.claim_artifact_gc(&owner,30_000,batch)=>claim };
            match claim {
                Ok(claims) if !claims.is_empty() => {
                    crate::artifact_production_checkpoint("gc_tombstone_claim_before_unlink");
                    for claim in claims {
                        let receipt = content_digest(
                            format!(
                                "{}\0{}\0{}",
                                claim.object_id, claim.tombstone_generation, claim.backend_locator
                            )
                            .as_bytes(),
                        );
                        match artifact.commit_artifact_gc(&claim, &receipt).await {
                            Ok(true) => {
                                deleted = deleted.saturating_add(1);
                                let _ = state_tx.send(ArtifactGcState {
                                    fatal: None,
                                    deleted,
                                });
                            }
                            Ok(false) => {}
                            Err(error) => {
                                let digest = content_digest(error.message.as_bytes());
                                if artifact.fail_artifact_gc(&claim, &digest).await.is_err() {
                                    let _ = state_tx.send(ArtifactGcState {
                                        fatal: Some("artifact gc authority failure".into()),
                                        deleted,
                                    });
                                    break;
                                }
                            }
                        }
                    }
                }
                Ok(_) => {
                    tokio::select! {()=worker_cancel.cancelled()=>break,()=tokio::time::sleep(Duration::from_millis(100))=>{}}
                }
                Err(_) => {
                    let _ = state_tx.send(ArtifactGcState {
                        fatal: Some("artifact gc claim failure".into()),
                        deleted,
                    });
                    break;
                }
            }
        }
    });
    Some(ArtifactGcHandle {
        cancel,
        state,
        join: Some(join),
    })
}
