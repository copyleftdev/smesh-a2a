use std::{sync::Arc, time::Duration};

use a2a::A2AError;
use tokio::{sync::watch, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{DurableAuthority, content_digest};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ArtifactPromoterState {
    pub fatal: Option<String>,
    pub promoted: u64,
}

/// Joinable owner for the production artifact upload promoter.
pub struct ArtifactPromoterHandle {
    cancel: CancellationToken,
    state: watch::Receiver<ArtifactPromoterState>,
    join: Option<JoinHandle<()>>,
}

impl ArtifactPromoterHandle {
    #[must_use]
    pub fn state(&self) -> ArtifactPromoterState {
        self.state.borrow().clone()
    }

    /// Stop the promoter and join its worker.
    ///
    /// # Errors
    /// Returns an internal error if the worker panics or cannot stop within the watchdog.
    pub async fn shutdown(mut self) -> Result<(), A2AError> {
        self.cancel.cancel();
        let Some(mut join) = self.join.take() else {
            return Ok(());
        };
        match tokio::time::timeout(Duration::from_secs(5), &mut join).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(A2AError::internal("artifact promoter join failed")),
            Err(_) => {
                join.abort();
                let _ = join.await;
                Err(A2AError::internal("artifact promoter shutdown timed out"))
            }
        }
    }
}

impl Drop for ArtifactPromoterHandle {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

#[must_use]
pub fn spawn_artifact_promoter(
    authority: Arc<dyn DurableAuthority>,
) -> Option<ArtifactPromoterHandle> {
    let artifact = authority.artifact_authority()?;
    if !artifact.artifact_capabilities().promotion {
        return None;
    }
    let cancel = CancellationToken::new();
    let worker_cancel = cancel.clone();
    let (state_tx, state) = watch::channel(ArtifactPromoterState::default());
    let batch = artifact.artifact_runtime_limits().worker_batch;
    let join = tokio::spawn(async move {
        let owner = content_digest(&rand::random::<[u8; 32]>());
        let mut promoted = 0_u64;
        while let Some(artifact) = authority.artifact_authority() {
            let claim = tokio::select! {
                () = worker_cancel.cancelled() => break,
                claim = artifact.claim_artifact_promotion(&owner, 30_000, batch) => claim,
            };
            match claim {
                Ok(claims) if !claims.is_empty() => {
                    crate::artifact_production_checkpoint(
                        "promoter_claim_before_physical_promotion",
                    );
                    for claim in claims {
                        match artifact.commit_artifact_promotion(&claim).await {
                            Ok(true) => {
                                promoted = promoted.saturating_add(1);
                                let _ = state_tx.send(ArtifactPromoterState {
                                    fatal: None,
                                    promoted,
                                });
                            }
                            Ok(false) => {}
                            Err(error) => {
                                let digest = content_digest(error.message.as_bytes());
                                if artifact
                                    .fail_artifact_promotion(&claim, &digest)
                                    .await
                                    .is_err()
                                {
                                    let _ = state_tx.send(ArtifactPromoterState {
                                        fatal: Some("artifact promoter authority failure".into()),
                                        promoted,
                                    });
                                    break;
                                }
                            }
                        }
                    }
                }
                Ok(_) => tokio::select! {
                    () = worker_cancel.cancelled() => break,
                    () = tokio::time::sleep(Duration::from_millis(100)) => {}
                },
                Err(_) => {
                    let _ = state_tx.send(ArtifactPromoterState {
                        fatal: Some("artifact promoter claim failure".into()),
                        promoted,
                    });
                    break;
                }
            }
        }
    });
    Some(ArtifactPromoterHandle {
        cancel,
        state,
        join: Some(join),
    })
}
