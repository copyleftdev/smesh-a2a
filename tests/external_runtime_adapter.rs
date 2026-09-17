use async_trait::async_trait;
use smesh_a2a::{
    DurableDispatchCorrelation, DurableRuntimeAdapter, DurableWorkEnvelope,
    PreparedDurableRuntimeDispatch, RuntimeAdapterAdmission, RuntimeAdapterExecution,
    RuntimeAdapterOutcome, RuntimeAdapterPreparation, RuntimeCancellationRequest,
};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

struct ExternalAdapter;
struct ExternalPrepared;

#[async_trait]
impl DurableRuntimeAdapter for ExternalAdapter {
    async fn prepare(&self) -> RuntimeAdapterPreparation {
        RuntimeAdapterPreparation::Ready(Box::new(ExternalPrepared))
    }

    async fn cancel_durable(
        &self,
        _correlation: &DurableDispatchCorrelation,
    ) -> RuntimeCancellationRequest {
        RuntimeCancellationRequest::Unknown
    }
}

#[async_trait]
impl PreparedDurableRuntimeDispatch for ExternalPrepared {
    async fn admit(
        self: Box<Self>,
        _envelope: DurableWorkEnvelope,
        _cancellation: CancellationToken,
    ) -> RuntimeAdapterAdmission {
        let (sender, receiver) = oneshot::channel();
        sender.send(RuntimeAdapterOutcome::AdmittedUnknown).unwrap();
        RuntimeAdapterAdmission::Admitted(RuntimeAdapterExecution::new(receiver))
    }
}

#[tokio::test]
async fn external_adapter_constructs_authority_free_execution() {
    assert!(matches!(
        ExternalAdapter.prepare().await,
        RuntimeAdapterPreparation::Ready(_)
    ));
    let (sender, receiver) = oneshot::channel();
    let execution = RuntimeAdapterExecution::new(receiver);
    sender
        .send(RuntimeAdapterOutcome::ConfirmedStopped)
        .unwrap();
    assert_eq!(
        execution.finish().await,
        RuntimeAdapterOutcome::ConfirmedStopped
    );

    let (sender, receiver) = oneshot::channel();
    let execution = RuntimeAdapterExecution::new(receiver);
    drop(sender);
    assert_eq!(
        execution.finish().await,
        RuntimeAdapterOutcome::AdmittedUnknown
    );
}
