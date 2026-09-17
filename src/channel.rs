use async_trait::async_trait;
use futures::stream::BoxStream;
use smesh_core::Signal;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;

use crate::{
    DispatchError, DurableDispatchCorrelation, DurableRuntimeAdapter, DurableWorkEnvelope,
    ExecutionBudget, MeshDispatcher, MeshEvent, MeshRequest, PreparedDurableRuntimeDispatch,
    RuntimeAdapterAdmission, RuntimeAdapterExecution, RuntimeAdapterOutcome,
    RuntimeAdapterPreparation, RuntimeCancellationRequest, RuntimePreAdmissionFailure,
};

/// Commands handed from the A2A gateway to a real SMESH worker/runtime.
pub enum DispatchCommand {
    Execute {
        request: MeshRequest,
        budget: ExecutionBudget,
        signal: Box<Signal>,
        events: mpsc::Sender<Result<MeshEvent, DispatchError>>,
    },
    ExecuteDurable {
        envelope: Box<DurableWorkEnvelope>,
        signal: Box<Signal>,
        cancellation: tokio_util::sync::CancellationToken,
        admitted: oneshot::Sender<Result<(), RuntimePreAdmissionFailure>>,
        outcome: oneshot::Sender<RuntimeAdapterOutcome>,
        runtime_capacity: Option<tokio::sync::OwnedSemaphorePermit>,
    },
    CancelDurable {
        correlation: DurableDispatchCorrelation,
        ack: oneshot::Sender<RuntimeCancellationRequest>,
    },
    Cancel {
        task_id: String,
        ack: oneshot::Sender<Result<(), DispatchError>>,
    },
}

/// Dispatcher boundary for embedding the gateway around a SMESH runtime.
#[derive(Clone)]
pub struct ChannelDispatcher {
    commands: mpsc::Sender<DispatchCommand>,
    control: Option<mpsc::Sender<DispatchCommand>>,
    gateway_node_id: String,
    command_timeout: Duration,
    runtime_capacity: Option<Arc<tokio::sync::Semaphore>>,
}

impl ChannelDispatcher {
    #[must_use]
    pub fn new(
        commands: mpsc::Sender<DispatchCommand>,
        gateway_node_id: impl Into<String>,
    ) -> Self {
        Self {
            commands,
            control: None,
            gateway_node_id: gateway_node_id.into(),
            command_timeout: Duration::from_secs(5),
            runtime_capacity: None,
        }
    }

    pub(crate) fn with_control(mut self, control: mpsc::Sender<DispatchCommand>) -> Self {
        self.control = Some(control);
        self
    }

    pub(crate) fn with_runtime_capacity(
        mut self,
        runtime_capacity: Arc<tokio::sync::Semaphore>,
    ) -> Self {
        self.runtime_capacity = Some(runtime_capacity);
        self
    }

    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.command_timeout = timeout;
        self
    }
}

struct ChannelRuntimePermit {
    permit: mpsc::OwnedPermit<DispatchCommand>,
    _runtime_capacity: tokio::sync::OwnedSemaphorePermit,
    gateway_node_id: String,
    acknowledgement_timeout: Duration,
}

#[async_trait]
impl PreparedDurableRuntimeDispatch for ChannelRuntimePermit {
    async fn admit(
        self: Box<Self>,
        envelope: DurableWorkEnvelope,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> RuntimeAdapterAdmission {
        if cancellation.is_cancelled() {
            return RuntimeAdapterAdmission::Rejected(RuntimePreAdmissionFailure::Canceled);
        }
        if envelope.execution_reservation().is_none() {
            return RuntimeAdapterAdmission::Rejected(
                RuntimePreAdmissionFailure::MissingExecutionReservation,
            );
        }
        let ChannelRuntimePermit {
            permit,
            _runtime_capacity: runtime_capacity,
            gateway_node_id,
            acknowledgement_timeout,
        } = *self;
        let signal = envelope.request().to_signal(&gateway_node_id);
        let (admitted_tx, admitted_rx) = oneshot::channel();
        let (outcome_tx, outcome_rx) = oneshot::channel();
        permit.send(DispatchCommand::ExecuteDurable {
            envelope: Box::new(envelope),
            signal: Box::new(signal),
            cancellation,
            admitted: admitted_tx,
            outcome: outcome_tx,
            runtime_capacity: Some(runtime_capacity),
        });
        match tokio::time::timeout(acknowledgement_timeout, admitted_rx).await {
            Ok(Ok(Err(
                reason @ (RuntimePreAdmissionFailure::Capacity
                | RuntimePreAdmissionFailure::DuplicateCorrelation),
            ))) => RuntimeAdapterAdmission::Retryable(reason),
            Ok(Ok(Err(reason))) => RuntimeAdapterAdmission::Rejected(reason),
            Ok(Ok(Ok(())) | Err(_)) | Err(_) => {
                RuntimeAdapterAdmission::Admitted(RuntimeAdapterExecution::new(outcome_rx))
            }
        }
    }
}

#[async_trait]
impl DurableRuntimeAdapter for ChannelDispatcher {
    async fn prepare(&self) -> RuntimeAdapterPreparation {
        let channel_permit = match self.commands.clone().try_reserve_owned() {
            Ok(permit) => permit,
            Err(mpsc::error::TrySendError::Full(_)) => {
                return RuntimeAdapterPreparation::Retryable(RuntimePreAdmissionFailure::Capacity);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return RuntimeAdapterPreparation::Rejected(
                    RuntimePreAdmissionFailure::Unavailable,
                );
            }
        };
        let Some(capacity) = &self.runtime_capacity else {
            return RuntimeAdapterPreparation::Rejected(RuntimePreAdmissionFailure::Unavailable);
        };
        let runtime_capacity = match Arc::clone(capacity).try_acquire_owned() {
            Ok(permit) => permit,
            Err(tokio::sync::TryAcquireError::NoPermits) => {
                return RuntimeAdapterPreparation::Retryable(RuntimePreAdmissionFailure::Capacity);
            }
            Err(tokio::sync::TryAcquireError::Closed) => {
                return RuntimeAdapterPreparation::Rejected(
                    RuntimePreAdmissionFailure::Unavailable,
                );
            }
        };
        RuntimeAdapterPreparation::Ready(Box::new(ChannelRuntimePermit {
            permit: channel_permit,
            _runtime_capacity: runtime_capacity,
            gateway_node_id: self.gateway_node_id.clone(),
            acknowledgement_timeout: self.command_timeout,
        }))
    }

    async fn cancel_durable(
        &self,
        correlation: &DurableDispatchCorrelation,
    ) -> RuntimeCancellationRequest {
        let (ack, received) = oneshot::channel();
        let command = DispatchCommand::CancelDurable {
            correlation: correlation.clone(),
            ack,
        };
        match tokio::time::timeout(
            self.command_timeout,
            self.control
                .as_ref()
                .unwrap_or(&self.commands)
                .send(command),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => return RuntimeCancellationRequest::Unknown,
        }
        match tokio::time::timeout(self.command_timeout, received).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) | Err(_) => RuntimeCancellationRequest::Unknown,
        }
    }
}

#[async_trait]
impl MeshDispatcher for ChannelDispatcher {
    fn dispatch(
        &self,
        request: MeshRequest,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        self.dispatch_bounded(
            request,
            ExecutionBudget::new(64 * 1024 * 1024, 1_000_000)
                .expect("static dispatcher budget is valid"),
        )
    }

    fn dispatch_bounded(
        &self,
        request: MeshRequest,
        budget: ExecutionBudget,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        let signal = request.to_signal(&self.gateway_node_id);
        let commands = self.commands.clone();
        let (event_tx, event_rx) = mpsc::channel(32);
        let command = DispatchCommand::Execute {
            request,
            budget,
            signal: Box::new(signal),
            events: event_tx.clone(),
        };
        let error = match commands.try_send(command) {
            Ok(()) => None,
            Err(mpsc::error::TrySendError::Full(_)) => Some("SMESH worker command channel is full"),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Some("SMESH worker command channel is closed")
            }
        };
        if let Some(message) = error {
            let _ = event_tx.try_send(Err(DispatchError::Message(message.to_owned())));
        }

        Box::pin(ReceiverStream::new(event_rx))
    }

    async fn cancel(&self, task_id: &str) -> Result<(), DispatchError> {
        let (ack_tx, ack_rx) = oneshot::channel();
        let send = self.commands.send(DispatchCommand::Cancel {
            task_id: task_id.to_owned(),
            ack: ack_tx,
        });
        tokio::time::timeout(self.command_timeout, send)
            .await
            .map_err(|_| DispatchError::Message("SMESH cancellation command timed out".to_owned()))?
            .map_err(|_| {
                DispatchError::Message("SMESH worker command channel is closed".to_owned())
            })?;
        tokio::time::timeout(self.command_timeout, ack_rx)
            .await
            .map_err(|_| {
                DispatchError::Message("SMESH cancellation acknowledgement timed out".to_owned())
            })?
            .map_err(|_| {
                DispatchError::Message(
                    "SMESH worker dropped cancellation acknowledgement".to_owned(),
                )
            })?
    }
}
