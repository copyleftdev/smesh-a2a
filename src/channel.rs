use async_trait::async_trait;
use futures::stream::BoxStream;
use smesh_core::Signal;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;

use crate::{DispatchError, MeshDispatcher, MeshEvent, MeshRequest};

/// Commands handed from the A2A gateway to a real SMESH worker/runtime.
pub enum DispatchCommand {
    Execute {
        request: MeshRequest,
        signal: Box<Signal>,
        events: mpsc::Sender<Result<MeshEvent, DispatchError>>,
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
    gateway_node_id: String,
    command_timeout: Duration,
}

impl ChannelDispatcher {
    #[must_use]
    pub fn new(
        commands: mpsc::Sender<DispatchCommand>,
        gateway_node_id: impl Into<String>,
    ) -> Self {
        Self {
            commands,
            gateway_node_id: gateway_node_id.into(),
            command_timeout: Duration::from_secs(5),
        }
    }

    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.command_timeout = timeout;
        self
    }
}

#[async_trait]
impl MeshDispatcher for ChannelDispatcher {
    fn dispatch(
        &self,
        request: MeshRequest,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>> {
        let signal = request.to_signal(&self.gateway_node_id);
        let commands = self.commands.clone();
        let command_timeout = self.command_timeout;
        let (event_tx, event_rx) = mpsc::channel(32);

        tokio::spawn(async move {
            let send = commands.send(DispatchCommand::Execute {
                request,
                signal: Box::new(signal),
                events: event_tx.clone(),
            });
            let error = match tokio::time::timeout(command_timeout, send).await {
                Ok(Ok(())) => None,
                Ok(Err(_)) => Some("SMESH worker command channel is closed"),
                Err(_) => Some("SMESH worker command send timed out"),
            };
            if let Some(message) = error {
                let _ = event_tx
                    .send(Err(DispatchError::Message(message.to_owned())))
                    .await;
            }
        });

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
