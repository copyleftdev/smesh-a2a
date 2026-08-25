use a2a::Message;
use async_trait::async_trait;
use futures::stream::BoxStream;
use serde::{Deserialize, Serialize};
use smesh_core::{Signal, SignalType};
use thiserror::Error;

use crate::{InputError, InputLimits, extract_text};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DispatchError {
    #[error("mesh dispatch failed: {0}")]
    Message(String),
}

/// Progress emitted by the internal mesh and translated to A2A events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshEvent {
    Progress(String),
    Artifact {
        name: String,
        media_type: String,
        content: String,
    },
    Completed {
        summary: String,
    },
}

#[async_trait]
pub trait MeshDispatcher: Send + Sync + 'static {
    fn dispatch(
        &self,
        request: MeshRequest,
    ) -> BoxStream<'static, Result<MeshEvent, DispatchError>>;

    async fn cancel(&self, task_id: &str) -> Result<(), DispatchError>;
}

/// Validated work crossing from the A2A boundary into SMESH.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshRequest {
    pub protocol: String,
    pub task_id: String,
    pub context_id: String,
    pub text: String,
}

impl MeshRequest {
    /// Validate an A2A message and create the internal task envelope.
    ///
    /// # Errors
    ///
    /// Returns [`InputError`] when the message is empty, oversized, or
    /// contains a non-text part.
    pub fn from_a2a(
        task_id: String,
        context_id: String,
        message: &Message,
        limits: InputLimits,
    ) -> Result<Self, InputError> {
        Ok(Self {
            protocol: "a2a-v1".to_owned(),
            task_id,
            context_id,
            text: extract_text(message, limits)?,
        })
    }

    /// Encode this request as a real SMESH query signal.
    #[must_use]
    pub fn to_signal(&self, gateway_node_id: &str) -> Signal {
        Signal::builder(SignalType::Query)
            .payload_json(self)
            .origin(gateway_node_id)
            .build()
    }
}
