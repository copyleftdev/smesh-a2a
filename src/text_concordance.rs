use std::collections::BTreeMap;

use a2a::{Message, PartContent, Role};
use async_trait::async_trait;
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::{
    ArtifactManifest, DispatchError, DurableReceiverResult, DurableReceiverTermination, MeshEvent,
    RuntimeEventSink, RuntimeTask, RuntimeTaskProcessor, artifact_set_digest, content_digest,
};

pub const STANDALONE_TEXT_CONCORDANCE_PROFILE_V1: &str = "standalone-postgres-text-concordance/v1";
pub const TEXT_CONCORDANCE_WORKLOAD_V1: &str = "text-concordance/v1";
pub const TEXT_CONCORDANCE_ARTIFACT_NAME_V1: &str = "text-concordance.v1.json";
pub const TEXT_CONCORDANCE_MEDIA_TYPE: &str = "application/json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextConcordanceLimits {
    pub max_input_bytes: u64,
    pub max_line_count: u64,
    pub max_ascii_word_count: u64,
    pub max_word_frequency: u64,
    pub max_artifact_bytes: u64,
}

impl Default for TextConcordanceLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 64 * 1024,
            max_line_count: 64 * 1024,
            max_ascii_word_count: 32 * 1024,
            max_word_frequency: 32 * 1024,
            max_artifact_bytes: 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextConcordanceOutput {
    pub request_digest: String,
    pub artifact_bytes: Vec<u8>,
    pub artifact_digest: String,
    pub manifest: ArtifactManifest,
    pub artifact_set_digest: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TextConcordanceProcessor {
    limits: TextConcordanceLimits,
}

impl TextConcordanceProcessor {
    #[must_use]
    pub const fn new(limits: TextConcordanceLimits) -> Self {
        Self { limits }
    }
}

#[async_trait]
impl RuntimeTaskProcessor for TextConcordanceProcessor {
    async fn process(
        &self,
        task: RuntimeTask,
        cancellation: CancellationToken,
        events: RuntimeEventSink,
    ) -> Result<(), DispatchError> {
        if cancellation.is_cancelled() {
            return Err(DispatchError::message(
                "text-concordance processor canceled",
            ));
        }
        let signal_exists = {
            let network = task.runtime.network();
            let network = network.read().await;
            network.field.signals.contains_key(&task.signal_hash)
        };
        if !signal_exists {
            return Err(DispatchError::message(
                "runtime did not retain the emitted text-concordance query signal",
            ));
        }
        let output = process_text_concordance(&task.request.text, self.limits)
            .map_err(|_| DispatchError::message("text-concordance processing rejected input"))?;
        if cancellation.is_cancelled() {
            return Err(DispatchError::message(
                "text-concordance processor canceled",
            ));
        }
        events
            .artifact_bytes(
                TEXT_CONCORDANCE_ARTIFACT_NAME_V1,
                TEXT_CONCORDANCE_MEDIA_TYPE,
                &output.artifact_bytes,
            )
            .await?;
        if cancellation.is_cancelled() {
            return Err(DispatchError::message(
                "text-concordance processor canceled",
            ));
        }
        events
            .propose_completion("text-concordance/v1 candidate proposed")
            .await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TextConcordanceError {
    #[error("text-concordance input byte limit exceeded")]
    InputBytesExceeded,
    #[error("text-concordance line-count limit exceeded")]
    LineCountExceeded,
    #[error("text-concordance ASCII-word-count limit exceeded")]
    AsciiWordCountExceeded,
    #[error("text-concordance word-frequency limit exceeded")]
    WordFrequencyExceeded,
    #[error("text-concordance artifact byte limit exceeded")]
    ArtifactBytesExceeded,
    #[error("text-concordance counter overflow")]
    CounterOverflow,
    #[error("text-concordance canonical encoding failed")]
    CanonicalEncoding,
    #[error("text-concordance runtime proposal is invalid")]
    InvalidRuntimeProposal,
}

/// Validate that an authority-free runtime proposed exactly the deterministic closed workload
/// artifact. This validates candidate material only; it does not authorize completion.
///
/// # Errors
/// Returns an error for any non-success termination, extra/missing event, wrong artifact
/// metadata, runtime-supplied evidence, malformed internal payload, or byte mismatch.
pub fn validate_text_concordance_runtime_proposal(
    input: &str,
    proposal: &DurableReceiverResult,
) -> Result<Vec<u8>, TextConcordanceError> {
    if proposal.termination != DurableReceiverTermination::Success
        || proposal.events.len() != 3
        || !matches!(
            &proposal.events[0],
            MeshEvent::Progress(message) if message == "SMESH runtime retained the query"
        )
    {
        return Err(TextConcordanceError::InvalidRuntimeProposal);
    }
    let bytes = match &proposal.events[1] {
        MeshEvent::Artifact {
            name,
            media_type,
            content,
        } if name == TEXT_CONCORDANCE_ARTIFACT_NAME_V1
            && media_type == TEXT_CONCORDANCE_MEDIA_TYPE =>
        {
            match crate::bridge::internal_artifact_payload(content) {
                Some(crate::bridge::InternalArtifactPayload::Binary { bytes }) => {
                    use base64::Engine as _;
                    base64::engine::general_purpose::STANDARD
                        .decode(bytes)
                        .map_err(|_| TextConcordanceError::InvalidRuntimeProposal)?
                }
                Some(crate::bridge::InternalArtifactPayload::Published { .. }) | None => {
                    return Err(TextConcordanceError::InvalidRuntimeProposal);
                }
            }
        }
        _ => return Err(TextConcordanceError::InvalidRuntimeProposal),
    };
    if !matches!(
        &proposal.events[2],
        MeshEvent::Completed { summary }
            if summary == "text-concordance/v1 candidate proposed"
    ) {
        return Err(TextConcordanceError::InvalidRuntimeProposal);
    }
    let expected = process_text_concordance(input, TextConcordanceLimits::default())?;
    if bytes != expected.artifact_bytes {
        return Err(TextConcordanceError::InvalidRuntimeProposal);
    }
    Ok(bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TextConcordanceInputError {
    #[error("text-concordance requires exactly one message part")]
    PartCount,
    #[error("text-concordance requires an inline text part")]
    UnsupportedPart,
    #[error("text-concordance part decorations are not supported")]
    PartDecorations,
    #[error("text-concordance message extensions are not supported")]
    MessageExtensions,
    #[error("text-concordance requires a user message")]
    WrongRole,
    #[error("text-concordance input byte limit exceeded")]
    InputBytesExceeded,
}

#[derive(Serialize)]
struct CanonicalArtifact<'a> {
    schema: &'static str,
    input_sha256: &'a str,
    utf8_bytes: u64,
    line_count: u64,
    ascii_word_count: u64,
    word_frequencies: &'a BTreeMap<String, u64>,
}

/// Validate the closed A2A input shape without joining, trimming, or normalizing text.
///
/// # Errors
///
/// Returns a typed shape or byte-bound error before durable admission.
pub fn extract_text_concordance_input(
    message: &Message,
    max_input_bytes: usize,
) -> Result<String, TextConcordanceInputError> {
    if message.role != Role::User {
        return Err(TextConcordanceInputError::WrongRole);
    }
    if message.metadata.is_some()
        || message.extensions.is_some()
        || message.reference_task_ids.is_some()
    {
        return Err(TextConcordanceInputError::MessageExtensions);
    }
    let [part] = message.parts.as_slice() else {
        return Err(TextConcordanceInputError::PartCount);
    };
    if part.filename.is_some() || part.media_type.is_some() || part.metadata.is_some() {
        return Err(TextConcordanceInputError::PartDecorations);
    }
    let PartContent::Text(text) = &part.content else {
        return Err(TextConcordanceInputError::UnsupportedPart);
    };
    if text.len() > max_input_bytes {
        return Err(TextConcordanceInputError::InputBytesExceeded);
    }
    Ok(text.clone())
}

/// Produce the exact bounded `text-concordance/v1` artifact and authority digests.
///
/// # Errors
///
/// Returns a typed limit or canonical-encoding error without producing partial output.
pub fn process_text_concordance(
    input: &str,
    limits: TextConcordanceLimits,
) -> Result<TextConcordanceOutput, TextConcordanceError> {
    let input_bytes = input.as_bytes();
    let utf8_bytes =
        u64::try_from(input_bytes.len()).map_err(|_| TextConcordanceError::CounterOverflow)?;
    if utf8_bytes > limits.max_input_bytes {
        return Err(TextConcordanceError::InputBytesExceeded);
    }

    let line_count = if input_bytes.is_empty() {
        0
    } else {
        let delimiters = input_bytes.iter().try_fold(0_u64, |count, byte| {
            if *byte == b'\n' {
                count.checked_add(1)
            } else {
                Some(count)
            }
        });
        let delimiters = delimiters.ok_or(TextConcordanceError::CounterOverflow)?;
        if input_bytes.last() == Some(&b'\n') {
            delimiters
        } else {
            delimiters
                .checked_add(1)
                .ok_or(TextConcordanceError::CounterOverflow)?
        }
    };
    if line_count > limits.max_line_count {
        return Err(TextConcordanceError::LineCountExceeded);
    }

    let mut word_frequencies = BTreeMap::<String, u64>::new();
    let mut ascii_word_count = 0_u64;
    let mut start = None;
    for (index, byte) in input_bytes.iter().copied().enumerate() {
        if byte.is_ascii_alphabetic() {
            start.get_or_insert(index);
        } else if let Some(word_start) = start.take() {
            record_word(
                &input_bytes[word_start..index],
                &mut ascii_word_count,
                &mut word_frequencies,
                limits,
            )?;
        }
    }
    if let Some(word_start) = start {
        record_word(
            &input_bytes[word_start..],
            &mut ascii_word_count,
            &mut word_frequencies,
            limits,
        )?;
    }

    let input_hash = hex_sha256(input_bytes);
    let canonical = CanonicalArtifact {
        schema: TEXT_CONCORDANCE_WORKLOAD_V1,
        input_sha256: &input_hash,
        utf8_bytes,
        line_count,
        ascii_word_count,
        word_frequencies: &word_frequencies,
    };
    let mut artifact_bytes =
        serde_json::to_vec(&canonical).map_err(|_| TextConcordanceError::CanonicalEncoding)?;
    artifact_bytes.push(b'\n');
    let artifact_length =
        u64::try_from(artifact_bytes.len()).map_err(|_| TextConcordanceError::CounterOverflow)?;
    if artifact_length > limits.max_artifact_bytes {
        return Err(TextConcordanceError::ArtifactBytesExceeded);
    }

    let artifact_digest = content_digest(&artifact_bytes);
    let manifest = ArtifactManifest {
        name: TEXT_CONCORDANCE_ARTIFACT_NAME_V1.to_owned(),
        media_type: TEXT_CONCORDANCE_MEDIA_TYPE.to_owned(),
        digest: artifact_digest.clone(),
    };
    let artifact_set_digest = artifact_set_digest(std::slice::from_ref(&manifest))
        .map_err(|_| TextConcordanceError::CanonicalEncoding)?;

    Ok(TextConcordanceOutput {
        request_digest: text_concordance_request_digest(input_bytes),
        artifact_bytes,
        artifact_digest,
        manifest,
        artifact_set_digest,
    })
}

fn record_word(
    bytes: &[u8],
    ascii_word_count: &mut u64,
    frequencies: &mut BTreeMap<String, u64>,
    limits: TextConcordanceLimits,
) -> Result<(), TextConcordanceError> {
    *ascii_word_count = ascii_word_count
        .checked_add(1)
        .ok_or(TextConcordanceError::CounterOverflow)?;
    if *ascii_word_count > limits.max_ascii_word_count {
        return Err(TextConcordanceError::AsciiWordCountExceeded);
    }
    let normalized = bytes
        .iter()
        .map(u8::to_ascii_lowercase)
        .map(char::from)
        .collect::<String>();
    let frequency = frequencies.entry(normalized).or_insert(0);
    *frequency = frequency
        .checked_add(1)
        .ok_or(TextConcordanceError::CounterOverflow)?;
    if *frequency > limits.max_word_frequency {
        return Err(TextConcordanceError::WordFrequencyExceeded);
    }
    Ok(())
}

#[must_use]
pub fn text_concordance_request_digest(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"SMESH-A2A\0standalone-request\0v1\0");
    update_length_prefixed(
        &mut hasher,
        STANDALONE_TEXT_CONCORDANCE_PROFILE_V1.as_bytes(),
    );
    update_length_prefixed(&mut hasher, TEXT_CONCORDANCE_WORKLOAD_V1.as_bytes());
    update_length_prefixed(&mut hasher, input);
    format!("sha256:{:x}", hasher.finalize())
}

fn update_length_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    hasher.update(length.to_be_bytes());
    hasher.update(bytes);
}

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
