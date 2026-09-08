//! Durable human-ratification review packets and append-only decision receipts.

use std::path::Path;
use std::sync::{Arc, Mutex};

use a2a::{Message, Part, Role, SendMessageResponse, StreamResponse, Task, TaskStatusUpdateEvent};
use hmac::{Hmac, Mac as _};
use rusqlite::{Connection, OptionalExtension as _, params};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use thiserror::Error;

use crate::content_digest;

type ReceiptMac = Hmac<Sha256>;
pub(crate) const PACKET_DOMAIN: &[u8] = b"smesh-human-ratification-packet/v1\0";
pub(crate) const RECEIPT_DOMAIN: &[u8] = b"smesh-human-ratification-receipt/v1\0";
const LEDGER_KEY_DOMAIN: &[u8] = b"smesh-human-ratification-ledger-key/v1\0";
const LEDGER_KEY_SENTINEL: &[u8] = b"standalone-compatibility-ledger";
const LEDGER_STATE_DOMAIN: &[u8] = b"smesh-human-ratification-ledger-state/v2\0";
const LEDGER_APPLICATION_ID: i64 = 0x534d_4553;
const LEDGER_SCHEMA_VERSION: i64 = 2;
const LEDGER_RETAINED_AUTHORITY_LIMIT: u64 = 64 * 1024 * 1024;
const MAX_TEXT_BYTES: usize = 4_096;
const MAX_HASHES: usize = 256;
const MAX_ARTIFACTS: usize = 128;
const MAX_PUBLICATION_TASK_BYTES: usize = 1024 * 1024;

/// A named artifact in the exact frozen candidate reviewed by a human.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewArtifact {
    pub name: String,
    pub media_type: String,
    /// Canonical JSON of the exact A2A artifact published after approval.
    pub canonical_json: String,
    pub digest: String,
}

/// Server-side input used to freeze a review candidate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewPacketInput {
    pub task_id: String,
    pub tenant_id: String,
    pub generation: u64,
    pub task_revision: u64,
    pub authorization_policy_id: String,
    pub authorization_policy_revision: u64,
    pub authorization_policy_digest: String,
    pub principal_scope: String,
    pub authentication_method: String,
    pub context_id: String,
    pub request_digest: String,
    pub idempotency_key_digest: String,
    pub ratification_key_generation: String,
    pub checkpoint: String,
    pub checkpoint_hash: String,
    pub completion_policy_id: String,
    pub completion_policy_version: u32,
    pub completion_policy_hash: String,
    pub evidence_snapshot_hash: String,
    pub artifact_set_digest: String,
    pub evidence: Vec<String>,
    pub evidence_hashes: Vec<String>,
    pub artifacts: Vec<ReviewArtifact>,
    pub approved_task_digest: String,
    pub approved_result_digest: String,
    pub approved_transcript_digest: String,
    pub uncertainty_summary: String,
    pub created_at_millis: i64,
}

/// Immutable, integrity-protected packet presented to the human reviewer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewPacket {
    #[serde(flatten)]
    pub input: ReviewPacketInput,
    pub revision: u64,
    pub packet_hash: String,
    pub seal: String,
}

impl std::ops::Deref for ReviewPacket {
    type Target = ReviewPacketInput;

    fn deref(&self) -> &Self::Target {
        &self.input
    }
}

impl ReviewPacket {
    pub(crate) fn freeze(
        input: ReviewPacketInput,
        key: &[u8; 32],
    ) -> Result<Self, RatificationError> {
        validate_packet(&input)?;
        let packet_hash = packet_statement_hash(&input, 0)?;
        let seal = ratification_mac(key, PACKET_DOMAIN, packet_hash.as_bytes());
        Ok(Self {
            input,
            revision: 0,
            packet_hash,
            seal,
        })
    }

    pub(crate) fn verify(&self, key: &[u8; 32]) -> Result<(), RatificationError> {
        validate_packet(&self.input)?;
        let expected_hash = packet_statement_hash(&self.input, self.revision)?;
        if !bool::from(expected_hash.as_bytes().ct_eq(self.packet_hash.as_bytes()))
            || !bool::from(
                ratification_mac(key, PACKET_DOMAIN, self.packet_hash.as_bytes())
                    .as_bytes()
                    .ct_eq(self.seal.as_bytes()),
            )
        {
            return Err(RatificationError::Integrity);
        }
        Ok(())
    }
}

/// Exact completion material supplied by the trusted durable delivery driver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthoritativeReviewCandidate {
    pub(crate) completion_policy_id: String,
    pub(crate) completion_policy_version: u32,
    pub(crate) completion_policy_hash: String,
    pub(crate) checkpoint: Vec<u8>,
    pub(crate) evidence: Vec<Vec<u8>>,
    pub(crate) uncertainty_summary: String,
}

impl AuthoritativeReviewCandidate {
    #[allow(clippy::missing_errors_doc)]
    pub fn new(
        completion_policy_id: impl Into<String>,
        completion_policy_version: u32,
        completion_policy_hash: impl Into<String>,
        checkpoint: Vec<u8>,
        evidence: Vec<Vec<u8>>,
        uncertainty_summary: impl Into<String>,
    ) -> Result<Self, RatificationError> {
        let value = Self {
            completion_policy_id: completion_policy_id.into(),
            completion_policy_version,
            completion_policy_hash: completion_policy_hash.into(),
            checkpoint,
            evidence,
            uncertainty_summary: uncertainty_summary.into(),
        };
        validate_id(&value.completion_policy_id)?;
        validate_text(&value.uncertainty_summary)?;
        if value.completion_policy_version == 0
            || !valid_digest(&value.completion_policy_hash)
            || value.checkpoint.is_empty()
            || value.checkpoint.len() > MAX_TEXT_BYTES
            || value.evidence.is_empty()
            || value.evidence.len() > MAX_HASHES
            || value
                .evidence
                .iter()
                .any(|item| item.is_empty() || item.len() > MAX_TEXT_BYTES)
        {
            return Err(RatificationError::InvalidInput);
        }
        Ok(value)
    }
}

#[derive(Clone)]
pub(crate) struct PreparedRatification {
    pub packet_input: ReviewPacketInput,
    pub approved_task_json: String,
    pub approved_result_json: String,
    pub approved_transcript_json: String,
    pub awaiting_task: Task,
    pub awaiting_result: SendMessageResponse,
    pub awaiting_transcript: Vec<StreamResponse>,
}

/// Decode through the same A2A task type used by publication, then derive the
/// canonical manifest and exact per-artifact JSON shown to the reviewer.
pub(crate) fn publication_artifact_manifest(
    approved_task_json: &str,
) -> Result<(Vec<ReviewArtifact>, String), a2a::A2AError> {
    let task = decode_publication_task(approved_task_json)?;
    let published = task.artifacts.unwrap_or_default();
    let manifest_value = serde_json::to_value(&published)
        .map_err(|_| a2a::A2AError::internal("ratification manifest encoding failed"))?;
    let manifest = serde_json::to_vec(&manifest_value)
        .map_err(|_| a2a::A2AError::internal("ratification manifest encoding failed"))?;
    let mut review = Vec::with_capacity(published.len());
    for artifact in published {
        let value = serde_json::to_value(&artifact)
            .map_err(|_| a2a::A2AError::internal("ratification artifact encoding failed"))?;
        let canonical = serde_json::to_vec(&value)
            .map_err(|_| a2a::A2AError::internal("ratification artifact encoding failed"))?;
        let media_types = value
            .get("parts")
            .and_then(serde_json::Value::as_array)
            .map(|parts| {
                parts
                    .iter()
                    .filter_map(|part| part.get("mediaType").and_then(serde_json::Value::as_str))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let digest = content_digest(&canonical);
        review.push(ReviewArtifact {
            name: artifact.name.unwrap_or(artifact.artifact_id),
            media_type: match media_types.as_slice() {
                [only] => (*only).to_owned(),
                _ => "multipart/mixed".to_owned(),
            },
            canonical_json: String::from_utf8(canonical)
                .map_err(|_| a2a::A2AError::internal("ratification artifact encoding failed"))?,
            digest,
        });
    }
    Ok((review, content_digest(&manifest)))
}

pub(crate) fn decode_publication_task(approved_task_json: &str) -> Result<Task, a2a::A2AError> {
    if approved_task_json.len() > MAX_PUBLICATION_TASK_BYTES {
        return Err(a2a::A2AError::internal(
            "ratification publication candidate exceeds storage limit",
        ));
    }
    serde_json::from_str(approved_task_json)
        .map_err(|_| a2a::A2AError::internal("ratification candidate decoding failed"))
}

pub(crate) fn publication_manifest_matches(
    packet: &ReviewPacket,
    approved_task_json: &str,
) -> bool {
    matches!(
        publication_artifact_manifest(approved_task_json),
        Ok((artifacts, digest))
            if artifacts == packet.artifacts && digest == packet.artifact_set_digest
    )
}

#[allow(clippy::too_many_lines)] // Keep canonical packet byte construction in one backend-neutral path.
pub(crate) fn prepare_authoritative_review_candidate(
    lease: &crate::OutboxLease,
    approved_task: Task,
    approved_result: &SendMessageResponse,
    approved_transcript: &[StreamResponse],
    candidate: AuthoritativeReviewCandidate,
    now: i64,
) -> Result<PreparedRatification, a2a::A2AError> {
    let evidence = candidate
        .evidence
        .iter()
        .map(|bytes| {
            String::from_utf8(bytes.clone())
                .map_err(|_| a2a::A2AError::invalid_params("ratification evidence must be UTF-8"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let evidence_hashes = evidence
        .iter()
        .map(|value| content_digest(value.as_bytes()))
        .collect();
    let approved_task_json = serde_json::to_string(&approved_task)
        .map_err(|_| a2a::A2AError::internal("ratification candidate encoding failed"))?;
    let (artifacts, artifact_set_digest) = publication_artifact_manifest(&approved_task_json)?;
    if artifacts.is_empty() {
        return Err(a2a::A2AError::invalid_params(
            "ratification candidate has no artifacts",
        ));
    }
    let checkpoint = String::from_utf8(candidate.checkpoint)
        .map_err(|_| a2a::A2AError::invalid_params("ratification checkpoint must be UTF-8"))?;
    let approved_result_json = serde_json::to_string(approved_result)
        .map_err(|_| a2a::A2AError::internal("ratification result encoding failed"))?;
    let approved_transcript_json = serde_json::to_string(approved_transcript)
        .map_err(|_| a2a::A2AError::internal("ratification transcript encoding failed"))?;
    let packet_input = ReviewPacketInput {
        task_id: lease.task_id.clone(),
        tenant_id: lease.tenant_scope.clone(),
        generation: 0,
        task_revision: 0,
        authorization_policy_id: String::new(),
        authorization_policy_revision: 0,
        authorization_policy_digest: String::new(),
        principal_scope: String::new(),
        authentication_method: String::new(),
        context_id: String::new(),
        request_digest: String::new(),
        idempotency_key_digest: String::new(),
        ratification_key_generation: String::new(),
        checkpoint_hash: content_digest(checkpoint.as_bytes()),
        checkpoint,
        completion_policy_id: candidate.completion_policy_id,
        completion_policy_version: candidate.completion_policy_version,
        completion_policy_hash: candidate.completion_policy_hash,
        evidence_snapshot_hash: content_digest(
            &serde_json::to_vec(&evidence)
                .map_err(|_| a2a::A2AError::internal("ratification evidence encoding failed"))?,
        ),
        artifact_set_digest,
        evidence,
        evidence_hashes,
        artifacts,
        approved_task_digest: content_digest(approved_task_json.as_bytes()),
        approved_result_digest: content_digest(approved_result_json.as_bytes()),
        approved_transcript_digest: content_digest(approved_transcript_json.as_bytes()),
        uncertainty_summary: candidate.uncertainty_summary,
        created_at_millis: now,
    };
    let mut awaiting_task = approved_task;
    awaiting_task.artifacts = None;
    awaiting_task.status.state = a2a::TaskState::InputRequired;
    awaiting_task.status.message = Some(Message::new(
        Role::Agent,
        vec![Part::text("Human ratification required")],
    ));
    let awaiting_result = SendMessageResponse::Task(awaiting_task.clone());
    let awaiting_transcript = vec![
        approved_transcript
            .first()
            .cloned()
            .unwrap_or_else(|| StreamResponse::Task(awaiting_task.clone())),
        StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
            task_id: awaiting_task.id.clone(),
            context_id: awaiting_task.context_id.clone(),
            status: awaiting_task.status.clone(),
            metadata: None,
        }),
    ];
    Ok(PreparedRatification {
        packet_input,
        approved_task_json,
        approved_result_json,
        approved_transcript_json,
        awaiting_task,
        awaiting_result,
        awaiting_transcript,
    })
}

/// Human decision recorded after an exact review acknowledgement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HumanDecision {
    Approve,
    Reject,
    Amend,
}

/// Optimistic, idempotent decision command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RatificationCommand {
    pub tenant_id: String,
    pub task_id: String,
    pub generation: u64,
    pub account_id: String,
    pub authorization_policy_id: String,
    pub authorization_policy_revision: u64,
    pub authorization_policy_digest: String,
    pub principal_scope: String,
    pub authentication_method: String,
    pub context_id: String,
    pub request_digest: String,
    pub ratification_key_generation: String,
    pub expected_revision: u64,
    pub checkpoint_hash: String,
    pub packet_hash: String,
    pub artifact_manifest_digest: String,
    pub idempotency_key: String,
    pub decision: HumanDecision,
    pub rationale: String,
    pub decided_at_millis: i64,
}

/// Exact candidate acknowledgement supplied by the authenticated human.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewAcknowledgement {
    pub tenant_id: String,
    pub task_id: String,
    pub generation: u64,
    pub account_id: String,
    pub authorization_policy_id: String,
    pub authorization_policy_revision: u64,
    pub authorization_policy_digest: String,
    pub principal_scope: String,
    pub authentication_method: String,
    pub context_id: String,
    pub request_digest: String,
    pub ratification_key_generation: String,
    pub expected_revision: u64,
    pub checkpoint_hash: String,
    pub packet_hash: String,
    pub evidence_hashes: Vec<String>,
    pub artifact_hashes: Vec<String>,
    pub artifact_manifest_digest: String,
    pub uncertainty_acknowledged: bool,
    pub idempotency_key: String,
    pub reviewed_at_millis: i64,
}

pub(crate) fn review_command_matches_packet(
    command: &ReviewAcknowledgement,
    packet: &ReviewPacket,
) -> bool {
    command.tenant_id == packet.tenant_id
        && command.task_id == packet.task_id
        && command.generation == packet.generation
        && command.authorization_policy_id == packet.authorization_policy_id
        && command.authorization_policy_revision == packet.authorization_policy_revision
        && command.authorization_policy_digest == packet.authorization_policy_digest
        && command.context_id == packet.context_id
        && command.request_digest == packet.request_digest
        && command.ratification_key_generation == packet.ratification_key_generation
        && command.checkpoint_hash == packet.checkpoint_hash
        && command.packet_hash == packet.packet_hash
        && command.artifact_manifest_digest == packet.artifact_set_digest
}

pub(crate) fn decision_command_matches_packet(
    command: &RatificationCommand,
    packet: &ReviewPacket,
) -> bool {
    command.tenant_id == packet.tenant_id
        && command.task_id == packet.task_id
        && command.generation == packet.generation
        && command.authorization_policy_id == packet.authorization_policy_id
        && command.authorization_policy_revision == packet.authorization_policy_revision
        && command.authorization_policy_digest == packet.authorization_policy_digest
        && command.context_id == packet.context_id
        && command.request_digest == packet.request_digest
        && command.ratification_key_generation == packet.ratification_key_generation
        && command.checkpoint_hash == packet.checkpoint_hash
        && command.packet_hash == packet.packet_hash
        && command.artifact_manifest_digest == packet.artifact_set_digest
}

fn review_command_semantic_digest(
    command: &ReviewAcknowledgement,
) -> Result<String, RatificationError> {
    semantic_digest(&serde_json::json!({
        "tenantId": command.tenant_id,
        "taskId": command.task_id,
        "generation": command.generation,
        "accountId": command.account_id,
        "authorizationPolicyId": command.authorization_policy_id,
        "authorizationPolicyRevision": command.authorization_policy_revision,
        "authorizationPolicyDigest": command.authorization_policy_digest,
        "principalScope": command.principal_scope,
        "authenticationMethod": command.authentication_method,
        "contextId": command.context_id,
        "requestDigest": command.request_digest,
        "ratificationKeyGeneration": command.ratification_key_generation,
        "expectedRevision": command.expected_revision,
        "checkpointHash": command.checkpoint_hash,
        "packetHash": command.packet_hash,
        "evidenceHashes": command.evidence_hashes,
        "artifactHashes": command.artifact_hashes,
        "artifactManifestDigest": command.artifact_manifest_digest,
        "uncertaintyAcknowledged": command.uncertainty_acknowledged,
        "idempotencyKey": command.idempotency_key,
    }))
}

fn decision_command_semantic_digest(
    command: &RatificationCommand,
) -> Result<String, RatificationError> {
    semantic_digest(&serde_json::json!({
        "tenantId": command.tenant_id,
        "taskId": command.task_id,
        "generation": command.generation,
        "accountId": command.account_id,
        "authorizationPolicyId": command.authorization_policy_id,
        "authorizationPolicyRevision": command.authorization_policy_revision,
        "authorizationPolicyDigest": command.authorization_policy_digest,
        "principalScope": command.principal_scope,
        "authenticationMethod": command.authentication_method,
        "contextId": command.context_id,
        "requestDigest": command.request_digest,
        "ratificationKeyGeneration": command.ratification_key_generation,
        "expectedRevision": command.expected_revision,
        "checkpointHash": command.checkpoint_hash,
        "packetHash": command.packet_hash,
        "artifactManifestDigest": command.artifact_manifest_digest,
        "idempotencyKey": command.idempotency_key,
        "decision": command.decision,
        "rationale": command.rationale,
    }))
}

pub(crate) fn receipt_command_semantic_digest(
    receipt: &HumanRatificationReceipt,
) -> Result<String, RatificationError> {
    match &receipt.action {
        HumanRatificationAction::ReviewAcknowledged => {
            review_command_semantic_digest(&ReviewAcknowledgement {
                tenant_id: receipt.tenant_id.clone(),
                task_id: receipt.task_id.clone(),
                generation: receipt.generation,
                account_id: receipt.account_id.clone(),
                authorization_policy_id: receipt.authorization_policy_id.clone(),
                authorization_policy_revision: receipt.authorization_policy_revision,
                authorization_policy_digest: receipt.authorization_policy_digest.clone(),
                principal_scope: receipt.principal_scope.clone(),
                authentication_method: receipt.authentication_method.clone(),
                context_id: receipt.context_id.clone(),
                request_digest: receipt.request_digest.clone(),
                ratification_key_generation: receipt.ratification_key_generation.clone(),
                expected_revision: receipt.revision.saturating_sub(1),
                checkpoint_hash: receipt.checkpoint_hash.clone(),
                packet_hash: receipt.packet_hash.clone(),
                evidence_hashes: receipt.evidence_hashes.clone(),
                artifact_hashes: receipt
                    .artifacts
                    .iter()
                    .map(|artifact| artifact.digest.clone())
                    .collect(),
                artifact_manifest_digest: receipt.artifact_set_digest.clone(),
                uncertainty_acknowledged: true,
                idempotency_key: receipt.idempotency_key.clone(),
                reviewed_at_millis: receipt.occurred_at_millis,
            })
        }
        HumanRatificationAction::Decision(decision) => {
            decision_command_semantic_digest(&RatificationCommand {
                tenant_id: receipt.tenant_id.clone(),
                task_id: receipt.task_id.clone(),
                generation: receipt.generation,
                account_id: receipt.account_id.clone(),
                authorization_policy_id: receipt.authorization_policy_id.clone(),
                authorization_policy_revision: receipt.authorization_policy_revision,
                authorization_policy_digest: receipt.authorization_policy_digest.clone(),
                principal_scope: receipt.principal_scope.clone(),
                authentication_method: receipt.authentication_method.clone(),
                context_id: receipt.context_id.clone(),
                request_digest: receipt.request_digest.clone(),
                ratification_key_generation: receipt.ratification_key_generation.clone(),
                expected_revision: receipt.revision.saturating_sub(1),
                checkpoint_hash: receipt.checkpoint_hash.clone(),
                packet_hash: receipt.packet_hash.clone(),
                artifact_manifest_digest: receipt.artifact_set_digest.clone(),
                idempotency_key: receipt.idempotency_key.clone(),
                decision: decision.clone(),
                rationale: receipt.rationale.clone(),
                decided_at_millis: receipt.occurred_at_millis,
            })
        }
    }
}

fn semantic_digest(value: &serde_json::Value) -> Result<String, RatificationError> {
    serde_json::to_vec(value)
        .map(|bytes| content_digest(&bytes))
        .map_err(|_| RatificationError::InvalidInput)
}

/// Durable state of one immutable ratification packet generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RatificationState {
    AwaitingReview,
    Reviewed,
    Approved,
    Rejected,
    Amended,
    Canceled,
    Superseded,
}

pub(crate) fn state_revision_is_valid(state: &str, revision: i64) -> bool {
    match state {
        "awaiting_review" => revision == 0,
        "reviewed" => revision == 1,
        "approved" | "rejected" | "amended" => revision == 2,
        "canceled" | "superseded" => matches!(revision, 0 | 1),
        _ => false,
    }
}

/// Scoped packet state and its authenticated append-only history.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RatificationView {
    pub packet: ReviewPacket,
    pub state: RatificationState,
    pub revision: u64,
    pub history: Vec<HumanRatificationReceipt>,
}

/// Append-only ratification event represented by a receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind", content = "decision")]
pub enum HumanRatificationAction {
    ReviewAcknowledged,
    Decision(HumanDecision),
}

/// Domain-separated, chained HMAC receipt over the exact reviewed candidate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HumanRatificationReceipt {
    pub tenant_id: String,
    pub task_id: String,
    pub account_id: String,
    pub revision: u64,
    pub generation: u64,
    pub task_revision: u64,
    pub authorization_policy_id: String,
    pub authorization_policy_revision: u64,
    pub authorization_policy_digest: String,
    pub principal_scope: String,
    pub authentication_method: String,
    pub context_id: String,
    pub request_digest: String,
    pub idempotency_key_digest: String,
    pub ratification_key_generation: String,
    pub action: HumanRatificationAction,
    pub rationale: String,
    pub occurred_at_millis: i64,
    pub idempotency_key: String,
    pub checkpoint_hash: String,
    pub packet_hash: String,
    pub completion_policy_id: String,
    pub completion_policy_version: u32,
    pub completion_policy_hash: String,
    pub evidence_snapshot_hash: String,
    pub evidence_hashes: Vec<String>,
    pub artifact_set_digest: String,
    pub artifacts: Vec<ReviewArtifact>,
    pub previous_receipt_hash: Option<String>,
    pub receipt_hash: String,
    pub seal: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptStatement<'a> {
    tenant_id: &'a str,
    task_id: &'a str,
    account_id: &'a str,
    revision: u64,
    generation: u64,
    task_revision: u64,
    authorization_policy_id: &'a str,
    authorization_policy_revision: u64,
    authorization_policy_digest: &'a str,
    principal_scope: &'a str,
    authentication_method: &'a str,
    context_id: &'a str,
    request_digest: &'a str,
    idempotency_key_digest: &'a str,
    ratification_key_generation: &'a str,
    action: &'a HumanRatificationAction,
    rationale: &'a str,
    occurred_at_millis: i64,
    idempotency_key: &'a str,
    checkpoint_hash: &'a str,
    packet_hash: &'a str,
    completion_policy_id: &'a str,
    completion_policy_version: u32,
    completion_policy_hash: &'a str,
    evidence_snapshot_hash: &'a str,
    evidence_hashes: &'a [String],
    artifact_set_digest: &'a str,
    artifacts: &'a [ReviewArtifact],
    previous_receipt_hash: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PacketStatement<'a> {
    input: &'a ReviewPacketInput,
    revision: u64,
}

/// Stable bounded failure categories for the ratification authority.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum RatificationError {
    #[error("ratification input is invalid")]
    InvalidInput,
    #[error("ratification packet was not found")]
    NotFound,
    #[error("exact evidence review is required")]
    ReviewRequired,
    #[error("review acknowledgement does not name the exact candidate")]
    ExactReviewRequired,
    #[error("ratification state conflict")]
    Conflict,
    #[error("ratification precondition failed")]
    PreconditionFailed,
    #[error("ratification idempotency key conflicts with another command")]
    IdempotencyConflict,
    #[error("ratification integrity check failed")]
    Integrity,
    #[error("ratification retained authority capacity exceeded")]
    CapacityExceeded,
    #[error("ratification store is unavailable")]
    Unavailable,
}

/// SQLite-backed compatibility/test ledger; production task stores are authoritative.
#[derive(Clone)]
pub struct RatificationLedger {
    connection: Arc<Mutex<Connection>>,
    key: Arc<[u8; 32]>,
}

const LEDGER_SCHEMA: &str = "
CREATE TABLE ratification_metadata(singleton INTEGER PRIMARY KEY CHECK(singleton=1),schema_version INTEGER NOT NULL CHECK(schema_version=2),key_check BLOB NOT NULL,packet_count INTEGER NOT NULL CHECK(packet_count>=0),root_count INTEGER NOT NULL CHECK(root_count>=0),event_count INTEGER NOT NULL CHECK(event_count>=0),head_count INTEGER NOT NULL CHECK(head_count>=0),retained_bytes INTEGER NOT NULL CHECK(retained_bytes>=0),state_hash TEXT NOT NULL,state_seal TEXT NOT NULL) STRICT;
CREATE TABLE ratification_packets(tenant_id TEXT NOT NULL,task_id TEXT NOT NULL,generation INTEGER NOT NULL CHECK(generation>0),packet_json BLOB NOT NULL,packet_hash TEXT NOT NULL,seal TEXT NOT NULL,PRIMARY KEY(tenant_id,task_id,generation)) STRICT;
CREATE TABLE ratification_roots(tenant_id TEXT NOT NULL,task_id TEXT NOT NULL,generation INTEGER NOT NULL CHECK(generation>0),packet_hash TEXT NOT NULL,PRIMARY KEY(tenant_id,task_id,generation),FOREIGN KEY(tenant_id,task_id,generation) REFERENCES ratification_packets(tenant_id,task_id,generation) ON DELETE RESTRICT) STRICT;
CREATE TABLE ratification_events(tenant_id TEXT NOT NULL,task_id TEXT NOT NULL,generation INTEGER NOT NULL CHECK(generation>0),account_id TEXT NOT NULL,revision INTEGER NOT NULL CHECK(revision>0),event_kind TEXT NOT NULL CHECK(event_kind IN('review','decision')),event_json BLOB NOT NULL,event_hash TEXT NOT NULL,seal TEXT NOT NULL,idempotency_key TEXT NOT NULL,PRIMARY KEY(tenant_id,task_id,generation,revision),UNIQUE(tenant_id,account_id,idempotency_key),UNIQUE(tenant_id,task_id,generation,revision,event_hash),FOREIGN KEY(tenant_id,task_id,generation) REFERENCES ratification_packets(tenant_id,task_id,generation) ON DELETE RESTRICT) STRICT;
CREATE TABLE ratification_heads(tenant_id TEXT NOT NULL,task_id TEXT NOT NULL,generation INTEGER NOT NULL CHECK(generation>0),revision INTEGER NOT NULL CHECK(revision>0),event_hash TEXT NOT NULL,PRIMARY KEY(tenant_id,task_id,generation),FOREIGN KEY(tenant_id,task_id,generation,revision,event_hash) REFERENCES ratification_events(tenant_id,task_id,generation,revision,event_hash) ON DELETE RESTRICT) STRICT;
CREATE TRIGGER ratification_metadata_identity BEFORE UPDATE ON ratification_metadata WHEN NEW.singleton<>OLD.singleton OR NEW.schema_version<>OLD.schema_version OR NEW.key_check<>OLD.key_check BEGIN SELECT RAISE(ABORT,'ratification metadata identity is immutable'); END;
CREATE TRIGGER ratification_metadata_no_delete BEFORE DELETE ON ratification_metadata BEGIN SELECT RAISE(ABORT,'ratification metadata is durable'); END;
CREATE TRIGGER ratification_packets_no_update BEFORE UPDATE ON ratification_packets BEGIN SELECT RAISE(ABORT,'ratification packet is immutable'); END;
CREATE TRIGGER ratification_packets_no_delete BEFORE DELETE ON ratification_packets BEGIN SELECT RAISE(ABORT,'ratification packet is durable'); END;
CREATE TRIGGER ratification_roots_no_update BEFORE UPDATE ON ratification_roots BEGIN SELECT RAISE(ABORT,'ratification root is immutable'); END;
CREATE TRIGGER ratification_roots_no_delete BEFORE DELETE ON ratification_roots BEGIN SELECT RAISE(ABORT,'ratification root is durable'); END;
CREATE TRIGGER ratification_events_no_update BEFORE UPDATE ON ratification_events BEGIN SELECT RAISE(ABORT,'ratification event is immutable'); END;
CREATE TRIGGER ratification_events_no_delete BEFORE DELETE ON ratification_events BEGIN SELECT RAISE(ABORT,'ratification event is durable'); END;
CREATE TRIGGER ratification_heads_monotonic BEFORE UPDATE ON ratification_heads WHEN NEW.tenant_id<>OLD.tenant_id OR NEW.task_id<>OLD.task_id OR NEW.generation<>OLD.generation OR NEW.revision<>OLD.revision+1 BEGIN SELECT RAISE(ABORT,'ratification head must advance exactly once'); END;
CREATE TRIGGER ratification_heads_no_delete BEFORE DELETE ON ratification_heads BEGIN SELECT RAISE(ABORT,'ratification head is durable'); END;";

#[derive(Clone, Debug, PartialEq, Eq)]
struct LedgerState {
    packet_count: u64,
    root_count: u64,
    event_count: u64,
    head_count: u64,
    retained_bytes: u64,
    state_hash: String,
}

type IdempotencyLocatorRow = (
    String,
    u64,
    String,
    u64,
    String,
    Vec<u8>,
    String,
    String,
    String,
);

fn add_retained(total: &mut u64, value: usize) -> Result<(), RatificationError> {
    *total = total
        .checked_add(u64::try_from(value).map_err(|_| RatificationError::Integrity)?)
        .ok_or(RatificationError::Integrity)?;
    Ok(())
}

fn canonical_bytes(target: &mut Vec<u8>, value: &[u8]) -> Result<(), RatificationError> {
    let length = u64::try_from(value.len()).map_err(|_| RatificationError::Integrity)?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
    Ok(())
}

fn canonical_integer(target: &mut Vec<u8>, value: i64) {
    target.extend_from_slice(&value.to_be_bytes());
}

#[allow(clippy::too_many_lines)]
fn compute_ledger_state(connection: &Connection) -> Result<LedgerState, RatificationError> {
    let (schema_version, key_check, stored_hash, stored_seal): (i64, Vec<u8>, String, String) =
        connection
            .query_row(
                "SELECT schema_version,key_check,state_hash,state_seal FROM ratification_metadata WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(|_| RatificationError::Integrity)?;
    let metadata_count: i64 = connection
        .query_row("SELECT count(*) FROM ratification_metadata", [], |row| {
            row.get(0)
        })
        .map_err(|_| RatificationError::Integrity)?;
    if metadata_count != 1 || schema_version != LEDGER_SCHEMA_VERSION {
        return Err(RatificationError::Integrity);
    }

    let mut canonical = Vec::new();
    canonical_bytes(&mut canonical, b"metadata")?;
    canonical_integer(&mut canonical, 1);
    canonical_integer(&mut canonical, schema_version);
    canonical_bytes(&mut canonical, &key_check)?;
    let mut retained_bytes = 7_u64 * 8;
    add_retained(&mut retained_bytes, key_check.len())?;
    add_retained(&mut retained_bytes, stored_hash.len())?;
    add_retained(&mut retained_bytes, stored_seal.len())?;

    let mut packet_count = 0_u64;
    let mut statement = connection
        .prepare("SELECT tenant_id,task_id,generation,packet_json,packet_hash,seal FROM ratification_packets ORDER BY tenant_id,task_id,generation")
        .map_err(|_| RatificationError::Integrity)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })
        .map_err(|_| RatificationError::Integrity)?;
    for row in rows {
        let (tenant, task, generation, json, hash, seal) =
            row.map_err(|_| RatificationError::Integrity)?;
        packet_count = packet_count
            .checked_add(1)
            .ok_or(RatificationError::Integrity)?;
        canonical_bytes(&mut canonical, b"packet")?;
        for value in [&tenant, &task] {
            canonical_bytes(&mut canonical, value.as_bytes())?;
            add_retained(&mut retained_bytes, value.len())?;
        }
        canonical_integer(&mut canonical, generation);
        retained_bytes = retained_bytes
            .checked_add(8)
            .ok_or(RatificationError::Integrity)?;
        canonical_bytes(&mut canonical, &json)?;
        add_retained(&mut retained_bytes, json.len())?;
        for value in [&hash, &seal] {
            canonical_bytes(&mut canonical, value.as_bytes())?;
            add_retained(&mut retained_bytes, value.len())?;
        }
    }

    let mut root_count = 0_u64;
    let mut statement = connection.prepare("SELECT tenant_id,task_id,generation,packet_hash FROM ratification_roots ORDER BY tenant_id,task_id,generation").map_err(|_| RatificationError::Integrity)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|_| RatificationError::Integrity)?;
    for row in rows {
        let (tenant, task, generation, hash) = row.map_err(|_| RatificationError::Integrity)?;
        root_count = root_count
            .checked_add(1)
            .ok_or(RatificationError::Integrity)?;
        canonical_bytes(&mut canonical, b"root")?;
        for value in [&tenant, &task] {
            canonical_bytes(&mut canonical, value.as_bytes())?;
            add_retained(&mut retained_bytes, value.len())?;
        }
        canonical_integer(&mut canonical, generation);
        retained_bytes = retained_bytes
            .checked_add(8)
            .ok_or(RatificationError::Integrity)?;
        canonical_bytes(&mut canonical, hash.as_bytes())?;
        add_retained(&mut retained_bytes, hash.len())?;
    }

    let mut event_count = 0_u64;
    let mut statement = connection.prepare("SELECT tenant_id,task_id,generation,account_id,revision,event_kind,event_json,event_hash,seal,idempotency_key FROM ratification_events ORDER BY tenant_id,task_id,generation,revision").map_err(|_| RatificationError::Integrity)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
            ))
        })
        .map_err(|_| RatificationError::Integrity)?;
    for row in rows {
        let (tenant, task, generation, account, revision, kind, json, hash, seal, idempotency) =
            row.map_err(|_| RatificationError::Integrity)?;
        event_count = event_count
            .checked_add(1)
            .ok_or(RatificationError::Integrity)?;
        canonical_bytes(&mut canonical, b"event")?;
        for value in [&tenant, &task, &account, &kind, &hash, &seal, &idempotency] {
            canonical_bytes(&mut canonical, value.as_bytes())?;
            add_retained(&mut retained_bytes, value.len())?;
        }
        canonical_integer(&mut canonical, generation);
        canonical_integer(&mut canonical, revision);
        retained_bytes = retained_bytes
            .checked_add(16)
            .ok_or(RatificationError::Integrity)?;
        canonical_bytes(&mut canonical, &json)?;
        add_retained(&mut retained_bytes, json.len())?;
    }

    let mut head_count = 0_u64;
    let mut statement=connection.prepare("SELECT tenant_id,task_id,generation,revision,event_hash FROM ratification_heads ORDER BY tenant_id,task_id,generation").map_err(|_|RatificationError::Integrity)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|_| RatificationError::Integrity)?;
    for row in rows {
        let (tenant, task, generation, revision, hash) =
            row.map_err(|_| RatificationError::Integrity)?;
        head_count = head_count
            .checked_add(1)
            .ok_or(RatificationError::Integrity)?;
        canonical_bytes(&mut canonical, b"head")?;
        for value in [&tenant, &task, &hash] {
            canonical_bytes(&mut canonical, value.as_bytes())?;
            add_retained(&mut retained_bytes, value.len())?;
        }
        canonical_integer(&mut canonical, generation);
        canonical_integer(&mut canonical, revision);
        retained_bytes = retained_bytes
            .checked_add(16)
            .ok_or(RatificationError::Integrity)?;
    }
    for value in [
        packet_count,
        root_count,
        event_count,
        head_count,
        retained_bytes,
    ] {
        canonical.extend_from_slice(&value.to_be_bytes());
    }
    Ok(LedgerState {
        packet_count,
        root_count,
        event_count,
        head_count,
        retained_bytes,
        state_hash: content_digest(&canonical),
    })
}

fn ledger_state_seal(key: &[u8; 32], state: &LedgerState) -> String {
    let payload = format!(
        "{}:{}:{}:{}:{}:{}",
        state.packet_count,
        state.root_count,
        state.event_count,
        state.head_count,
        state.retained_bytes,
        state.state_hash
    );
    ratification_mac(key, LEDGER_STATE_DOMAIN, payload.as_bytes())
}

fn ensure_retained_capacity(retained_bytes: u64, limit: u64) -> Result<(), RatificationError> {
    if retained_bytes > limit {
        Err(RatificationError::CapacityExceeded)
    } else {
        Ok(())
    }
}

fn write_ledger_state_with_limit(
    connection: &Connection,
    key: &[u8; 32],
    limit: u64,
) -> Result<(), RatificationError> {
    let state = compute_ledger_state(connection)?;
    ensure_retained_capacity(state.retained_bytes, limit)?;
    let seal = ledger_state_seal(key, &state);
    let updated=connection.execute("UPDATE ratification_metadata SET packet_count=?1,root_count=?2,event_count=?3,head_count=?4,retained_bytes=?5,state_hash=?6,state_seal=?7 WHERE singleton=1",params![state.packet_count,state.root_count,state.event_count,state.head_count,state.retained_bytes,&state.state_hash,&seal]).map_err(|_|RatificationError::Unavailable)?;
    if updated != 1 {
        return Err(RatificationError::Integrity);
    }
    Ok(())
}

fn write_ledger_state(connection: &Connection, key: &[u8; 32]) -> Result<(), RatificationError> {
    write_ledger_state_with_limit(connection, key, LEDGER_RETAINED_AUTHORITY_LIMIT)
}

fn validate_ledger_state(connection: &Connection, key: &[u8; 32]) -> Result<(), RatificationError> {
    let foreign_key_errors: i64 = connection
        .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .map_err(|_| RatificationError::Integrity)?;
    if foreign_key_errors != 0 {
        return Err(RatificationError::Integrity);
    }
    let stored:(u64,u64,u64,u64,u64,String,String)=connection.query_row("SELECT packet_count,root_count,event_count,head_count,retained_bytes,state_hash,state_seal FROM ratification_metadata WHERE singleton=1",[],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?))).map_err(|_|RatificationError::Integrity)?;
    let state = compute_ledger_state(connection)?;
    let expected_seal = ledger_state_seal(key, &state);
    if state.retained_bytes > LEDGER_RETAINED_AUTHORITY_LIMIT
        || stored.0 != state.packet_count
        || stored.1 != state.root_count
        || stored.2 != state.event_count
        || stored.3 != state.head_count
        || stored.4 != state.retained_bytes
        || stored.5 != state.state_hash
        || stored
            .6
            .as_bytes()
            .ct_eq(expected_seal.as_bytes())
            .unwrap_u8()
            != 1
    {
        return Err(RatificationError::Integrity);
    }
    Ok(())
}

fn initialize_ledger_schema(
    connection: &Connection,
    key: &[u8; 32],
) -> Result<(), RatificationError> {
    connection
        .execute_batch(LEDGER_SCHEMA)
        .map_err(|_| RatificationError::Unavailable)?;
    connection
        .pragma_update(None, "application_id", LEDGER_APPLICATION_ID)
        .map_err(|_| RatificationError::Unavailable)?;
    connection
        .pragma_update(None, "user_version", LEDGER_SCHEMA_VERSION)
        .map_err(|_| RatificationError::Unavailable)?;
    let check = ratification_mac(key, LEDGER_KEY_DOMAIN, LEDGER_KEY_SENTINEL);
    let empty_hash = format!("sha256:{}", "0".repeat(64));
    let empty_seal = "0".repeat(43);
    connection
        .execute(
            "INSERT INTO ratification_metadata(singleton,schema_version,key_check,packet_count,root_count,event_count,head_count,retained_bytes,state_hash,state_seal) VALUES(1,?1,?2,0,0,0,0,0,?3,?4)",
            params![LEDGER_SCHEMA_VERSION, check.as_bytes(), empty_hash, empty_seal],
        )
        .map_err(|_| RatificationError::Unavailable)?;
    write_ledger_state(connection, key)?;
    Ok(())
}

fn schema_manifest(
    connection: &Connection,
) -> Result<Vec<(String, String, String, String)>, RatificationError> {
    let mut statement = connection.prepare(
        "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name",
    ).map_err(|_| RatificationError::Integrity)?;
    statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(|_| RatificationError::Integrity)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| RatificationError::Integrity)
}

fn validate_ledger_schema(connection: &Connection) -> Result<(), RatificationError> {
    let application_id: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(|_| RatificationError::Integrity)?;
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| RatificationError::Integrity)?;
    if application_id != LEDGER_APPLICATION_ID || version != LEDGER_SCHEMA_VERSION {
        return Err(RatificationError::Integrity);
    }
    let expected = Connection::open_in_memory().map_err(|_| RatificationError::Unavailable)?;
    expected
        .execute_batch(LEDGER_SCHEMA)
        .map_err(|_| RatificationError::Unavailable)?;
    if schema_manifest(connection)? != schema_manifest(&expected)? {
        return Err(RatificationError::Integrity);
    }
    let foreign_keys: i64 = connection
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .map_err(|_| RatificationError::Integrity)?;
    if foreign_keys != 1 {
        return Err(RatificationError::Integrity);
    }
    Ok(())
}

fn authenticate_packet_connection(
    connection: &Connection,
    key: &[u8; 32],
    tenant_id: &str,
    task_id: &str,
    generation: u64,
) -> Result<ReviewPacket, RatificationError> {
    let (json,stored_hash,stored_seal):(Vec<u8>,String,String)=connection.query_row(
        "SELECT packet_json,packet_hash,seal FROM ratification_packets WHERE tenant_id=?1 AND task_id=?2 AND generation=?3",
        params![tenant_id,task_id,generation],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
    ).map_err(|_|RatificationError::Integrity)?;
    let packet: ReviewPacket =
        serde_json::from_slice(&json).map_err(|_| RatificationError::Integrity)?;
    let hash = packet_statement_hash(&packet.input, packet.revision)
        .map_err(|_| RatificationError::Integrity)?;
    let seal = ratification_mac(key, PACKET_DOMAIN, hash.as_bytes());
    if packet.tenant_id != tenant_id
        || packet.task_id != task_id
        || packet.generation != generation
        || packet.packet_hash != hash
        || stored_hash != hash
        || packet.seal != stored_seal
        || stored_seal.as_bytes().ct_eq(seal.as_bytes()).unwrap_u8() != 1
    {
        return Err(RatificationError::Integrity);
    }
    let root: Option<String> = connection
        .query_row(
            "SELECT packet_hash FROM ratification_roots WHERE tenant_id=?1 AND task_id=?2 AND generation=?3",
            params![tenant_id, task_id, generation],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| RatificationError::Integrity)?;
    if root.as_deref() != Some(hash.as_str()) {
        return Err(RatificationError::Integrity);
    }
    Ok(packet)
}

fn receipt_matches_packet(receipt: &HumanRatificationReceipt, packet: &ReviewPacket) -> bool {
    receipt.tenant_id == packet.tenant_id
        && receipt.task_id == packet.task_id
        && receipt.generation == packet.generation
        && receipt.task_revision == packet.task_revision
        && receipt.authorization_policy_id == packet.authorization_policy_id
        && receipt.authorization_policy_revision == packet.authorization_policy_revision
        && receipt.authorization_policy_digest == packet.authorization_policy_digest
        && receipt.context_id == packet.context_id
        && receipt.request_digest == packet.request_digest
        && receipt.ratification_key_generation == packet.ratification_key_generation
        && receipt.checkpoint_hash == packet.checkpoint_hash
        && receipt.packet_hash == packet.packet_hash
        && receipt.completion_policy_id == packet.completion_policy_id
        && receipt.completion_policy_version == packet.completion_policy_version
        && receipt.completion_policy_hash == packet.completion_policy_hash
        && receipt.evidence_snapshot_hash == packet.evidence_snapshot_hash
        && receipt.evidence_hashes == packet.evidence_hashes
        && receipt.artifact_set_digest == packet.artifact_set_digest
        && receipt.artifacts == packet.artifacts
}

fn authenticate_history_connection(
    connection: &Connection,
    key: &[u8; 32],
    tenant_id: &str,
    task_id: &str,
    generation: u64,
    packet: &ReviewPacket,
) -> Result<Vec<HumanRatificationReceipt>, RatificationError> {
    let mut statement=connection.prepare(
        "SELECT account_id,revision,event_kind,event_json,event_hash,seal,idempotency_key FROM ratification_events WHERE tenant_id=?1 AND task_id=?2 AND generation=?3 ORDER BY revision ASC",
    ).map_err(|_|RatificationError::Integrity)?;
    let rows = statement
        .query_map(params![tenant_id, task_id, generation], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })
        .map_err(|_| RatificationError::Integrity)?;
    let mut receipts = Vec::new();
    let mut previous: Option<String> = None;
    for row in rows {
        let (account, revision, kind, bytes, hash, seal, idempotency) =
            row.map_err(|_| RatificationError::Integrity)?;
        let receipt: HumanRatificationReceipt =
            serde_json::from_slice(&bytes).map_err(|_| RatificationError::Integrity)?;
        let expected_kind = match receipt.action {
            HumanRatificationAction::ReviewAcknowledged => "review",
            HumanRatificationAction::Decision(_) => "decision",
        };
        let statement_hash =
            receipt_statement_hash(&receipt).map_err(|_| RatificationError::Integrity)?;
        let expected_seal = ratification_mac(key, RECEIPT_DOMAIN, statement_hash.as_bytes());
        if receipt.tenant_id != tenant_id
            || receipt.task_id != task_id
            || receipt.generation != generation
            || !receipt_matches_packet(&receipt, packet)
            || receipt.account_id != account
            || receipt.revision != revision
            || receipt.revision != u64::try_from(receipts.len()).unwrap_or(u64::MAX) + 1
            || kind != expected_kind
            || receipt.receipt_hash != hash
            || receipt.receipt_hash != statement_hash
            || receipt.seal != seal
            || seal.as_bytes().ct_eq(expected_seal.as_bytes()).unwrap_u8() != 1
            || receipt.idempotency_key != idempotency
            || receipt.idempotency_key_digest != content_digest(idempotency.as_bytes())
            || receipt.previous_receipt_hash.as_deref() != previous.as_deref()
        {
            return Err(RatificationError::Integrity);
        }
        previous = Some(receipt.receipt_hash.clone());
        receipts.push(receipt);
    }
    let head: Option<(u64, String)> = connection
        .query_row(
            "SELECT revision,event_hash FROM ratification_heads WHERE tenant_id=?1 AND task_id=?2 AND generation=?3",
            params![tenant_id, task_id, generation],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| RatificationError::Integrity)?;
    match (receipts.last(), head) {
        (None, None) => {}
        (Some(last), Some((revision, hash)))
            if revision == last.revision && hash == last.receipt_hash => {}
        _ => return Err(RatificationError::Integrity),
    }
    Ok(receipts)
}

fn authenticate_all_connection(
    connection: &Connection,
    key: &[u8; 32],
) -> Result<(), RatificationError> {
    validate_ledger_state(connection, key)?;
    let mut statement = connection
        .prepare("SELECT tenant_id,task_id,generation FROM ratification_packets ORDER BY tenant_id,task_id,generation")
        .map_err(|_| RatificationError::Integrity)?;
    let keys = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u64>(2)?,
            ))
        })
        .map_err(|_| RatificationError::Integrity)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| RatificationError::Integrity)?;
    let mut prior: Option<(String, String, u64, Vec<HumanRatificationReceipt>)> = None;
    for (tenant, task, generation) in keys {
        match prior.as_ref() {
            Some((prior_tenant, prior_task, prior_generation, history))
                if prior_tenant == &tenant && prior_task == &task =>
            {
                if generation != prior_generation.saturating_add(1)
                    || history.len() != 2
                    || !matches!(
                        history.last().map(|receipt| &receipt.action),
                        Some(HumanRatificationAction::Decision(HumanDecision::Amend))
                    )
                {
                    return Err(RatificationError::Integrity);
                }
            }
            _ if generation != 1 => return Err(RatificationError::Integrity),
            _ => {}
        }
        let packet = authenticate_packet_connection(connection, key, &tenant, &task, generation)?;
        let history =
            authenticate_history_connection(connection, key, &tenant, &task, generation, &packet)?;
        prior = Some((tenant, task, generation, history));
    }
    Ok(())
}

impl RatificationLedger {
    /// Open or create a ratification ledger and validate its schema.
    ///
    /// # Errors
    /// Returns [`RatificationError::Unavailable`] when `SQLite` cannot initialize the ledger.
    pub fn open(path: impl AsRef<Path>, key: [u8; 32]) -> Result<Self, RatificationError> {
        let connection = Connection::open(path).map_err(|_| RatificationError::Unavailable)?;
        connection
            .execute_batch("PRAGMA foreign_keys=ON;")
            .map_err(|_| RatificationError::Unavailable)?;
        let object_count: i64 = connection
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| RatificationError::Unavailable)?;
        if object_count == 0 {
            let application_id: i64 = connection
                .pragma_query_value(None, "application_id", |row| row.get(0))
                .map_err(|_| RatificationError::Integrity)?;
            let user_version: i64 = connection
                .pragma_query_value(None, "user_version", |row| row.get(0))
                .map_err(|_| RatificationError::Integrity)?;
            if application_id != 0 || user_version != 0 {
                return Err(RatificationError::Integrity);
            }
            initialize_ledger_schema(&connection, &key)?;
        }
        validate_ledger_schema(&connection)?;
        let stored_check: Vec<u8> = connection.query_row(
            "SELECT key_check FROM ratification_metadata WHERE singleton=1 AND schema_version=?1",
            [LEDGER_SCHEMA_VERSION], |row| row.get(0),
        ).map_err(|_| RatificationError::Integrity)?;
        let expected = ratification_mac(&key, LEDGER_KEY_DOMAIN, LEDGER_KEY_SENTINEL);
        if stored_check
            .as_slice()
            .ct_eq(expected.as_bytes())
            .unwrap_u8()
            != 1
        {
            return Err(RatificationError::Integrity);
        }
        connection
            .execute_batch("PRAGMA journal_mode=WAL;")
            .map_err(|_| RatificationError::Unavailable)?;
        let ledger = Self {
            connection: Arc::new(Mutex::new(connection)),
            key: Arc::new(key),
        };
        ledger.authenticate_all_records()?;
        Ok(ledger)
    }

    fn authenticate_all_records(&self) -> Result<(), RatificationError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| RatificationError::Unavailable)?;
        authenticate_all_connection(&connection, self.key.as_ref())
    }

    /// Persist a packet once. The same exact packet is idempotent; replacement is forbidden.
    ///
    /// # Errors
    /// Returns a bounded validation, conflict, integrity, or storage error.
    pub fn freeze_packet(
        &self,
        input: ReviewPacketInput,
    ) -> Result<ReviewPacket, RatificationError> {
        let packet = ReviewPacket::freeze(input, self.key.as_ref())?;
        let packet_hash = packet.packet_hash.clone();
        let seal = packet.seal.clone();
        let packet_json =
            serde_json::to_vec(&packet).map_err(|_| RatificationError::InvalidInput)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| RatificationError::Unavailable)?;
        let transaction = connection
            .transaction()
            .map_err(|_| RatificationError::Unavailable)?;
        authenticate_all_connection(&transaction, self.key.as_ref())?;
        let exists: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM ratification_packets WHERE tenant_id=?1 AND task_id=?2 AND generation=?3)",
                params![&packet.tenant_id, &packet.task_id, packet.generation],
                |row| row.get(0),
            )
            .map_err(|_| RatificationError::Integrity)?;
        if exists {
            let existing = authenticate_packet_connection(
                &transaction,
                self.key.as_ref(),
                &packet.tenant_id,
                &packet.task_id,
                packet.generation,
            )?;
            return if existing == packet {
                Ok(existing)
            } else {
                Err(RatificationError::Conflict)
            };
        }
        let latest: Option<u64> = transaction
            .query_row(
                "SELECT max(generation) FROM ratification_packets WHERE tenant_id=?1 AND task_id=?2",
                params![&packet.tenant_id, &packet.task_id],
                |row| row.get(0),
            )
            .map_err(|_| RatificationError::Integrity)?;
        let expected_generation = latest.map_or(1, |value| value.saturating_add(1));
        if packet.generation != expected_generation {
            return Err(RatificationError::Conflict);
        }
        if let Some(previous_generation) = latest {
            let previous_packet = authenticate_packet_connection(
                &transaction,
                self.key.as_ref(),
                &packet.tenant_id,
                &packet.task_id,
                previous_generation,
            )?;
            let previous_history = authenticate_history_connection(
                &transaction,
                self.key.as_ref(),
                &packet.tenant_id,
                &packet.task_id,
                previous_generation,
                &previous_packet,
            )?;
            if previous_history.len() != 2
                || !matches!(
                    previous_history.last().map(|receipt| &receipt.action),
                    Some(HumanRatificationAction::Decision(HumanDecision::Amend))
                )
            {
                return Err(RatificationError::Conflict);
            }
        }
        transaction.execute(
            "INSERT INTO ratification_packets (tenant_id,task_id,generation,packet_json,packet_hash,seal) VALUES (?1,?2,?3,?4,?5,?6)",
            params![&packet.tenant_id,&packet.task_id,packet.generation,packet_json,&packet_hash,&seal],
        ).map_err(|_|RatificationError::Conflict)?;
        transaction.execute(
            "INSERT INTO ratification_roots(tenant_id,task_id,generation,packet_hash) VALUES(?1,?2,?3,?4)",
            params![&packet.tenant_id,&packet.task_id,packet.generation,&packet.packet_hash],
        ).map_err(|_|RatificationError::Unavailable)?;
        write_ledger_state(&transaction, self.key.as_ref())?;
        transaction
            .commit()
            .map_err(|_| RatificationError::Unavailable)?;
        Ok(packet)
    }

    /// Read and authenticate a tenant-scoped frozen packet.
    ///
    /// # Errors
    /// Returns a validation, integrity, or storage error.
    pub fn packet(
        &self,
        tenant_id: &str,
        task_id: &str,
    ) -> Result<Option<ReviewPacket>, RatificationError> {
        validate_id(tenant_id)?;
        validate_id(task_id)?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| RatificationError::Unavailable)?;
        authenticate_all_connection(&connection, self.key.as_ref())?;
        let generation: Option<u64> = connection
            .query_row(
                "SELECT max(generation) FROM ratification_packets WHERE tenant_id=?1 AND task_id=?2",
                params![tenant_id, task_id],
                |row| row.get(0),
            )
            .map_err(|_| RatificationError::Integrity)?;
        generation
            .map(|generation| {
                authenticate_packet_connection(
                    &connection,
                    self.key.as_ref(),
                    tenant_id,
                    task_id,
                    generation,
                )
            })
            .transpose()
    }

    /// Read and authenticate one tenant-scoped frozen packet generation.
    ///
    /// # Errors
    /// Returns a validation, integrity, or storage error.
    pub fn packet_at_generation(
        &self,
        tenant_id: &str,
        task_id: &str,
        generation: u64,
    ) -> Result<Option<ReviewPacket>, RatificationError> {
        validate_id(tenant_id)?;
        validate_id(task_id)?;
        if generation == 0 {
            return Err(RatificationError::InvalidInput);
        }
        let connection = self
            .connection
            .lock()
            .map_err(|_| RatificationError::Unavailable)?;
        authenticate_all_connection(&connection, self.key.as_ref())?;
        connection
            .query_row(
                "SELECT 1 FROM ratification_packets WHERE tenant_id=?1 AND task_id=?2 AND generation=?3",
                params![tenant_id, task_id, generation],
                |_| Ok(()),
            )
            .optional()
            .map_err(|_| RatificationError::Integrity)?
            .map(|()| {
                authenticate_packet_connection(
                    &connection,
                    self.key.as_ref(),
                    tenant_id,
                    task_id,
                    generation,
                )
            })
            .transpose()
    }

    /// Append an acknowledgement only when every frozen evidence and artifact hash is named.
    ///
    /// # Errors
    /// Returns an exact-review, optimistic-concurrency, integrity, or storage error.
    #[allow(clippy::needless_pass_by_value)] // Commands are single-use mutation envelopes.
    pub fn acknowledge_review(
        &self,
        acknowledgement: ReviewAcknowledgement,
    ) -> Result<HumanRatificationReceipt, RatificationError> {
        validate_id(&acknowledgement.account_id)?;
        validate_id(&acknowledgement.idempotency_key)?;
        if !crate::durable_authority::principal_and_authentication_are_valid(
            &acknowledgement.principal_scope,
            &acknowledgement.authentication_method,
        ) {
            return Err(RatificationError::InvalidInput);
        }
        let packet = self
            .packet(&acknowledgement.tenant_id, &acknowledgement.task_id)?
            .ok_or(RatificationError::NotFound)?;
        let expected_artifact_hashes: Vec<_> = packet
            .artifacts
            .iter()
            .map(|artifact| artifact.digest.clone())
            .collect();
        if acknowledgement.evidence_hashes != packet.evidence_hashes
            || acknowledgement.artifact_hashes != expected_artifact_hashes
            || acknowledgement.artifact_manifest_digest != packet.artifact_set_digest
            || !acknowledgement.uncertainty_acknowledged
        {
            return Err(RatificationError::ExactReviewRequired);
        }
        if !review_command_matches_packet(&acknowledgement, &packet) {
            return Err(RatificationError::PreconditionFailed);
        }
        let command_digest = review_command_semantic_digest(&acknowledgement)?;
        self.append_receipt(
            &packet,
            &acknowledgement.account_id,
            &acknowledgement.principal_scope,
            &acknowledgement.authentication_method,
            acknowledgement.expected_revision,
            &acknowledgement.idempotency_key,
            &command_digest,
            HumanRatificationAction::ReviewAcknowledged,
            "exact evidence, artifacts, and uncertainty reviewed",
            acknowledgement.reviewed_at_millis,
        )
    }

    /// Record a decision only when the latest event is a matching exact review.
    ///
    /// # Errors
    /// Returns a review-required, optimistic-concurrency, integrity, or storage error.
    pub fn decide(
        &self,
        command: RatificationCommand,
    ) -> Result<HumanRatificationReceipt, RatificationError> {
        validate_id(&command.tenant_id)?;
        validate_id(&command.task_id)?;
        validate_id(&command.account_id)?;
        validate_id(&command.idempotency_key)?;
        validate_text(&command.rationale)?;
        if !crate::durable_authority::principal_and_authentication_are_valid(
            &command.principal_scope,
            &command.authentication_method,
        ) {
            return Err(RatificationError::InvalidInput);
        }
        let packet = self
            .packet(&command.tenant_id, &command.task_id)?
            .ok_or(RatificationError::NotFound)?;
        if !decision_command_matches_packet(&command, &packet) {
            return Err(RatificationError::PreconditionFailed);
        }
        let command_digest = decision_command_semantic_digest(&command)?;
        let history = self.history(&command.tenant_id, &command.task_id)?;
        match history.last() {
            Some(receipt)
                if matches!(receipt.action, HumanRatificationAction::ReviewAcknowledged)
                    && receipt.account_id == command.account_id => {}
            Some(receipt) if matches!(receipt.action, HumanRatificationAction::Decision(_)) => {
                if receipt.idempotency_key == command.idempotency_key {
                    return self.append_receipt(
                        &packet,
                        &command.account_id,
                        &command.principal_scope,
                        &command.authentication_method,
                        command.expected_revision,
                        &command.idempotency_key,
                        &command_digest,
                        HumanRatificationAction::Decision(command.decision),
                        &command.rationale,
                        command.decided_at_millis,
                    );
                }
                return Err(RatificationError::PreconditionFailed);
            }
            _ => return Err(RatificationError::ReviewRequired),
        }
        self.append_receipt(
            &packet,
            &command.account_id,
            &command.principal_scope,
            &command.authentication_method,
            command.expected_revision,
            &command.idempotency_key,
            &command_digest,
            HumanRatificationAction::Decision(command.decision),
            &command.rationale,
            command.decided_at_millis,
        )
    }

    /// Return and authenticate the full event history and receipt chain.
    ///
    /// # Errors
    /// Returns a validation, integrity, or storage error.
    pub fn history(
        &self,
        tenant_id: &str,
        task_id: &str,
    ) -> Result<Vec<HumanRatificationReceipt>, RatificationError> {
        validate_id(tenant_id)?;
        validate_id(task_id)?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| RatificationError::Unavailable)?;
        authenticate_all_connection(&connection, self.key.as_ref())?;
        let generation: Option<u64> = connection
            .query_row(
                "SELECT max(generation) FROM ratification_packets WHERE tenant_id=?1 AND task_id=?2",
                params![tenant_id, task_id],
                |row| row.get(0),
            )
            .map_err(|_| RatificationError::Integrity)?;
        let Some(generation) = generation else {
            return Ok(Vec::new());
        };
        let packet = authenticate_packet_connection(
            &connection,
            self.key.as_ref(),
            tenant_id,
            task_id,
            generation,
        )?;
        authenticate_history_connection(
            &connection,
            self.key.as_ref(),
            tenant_id,
            task_id,
            generation,
            &packet,
        )
    }

    /// Return and authenticate the event history for one packet generation.
    ///
    /// # Errors
    /// Returns a validation, integrity, or storage error.
    pub fn history_at_generation(
        &self,
        tenant_id: &str,
        task_id: &str,
        generation: u64,
    ) -> Result<Vec<HumanRatificationReceipt>, RatificationError> {
        let Some(packet) = self.packet_at_generation(tenant_id, task_id, generation)? else {
            return Ok(Vec::new());
        };
        let connection = self
            .connection
            .lock()
            .map_err(|_| RatificationError::Unavailable)?;
        authenticate_history_connection(
            &connection,
            self.key.as_ref(),
            tenant_id,
            task_id,
            generation,
            &packet,
        )
    }

    /// Verify a receipt without trusting mutable database columns.
    #[must_use]
    pub fn verify_receipt(&self, receipt: &HumanRatificationReceipt) -> bool {
        let Ok(hash) = receipt_statement_hash(receipt) else {
            return false;
        };
        receipt.receipt_hash == hash
            && self.verify_mac(RECEIPT_DOMAIN, hash.as_bytes(), &receipt.seal)
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_lines)] // One transaction intentionally binds the full receipt.
    fn append_receipt(
        &self,
        packet: &ReviewPacket,
        account_id: &str,
        principal_scope: &str,
        authentication_method: &str,
        expected_revision: u64,
        idempotency_key: &str,
        command_digest: &str,
        action: HumanRatificationAction,
        rationale: &str,
        occurred_at_millis: i64,
    ) -> Result<HumanRatificationReceipt, RatificationError> {
        validate_id(account_id)?;
        validate_id(idempotency_key)?;
        validate_text(rationale)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| RatificationError::Unavailable)?;
        let transaction = connection
            .transaction()
            .map_err(|_| RatificationError::Unavailable)?;
        authenticate_all_connection(&transaction, self.key.as_ref())?;
        let authenticated_packet = authenticate_packet_connection(
            &transaction,
            self.key.as_ref(),
            &packet.tenant_id,
            &packet.task_id,
            packet.generation,
        )?;
        if authenticated_packet != *packet {
            return Err(RatificationError::Integrity);
        }
        let authenticated_history = authenticate_history_connection(
            &transaction,
            self.key.as_ref(),
            &packet.tenant_id,
            &packet.task_id,
            packet.generation,
            packet,
        )?;
        let replay: Option<IdempotencyLocatorRow> = transaction
            .query_row(
                "SELECT task_id,generation,account_id,revision,event_kind,event_json,event_hash,seal,idempotency_key FROM ratification_events WHERE tenant_id=?1 AND account_id=?2 AND idempotency_key=?3",
                params![&packet.tenant_id, account_id, idempotency_key],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?)),
            )
            .optional()
            .map_err(|_| RatificationError::Integrity)?;
        if let Some((
            owner_task,
            owner_generation,
            row_account,
            row_revision,
            row_kind,
            bytes,
            row_hash,
            row_seal,
            row_key,
        )) = replay
        {
            let owner_packet = authenticate_packet_connection(
                &transaction,
                self.key.as_ref(),
                &packet.tenant_id,
                &owner_task,
                owner_generation,
            )?;
            let owner_history = authenticate_history_connection(
                &transaction,
                self.key.as_ref(),
                &packet.tenant_id,
                &owner_task,
                owner_generation,
                &owner_packet,
            )?;
            let receipt: HumanRatificationReceipt =
                serde_json::from_slice(&bytes).map_err(|_| RatificationError::Integrity)?;
            let expected_kind = match receipt.action {
                HumanRatificationAction::ReviewAcknowledged => "review",
                HumanRatificationAction::Decision(_) => "decision",
            };
            if receipt.tenant_id != packet.tenant_id
                || receipt.task_id != owner_task
                || receipt.generation != owner_generation
                || receipt.account_id != row_account
                || receipt.account_id != account_id
                || receipt.revision != row_revision
                || row_kind != expected_kind
                || receipt.receipt_hash != row_hash
                || receipt.seal != row_seal
                || receipt.idempotency_key != row_key
                || receipt.idempotency_key != idempotency_key
                || !owner_history.iter().any(|item| item == &receipt)
            {
                return Err(RatificationError::Integrity);
            }
            if receipt_command_semantic_digest(&receipt)? == command_digest {
                return Ok(receipt);
            }
            return Err(RatificationError::IdempotencyConflict);
        }
        let current_revision =
            u64::try_from(authenticated_history.len()).map_err(|_| RatificationError::Integrity)?;
        let previous_hash = authenticated_history
            .last()
            .map(|receipt| receipt.receipt_hash.clone());
        if current_revision != expected_revision
            || (matches!(&action, HumanRatificationAction::ReviewAcknowledged)
                && current_revision != 0)
        {
            return Err(RatificationError::PreconditionFailed);
        }
        let mut receipt = HumanRatificationReceipt {
            tenant_id: packet.tenant_id.clone(),
            task_id: packet.task_id.clone(),
            account_id: account_id.to_owned(),
            revision: current_revision.saturating_add(1),
            generation: packet.generation,
            task_revision: packet.task_revision,
            authorization_policy_id: packet.authorization_policy_id.clone(),
            authorization_policy_revision: packet.authorization_policy_revision,
            authorization_policy_digest: packet.authorization_policy_digest.clone(),
            principal_scope: principal_scope.to_owned(),
            authentication_method: authentication_method.to_owned(),
            context_id: packet.context_id.clone(),
            request_digest: packet.request_digest.clone(),
            idempotency_key_digest: content_digest(idempotency_key.as_bytes()),
            ratification_key_generation: packet.ratification_key_generation.clone(),
            action,
            rationale: rationale.to_owned(),
            occurred_at_millis,
            idempotency_key: idempotency_key.to_owned(),
            checkpoint_hash: packet.checkpoint_hash.clone(),
            packet_hash: packet.packet_hash.clone(),
            completion_policy_id: packet.completion_policy_id.clone(),
            completion_policy_version: packet.completion_policy_version,
            completion_policy_hash: packet.completion_policy_hash.clone(),
            evidence_snapshot_hash: packet.evidence_snapshot_hash.clone(),
            evidence_hashes: packet.evidence_hashes.clone(),
            artifact_set_digest: packet.artifact_set_digest.clone(),
            artifacts: packet.artifacts.clone(),
            previous_receipt_hash: previous_hash,
            receipt_hash: String::new(),
            seal: String::new(),
        };
        receipt.receipt_hash = receipt_statement_hash(&receipt)?;
        receipt.seal = self.mac(RECEIPT_DOMAIN, receipt.receipt_hash.as_bytes());
        let bytes = serde_json::to_vec(&receipt).map_err(|_| RatificationError::InvalidInput)?;
        let event_kind = match receipt.action {
            HumanRatificationAction::ReviewAcknowledged => "review",
            HumanRatificationAction::Decision(_) => "decision",
        };
        transaction
            .execute(
                "INSERT INTO ratification_events
                 (tenant_id, task_id, generation, account_id, revision, event_kind, event_json,
                  event_hash, seal, idempotency_key)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    &receipt.tenant_id,
                    &receipt.task_id,
                    receipt.generation,
                    &receipt.account_id,
                    receipt.revision,
                    event_kind,
                    bytes,
                    &receipt.receipt_hash,
                    &receipt.seal,
                    &receipt.idempotency_key,
                ],
            )
            .map_err(|_| RatificationError::Conflict)?;
        let head_updated = transaction
            .execute(
                "INSERT INTO ratification_heads(tenant_id,task_id,generation,revision,event_hash)
                 VALUES(?1,?2,?3,?4,?5)
                 ON CONFLICT(tenant_id,task_id,generation) DO UPDATE SET
                   revision=excluded.revision,event_hash=excluded.event_hash
                 WHERE ratification_heads.revision + 1 = excluded.revision",
                params![
                    &receipt.tenant_id,
                    &receipt.task_id,
                    receipt.generation,
                    receipt.revision,
                    &receipt.receipt_hash,
                ],
            )
            .map_err(|_| RatificationError::Conflict)?;
        if head_updated != 1 {
            return Err(RatificationError::Integrity);
        }
        write_ledger_state(&transaction, self.key.as_ref())?;
        transaction
            .commit()
            .map_err(|_| RatificationError::Unavailable)?;
        Ok(receipt)
    }

    fn mac(&self, domain: &[u8], payload: &[u8]) -> String {
        use base64::Engine as _;
        let mut mac =
            ReceiptMac::new_from_slice(self.key.as_ref()).expect("HMAC accepts any key size");
        mac.update(domain);
        mac.update(payload);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    fn verify_mac(&self, domain: &[u8], payload: &[u8], encoded: &str) -> bool {
        use base64::Engine as _;
        let Ok(tag) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded) else {
            return false;
        };
        let mut mac =
            ReceiptMac::new_from_slice(self.key.as_ref()).expect("HMAC accepts any key size");
        mac.update(domain);
        mac.update(payload);
        mac.verify_slice(&tag).is_ok()
    }
}

fn packet_statement_hash(
    input: &ReviewPacketInput,
    revision: u64,
) -> Result<String, RatificationError> {
    let bytes = serde_json::to_vec(&PacketStatement { input, revision })
        .map_err(|_| RatificationError::InvalidInput)?;
    Ok(content_digest(&bytes))
}

pub(crate) fn ratification_mac(key: &[u8; 32], domain: &[u8], payload: &[u8]) -> String {
    use base64::Engine as _;
    let mut mac = ReceiptMac::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(domain);
    mac.update(payload);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

pub(crate) fn receipt_statement_hash(
    receipt: &HumanRatificationReceipt,
) -> Result<String, RatificationError> {
    let statement = ReceiptStatement {
        tenant_id: &receipt.tenant_id,
        task_id: &receipt.task_id,
        account_id: &receipt.account_id,
        revision: receipt.revision,
        generation: receipt.generation,
        task_revision: receipt.task_revision,
        authorization_policy_id: &receipt.authorization_policy_id,
        authorization_policy_revision: receipt.authorization_policy_revision,
        authorization_policy_digest: &receipt.authorization_policy_digest,
        principal_scope: &receipt.principal_scope,
        authentication_method: &receipt.authentication_method,
        context_id: &receipt.context_id,
        request_digest: &receipt.request_digest,
        idempotency_key_digest: &receipt.idempotency_key_digest,
        ratification_key_generation: &receipt.ratification_key_generation,
        action: &receipt.action,
        rationale: &receipt.rationale,
        occurred_at_millis: receipt.occurred_at_millis,
        idempotency_key: &receipt.idempotency_key,
        checkpoint_hash: &receipt.checkpoint_hash,
        packet_hash: &receipt.packet_hash,
        completion_policy_id: &receipt.completion_policy_id,
        completion_policy_version: receipt.completion_policy_version,
        completion_policy_hash: &receipt.completion_policy_hash,
        evidence_snapshot_hash: &receipt.evidence_snapshot_hash,
        evidence_hashes: &receipt.evidence_hashes,
        artifact_set_digest: &receipt.artifact_set_digest,
        artifacts: &receipt.artifacts,
        previous_receipt_hash: receipt.previous_receipt_hash.as_deref(),
    };
    let bytes = serde_json::to_vec(&statement).map_err(|_| RatificationError::Integrity)?;
    Ok(content_digest(&bytes))
}

fn validate_packet(input: &ReviewPacketInput) -> Result<(), RatificationError> {
    validate_id(&input.task_id)?;
    validate_id(&input.tenant_id)?;
    validate_id(&input.completion_policy_id)?;
    validate_id(&input.authorization_policy_id)?;
    validate_id(&input.authentication_method)?;
    validate_id(&input.context_id)?;
    validate_text(&input.principal_scope)?;
    let mut published_artifacts = Vec::with_capacity(input.artifacts.len());
    for artifact in &input.artifacts {
        let published: a2a::Artifact = serde_json::from_str(&artifact.canonical_json)
            .map_err(|_| RatificationError::InvalidInput)?;
        let canonical = serde_json::to_value(&published)
            .and_then(|value| serde_json::to_string(&value))
            .map_err(|_| RatificationError::InvalidInput)?;
        if canonical != artifact.canonical_json
            || content_digest(canonical.as_bytes()) != artifact.digest
        {
            return Err(RatificationError::InvalidInput);
        }
        published_artifacts.push(published);
    }
    let artifact_manifest = serde_json::to_value(&published_artifacts)
        .and_then(|value| serde_json::to_vec(&value))
        .map_err(|_| RatificationError::InvalidInput)?;
    if input.generation == 0
        || input.task_revision == 0
        || input.completion_policy_version == 0
        || input.authorization_policy_revision == 0
        || input.evidence_hashes.is_empty()
        || input.evidence_hashes.len() > MAX_HASHES
        || input.artifacts.is_empty()
        || input.artifacts.len() > MAX_ARTIFACTS
        || input.checkpoint.is_empty()
        || input.checkpoint.len() > MAX_TEXT_BYTES
        || content_digest(input.checkpoint.as_bytes()) != input.checkpoint_hash
        || !valid_digest(&input.checkpoint_hash)
        || !valid_digest(&input.completion_policy_hash)
        || !valid_digest(&input.authorization_policy_digest)
        || !valid_digest(&input.request_digest)
        || !valid_digest(&input.idempotency_key_digest)
        || !valid_digest(&input.ratification_key_generation)
        || !valid_digest(&input.evidence_snapshot_hash)
        || !valid_digest(&input.approved_task_digest)
        || !valid_digest(&input.approved_result_digest)
        || !valid_digest(&input.approved_transcript_digest)
        || input.artifact_set_digest != content_digest(&artifact_manifest)
        || input
            .evidence_hashes
            .iter()
            .any(|value| !valid_digest(value))
        || input.evidence.len() != input.evidence_hashes.len()
        || input
            .evidence
            .iter()
            .zip(&input.evidence_hashes)
            .any(|(value, digest)| {
                value.is_empty()
                    || value.len() > MAX_TEXT_BYTES
                    || content_digest(value.as_bytes()) != *digest
            })
    {
        return Err(RatificationError::InvalidInput);
    }
    validate_text(&input.uncertainty_summary)?;
    for artifact in &input.artifacts {
        validate_text(&artifact.name)?;
        validate_text(&artifact.media_type)?;
        if artifact.canonical_json.is_empty()
            || artifact.canonical_json.len() > 1024 * 1024
            || !valid_digest(&artifact.digest)
        {
            return Err(RatificationError::InvalidInput);
        }
    }
    Ok(())
}

fn validate_id(value: &str) -> Result<(), RatificationError> {
    if (1..=128).contains(&value.len())
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Ok(())
    } else {
        Err(RatificationError::InvalidInput)
    }
}

fn validate_text(value: &str) -> Result<(), RatificationError> {
    if !value.is_empty() && value.len() <= MAX_TEXT_BYTES && !value.contains('\0') {
        Ok(())
    } else {
        Err(RatificationError::InvalidInput)
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod standalone_accounting_tests {
    use super::*;

    #[test]
    fn exact_sixty_four_mib_boundary_and_one_byte_over_are_distinct() {
        assert_eq!(
            ensure_retained_capacity(
                LEDGER_RETAINED_AUTHORITY_LIMIT,
                LEDGER_RETAINED_AUTHORITY_LIMIT
            ),
            Ok(())
        );
        assert_eq!(
            ensure_retained_capacity(
                LEDGER_RETAINED_AUTHORITY_LIMIT + 1,
                LEDGER_RETAINED_AUTHORITY_LIMIT
            ),
            Err(RatificationError::CapacityExceeded)
        );
    }

    #[test]
    fn retained_authority_counts_utf8_bytes_and_accepts_exact_boundary() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        initialize_ledger_schema(&connection, &[91; 32]).unwrap();
        let before = compute_ledger_state(&connection).unwrap().retained_bytes;
        connection.execute("INSERT INTO ratification_packets(tenant_id,task_id,generation,packet_json,packet_hash,seal) VALUES(?1,'t',1,X'00','h','s')", ["é"]).unwrap();
        let after = compute_ledger_state(&connection).unwrap().retained_bytes;
        assert_eq!(after - before, "é".len() as u64 + 1 + 8 + 1 + 1 + 1);
        write_ledger_state_with_limit(&connection, &[91; 32], after).unwrap();
    }

    #[test]
    fn retained_authority_rejects_one_byte_over_without_updating_anchor() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        initialize_ledger_schema(&connection, &[92; 32]).unwrap();
        let before: (u64, String) = connection
            .query_row(
                "SELECT retained_bytes,state_hash FROM ratification_metadata",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let transaction = connection.transaction().unwrap();
        transaction
            .execute(
                "INSERT INTO ratification_packets VALUES('tenant','task',1,X'00','h','s')",
                [],
            )
            .unwrap();
        let used = compute_ledger_state(&transaction).unwrap().retained_bytes;
        assert_eq!(
            write_ledger_state_with_limit(&transaction, &[92; 32], used - 1),
            Err(RatificationError::CapacityExceeded)
        );
        drop(transaction);
        let after: (u64, String) = connection
            .query_row(
                "SELECT retained_bytes,state_hash FROM ratification_metadata",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(after, before);
    }
}
