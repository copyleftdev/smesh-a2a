use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{TextConcordanceLimits, process_text_concordance};

const CANONICAL_PREFIX: &[u8] = b"SMESH-A2A\0completion-policy\0smesh-json-v1\0";
pub const ISSUER_EVIDENCE_SCHEMA_V1: &str = "issuer-evidence/v1";
pub const TEXT_CONCORDANCE_COMPLETION_POLICY_V1: &str = "smesh-completion/v1";
pub const TEXT_CONCORDANCE_COMPLETION_POLICY_REVISION_V1: u64 = 1;
const MAX_AUTHORITY_TEXT_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateGenerationV1 {
    pub tenant_scope: String,
    pub task_id: String,
    pub context_id: String,
    pub request_digest: String,
    pub artifact_set_digest: String,
    pub dispatch_id: String,
    pub attempt: u64,
    pub fence: u64,
    pub completion_policy: String,
    pub completion_policy_revision: u64,
}

impl CandidateGenerationV1 {
    /// Return the closed candidate-generation digest after validating every field.
    ///
    /// # Errors
    ///
    /// Returns a typed structural or canonical-encoding error.
    pub fn id(&self) -> Result<String, SemanticEvidenceError> {
        validate_candidate(self)?;
        canonical_digest(b"candidate-generation", self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IssuerRoleV1 {
    #[serde(rename = "text-concordance-review/v1")]
    Review,
    #[serde(rename = "text-concordance-test/v1")]
    Test,
    #[serde(rename = "text-concordance-contradiction/v1")]
    Contradiction,
}

impl IssuerRoleV1 {
    #[must_use]
    pub const fn decision(self) -> IssuerDecisionV1 {
        match self {
            Self::Review | Self::Test => IssuerDecisionV1::Approve,
            Self::Contradiction => IssuerDecisionV1::Clear,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IssuerDecisionV1 {
    #[serde(rename = "approve")]
    Approve,
    #[serde(rename = "clear")]
    Clear,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticEvidenceIngestOutcome {
    Accepted,
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerEvidenceV1 {
    pub schema: String,
    pub candidate_generation_id: String,
    pub tenant_scope: String,
    pub task_id: String,
    pub context_id: String,
    pub request_digest: String,
    pub artifact_set_digest: String,
    pub dispatch_id: String,
    pub attempt: u64,
    pub fence: u64,
    pub completion_policy: String,
    pub completion_policy_revision: u64,
    pub issuer_role: IssuerRoleV1,
    pub issuer_identity: String,
    pub decision: IssuerDecisionV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerEnrollmentV1 {
    pub tenant_scope: String,
    pub issuer_role: IssuerRoleV1,
    pub issuer_identity: String,
    pub public_key: String,
    pub valid_from: u64,
    pub expires_at: u64,
    pub revoked_at: Option<u64>,
}

impl IssuerEnrollmentV1 {
    /// Validate canonical key encoding and active validity at `now`.
    ///
    /// # Errors
    ///
    /// Returns a typed structural, key, or validity error.
    pub fn validate_at(&self, now: u64) -> Result<(), SemanticEvidenceError> {
        validate_enrollment(self)?;
        let public_key = decode_exact::<32>(&self.public_key)
            .map_err(|()| SemanticEvidenceError::InvalidPublicKey)?;
        VerifyingKey::from_bytes(&public_key)
            .map_err(|_| SemanticEvidenceError::InvalidPublicKey)?;
        if now < self.valid_from
            || now >= self.expires_at
            || self.revoked_at.is_some_and(|revoked_at| revoked_at <= now)
        {
            return Err(SemanticEvidenceError::EnrollmentInactive);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedIssuerEvidenceV1 {
    pub evidence: IssuerEvidenceV1,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextConcordanceCandidatePacketV1 {
    pub candidate: CandidateGenerationV1,
    pub input: String,
    pub artifact: String,
    pub observed_conflict_digests: Vec<String>,
}

/// Validate a frozen candidate packet by independently recomputing the closed workload.
///
/// # Errors
///
/// Returns an error for a malformed candidate, non-canonical artifact encoding,
/// workload rejection, or any digest/artifact mismatch.
pub fn validate_text_concordance_candidate(
    packet: &TextConcordanceCandidatePacketV1,
) -> Result<Vec<u8>, SemanticEvidenceError> {
    if packet.candidate.completion_policy != TEXT_CONCORDANCE_COMPLETION_POLICY_V1
        || packet.candidate.completion_policy_revision
            != TEXT_CONCORDANCE_COMPLETION_POLICY_REVISION_V1
    {
        return Err(SemanticEvidenceError::BindingMismatch);
    }
    packet.candidate.id()?;
    if packet.observed_conflict_digests.len() > 64 {
        return Err(SemanticEvidenceError::ConflictObserved);
    }
    for digest in &packet.observed_conflict_digests {
        validate_digest("observed_conflict_digest", digest)?;
    }
    let artifact = decode_canonical(&packet.artifact)
        .map_err(|()| SemanticEvidenceError::CandidateArtifactMismatch)?;
    let output = process_text_concordance(&packet.input, TextConcordanceLimits::default())
        .map_err(|_| SemanticEvidenceError::CandidateArtifactMismatch)?;
    if artifact != output.artifact_bytes
        || packet.candidate.request_digest != output.request_digest
        || packet.candidate.artifact_set_digest != output.artifact_set_digest
    {
        return Err(SemanticEvidenceError::CandidateArtifactMismatch);
    }
    Ok(artifact)
}

/// Independently recompute one candidate and sign the closed role decision.
///
/// # Errors
///
/// Returns a typed error without producing evidence when any candidate byte,
/// authority binding, or contradiction observation is invalid.
pub fn sign_text_concordance_evidence(
    packet: &TextConcordanceCandidatePacketV1,
    issuer_role: IssuerRoleV1,
    issuer_identity: String,
    signing_seed: &[u8; 32],
) -> Result<SignedIssuerEvidenceV1, SemanticEvidenceError> {
    validate_text_concordance_candidate(packet)?;
    if issuer_role == IssuerRoleV1::Contradiction && !packet.observed_conflict_digests.is_empty() {
        return Err(SemanticEvidenceError::ConflictObserved);
    }
    let evidence =
        IssuerEvidenceV1::for_candidate(&packet.candidate, issuer_role, issuer_identity)?;
    let digest = evidence.digest()?;
    let signing_key = SigningKey::from_bytes(signing_seed);
    let signature = signing_key.sign(digest.as_bytes());
    Ok(SignedIssuerEvidenceV1 {
        evidence,
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
}

/// Load one no-follow owner-private Ed25519 seed and issue independently checked evidence.
///
/// # Errors
///
/// Returns a redacted key-file or semantic validation error without exposing key material.
pub fn sign_text_concordance_evidence_from_private_file(
    packet: &TextConcordanceCandidatePacketV1,
    issuer_role: IssuerRoleV1,
    issuer_identity: String,
    key_path: &std::path::Path,
) -> Result<SignedIssuerEvidenceV1, SemanticEvidenceError> {
    let seed = crate::private_file::read_owner_private_exact::<32>(key_path)
        .map_err(|_| SemanticEvidenceError::SigningKeyFile)?;
    sign_text_concordance_evidence(packet, issuer_role, issuer_identity, &seed)
}

impl SignedIssuerEvidenceV1 {
    /// Verify all durable bindings, enrollment authority, and the Ed25519 signature.
    ///
    /// # Errors
    ///
    /// Returns a typed validation error and never accepts a descriptive issuer label alone.
    pub fn verify(
        &self,
        candidate: &CandidateGenerationV1,
        enrollment: &IssuerEnrollmentV1,
        now: u64,
    ) -> Result<(), SemanticEvidenceError> {
        self.evidence.validate_candidate(candidate)?;
        validate_enrollment(enrollment)?;
        if enrollment.tenant_scope != self.evidence.tenant_scope
            || enrollment.issuer_role != self.evidence.issuer_role
            || enrollment.issuer_identity != self.evidence.issuer_identity
        {
            return Err(SemanticEvidenceError::EnrollmentMismatch);
        }
        if now < enrollment.valid_from
            || now >= enrollment.expires_at
            || enrollment
                .revoked_at
                .is_some_and(|revoked_at| revoked_at <= now)
        {
            return Err(SemanticEvidenceError::EnrollmentInactive);
        }

        let public_key = decode_exact::<32>(&enrollment.public_key)
            .map_err(|()| SemanticEvidenceError::InvalidPublicKey)?;
        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| SemanticEvidenceError::InvalidPublicKey)?;
        let signature_bytes = decode_exact::<64>(&self.signature)
            .map_err(|()| SemanticEvidenceError::InvalidSignatureEncoding)?;
        let signature = Signature::from_bytes(&signature_bytes);
        let digest = self.evidence.digest()?;
        verifying_key
            .verify_strict(digest.as_bytes(), &signature)
            .map_err(|_| SemanticEvidenceError::InvalidSignature)
    }
}

impl IssuerEvidenceV1 {
    /// Construct the only evidence record shape accepted for a frozen generation.
    ///
    /// # Errors
    ///
    /// Returns an error when the candidate or issuer identity is malformed.
    pub fn for_candidate(
        candidate: &CandidateGenerationV1,
        issuer_role: IssuerRoleV1,
        issuer_identity: String,
    ) -> Result<Self, SemanticEvidenceError> {
        validate_text("issuer_identity", &issuer_identity)?;
        Ok(Self {
            schema: ISSUER_EVIDENCE_SCHEMA_V1.to_owned(),
            candidate_generation_id: candidate.id()?,
            tenant_scope: candidate.tenant_scope.clone(),
            task_id: candidate.task_id.clone(),
            context_id: candidate.context_id.clone(),
            request_digest: candidate.request_digest.clone(),
            artifact_set_digest: candidate.artifact_set_digest.clone(),
            dispatch_id: candidate.dispatch_id.clone(),
            attempt: candidate.attempt,
            fence: candidate.fence,
            completion_policy: candidate.completion_policy.clone(),
            completion_policy_revision: candidate.completion_policy_revision,
            issuer_role,
            issuer_identity,
            decision: issuer_role.decision(),
        })
    }

    /// Return the closed evidence-record digest after structural validation.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or noncanonical evidence.
    pub fn digest(&self) -> Result<String, SemanticEvidenceError> {
        validate_evidence(self)?;
        canonical_digest(b"evidence-record", self)
    }

    /// Recompute and compare every candidate authority binding.
    ///
    /// # Errors
    ///
    /// Returns [`SemanticEvidenceError::BindingMismatch`] for any difference.
    pub fn validate_candidate(
        &self,
        candidate: &CandidateGenerationV1,
    ) -> Result<(), SemanticEvidenceError> {
        validate_evidence(self)?;
        let expected_id = candidate.id()?;
        if self.candidate_generation_id != expected_id
            || self.tenant_scope != candidate.tenant_scope
            || self.task_id != candidate.task_id
            || self.context_id != candidate.context_id
            || self.request_digest != candidate.request_digest
            || self.artifact_set_digest != candidate.artifact_set_digest
            || self.dispatch_id != candidate.dispatch_id
            || self.attempt != candidate.attempt
            || self.fence != candidate.fence
            || self.completion_policy != candidate.completion_policy
            || self.completion_policy_revision != candidate.completion_policy_revision
        {
            return Err(SemanticEvidenceError::BindingMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SemanticEvidenceError {
    #[error("semantic evidence text field is invalid: {0}")]
    InvalidText(&'static str),
    #[error("semantic evidence digest is invalid: {0}")]
    InvalidDigest(&'static str),
    #[error("semantic evidence policy revision must be non-zero")]
    InvalidPolicyRevision,
    #[error("semantic evidence schema is unsupported")]
    InvalidSchema,
    #[error("semantic evidence role and decision do not match")]
    RoleDecisionMismatch,
    #[error("semantic evidence authority binding does not match candidate")]
    BindingMismatch,
    #[error("semantic evidence enrollment does not match the signed record")]
    EnrollmentMismatch,
    #[error("semantic evidence enrollment is not active")]
    EnrollmentInactive,
    #[error("semantic evidence public key is invalid or noncanonical")]
    InvalidPublicKey,
    #[error("semantic evidence signature encoding is invalid or noncanonical")]
    InvalidSignatureEncoding,
    #[error("semantic evidence signature is invalid")]
    InvalidSignature,
    #[error("semantic candidate artifact does not match the independently recomputed result")]
    CandidateArtifactMismatch,
    #[error("semantic contradiction evidence cannot clear an observed conflict")]
    ConflictObserved,
    #[error("semantic issuer signing key file was rejected")]
    SigningKeyFile,
    #[error("semantic evidence canonical encoding failed")]
    CanonicalEncoding,
}

fn validate_enrollment(enrollment: &IssuerEnrollmentV1) -> Result<(), SemanticEvidenceError> {
    validate_text("tenant_scope", &enrollment.tenant_scope)?;
    validate_text("issuer_identity", &enrollment.issuer_identity)?;
    if enrollment.valid_from >= enrollment.expires_at {
        return Err(SemanticEvidenceError::EnrollmentInactive);
    }
    Ok(())
}

fn decode_canonical(value: &str) -> Result<Vec<u8>, ()> {
    if value.contains('=') || value.len() > 1_500_000 {
        return Err(());
    }
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| ())?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(());
    }
    Ok(bytes)
}

fn decode_exact<const N: usize>(value: &str) -> Result<[u8; N], ()> {
    if value.contains('=') {
        return Err(());
    }
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| ())?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(());
    }
    bytes.try_into().map_err(|_| ())
}

fn validate_candidate(candidate: &CandidateGenerationV1) -> Result<(), SemanticEvidenceError> {
    validate_text("tenant_scope", &candidate.tenant_scope)?;
    validate_text("task_id", &candidate.task_id)?;
    validate_text("context_id", &candidate.context_id)?;
    validate_digest("request_digest", &candidate.request_digest)?;
    validate_digest("artifact_set_digest", &candidate.artifact_set_digest)?;
    validate_text("dispatch_id", &candidate.dispatch_id)?;
    validate_text("completion_policy", &candidate.completion_policy)?;
    if candidate.completion_policy_revision == 0 {
        return Err(SemanticEvidenceError::InvalidPolicyRevision);
    }
    Ok(())
}

fn validate_evidence(evidence: &IssuerEvidenceV1) -> Result<(), SemanticEvidenceError> {
    if evidence.schema != ISSUER_EVIDENCE_SCHEMA_V1 {
        return Err(SemanticEvidenceError::InvalidSchema);
    }
    validate_digest("candidate_generation_id", &evidence.candidate_generation_id)?;
    let candidate = CandidateGenerationV1 {
        tenant_scope: evidence.tenant_scope.clone(),
        task_id: evidence.task_id.clone(),
        context_id: evidence.context_id.clone(),
        request_digest: evidence.request_digest.clone(),
        artifact_set_digest: evidence.artifact_set_digest.clone(),
        dispatch_id: evidence.dispatch_id.clone(),
        attempt: evidence.attempt,
        fence: evidence.fence,
        completion_policy: evidence.completion_policy.clone(),
        completion_policy_revision: evidence.completion_policy_revision,
    };
    validate_candidate(&candidate)?;
    validate_text("issuer_identity", &evidence.issuer_identity)?;
    if evidence.decision != evidence.issuer_role.decision() {
        return Err(SemanticEvidenceError::RoleDecisionMismatch);
    }
    Ok(())
}

fn validate_text(field: &'static str, value: &str) -> Result<(), SemanticEvidenceError> {
    if value.is_empty() || value.len() > MAX_AUTHORITY_TEXT_BYTES {
        return Err(SemanticEvidenceError::InvalidText(field));
    }
    Ok(())
}

fn validate_digest(field: &'static str, value: &str) -> Result<(), SemanticEvidenceError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(SemanticEvidenceError::InvalidDigest(field));
    };
    if hex.len() != 64
        || !hex
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(SemanticEvidenceError::InvalidDigest(field));
    }
    Ok(())
}

fn canonical_digest<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<String, SemanticEvidenceError> {
    let bytes = serde_json::to_vec(value).map_err(|_| SemanticEvidenceError::CanonicalEncoding)?;
    let domain_len =
        u64::try_from(domain.len()).map_err(|_| SemanticEvidenceError::CanonicalEncoding)?;
    let bytes_len =
        u64::try_from(bytes.len()).map_err(|_| SemanticEvidenceError::CanonicalEncoding)?;
    let mut hasher = Sha256::new();
    hasher.update(CANONICAL_PREFIX);
    hasher.update(domain_len.to_be_bytes());
    hasher.update(domain);
    hasher.update(bytes_len.to_be_bytes());
    hasher.update(bytes);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}
