use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use smesh_core::Attestation;
use thiserror::Error;

pub const COMPLETION_POLICY_V1: &str = "smesh-completion/v1";
const MAX_TEXT_BYTES: usize = 512;
const MAX_EVIDENCE_PAYLOAD_BYTES: usize = 64 * 1024;
type ReceiptMac = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactManifest {
    pub name: String,
    pub media_type: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClosedAttestation {
    pub node_id: String,
    pub public_key: String,
    pub signature: String,
}

impl ClosedAttestation {
    fn verify(&self, claim_hash: &str) -> bool {
        Attestation::from(self.clone()).verify(claim_hash)
    }
}

impl From<Attestation> for ClosedAttestation {
    fn from(value: Attestation) -> Self {
        Self {
            node_id: value.node_id,
            public_key: value.public_key,
            signature: value.signature,
        }
    }
}

impl From<ClosedAttestation> for Attestation {
    fn from(value: ClosedAttestation) -> Self {
        Self {
            node_id: value.node_id,
            public_key: value.public_key,
            signature: value.signature,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind", deny_unknown_fields)]
pub enum CompletionEvidence {
    Review {
        id: String,
        issuer: String,
        subject_digest: String,
        evidence: Vec<u8>,
        evidence_digest: String,
        approved: bool,
        assurance_bps: u16,
    },
    Test {
        id: String,
        issuer: String,
        subject_digest: String,
        evidence: Vec<u8>,
        evidence_digest: String,
        passed: bool,
        assurance_bps: u16,
    },
    Attestation {
        id: String,
        subject_digest: String,
        attestation: ClosedAttestation,
        assurance_bps: u16,
    },
    Contradiction {
        id: String,
        issuer: String,
        subject_digest: String,
        evidence: Vec<u8>,
        evidence_digest: String,
        blocking: bool,
    },
    Ratification(RatificationReceipt),
}

impl CompletionEvidence {
    fn id(&self) -> Option<&str> {
        match self {
            Self::Review { id, .. }
            | Self::Test { id, .. }
            | Self::Attestation { id, .. }
            | Self::Contradiction { id, .. } => Some(id),
            Self::Ratification(_) => None,
        }
    }

    fn subject_digest(&self) -> Option<&str> {
        match self {
            Self::Review { subject_digest, .. }
            | Self::Test { subject_digest, .. }
            | Self::Attestation { subject_digest, .. }
            | Self::Contradiction { subject_digest, .. } => Some(subject_digest),
            Self::Ratification(_) => None,
        }
    }

    fn assurance_bps(&self) -> Option<u16> {
        match self {
            Self::Review { assurance_bps, .. }
            | Self::Test { assurance_bps, .. }
            | Self::Attestation { assurance_bps, .. } => Some(*assurance_bps),
            Self::Contradiction { .. } | Self::Ratification(_) => None,
        }
    }

    fn provenance_identity(&self) -> Option<String> {
        match self {
            Self::Review {
                evidence_digest, ..
            }
            | Self::Test {
                evidence_digest, ..
            }
            | Self::Contradiction {
                evidence_digest, ..
            } => Some(evidence_digest.clone()),
            Self::Attestation { attestation, .. } => Some(format!(
                "attestation:{}:{}:{}",
                attestation.node_id, attestation.public_key, attestation.signature
            )),
            Self::Ratification(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompletionSnapshot {
    pub task_id: String,
    pub context_id: String,
    pub request_digest: String,
    pub artifacts: Vec<ArtifactManifest>,
    pub evidence: Vec<CompletionEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedAuthority {
    pub node_id: String,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompletionPolicySpec {
    pub policy_id: String,
    pub version: u32,
    pub required_reviews: u16,
    pub required_tests: u16,
    pub required_attestations: u16,
    pub required_contradiction_clearances: u16,
    pub min_assurance_bps: u16,
    pub require_human_ratification: bool,
    pub review_issuers: Vec<String>,
    pub test_issuers: Vec<String>,
    pub contradiction_issuers: Vec<String>,
    pub attestation_authorities: Vec<TrustedAuthority>,
    pub ratification_authorities: Vec<TrustedAuthority>,
    pub max_evidence_records: u16,
    pub max_artifacts: u16,
}

impl CompletionPolicySpec {
    #[must_use]
    pub fn development() -> Self {
        Self {
            policy_id: COMPLETION_POLICY_V1.to_owned(),
            version: 1,
            required_reviews: 1,
            required_tests: 1,
            required_attestations: 0,
            required_contradiction_clearances: 1,
            min_assurance_bps: 7_500,
            require_human_ratification: false,
            review_issuers: vec!["review-authority".to_owned()],
            test_issuers: vec!["test-authority".to_owned()],
            contradiction_issuers: vec!["contradiction-monitor".to_owned()],
            attestation_authorities: Vec::new(),
            ratification_authorities: Vec::new(),
            max_evidence_records: 32,
            max_artifacts: 16,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RatificationStatement {
    pub policy_hash: String,
    pub evidence_snapshot_hash: String,
    pub artifact_set_digest: String,
    pub approved: bool,
}

impl RatificationStatement {
    /// Hash the closed ratification statement schema.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::CanonicalEncoding`] if serialization fails.
    pub fn digest(&self) -> Result<String, PolicyError> {
        canonical_digest(b"ratification-statement", self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RatificationReceipt {
    pub statement: RatificationStatement,
    pub authority: ClosedAttestation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyCheckpoint {
    pub task_id: String,
    pub context_id: String,
    pub request_digest: String,
    pub policy_id: String,
    pub policy_version: u32,
    pub policy_hash: String,
    pub evidence_snapshot_hash: String,
    pub artifact_set_digest: String,
    pub evidence_hashes: Vec<String>,
    pub assurance_bps: u16,
    pub seal: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum PolicyBlockReason {
    BlockingContradiction,
    FailedReview,
    FailedTest,
    InsufficientReviews,
    InsufficientTests,
    InsufficientAttestations,
    InsufficientContradictionClearances,
    InsufficientAssurance,
    HumanRejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyBlock {
    pub checkpoint: PolicyCheckpoint,
    pub reasons: Vec<PolicyBlockReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompletionReceipt {
    pub task_id: String,
    pub context_id: String,
    pub request_digest: String,
    pub policy_id: String,
    pub policy_version: u32,
    pub policy_hash: String,
    pub evidence_snapshot_hash: String,
    pub artifact_set_digest: String,
    pub evidence_hashes: Vec<String>,
    pub assurance_bps: u16,
    pub ratification_receipt_hash: Option<String>,
    pub seal: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "camelCase",
    tag = "decision",
    content = "details",
    deny_unknown_fields
)]
pub enum PolicyDecision {
    Accepted(CompletionReceipt),
    AwaitingRatification(PolicyCheckpoint),
    Blocked(PolicyBlock),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PolicyError {
    #[error("invalid completion policy: {0}")]
    InvalidPolicy(String),
    #[error("completion snapshot requires at least one artifact")]
    MissingArtifact,
    #[error("artifact limit exceeded: {actual} > {limit}")]
    ArtifactLimitExceeded { actual: usize, limit: usize },
    #[error("evidence limit exceeded: {actual} > {limit}")]
    EvidenceLimitExceeded { actual: usize, limit: usize },
    #[error("invalid digest in {field}: {value}")]
    InvalidDigest { field: String, value: String },
    #[error("evidence payload exceeds {limit} bytes")]
    EvidencePayloadTooLarge { limit: usize },
    #[error("evidence digest does not match submitted bytes")]
    EvidenceDigestMismatch,
    #[error("duplicate evidence id: {0}")]
    DuplicateEvidenceId(String),
    #[error("duplicate evidence provenance: {0}")]
    DuplicateEvidenceProvenance(String),
    #[error("duplicate artifact digest: {0}")]
    DuplicateArtifactDigest(String),
    #[error("evidence subject {actual} does not match artifact set {expected}")]
    SubjectDigestMismatch { expected: String, actual: String },
    #[error("assurance basis points out of range: {0}")]
    InvalidAssurance(u16),
    #[error("invalid attestation: {0}")]
    InvalidAttestation(String),
    #[error("evidence issuer is not configured for kind {kind}: {issuer}")]
    UntrustedEvidenceIssuer { kind: String, issuer: String },
    #[error("multiple ratification receipts are ambiguous")]
    MultipleRatifications,
    #[error("ratification was supplied to a policy that does not require it")]
    UnexpectedRatification,
    #[error("ratification statement does not match this evaluation")]
    RatificationStatementMismatch,
    #[error("ratification authority is not allowlisted")]
    UntrustedRatificationAuthority,
    #[error("ratification signature is invalid")]
    InvalidRatificationSignature,
    #[error("completion receipt seal is invalid")]
    InvalidReceiptSeal,
    #[error("canonical encoding failed: {0}")]
    CanonicalEncoding(String),
    #[error("text field {field} is empty or exceeds {limit} bytes")]
    InvalidText { field: String, limit: usize },
}

#[derive(Clone)]
pub struct VersionedCompletionPolicy {
    spec: CompletionPolicySpec,
    policy_hash: String,
    receipt_key: Arc<[u8; 32]>,
}

impl fmt::Debug for VersionedCompletionPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VersionedCompletionPolicy")
            .field("spec", &self.spec)
            .field("policy_hash", &self.policy_hash)
            .field("receipt_key", &"[REDACTED]")
            .finish()
    }
}

impl Default for VersionedCompletionPolicy {
    fn default() -> Self {
        Self::new(CompletionPolicySpec::development())
            .unwrap_or_else(|error| panic!("static development policy is invalid: {error}"))
    }
}

impl VersionedCompletionPolicy {
    pub(crate) fn receipt_key(&self) -> [u8; 32] {
        *self.receipt_key
    }

    /// Build and validate a deterministic policy profile.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::InvalidPolicy`] for invalid thresholds, limits,
    /// duplicate authorities, or an unusable human-ratification configuration.
    pub fn new(spec: CompletionPolicySpec) -> Result<Self, PolicyError> {
        Self::new_with_receipt_key(spec, rand::random())
    }

    /// Build a policy with restart-stable receipt/checkpoint key material.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::InvalidPolicy`] under the same conditions as [`Self::new`].
    pub fn new_with_receipt_key(
        mut spec: CompletionPolicySpec,
        receipt_key: [u8; 32],
    ) -> Result<Self, PolicyError> {
        validate_text("policyId", &spec.policy_id)?;
        if spec.version != 1 {
            return Err(PolicyError::InvalidPolicy(
                "only completion policy version 1 is supported".to_owned(),
            ));
        }
        if spec.required_reviews == 0 || spec.required_tests == 0 {
            return Err(PolicyError::InvalidPolicy(
                "at least one review and one test are mandatory".to_owned(),
            ));
        }
        if !(1..=10_000).contains(&spec.min_assurance_bps) {
            return Err(PolicyError::InvalidPolicy(
                "minAssuranceBps must be between 1 and 10000".to_owned(),
            ));
        }
        if spec.max_evidence_records == 0 || spec.max_artifacts == 0 {
            return Err(PolicyError::InvalidPolicy(
                "evidence and artifact limits must be non-zero".to_owned(),
            ));
        }
        let required = u32::from(spec.required_reviews)
            + u32::from(spec.required_tests)
            + u32::from(spec.required_attestations)
            + u32::from(spec.required_contradiction_clearances);
        if required > u32::from(spec.max_evidence_records) {
            return Err(PolicyError::InvalidPolicy(
                "required evidence exceeds maxEvidenceRecords".to_owned(),
            ));
        }
        normalize_issuers("reviewIssuers", &mut spec.review_issuers)?;
        normalize_issuers("testIssuers", &mut spec.test_issuers)?;
        normalize_issuers("contradictionIssuers", &mut spec.contradiction_issuers)?;
        normalize_authorities("attestationAuthorities", &mut spec.attestation_authorities)?;
        normalize_authorities(
            "ratificationAuthorities",
            &mut spec.ratification_authorities,
        )?;
        if spec.review_issuers.len() < usize::from(spec.required_reviews)
            || spec.test_issuers.len() < usize::from(spec.required_tests)
            || spec.attestation_authorities.len() < usize::from(spec.required_attestations)
        {
            return Err(PolicyError::InvalidPolicy(
                "configured evidence authorities cannot satisfy required counts".to_owned(),
            ));
        }
        if spec.required_contradiction_clearances == 0 {
            return Err(PolicyError::InvalidPolicy(
                "at least one contradiction clearance is mandatory".to_owned(),
            ));
        }
        if spec.contradiction_issuers.len() < usize::from(spec.required_contradiction_clearances) {
            return Err(PolicyError::InvalidPolicy(
                "configured contradiction issuers cannot satisfy required clearances".to_owned(),
            ));
        }
        if spec.require_human_ratification && spec.ratification_authorities.is_empty() {
            return Err(PolicyError::InvalidPolicy(
                "human ratification requires at least one authority".to_owned(),
            ));
        }
        if !spec.require_human_ratification && !spec.ratification_authorities.is_empty() {
            return Err(PolicyError::InvalidPolicy(
                "authorities are invalid when human ratification is disabled".to_owned(),
            ));
        }
        let policy_hash = canonical_digest(b"policy-profile", &spec)?;
        Ok(Self {
            spec,
            policy_hash,
            receipt_key: Arc::new(receipt_key),
        })
    }

    #[must_use]
    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }

    #[must_use]
    pub fn spec(&self) -> &CompletionPolicySpec {
        &self.spec
    }

    #[must_use]
    pub fn verify_checkpoint(
        &self,
        checkpoint: &PolicyCheckpoint,
        task_id: &str,
        context_id: &str,
    ) -> bool {
        let structurally_valid = checkpoint.task_id == task_id
            && checkpoint.context_id == context_id
            && checkpoint.policy_id == self.spec.policy_id
            && checkpoint.policy_version == self.spec.version
            && checkpoint.policy_hash == self.policy_hash
            && validate_digest("checkpoint.requestDigest", &checkpoint.request_digest).is_ok()
            && validate_digest(
                "checkpoint.evidenceSnapshotHash",
                &checkpoint.evidence_snapshot_hash,
            )
            .is_ok()
            && validate_digest(
                "checkpoint.artifactSetDigest",
                &checkpoint.artifact_set_digest,
            )
            .is_ok()
            && checkpoint
                .evidence_hashes
                .iter()
                .all(|digest| validate_digest("checkpoint.evidenceHash", digest).is_ok())
            && checkpoint.assurance_bps >= self.spec.min_assurance_bps;
        if !structurally_valid {
            return false;
        }
        let claims = CheckpointClaims::from(checkpoint);
        let Ok(bytes) = serde_json::to_vec(&claims) else {
            return false;
        };
        let Some(tag) = decode_sha256_tag(&checkpoint.seal) else {
            return false;
        };
        let Ok(mut mac) = ReceiptMac::new_from_slice(self.receipt_key.as_ref()) else {
            return false;
        };
        mac.update(b"SMESH-A2A\0completion-checkpoint\0v1\0");
        mac.update(&(bytes.len() as u64).to_be_bytes());
        mac.update(&bytes);
        mac.verify_slice(&tag).is_ok()
    }

    #[must_use]
    pub fn verify_receipt(&self, receipt: &CompletionReceipt) -> bool {
        if receipt.policy_id != self.spec.policy_id
            || receipt.policy_version != self.spec.version
            || receipt.policy_hash != self.policy_hash
        {
            return false;
        }
        let claims = ReceiptClaims::from(receipt);
        let Ok(bytes) = serde_json::to_vec(&claims) else {
            return false;
        };
        let Some(tag) = decode_sha256_tag(&receipt.seal) else {
            return false;
        };
        let Ok(mut mac) = ReceiptMac::new_from_slice(self.receipt_key.as_ref()) else {
            return false;
        };
        mac.update(b"SMESH-A2A\0completion-receipt\0v1\0");
        mac.update(&(bytes.len() as u64).to_be_bytes());
        mac.update(&bytes);
        mac.verify_slice(&tag).is_ok()
    }

    /// Evaluate one immutable evidence snapshot.
    ///
    /// # Errors
    ///
    /// Malformed, ambiguous, oversized, mismatched, or cryptographically invalid
    /// evidence returns a [`PolicyError`] rather than a permissive decision.
    #[allow(clippy::too_many_lines)] // Linear fail-closed evaluation order is audit-significant.
    pub fn evaluate(&self, snapshot: &CompletionSnapshot) -> Result<PolicyDecision, PolicyError> {
        validate_text("taskId", &snapshot.task_id)?;
        validate_text("contextId", &snapshot.context_id)?;
        validate_digest("requestDigest", &snapshot.request_digest)?;
        if snapshot.artifacts.is_empty() {
            return Err(PolicyError::MissingArtifact);
        }
        if snapshot.artifacts.len() > usize::from(self.spec.max_artifacts) {
            return Err(PolicyError::ArtifactLimitExceeded {
                actual: snapshot.artifacts.len(),
                limit: usize::from(self.spec.max_artifacts),
            });
        }
        if snapshot.evidence.len() > usize::from(self.spec.max_evidence_records) + 1 {
            return Err(PolicyError::EvidenceLimitExceeded {
                actual: snapshot.evidence.len(),
                limit: usize::from(self.spec.max_evidence_records) + 1,
            });
        }

        let mut artifacts = snapshot.artifacts.clone();
        artifacts.sort_by(|left, right| {
            (&left.digest, &left.name, &left.media_type).cmp(&(
                &right.digest,
                &right.name,
                &right.media_type,
            ))
        });
        let mut artifact_digests = BTreeSet::new();
        for artifact in &artifacts {
            validate_text("artifact.name", &artifact.name)?;
            validate_text("artifact.mediaType", &artifact.media_type)?;
            validate_digest("artifact.digest", &artifact.digest)?;
            if !artifact_digests.insert(artifact.digest.clone()) {
                return Err(PolicyError::DuplicateArtifactDigest(
                    artifact.digest.clone(),
                ));
            }
        }
        let artifact_set_digest = artifact_set_digest(&artifacts)?;

        let mut records = Vec::new();
        let mut ratifications = Vec::new();
        for item in &snapshot.evidence {
            match item {
                CompletionEvidence::Ratification(receipt) => ratifications.push(receipt.clone()),
                other => records.push(other.clone()),
            }
        }
        if records.len() > usize::from(self.spec.max_evidence_records) {
            return Err(PolicyError::EvidenceLimitExceeded {
                actual: records.len(),
                limit: usize::from(self.spec.max_evidence_records),
            });
        }
        if ratifications.len() > 1 {
            return Err(PolicyError::MultipleRatifications);
        }
        records.sort_by(|left, right| left.id().cmp(&right.id()));
        let mut ids = BTreeSet::new();
        let mut provenance = BTreeSet::new();
        for record in &records {
            let Some(id) = record.id() else {
                return Err(PolicyError::UnexpectedRatification);
            };
            validate_text("evidence.id", id)?;
            if !ids.insert(id.to_owned()) {
                return Err(PolicyError::DuplicateEvidenceId(id.to_owned()));
            }
            let Some(actual_subject) = record.subject_digest() else {
                return Err(PolicyError::UnexpectedRatification);
            };
            validate_digest("evidence.subjectDigest", actual_subject)?;
            if actual_subject != artifact_set_digest {
                return Err(PolicyError::SubjectDigestMismatch {
                    expected: artifact_set_digest.clone(),
                    actual: actual_subject.to_owned(),
                });
            }
            if let Some(assurance) = record.assurance_bps()
                && assurance > 10_000
            {
                return Err(PolicyError::InvalidAssurance(assurance));
            }
            validate_evidence_record(record, &artifact_set_digest, &self.spec)?;
            let Some(identity) = record.provenance_identity() else {
                return Err(PolicyError::UnexpectedRatification);
            };
            if !provenance.insert(identity.clone()) {
                return Err(PolicyError::DuplicateEvidenceProvenance(identity));
            }
        }

        let evidence_hashes = records
            .iter()
            .map(|record| canonical_digest(b"evidence-record", record))
            .collect::<Result<Vec<_>, _>>()?;
        let normalized = NormalizedSnapshot {
            task_id: snapshot.task_id.clone(),
            context_id: snapshot.context_id.clone(),
            request_digest: snapshot.request_digest.clone(),
            artifacts,
            evidence: records.clone(),
        };
        let evidence_snapshot_hash = canonical_digest(b"evidence-snapshot", &normalized)?;

        let mut reasons = BTreeSet::new();
        let mut reviews = Vec::new();
        let mut tests = Vec::new();
        let mut attestations = Vec::new();
        let mut distinct_reviewers = BTreeSet::new();
        let mut distinct_testers = BTreeSet::new();
        let mut distinct_attesters = BTreeSet::new();
        let mut contradiction_clearances = BTreeSet::new();
        for record in &records {
            match record {
                CompletionEvidence::Review {
                    issuer,
                    approved,
                    assurance_bps,
                    ..
                } => {
                    if !approved {
                        reasons.insert(PolicyBlockReason::FailedReview);
                    } else if distinct_reviewers.insert(issuer) {
                        reviews.push(*assurance_bps);
                    }
                }
                CompletionEvidence::Test {
                    issuer,
                    passed,
                    assurance_bps,
                    ..
                } => {
                    if !passed {
                        reasons.insert(PolicyBlockReason::FailedTest);
                    } else if distinct_testers.insert(issuer) {
                        tests.push(*assurance_bps);
                    }
                }
                CompletionEvidence::Attestation {
                    attestation,
                    assurance_bps,
                    ..
                } => {
                    let identity = (attestation.node_id.clone(), attestation.public_key.clone());
                    if distinct_attesters.insert(identity) {
                        attestations.push(*assurance_bps);
                    }
                }
                CompletionEvidence::Contradiction { blocking: true, .. } => {
                    reasons.insert(PolicyBlockReason::BlockingContradiction);
                }
                CompletionEvidence::Contradiction {
                    issuer,
                    blocking: false,
                    ..
                } => {
                    contradiction_clearances.insert(issuer);
                }
                CompletionEvidence::Ratification(_) => {}
            }
        }

        reviews.sort_unstable_by(|left, right| right.cmp(left));
        tests.sort_unstable_by(|left, right| right.cmp(left));
        attestations.sort_unstable_by(|left, right| right.cmp(left));
        let qualifying_reviews = reviews
            .iter()
            .filter(|assurance| **assurance >= self.spec.min_assurance_bps)
            .count();
        let qualifying_tests = tests
            .iter()
            .filter(|assurance| **assurance >= self.spec.min_assurance_bps)
            .count();
        let qualifying_attestations = attestations
            .iter()
            .filter(|assurance| **assurance >= self.spec.min_assurance_bps)
            .count();
        if qualifying_reviews < usize::from(self.spec.required_reviews) {
            reasons.insert(PolicyBlockReason::InsufficientReviews);
        }
        if qualifying_tests < usize::from(self.spec.required_tests) {
            reasons.insert(PolicyBlockReason::InsufficientTests);
        }
        if qualifying_attestations < usize::from(self.spec.required_attestations) {
            reasons.insert(PolicyBlockReason::InsufficientAttestations);
        }
        if contradiction_clearances.len() < usize::from(self.spec.required_contradiction_clearances)
        {
            reasons.insert(PolicyBlockReason::InsufficientContradictionClearances);
        }

        let assurance_bps = selected_assurance(
            &reviews,
            self.spec.required_reviews,
            &tests,
            self.spec.required_tests,
            &attestations,
            self.spec.required_attestations,
        );
        if assurance_bps < self.spec.min_assurance_bps {
            reasons.insert(PolicyBlockReason::InsufficientAssurance);
        }
        let mut checkpoint = PolicyCheckpoint {
            task_id: snapshot.task_id.clone(),
            context_id: snapshot.context_id.clone(),
            request_digest: snapshot.request_digest.clone(),
            policy_id: self.spec.policy_id.clone(),
            policy_version: self.spec.version,
            policy_hash: self.policy_hash.clone(),
            evidence_snapshot_hash,
            artifact_set_digest,
            evidence_hashes,
            assurance_bps,
            seal: String::new(),
        };
        checkpoint.seal =
            compute_checkpoint_seal(&CheckpointClaims::from(&checkpoint), &self.receipt_key)?;

        if !reasons.is_empty() {
            return Ok(PolicyDecision::Blocked(PolicyBlock {
                checkpoint,
                reasons: reasons.into_iter().collect(),
            }));
        }

        if !self.spec.require_human_ratification {
            if !ratifications.is_empty() {
                return Err(PolicyError::UnexpectedRatification);
            }
            return Ok(PolicyDecision::Accepted(receipt_from_checkpoint(
                checkpoint,
                None,
                &self.receipt_key,
            )?));
        }

        let Some(ratification) = ratifications.first() else {
            return Ok(PolicyDecision::AwaitingRatification(checkpoint));
        };
        let expected_statement = RatificationStatement {
            policy_hash: checkpoint.policy_hash.clone(),
            evidence_snapshot_hash: checkpoint.evidence_snapshot_hash.clone(),
            artifact_set_digest: checkpoint.artifact_set_digest.clone(),
            approved: ratification.statement.approved,
        };
        if ratification.statement != expected_statement {
            return Err(PolicyError::RatificationStatementMismatch);
        }
        if !self.spec.ratification_authorities.iter().any(|authority| {
            authority.node_id == ratification.authority.node_id
                && authority.public_key == ratification.authority.public_key
        }) {
            return Err(PolicyError::UntrustedRatificationAuthority);
        }
        let statement_digest = ratification.statement.digest()?;
        if !ratification.authority.verify(&statement_digest) {
            return Err(PolicyError::InvalidRatificationSignature);
        }
        if !ratification.statement.approved {
            return Ok(PolicyDecision::Blocked(PolicyBlock {
                checkpoint,
                reasons: vec![PolicyBlockReason::HumanRejected],
            }));
        }
        let ratification_hash = canonical_digest(b"ratification-receipt", ratification)?;
        Ok(PolicyDecision::Accepted(receipt_from_checkpoint(
            checkpoint,
            Some(ratification_hash),
            &self.receipt_key,
        )?))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NormalizedSnapshot {
    task_id: String,
    context_id: String,
    request_digest: String,
    artifacts: Vec<ArtifactManifest>,
    evidence: Vec<CompletionEvidence>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CheckpointClaims {
    task_id: String,
    context_id: String,
    request_digest: String,
    policy_id: String,
    policy_version: u32,
    policy_hash: String,
    evidence_snapshot_hash: String,
    artifact_set_digest: String,
    evidence_hashes: Vec<String>,
    assurance_bps: u16,
}

impl From<&PolicyCheckpoint> for CheckpointClaims {
    fn from(checkpoint: &PolicyCheckpoint) -> Self {
        Self {
            task_id: checkpoint.task_id.clone(),
            context_id: checkpoint.context_id.clone(),
            request_digest: checkpoint.request_digest.clone(),
            policy_id: checkpoint.policy_id.clone(),
            policy_version: checkpoint.policy_version,
            policy_hash: checkpoint.policy_hash.clone(),
            evidence_snapshot_hash: checkpoint.evidence_snapshot_hash.clone(),
            artifact_set_digest: checkpoint.artifact_set_digest.clone(),
            evidence_hashes: checkpoint.evidence_hashes.clone(),
            assurance_bps: checkpoint.assurance_bps,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptClaims {
    task_id: String,
    context_id: String,
    request_digest: String,
    policy_id: String,
    policy_version: u32,
    policy_hash: String,
    evidence_snapshot_hash: String,
    artifact_set_digest: String,
    evidence_hashes: Vec<String>,
    assurance_bps: u16,
    ratification_receipt_hash: Option<String>,
}

impl From<&CompletionReceipt> for ReceiptClaims {
    fn from(receipt: &CompletionReceipt) -> Self {
        Self {
            task_id: receipt.task_id.clone(),
            context_id: receipt.context_id.clone(),
            request_digest: receipt.request_digest.clone(),
            policy_id: receipt.policy_id.clone(),
            policy_version: receipt.policy_version,
            policy_hash: receipt.policy_hash.clone(),
            evidence_snapshot_hash: receipt.evidence_snapshot_hash.clone(),
            artifact_set_digest: receipt.artifact_set_digest.clone(),
            evidence_hashes: receipt.evidence_hashes.clone(),
            assurance_bps: receipt.assurance_bps,
            ratification_receipt_hash: receipt.ratification_receipt_hash.clone(),
        }
    }
}

fn receipt_from_checkpoint(
    checkpoint: PolicyCheckpoint,
    ratification_receipt_hash: Option<String>,
    key: &[u8; 32],
) -> Result<CompletionReceipt, PolicyError> {
    let claims = ReceiptClaims {
        task_id: checkpoint.task_id,
        context_id: checkpoint.context_id,
        request_digest: checkpoint.request_digest,
        policy_id: checkpoint.policy_id,
        policy_version: checkpoint.policy_version,
        policy_hash: checkpoint.policy_hash,
        evidence_snapshot_hash: checkpoint.evidence_snapshot_hash,
        artifact_set_digest: checkpoint.artifact_set_digest,
        evidence_hashes: checkpoint.evidence_hashes,
        assurance_bps: checkpoint.assurance_bps,
        ratification_receipt_hash,
    };
    let seal = compute_receipt_seal(&claims, key)?;
    Ok(CompletionReceipt {
        task_id: claims.task_id,
        context_id: claims.context_id,
        request_digest: claims.request_digest,
        policy_id: claims.policy_id,
        policy_version: claims.policy_version,
        policy_hash: claims.policy_hash,
        evidence_snapshot_hash: claims.evidence_snapshot_hash,
        artifact_set_digest: claims.artifact_set_digest,
        evidence_hashes: claims.evidence_hashes,
        assurance_bps: claims.assurance_bps,
        ratification_receipt_hash: claims.ratification_receipt_hash,
        seal,
    })
}

fn compute_checkpoint_seal(
    claims: &CheckpointClaims,
    key: &[u8; 32],
) -> Result<String, PolicyError> {
    let bytes = serde_json::to_vec(claims)
        .map_err(|error| PolicyError::CanonicalEncoding(error.to_string()))?;
    let mut mac = ReceiptMac::new_from_slice(key)
        .map_err(|_| PolicyError::CanonicalEncoding("invalid receipt key".to_owned()))?;
    mac.update(b"SMESH-A2A\0completion-checkpoint\0v1\0");
    mac.update(&(bytes.len() as u64).to_be_bytes());
    mac.update(&bytes);
    Ok(format!("sha256:{:x}", mac.finalize().into_bytes()))
}

fn compute_receipt_seal(claims: &ReceiptClaims, key: &[u8; 32]) -> Result<String, PolicyError> {
    let bytes = serde_json::to_vec(claims)
        .map_err(|error| PolicyError::CanonicalEncoding(error.to_string()))?;
    let mut mac = ReceiptMac::new_from_slice(key)
        .map_err(|_| PolicyError::CanonicalEncoding("invalid receipt key".to_owned()))?;
    mac.update(b"SMESH-A2A\0completion-receipt\0v1\0");
    mac.update(&(bytes.len() as u64).to_be_bytes());
    mac.update(&bytes);
    Ok(format!("sha256:{:x}", mac.finalize().into_bytes()))
}

fn validate_evidence_record(
    record: &CompletionEvidence,
    subject_digest: &str,
    spec: &CompletionPolicySpec,
) -> Result<(), PolicyError> {
    match record {
        CompletionEvidence::Review {
            issuer,
            evidence,
            evidence_digest,
            ..
        } => validate_claimed_evidence(
            "review",
            issuer,
            evidence,
            evidence_digest,
            &spec.review_issuers,
        )?,
        CompletionEvidence::Test {
            issuer,
            evidence,
            evidence_digest,
            ..
        } => validate_claimed_evidence(
            "test",
            issuer,
            evidence,
            evidence_digest,
            &spec.test_issuers,
        )?,
        CompletionEvidence::Contradiction {
            issuer,
            evidence,
            evidence_digest,
            ..
        } => validate_claimed_evidence(
            "contradiction",
            issuer,
            evidence,
            evidence_digest,
            &spec.contradiction_issuers,
        )?,
        CompletionEvidence::Attestation { attestation, .. } => {
            validate_text("attestation.nodeId", &attestation.node_id)?;
            validate_text("attestation.publicKey", &attestation.public_key)?;
            if !attestation.verify(subject_digest) {
                return Err(PolicyError::InvalidAttestation(attestation.node_id.clone()));
            }
            if !spec.attestation_authorities.iter().any(|authority| {
                authority.node_id == attestation.node_id
                    && authority.public_key == attestation.public_key
            }) {
                return Err(PolicyError::UntrustedEvidenceIssuer {
                    kind: "attestation".to_owned(),
                    issuer: attestation.node_id.clone(),
                });
            }
        }
        CompletionEvidence::Ratification(_) => return Err(PolicyError::UnexpectedRatification),
    }
    Ok(())
}

fn validate_claimed_evidence(
    kind: &str,
    issuer: &str,
    evidence: &[u8],
    evidence_digest: &str,
    allowed_issuers: &[String],
) -> Result<(), PolicyError> {
    validate_text("evidence.issuer", issuer)?;
    if !allowed_issuers.iter().any(|allowed| allowed == issuer) {
        return Err(PolicyError::UntrustedEvidenceIssuer {
            kind: kind.to_owned(),
            issuer: issuer.to_owned(),
        });
    }
    if evidence.len() > MAX_EVIDENCE_PAYLOAD_BYTES {
        return Err(PolicyError::EvidencePayloadTooLarge {
            limit: MAX_EVIDENCE_PAYLOAD_BYTES,
        });
    }
    validate_digest("evidence.evidenceDigest", evidence_digest)?;
    if content_digest(evidence) != evidence_digest {
        return Err(PolicyError::EvidenceDigestMismatch);
    }
    Ok(())
}

fn selected_assurance(
    reviews: &[u16],
    required_reviews: u16,
    tests: &[u16],
    required_tests: u16,
    attestations: &[u16],
    required_attestations: u16,
) -> u16 {
    let mut selected = Vec::new();
    selected.extend(reviews.iter().take(usize::from(required_reviews)).copied());
    selected.extend(tests.iter().take(usize::from(required_tests)).copied());
    selected.extend(
        attestations
            .iter()
            .take(usize::from(required_attestations))
            .copied(),
    );
    selected.into_iter().min().unwrap_or(0)
}

fn normalize_issuers(field: &str, issuers: &mut [String]) -> Result<(), PolicyError> {
    issuers.sort();
    for issuer in issuers.iter() {
        validate_text(field, issuer)?;
    }
    if issuers.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(PolicyError::InvalidPolicy(format!(
            "{field} must contain unique values"
        )));
    }
    Ok(())
}

fn normalize_authorities(
    field: &str,
    authorities: &mut [TrustedAuthority],
) -> Result<(), PolicyError> {
    authorities.sort_by(|left, right| {
        (&left.node_id, &left.public_key).cmp(&(&right.node_id, &right.public_key))
    });
    for authority in authorities.iter() {
        validate_text(&format!("{field}.nodeId"), &authority.node_id)?;
        validate_text(&format!("{field}.publicKey"), &authority.public_key)?;
    }
    if authorities.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(PolicyError::InvalidPolicy(format!(
            "{field} must contain unique values"
        )));
    }
    Ok(())
}

fn decode_sha256_tag(value: &str) -> Option<[u8; 32]> {
    let hex = value.strip_prefix("sha256:")?;
    if hex.len() != 64 {
        return None;
    }
    let mut output = [0_u8; 32];
    for (index, pair) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        output[index] = (high << 4) | low;
    }
    Some(output)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn validate_text(field: &str, value: &str) -> Result<(), PolicyError> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.trim().is_empty()
        || value.chars().any(char::is_control)
    {
        return Err(PolicyError::InvalidText {
            field: field.to_owned(),
            limit: MAX_TEXT_BYTES,
        });
    }
    Ok(())
}

fn validate_digest(field: &str, value: &str) -> Result<(), PolicyError> {
    let valid = value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !valid {
        return Err(PolicyError::InvalidDigest {
            field: field.to_owned(),
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn canonical_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<String, PolicyError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| PolicyError::CanonicalEncoding(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(b"SMESH-A2A\0completion-policy\0smesh-json-v1\0");
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

/// Compute the canonical policy-record digest for one evidence item.
///
/// # Errors
///
/// Returns an error if the closed evidence record cannot be serialized.
pub fn completion_evidence_digest(evidence: &CompletionEvidence) -> Result<String, PolicyError> {
    canonical_digest(b"evidence-record", evidence)
}

#[must_use]
pub fn content_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// Hash a deterministic, sorted artifact manifest.
///
/// # Errors
///
/// Returns a [`PolicyError`] for malformed or duplicate artifact digests.
pub fn artifact_set_digest(artifacts: &[ArtifactManifest]) -> Result<String, PolicyError> {
    if artifacts.is_empty() {
        return Err(PolicyError::MissingArtifact);
    }
    let mut normalized = artifacts.to_vec();
    normalized.sort_by(|left, right| {
        (&left.digest, &left.name, &left.media_type).cmp(&(
            &right.digest,
            &right.name,
            &right.media_type,
        ))
    });
    let mut digests = BTreeSet::new();
    for artifact in &normalized {
        validate_text("artifact.name", &artifact.name)?;
        validate_text("artifact.mediaType", &artifact.media_type)?;
        validate_digest("artifact.digest", &artifact.digest)?;
        if !digests.insert(&artifact.digest) {
            return Err(PolicyError::DuplicateArtifactDigest(
                artifact.digest.clone(),
            ));
        }
    }
    canonical_digest(b"artifact-set", &normalized)
}
