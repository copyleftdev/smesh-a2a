use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

use crate::full_matrix_replay::{ReplayError, canonical, hash};

pub const CRITERIA_SCHEMA_VERSION: &str = "operational-lifeline-criteria/1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectClass {
    Callback,
    Medical,
    Messaging,
    Model,
    Outreach,
    Quarantine,
    RemoteTool,
    Shipping,
    Url,
}

impl EffectClass {
    pub const ALL: [Self; 9] = [
        Self::Callback,
        Self::Medical,
        Self::Messaging,
        Self::Model,
        Self::Outreach,
        Self::Quarantine,
        Self::RemoteTool,
        Self::Shipping,
        Self::Url,
    ];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
#[error("live effects are denied by the qualification authority")]
pub struct EffectDenied;

/// Executable qualification authority that denies before invoking any effect transport.
#[derive(Clone, Copy, Debug, Default)]
pub struct DenyEffectBroker;

impl DenyEffectBroker {
    /// Rejects a classified effect without evaluating its transport operation.
    ///
    /// # Errors
    /// Always returns [`EffectDenied`]; qualification grants no effect authority.
    pub fn attempt<T>(
        self,
        _class: EffectClass,
        _transport: impl FnOnce() -> T,
    ) -> Result<T, EffectDenied> {
        Err(EffectDenied)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptanceCriterion {
    pub evaluator: String,
    pub id: String,
    pub plane: AcceptancePlane,
    pub required_evidence: Vec<String>,
    pub statement: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AcceptancePlane {
    Retained,
    Qualification,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CriteriaRegistry {
    criteria: Vec<AcceptanceCriterion>,
    schema_version: String,
}

#[must_use]
pub fn criteria_evidence_digest(label: &str, bytes: &[u8]) -> String {
    hash(label, &[bytes])
}

/// Loads and verifies the repository-owned canonical criterion registry.
///
/// # Errors
/// Returns [`ReplayError::Malformed`] if the embedded registry is not the exact
/// closed, canonical 40-criterion contract.
pub fn canonical_criteria() -> Result<Vec<AcceptanceCriterion>, ReplayError> {
    let bytes = include_bytes!("../acceptance/lifeline-criteria.json");
    let registry: CriteriaRegistry =
        serde_json::from_slice(bytes).map_err(|_| ReplayError::Malformed)?;
    if registry.schema_version != CRITERIA_SCHEMA_VERSION
        || registry.criteria.len() != 40
        || canonical(&serde_json::to_value(&registry).map_err(|_| ReplayError::Malformed)?)?
            != bytes
    {
        return Err(ReplayError::Malformed);
    }
    for (index, criterion) in registry.criteria.iter().enumerate() {
        let expected = format!("m3-{}-ac{}", 20 + index / 4, 1 + index % 4);
        if criterion.id != expected
            || criterion.statement.is_empty()
            || criterion.evaluator.is_empty()
            || criterion.required_evidence.is_empty()
        {
            return Err(ReplayError::Malformed);
        }
    }
    Ok(registry.criteria)
}

pub const SCORECARD_SCHEMA_VERSION: &str = "operational-lifeline-acceptance-scorecard/1";
pub const RECEIPT_SCHEMA_VERSION: &str = "operational-lifeline-acceptance-receipt/1";
pub const QUALIFICATION_SCHEMA_VERSION: &str = "operational-lifeline-qualification-probes/1";
const EVALUATOR_ID: &str = "smesh-operational-lifeline-acceptance";
const EVALUATOR_VERSION: &str = "1";
const RUN_ID: &str = "lifeline-operational-0047";
const SEED: &str = "47";
const GENERATED_ARTIFACTS: [&str; 18] = [
    "actors.json",
    "browser-bootstrap.json",
    "editorial.json",
    "package.jsonl",
    "public-manifest.json",
    "receipt.json",
    "restricted/canonical-capture.jsonl",
    "restricted/causal-source.jsonl",
    "restricted/criteria-evidence.json",
    "restricted/decision-receipt.json",
    "restricted/evidence-manifest.json",
    "restricted/privacy-manifest.json",
    "restricted/redaction-log.json",
    "restricted/replay-receipt.json",
    "restricted/review-packet.json",
    "restricted/review-receipt.json",
    "restricted/sealed-replay.jsonl",
    "restricted/source-facts.json",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AcceptanceStatus {
    Pass,
    Fail,
}

impl AcceptanceStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DiagnosticCode {
    MissingEvidence,
    ContradictoryEvidence,
    InvalidEvidence,
    IntegrityMismatch,
    ProfileMismatch,
    ReproducibilityMismatch,
    SensitiveMaterial,
    RealActionAuthority,
}

impl DiagnosticCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingEvidence => "missingEvidence",
            Self::ContradictoryEvidence => "contradictoryEvidence",
            Self::InvalidEvidence => "invalidEvidence",
            Self::IntegrityMismatch => "integrityMismatch",
            Self::ProfileMismatch => "profileMismatch",
            Self::ReproducibilityMismatch => "reproducibilityMismatch",
            Self::SensitiveMaterial => "sensitiveMaterial",
            Self::RealActionAuthority => "realActionAuthority",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceRef {
    pub artifact: String,
    pub artifact_digest: String,
    pub event_ids: Vec<String>,
    pub selector: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissingEvidence {
    pub artifact: String,
    pub expectation: String,
    pub selector: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptanceDiagnostic {
    pub code: DiagnosticCode,
    pub criterion_id: String,
    pub evidence_refs: Vec<EvidenceRef>,
    pub expected: String,
    pub fact_id: String,
    pub observed: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CriterionResult {
    pub criterion_id: String,
    pub diagnostics: Vec<AcceptanceDiagnostic>,
    pub evaluator: String,
    pub evidence: Vec<EvidenceRef>,
    pub missing_evidence: Vec<MissingEvidence>,
    pub status: AcceptanceStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptanceSummary {
    pub failed: String,
    pub overall_status: AcceptanceStatus,
    pub passed: String,
    pub total: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptanceScorecard {
    pub canonicalization: String,
    pub criteria_definition_digest: String,
    pub evaluator_id: String,
    pub evaluator_version: String,
    pub hash_framing: String,
    pub input_set_digest: String,
    pub mode: String,
    pub qualification_facts: BTreeMap<String, Value>,
    pub results: Vec<CriterionResult>,
    pub run_id: String,
    pub schema_version: String,
    pub seed: String,
    pub summary: AcceptanceSummary,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptanceReceipt {
    pub criteria_definition_digest: String,
    pub input_set_digest: String,
    pub mode: String,
    pub receipt_digest: String,
    pub run_id: String,
    pub schema_version: String,
    pub scorecard_byte_length: String,
    pub scorecard_digest: String,
    pub seed: String,
    pub status: AcceptanceStatus,
}

#[derive(Clone, Debug)]
pub struct AcceptanceArtifacts {
    pub scorecard: AcceptanceScorecard,
    pub scorecard_json: Vec<u8>,
    pub receipt: AcceptanceReceipt,
    pub receipt_json: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum AcceptanceInfrastructureError {
    #[error("acceptance input is malformed or exceeds its bound")]
    Malformed,
    #[error("acceptance input contains an unexpected artifact")]
    UnexpectedArtifact,
    #[error("acceptance I/O failed")]
    Io,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QualificationEvidence {
    probes: Vec<QualificationProbe>,
    run_id: String,
    schema_version: String,
    seed: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QualificationProbe {
    criterion_id: String,
    evidence: Vec<EvidenceRef>,
    facts: Value,
    status: AcceptanceStatus,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum AcceptanceVerificationError {
    #[error("acceptance report is malformed or noncanonical")]
    Malformed,
    #[error("acceptance report integrity check failed")]
    Integrity,
}

/// Verifies a canonical scorecard against its non-circular receipt.
///
/// # Errors
/// Returns an error for malformed, noncanonical, structurally inconsistent, or
/// integrity-mismatched acceptance reports.
#[allow(clippy::too_many_lines)]
pub fn verify_acceptance_receipt(
    scorecard_json: &[u8],
    receipt_json: &[u8],
) -> Result<AcceptanceReceipt, AcceptanceVerificationError> {
    if scorecard_json.is_empty()
        || receipt_json.is_empty()
        || scorecard_json.len() > 128 * 1024
        || receipt_json.len() > 128 * 1024
    {
        return Err(AcceptanceVerificationError::Malformed);
    }
    let scorecard_value: Value = serde_json::from_slice(scorecard_json)
        .map_err(|_| AcceptanceVerificationError::Malformed)?;
    let receipt_value: Value =
        serde_json::from_slice(receipt_json).map_err(|_| AcceptanceVerificationError::Malformed)?;
    if canonical(&scorecard_value).map_err(|_| AcceptanceVerificationError::Malformed)?
        != scorecard_json
        || canonical(&receipt_value).map_err(|_| AcceptanceVerificationError::Malformed)?
            != receipt_json
    {
        return Err(AcceptanceVerificationError::Malformed);
    }
    let scorecard: AcceptanceScorecard = serde_json::from_value(scorecard_value)
        .map_err(|_| AcceptanceVerificationError::Malformed)?;
    let receipt: AcceptanceReceipt = serde_json::from_value(receipt_value)
        .map_err(|_| AcceptanceVerificationError::Malformed)?;
    let expected_receipt_digest =
        receipt_digest(&receipt).map_err(|_| AcceptanceVerificationError::Malformed)?;
    let criteria = canonical_criteria().map_err(|_| AcceptanceVerificationError::Integrity)?;
    let expected_ids = criteria
        .iter()
        .map(|criterion| criterion.id.as_str())
        .collect::<Vec<_>>();
    let expected_evaluators = criteria
        .iter()
        .map(|criterion| criterion.evaluator.as_str())
        .collect::<Vec<_>>();
    let actual_ids = scorecard
        .results
        .iter()
        .map(|result| result.criterion_id.as_str())
        .collect::<Vec<_>>();
    let actual_evaluators = scorecard
        .results
        .iter()
        .map(|result| result.evaluator.as_str())
        .collect::<Vec<_>>();
    let passed = scorecard
        .results
        .iter()
        .filter(|result| result.status == AcceptanceStatus::Pass)
        .count();
    let failed = scorecard.results.len().saturating_sub(passed);
    let expected_overall = if failed == 0 {
        AcceptanceStatus::Pass
    } else {
        AcceptanceStatus::Fail
    };
    let criteria_digest = hash(
        "operational-lifeline-acceptance-criteria",
        &[include_bytes!("../acceptance/lifeline-criteria.json")],
    );
    let repository_artifacts = repository_owned_artifacts();
    let expected_input_set_digest = input_set_digest(&repository_artifacts)
        .map_err(|_| AcceptanceVerificationError::Integrity)?;
    let qualification_ids = criteria
        .iter()
        .filter(|criterion| criterion.plane == AcceptancePlane::Qualification)
        .map(|criterion| criterion.id.as_str())
        .collect::<BTreeSet<_>>();
    let qualification_fact_ids = scorecard
        .qualification_facts
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let exact_results = criteria
        .iter()
        .zip(&scorecard.results)
        .all(|(criterion, result)| {
            if result.status != AcceptanceStatus::Pass {
                return true;
            }
            let required = criterion
                .required_evidence
                .iter()
                .map(|requirement| requirement.split_once('#').unwrap_or((requirement, "")));
            match criterion.plane {
                AcceptancePlane::Qualification => {
                    let Some(facts) = scorecard.qualification_facts.get(&criterion.id) else {
                        return false;
                    };
                    let Ok(facts_bytes) = canonical(facts) else {
                        return false;
                    };
                    valid_qualification_facts(&criterion.id, facts)
                        && result.evidence
                            == [EvidenceRef {
                                artifact: format!("qualification-probe/{}", criterion.id),
                                artifact_digest: criteria_evidence_digest(
                                    "operational-lifeline-qualification-evidence",
                                    &facts_bytes,
                                ),
                                event_ids: vec![format!("probe-{}", criterion.id)],
                                selector: "/facts".into(),
                            }]
                }
                AcceptancePlane::Retained => {
                    let expected = required
                        .filter(|(artifact, _)| !artifact.starts_with("acceptance-"))
                        .map(|(artifact, selector)| {
                            repository_artifacts.get(artifact).map(|bytes| EvidenceRef {
                                artifact: artifact.into(),
                                artifact_digest: hash(
                                    "operational-lifeline-acceptance-artifact",
                                    &[bytes],
                                ),
                                event_ids: Vec::new(),
                                selector: selector.into(),
                            })
                        })
                        .collect::<Option<Vec<_>>>();
                    expected.as_ref() == Some(&result.evidence)
                        && evaluate_retained(
                            &criterion.id,
                            &criterion.evaluator,
                            &repository_artifacts,
                        )
                        .is_ok()
                }
            }
        });
    if scorecard.schema_version != SCORECARD_SCHEMA_VERSION
        || receipt.schema_version != RECEIPT_SCHEMA_VERSION
        || scorecard.evaluator_id != EVALUATOR_ID
        || scorecard.evaluator_version != EVALUATOR_VERSION
        || scorecard.canonicalization != crate::CANONICALIZATION
        || scorecard.hash_framing != "SMESH-A2A-length-prefixed-v1"
        || scorecard.mode != "operational"
        || receipt.mode != "operational"
        || receipt.receipt_digest != expected_receipt_digest
        || scorecard.run_id != RUN_ID
        || receipt.run_id != RUN_ID
        || scorecard.seed != SEED
        || receipt.seed != SEED
        || actual_ids != expected_ids
        || actual_evaluators != expected_evaluators
        || scorecard.summary.total != "40"
        || scorecard.summary.passed != passed.to_string()
        || scorecard.summary.failed != failed.to_string()
        || scorecard.summary.overall_status != expected_overall
        || receipt.status != expected_overall
        || scorecard.criteria_definition_digest != criteria_digest
        || receipt.criteria_definition_digest != criteria_digest
        || receipt.input_set_digest != scorecard.input_set_digest
        || scorecard.input_set_digest != expected_input_set_digest
        || qualification_fact_ids != qualification_ids
        || !exact_results
        || receipt.scorecard_byte_length != scorecard_json.len().to_string()
        || receipt.scorecard_digest
            != hash(
                "operational-lifeline-acceptance-scorecard",
                &[scorecard_json],
            )
        || scorecard.results.iter().any(|result| {
            result
                .evidence
                .iter()
                .any(|reference| !valid_evidence_ref(reference))
                || result.status == AcceptanceStatus::Pass
                    && (!result.diagnostics.is_empty() || !result.missing_evidence.is_empty())
                || result.status == AcceptanceStatus::Fail && result.diagnostics.is_empty()
        })
    {
        return Err(AcceptanceVerificationError::Integrity);
    }
    Ok(receipt)
}

/// Verifies an offline report directory containing exactly the canonical scorecard and receipt.
///
/// # Errors
/// Returns an error for symlinks, missing/extra files, size violations, malformed bytes, or
/// inconsistent integrity/status bindings.
pub fn verify_acceptance_report(
    report: &Path,
) -> Result<AcceptanceReceipt, AcceptanceVerificationError> {
    let metadata =
        std::fs::symlink_metadata(report).map_err(|_| AcceptanceVerificationError::Malformed)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(AcceptanceVerificationError::Malformed);
    }
    let mut names = Vec::new();
    let mut total_size = 0_u64;
    for entry in std::fs::read_dir(report).map_err(|_| AcceptanceVerificationError::Malformed)? {
        let entry = entry.map_err(|_| AcceptanceVerificationError::Malformed)?;
        let file_type = entry
            .file_type()
            .map_err(|_| AcceptanceVerificationError::Malformed)?;
        if !file_type.is_file() || file_type.is_symlink() {
            return Err(AcceptanceVerificationError::Malformed);
        }
        let size = entry
            .metadata()
            .map_err(|_| AcceptanceVerificationError::Malformed)?
            .len();
        if size > 128 * 1024 {
            return Err(AcceptanceVerificationError::Malformed);
        }
        total_size = total_size.saturating_add(size);
        names.push(
            entry
                .file_name()
                .into_string()
                .map_err(|_| AcceptanceVerificationError::Malformed)?,
        );
    }
    names.sort();
    if names != ["acceptance-receipt.json", "acceptance-scorecard.json"] {
        return Err(AcceptanceVerificationError::Malformed);
    }
    if total_size > 256 * 1024 {
        return Err(AcceptanceVerificationError::Malformed);
    }
    let scorecard = std::fs::read(report.join("acceptance-scorecard.json"))
        .map_err(|_| AcceptanceVerificationError::Malformed)?;
    let receipt = std::fs::read(report.join("acceptance-receipt.json"))
        .map_err(|_| AcceptanceVerificationError::Malformed)?;
    verify_acceptance_receipt(&scorecard, &receipt)
}

/// Evaluates the retained package and bounded qualification evidence.
///
/// # Errors
/// Returns an infrastructure error for malformed/noncanonical input, package
/// I/O failures, or artifacts outside the closed operational allowlist.
#[allow(clippy::too_many_lines)]
pub fn evaluate_operational_lifeline(
    package: &Path,
    qualification_json: &[u8],
) -> Result<AcceptanceArtifacts, AcceptanceInfrastructureError> {
    if qualification_json.len() > 128 * 1024 {
        return Err(AcceptanceInfrastructureError::Malformed);
    }
    let qualification_value: Value = serde_json::from_slice(qualification_json)
        .map_err(|_| AcceptanceInfrastructureError::Malformed)?;
    if canonical(&qualification_value).map_err(|_| AcceptanceInfrastructureError::Malformed)?
        != qualification_json
    {
        return Err(AcceptanceInfrastructureError::Malformed);
    }
    let qualification: QualificationEvidence = serde_json::from_value(qualification_value)
        .map_err(|_| AcceptanceInfrastructureError::Malformed)?;
    if qualification.schema_version != QUALIFICATION_SCHEMA_VERSION
        || qualification.run_id != RUN_ID
        || qualification.seed != SEED
    {
        return Err(AcceptanceInfrastructureError::Malformed);
    }
    let criteria = canonical_criteria().map_err(|_| AcceptanceInfrastructureError::Malformed)?;
    let criterion_ids = criteria
        .iter()
        .map(|criterion| criterion.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut probes = BTreeMap::new();
    for mut probe in qualification.probes {
        if !criterion_ids.contains(probe.criterion_id.as_str())
            || criteria
                .iter()
                .find(|criterion| criterion.id == probe.criterion_id)
                .is_none_or(|criterion| criterion.plane != AcceptancePlane::Qualification)
            || probe.evidence.len() > 16
        {
            return Err(AcceptanceInfrastructureError::Malformed);
        }
        for reference in &mut probe.evidence {
            reference.event_ids.sort();
            if reference
                .event_ids
                .windows(2)
                .any(|pair| pair[0] == pair[1])
            {
                return Err(AcceptanceInfrastructureError::Malformed);
            }
        }
        probe.evidence.sort_by(|left, right| {
            (
                &left.artifact,
                &left.selector,
                &left.artifact_digest,
                &left.event_ids,
            )
                .cmp(&(
                    &right.artifact,
                    &right.selector,
                    &right.artifact_digest,
                    &right.event_ids,
                ))
        });
        if probe.evidence.windows(2).any(|pair| pair[0] == pair[1])
            || probes.insert(probe.criterion_id.clone(), probe).is_some()
        {
            return Err(AcceptanceInfrastructureError::Malformed);
        }
    }
    let mut package_artifacts = load_package(package)?;
    let criteria_bytes = include_bytes!("../acceptance/lifeline-criteria.json");
    package_artifacts.insert(
        "acceptance/lifeline-criteria.json".into(),
        criteria_bytes.to_vec(),
    );
    let criteria_digest = hash(
        "operational-lifeline-acceptance-criteria",
        &[criteria_bytes],
    );
    let production_input_set_digest = input_set_digest(&repository_owned_artifacts())?;
    let input_set_digest = input_set_digest(&package_artifacts)?;
    let qualification_facts = probes
        .iter()
        .map(|(id, probe)| (id.clone(), probe.facts.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut results = Vec::with_capacity(criteria.len());
    for criterion in criteria {
        let required = criterion
            .required_evidence
            .iter()
            .map(|requirement| requirement.split_once('#').unwrap_or((requirement, "")))
            .collect::<Vec<_>>();
        let mut evidence = Vec::new();
        let mut missing_evidence = Vec::new();
        let mut diagnostics = Vec::new();
        let status = match criterion.plane {
            AcceptancePlane::Qualification => match probes.remove(&criterion.id) {
                Some(probe)
                    if probe.status == AcceptanceStatus::Pass
                        && probe.evidence.len() == 1
                        && probe.evidence[0].artifact
                            == format!("qualification-probe/{}", criterion.id)
                        && probe.evidence[0].selector == "/facts"
                        && probe.evidence[0].event_ids == [format!("probe-{}", criterion.id)]
                        && valid_qualification_facts(&criterion.id, &probe.facts)
                        && canonical(&probe.facts).is_ok_and(|facts| {
                            probe.evidence[0].artifact_digest
                                == criteria_evidence_digest(
                                    "operational-lifeline-qualification-evidence",
                                    &facts,
                                )
                        }) =>
                {
                    if probe.evidence.iter().all(valid_evidence_ref) {
                        evidence = probe.evidence;
                        AcceptanceStatus::Pass
                    } else {
                        diagnostics.push(diagnostic(
                            DiagnosticCode::InvalidEvidence,
                            &criterion.id,
                            "qualificationEvidence",
                            "closed bounded evidence references",
                            vec!["invalid".into()],
                            Vec::new(),
                        ));
                        AcceptanceStatus::Fail
                    }
                }
                Some(probe) => {
                    evidence = probe.evidence;
                    diagnostics.push(diagnostic(
                        DiagnosticCode::ContradictoryEvidence,
                        &criterion.id,
                        "qualificationProbe",
                        "pass",
                        vec!["fail".into()],
                        evidence.clone(),
                    ));
                    AcceptanceStatus::Fail
                }
                None => {
                    let (artifact, selector) = required[0];
                    missing_evidence.push(MissingEvidence {
                        artifact: artifact.into(),
                        expectation: "explicit passing operational qualification probe".into(),
                        selector: selector.into(),
                    });
                    diagnostics.push(diagnostic(
                        DiagnosticCode::MissingEvidence,
                        &criterion.id,
                        "qualificationProbe",
                        "present",
                        vec!["missing".into()],
                        Vec::new(),
                    ));
                    AcceptanceStatus::Fail
                }
            },
            AcceptancePlane::Retained => {
                for (artifact, selector) in required {
                    if artifact.starts_with("acceptance-") {
                        continue;
                    }
                    if let Some(bytes) = package_artifacts.get(artifact) {
                        evidence.push(EvidenceRef {
                            artifact: artifact.into(),
                            artifact_digest: hash(
                                "operational-lifeline-acceptance-artifact",
                                &[bytes],
                            ),
                            event_ids: Vec::new(),
                            selector: selector.into(),
                        });
                    } else {
                        missing_evidence.push(MissingEvidence {
                            artifact: artifact.into(),
                            expectation: "required retained operational artifact".into(),
                            selector: selector.into(),
                        });
                    }
                }
                if missing_evidence.is_empty() {
                    match evaluate_retained(&criterion.id, &criterion.evaluator, &package_artifacts)
                    {
                        Ok(()) if input_set_digest == production_input_set_digest => {
                            AcceptanceStatus::Pass
                        }
                        Ok(()) => {
                            diagnostics.push(diagnostic(
                                DiagnosticCode::ProfileMismatch,
                                &criterion.id,
                                "productionInputSet",
                                "repository-owned operational profile",
                                vec!["substituted".into()],
                                evidence.clone(),
                            ));
                            AcceptanceStatus::Fail
                        }
                        Err(failure) => {
                            diagnostics.push(diagnostic(
                                failure.code,
                                &criterion.id,
                                failure.fact_id,
                                failure.expected,
                                failure.observed,
                                evidence.clone(),
                            ));
                            AcceptanceStatus::Fail
                        }
                    }
                } else {
                    diagnostics.push(diagnostic(
                        DiagnosticCode::MissingEvidence,
                        &criterion.id,
                        "retainedArtifact",
                        "present",
                        vec!["missing".into()],
                        evidence.clone(),
                    ));
                    AcceptanceStatus::Fail
                }
            }
        };
        results.push(CriterionResult {
            criterion_id: criterion.id,
            diagnostics,
            evaluator: criterion.evaluator,
            evidence,
            missing_evidence,
            status,
        });
    }
    let passed = results
        .iter()
        .filter(|result| result.status == AcceptanceStatus::Pass)
        .count();
    let failed = results.len() - passed;
    let overall_status = if failed == 0 {
        AcceptanceStatus::Pass
    } else {
        AcceptanceStatus::Fail
    };
    let scorecard = AcceptanceScorecard {
        canonicalization: crate::CANONICALIZATION.into(),
        criteria_definition_digest: criteria_digest.clone(),
        evaluator_id: EVALUATOR_ID.into(),
        evaluator_version: EVALUATOR_VERSION.into(),
        hash_framing: "SMESH-A2A-length-prefixed-v1".into(),
        input_set_digest: input_set_digest.clone(),
        mode: "operational".into(),
        qualification_facts,
        results,
        run_id: RUN_ID.into(),
        schema_version: SCORECARD_SCHEMA_VERSION.into(),
        seed: SEED.into(),
        summary: AcceptanceSummary {
            failed: failed.to_string(),
            overall_status,
            passed: passed.to_string(),
            total: "40".into(),
        },
    };
    let scorecard_json = canonical(
        &serde_json::to_value(&scorecard).map_err(|_| AcceptanceInfrastructureError::Malformed)?,
    )
    .map_err(|_| AcceptanceInfrastructureError::Malformed)?;
    let mut receipt = AcceptanceReceipt {
        criteria_definition_digest: criteria_digest,
        input_set_digest,
        mode: "operational".into(),
        receipt_digest: String::new(),
        run_id: RUN_ID.into(),
        schema_version: RECEIPT_SCHEMA_VERSION.into(),
        scorecard_byte_length: scorecard_json.len().to_string(),
        scorecard_digest: hash(
            "operational-lifeline-acceptance-scorecard",
            &[&scorecard_json],
        ),
        seed: SEED.into(),
        status: overall_status,
    };
    receipt.receipt_digest =
        receipt_digest(&receipt).map_err(|_| AcceptanceInfrastructureError::Malformed)?;
    let receipt_json = canonical(
        &serde_json::to_value(&receipt).map_err(|_| AcceptanceInfrastructureError::Malformed)?,
    )
    .map_err(|_| AcceptanceInfrastructureError::Malformed)?;
    Ok(AcceptanceArtifacts {
        scorecard,
        scorecard_json,
        receipt,
        receipt_json,
    })
}

fn receipt_digest(receipt: &AcceptanceReceipt) -> Result<String, ReplayError> {
    let mut value = serde_json::to_value(receipt).map_err(|_| ReplayError::Malformed)?;
    value
        .as_object_mut()
        .ok_or(ReplayError::Malformed)?
        .remove("receiptDigest");
    Ok(hash(
        "operational-lifeline-acceptance-receipt",
        &[&canonical(&value)?],
    ))
}

#[allow(clippy::too_many_lines)] // Closed per-criterion schemas stay contiguous for auditability.
fn valid_qualification_facts(criterion_id: &str, facts: &Value) -> bool {
    let exact = |expected: &[&str]| exact_value_keys(facts, expected).is_ok();
    match criterion_id {
        "m3-20-ac4" => {
            exact(&[
                "attemptKinds",
                "blockedAttemptCount",
                "bounded",
                "effectBoundaryDenyByDefault",
                "effectClassesAudited",
                "listeners",
                "loopbackOnly",
                "shutdownReaped",
                "successfulRealActions",
            ]) && facts
                == &json!({
                    "attemptKinds":["liveEffect"],
                    "blockedAttemptCount":"9","bounded":true,"effectBoundaryDenyByDefault":true,
                    "effectClassesAudited":["callback","medical","messaging","model","outreach","quarantine","remoteTool","shipping","url"],"listeners":"6","loopbackOnly":true,
                    "shutdownReaped":true,"successfulRealActions":"0"
                })
        }
        "m3-23-ac2" => {
            exact(&[
                "eventCount",
                "interactionBound",
                "parentBound",
                "rawPayloadRetained",
            ]) && facts
                == &json!({"eventCount":"2","interactionBound":true,"parentBound":true,"rawPayloadRetained":false})
        }
        "m3-23-ac3" => {
            exact(&[
                "captureGapRecorded",
                "missingParentRecorded",
                "strictTypedRejection",
            ]) && facts
                == &json!({"captureGapRecorded":true,"missingParentRecorded":true,"strictTypedRejection":true})
        }
        "m3-24-ac1" => {
            exact(&["byteIdentical", "orders"])
                && facts == &json!({"byteIdentical":true,"orders":"2"})
        }
        "m3-24-ac3" => {
            exact(&[
                "attackerControlledChainRebound",
                "derivedReceiptChanged",
                "derivedSealChanged",
                "originalReceiptAndPinRejected",
                "originalReceiptRejected",
                "originalVerified",
                "structurallyValidTamper",
                "tamperedReplayVerified",
            ]) && facts
                == &json!({"attackerControlledChainRebound":true,"derivedReceiptChanged":true,"derivedSealChanged":true,"originalReceiptAndPinRejected":true,"originalReceiptRejected":true,"originalVerified":true,"structurallyValidTamper":true,"tamperedReplayVerified":true})
        }
        "m3-25-ac2" => {
            exact(&[
                "allPublicSurfacesScanned",
                "canariesAbsent",
                "classesPlanted",
                "secretDropped",
                "surfaceCount",
            ]) && facts
                == &json!({"allPublicSurfacesScanned":true,"canariesAbsent":true,"classesPlanted":"3","secretDropped":true,"surfaceCount":"4"})
        }
        "m3-25-ac3" => {
            exact(&[
                "actionLogIdentical",
                "changedInputChangedOutput",
                "equivalentInputsCompared",
                "publicBytesIdentical",
            ]) && facts
                == &json!({"actionLogIdentical":true,"changedInputChangedOutput":true,"equivalentInputsCompared":true,"publicBytesIdentical":true})
        }
        "m3-27-ac3" => {
            exact(&["appendOnly", "historyLength", "receiptChainBound"])
                && facts == &json!({"appendOnly":true,"historyLength":"2","receiptChainBound":true})
        }
        "m3-27-ac4" => {
            exact(&[
                "authorizationAuditUnchanged",
                "authorizationToLedgerAttempt",
                "historyUnchanged",
                "principalIdentityBound",
                "principalRejected",
                "receiptAbsent",
                "stateUnchanged",
            ]) && facts
                == &json!({"authorizationAuditUnchanged":true,"authorizationToLedgerAttempt":true,"historyUnchanged":true,"principalIdentityBound":true,"principalRejected":true,"receiptAbsent":true,"stateUnchanged":true})
        }
        "m3-28-ac3" => {
            exact(&[
                "attackerDigestsRebound",
                "eventSemanticRejection",
                "partialStatePublished",
                "structurallyValidEvent",
            ]) && facts
                == &json!({"attackerDigestsRebound":true,"eventSemanticRejection":true,"partialStatePublished":false,"structurallyValidEvent":true})
        }
        "m3-28-ac4" => {
            let expected_paths = json!([
                "/fixtures/operational-lifeline-v1/actors.json",
                "/fixtures/operational-lifeline-v1/browser-bootstrap.json",
                "/fixtures/operational-lifeline-v1/editorial.json",
                "/fixtures/operational-lifeline-v1/package.jsonl",
                "/fixtures/operational-lifeline-v1/receipt.json",
                "/operational-app.mjs",
                "/operational-observatory.mjs",
                "/operational.css",
                "/operational.html",
                "/vendor/three.module.min.js"
            ]);
            exact(&[
                "attemptKinds",
                "offlineRendered",
                "requestPaths",
                "sameOriginOnly",
                "stateDigest",
                "syntheticCompleteInputSet",
                "syntheticRejected",
                "syntheticSemanticRejected",
            ]) && facts["attemptKinds"] == json!(["browserExternalFetch"])
                && facts["offlineRendered"] == true
                && facts["sameOriginOnly"] == true
                && facts["syntheticCompleteInputSet"] == true
                && facts["syntheticRejected"] == true
                && facts["syntheticSemanticRejected"] == true
                && facts["requestPaths"] == expected_paths
                && valid_digest_value(&facts["stateDigest"])
        }
        "m3-29-ac2" => {
            exact(&[
                "allDiagnosticFieldsInspected",
                "criterionNamed",
                "expectationNamed",
                "rawValuesAbsent",
                "selectorNamed",
            ]) && facts
                == &json!({"allDiagnosticFieldsInspected":true,"criterionNamed":true,"expectationNamed":true,"rawValuesAbsent":true,"selectorNamed":true})
        }
        "m3-29-ac3" => {
            exact(&["artifactCount", "byteIdentical", "seed"])
                && facts == &json!({"artifactCount":"18","byteIdentical":true,"seed":"47"})
        }
        "m3-29-ac4" => {
            exact(&[
                "browserSyntheticRejected",
                "completeArtifactSet",
                "eventCount",
                "profileMismatch",
                "rustSyntheticRejected",
                "semanticProfileReached",
            ]) && facts
                == &json!({"browserSyntheticRejected":true,"completeArtifactSet":true,"eventCount":"46","profileMismatch":true,"rustSyntheticRejected":true,"semanticProfileReached":true})
        }
        _ => false,
    }
}

struct RetainedFailure {
    code: DiagnosticCode,
    fact_id: &'static str,
    expected: &'static str,
    observed: Vec<String>,
}

#[allow(clippy::too_many_lines)]
fn evaluate_retained(
    criterion_id: &str,
    evaluator: &str,
    artifacts: &BTreeMap<String, Vec<u8>>,
) -> Result<(), RetainedFailure> {
    const CLOSED_EVALUATORS: [&str; 15] = [
        "acceptance-diagnostics-v1",
        "acceptance-links-v1",
        "capture-completeness-v1",
        "failure-facts-v1",
        "privacy-manifest-v1",
        "projection-integrity-v1",
        "projection-links-v1",
        "public-safety-v1",
        "ratification-chain-v1",
        "replay-integrity-v1",
        "replay-offline-v1",
        "source-concurrency-v1",
        "source-failure-v1",
        "source-identity-v1",
        "source-routing-v1",
    ];
    const TEAM_EVALUATORS: [&str; 4] = [
        "team-backoff-v1",
        "team-claims-v1",
        "team-decay-v1",
        "team-isolation-v1",
    ];
    const TOPOLOGY_EVALUATORS: [&str; 3] = [
        "topology-conformance-v1",
        "topology-resolution-v1",
        "topology-safety-v1",
    ];
    if !CLOSED_EVALUATORS.contains(&evaluator)
        && !TEAM_EVALUATORS.contains(&evaluator)
        && !TOPOLOGY_EVALUATORS.contains(&evaluator)
    {
        return Err(RetainedFailure {
            code: DiagnosticCode::InvalidEvidence,
            fact_id: "evaluator",
            expected: "registered evaluator",
            observed: vec!["unknown".into()],
        });
    }
    if ["replay-integrity-v1", "replay-offline-v1"].contains(&evaluator) {
        let replay = artifacts
            .get("restricted/sealed-replay.jsonl")
            .ok_or_else(invalid_artifact)?;
        let verified = crate::verify_sealed_replay(replay).map_err(|_| invalid_artifact())?;
        let retained = artifact_json(artifacts, "restricted/replay-receipt.json")?;
        let verified = serde_json::to_value(verified).map_err(|_| invalid_artifact())?;
        if verified != retained || retained["decisionMode"] != "recordedOnly" {
            return Err(integrity_failure("sealedReplay"));
        }
    }
    if ["projection-integrity-v1", "projection-links-v1"].contains(&evaluator) {
        let package = artifacts
            .get("package.jsonl")
            .ok_or_else(invalid_artifact)?;
        let receipt = artifacts.get("receipt.json").ok_or_else(invalid_artifact)?;
        let receipt_value = artifact_json(artifacts, "receipt.json")?;
        let input_digest = receipt_value["inputDigest"]
            .as_str()
            .ok_or_else(invalid_artifact)?;
        crate::verify_operational_projection(package, receipt, input_digest)
            .map_err(|_| integrity_failure("operationalProjection"))?;
    }
    if evaluator == "capture-completeness-v1" {
        let evidence = artifact_json(artifacts, "restricted/criteria-evidence.json")?;
        validate_criteria_evidence(&evidence)?;
        let capture = artifacts
            .get("restricted/canonical-capture.jsonl")
            .ok_or_else(invalid_artifact)?;
        let event_count = canonical_jsonl_record_count(capture)?;
        if event_count != 46
            || evidence
                .pointer("/sourceRecords/failureRecordCount")
                .and_then(Value::as_str)
                != Some("19")
            || evidence
                .pointer("/sourceRecords/teamCount")
                .and_then(Value::as_str)
                != Some("5")
        {
            return Err(integrity_failure("captureCompleteness"));
        }
    }
    if evaluator == "privacy-manifest-v1" || evaluator == "public-safety-v1" {
        let public = artifact_value(artifacts, "public-manifest.json")?;
        let public_manifests = public["manifests"]
            .as_array()
            .ok_or_else(invalid_artifact)?;
        let restricted_valid = if evaluator == "privacy-manifest-v1" {
            let restricted = artifact_value(artifacts, "restricted/privacy-manifest.json")?;
            let restricted_manifests = restricted["manifests"]
                .as_array()
                .ok_or_else(invalid_artifact)?;
            restricted["schemaVersion"] == "operational-lifeline-restricted-manifests/1"
                && restricted_manifests.len() == 47
                && restricted_manifests.iter().all(|manifest| {
                    manifest["runId"] == RUN_ID
                        && manifest
                            .pointer("/sourceArtifact/classification")
                            .and_then(Value::as_str)
                            == Some("secret")
                        && manifest
                            .pointer("/storagePolicy/publicExportForbidden")
                            .and_then(Value::as_bool)
                            == Some(true)
                })
        } else {
            true
        };
        let valid = public["schemaVersion"] == "operational-lifeline-public-manifests/1"
            && public_manifests.len() == 47
            && public_manifests.iter().all(|manifest| {
                manifest["runId"] == RUN_ID
                    && manifest
                        .pointer("/artifact/classification")
                        .and_then(Value::as_str)
                        == Some("public")
            })
            && restricted_valid;
        if !valid {
            return Err(integrity_failure("privacyProjection"));
        }
        if evaluator == "public-safety-v1" {
            for path in [
                "package.jsonl",
                "actors.json",
                "editorial.json",
                "browser-bootstrap.json",
                "public-manifest.json",
            ] {
                let bytes = artifacts.get(path).ok_or_else(invalid_artifact)?;
                let lower = String::from_utf8_lossy(bytes).to_ascii_lowercase();
                if [
                    "authorization:",
                    "bearer ",
                    "credential",
                    "private until approval",
                    "http://127.0.0.1",
                ]
                .iter()
                .any(|forbidden| lower.contains(forbidden))
                {
                    return Err(RetainedFailure {
                        code: DiagnosticCode::SensitiveMaterial,
                        fact_id: "publicArtifact",
                        expected: "sanitized public projection",
                        observed: vec!["forbiddenMarker".into()],
                    });
                }
            }
        }
    }
    if evaluator == "ratification-chain-v1" {
        let packet = artifact_value(artifacts, "restricted/review-packet.json")?;
        let review = artifact_value(artifacts, "restricted/review-receipt.json")?;
        let decision = artifact_value(artifacts, "restricted/decision-receipt.json")?;
        if review["packetHash"] != packet["packetHash"]
            || decision["packetHash"] != packet["packetHash"]
            || decision["previousReceiptHash"] != review["receiptHash"]
            || decision["evidenceSnapshotHash"] != packet["evidenceSnapshotHash"]
            || decision["authorizationPolicyId"] != packet["authorizationPolicyId"]
            || review.pointer("/action/kind").and_then(Value::as_str) != Some("reviewAcknowledged")
            || decision.pointer("/action/kind").and_then(Value::as_str) != Some("decision")
            || decision.pointer("/action/decision").and_then(Value::as_str) != Some("approve")
        {
            return Err(integrity_failure("ratificationChain"));
        }
    }
    if TOPOLOGY_EVALUATORS.contains(&evaluator) {
        let manifest = artifact_json(artifacts, "restricted/evidence-manifest.json")?;
        let cards = manifest["agentCards"]
            .as_array()
            .ok_or_else(invalid_artifact)?;
        let expected_gateways = BTreeSet::from([
            "atlas-fallback",
            "atlas-primary",
            "harbor",
            "helix",
            "meridian",
            "sentinel",
        ]);
        let actual_gateways = cards
            .iter()
            .filter_map(|card| card["gatewayId"].as_str())
            .collect::<BTreeSet<_>>();
        let cards_valid = cards.len() == 6
            && actual_gateways == expected_gateways
            && cards.iter().all(|card| {
                card["sourceSchema"].as_str() == Some("lifeline-failure-scenario-run/1")
                    && card["providerOrganization"]
                        .as_str()
                        .is_some_and(|value| !value.is_empty())
                    && card["skillIds"]
                        .as_array()
                        .is_some_and(|items| items.len() == 1)
                    && card["interfaceProtocols"].as_array().is_some_and(|items| {
                        items
                            == &[
                                Value::String("JSONRPC".into()),
                                Value::String("HTTP+JSON".into()),
                            ]
                    })
            });
        let valid = manifest["schemaVersion"] == "operational-lifeline-evidence/1"
            && manifest["runId"] == RUN_ID
            && manifest["gatewayCount"] == "6"
            && cards_valid;
        if !valid {
            return Err(RetainedFailure {
                code: DiagnosticCode::ContradictoryEvidence,
                fact_id: "topologyEvidence",
                expected: "six closed validated loopback gateway card projections",
                observed: vec!["invalid".into()],
            });
        }
    }
    if [
        "source-concurrency-v1",
        "source-failure-v1",
        "source-identity-v1",
        "source-routing-v1",
        "failure-facts-v1",
    ]
    .contains(&evaluator)
    {
        let evidence = artifact_json(artifacts, "restricted/criteria-evidence.json")?;
        validate_criteria_evidence(&evidence)?;
        let scenario = &evidence["scenario"];
        let no_post_cancel_completion = if criterion_id == "m3-26-ac2" {
            let facts = artifact_value(artifacts, "restricted/source-facts.json")?;
            let entries = facts["entries"].as_array().ok_or_else(invalid_artifact)?;
            entries.iter().any(|entry| {
                entry["failureKind"] == "primary-final-reconciled" && entry["outcome"] == "canceled"
            }) && entries.iter().any(|entry| {
                entry["failureKind"] == "late-output-fenced" && entry["outcome"] == "fenced"
            }) && !entries
                .iter()
                .any(|entry| entry["failureKind"] == "primary-completed")
        } else {
            true
        };
        let valid = match criterion_id {
            "m3-21-ac1" => {
                scenario
                    .pointer("/concurrentInitialTasks/observed")
                    .and_then(Value::as_bool)
                    == Some(true)
            }
            "m3-21-ac2" => scenario["loopbackRoutingOnly"].as_bool() == Some(true),
            "m3-21-ac3" => scenario["failureRecovery"].as_bool() == Some(true),
            "m3-21-ac4" => {
                scenario
                    .pointer("/identityReconciliation/matched")
                    .and_then(Value::as_bool)
                    == Some(true)
                    && scenario.pointer("/identityReconciliation/sourceIdentitySetDigest")
                        == scenario.pointer("/identityReconciliation/captureIdentitySetDigest")
                    && scenario.pointer("/identityReconciliation/unavailableIds")
                        == Some(&Value::Null)
                    && scenario
                        .pointer("/identityReconciliation/sourceEventBindings")
                        .and_then(Value::as_array)
                        .is_some_and(|bindings| bindings.len() == 19)
            }
            "m3-26-ac1" => scenario["primaryFinalState"].as_str() == Some("canceled"),
            "m3-26-ac2" => no_post_cancel_completion,
            "m3-26-ac3" => ["distinctTaskId", "replacementBound", "sameRootContext"]
                .iter()
                .all(|field| {
                    scenario
                        .pointer(&format!("/fallbackIdentity/{field}"))
                        .and_then(Value::as_bool)
                        == Some(true)
                }),
            "m3-26-ac4" => scenario["rootContextRestarts"].as_str() == Some("0"),
            _ => true,
        };
        if !valid {
            let observed = if criterion_id == "m3-26-ac4"
                && scenario["rootContextRestarts"].as_str() == Some("1")
            {
                vec!["1".into()]
            } else {
                vec!["false".into()]
            };
            return Err(RetainedFailure {
                code: DiagnosticCode::ContradictoryEvidence,
                fact_id: match criterion_id {
                    "m3-21-ac1" => "concurrentInitialTasks",
                    "m3-21-ac2" => "loopbackRoutingOnly",
                    "m3-21-ac3" => "failureRecovery",
                    "m3-21-ac4" => "sourceIdentityReconciliation",
                    "m3-26-ac1" => "primaryFinalState",
                    "m3-26-ac2" => "postCancelCompletion",
                    "m3-26-ac3" => "fallbackIdentity",
                    _ => "rootContextRestarts",
                },
                expected: "verified retained operational fact",
                observed,
            });
        }
    }
    if TEAM_EVALUATORS.contains(&evaluator) {
        let evidence = artifact_json(artifacts, "restricted/criteria-evidence.json")?;
        validate_criteria_evidence(&evidence)?;
        let teams = evidence["teams"].as_array().ok_or_else(invalid_artifact)?;
        let valid = match criterion_id {
            "m3-22-ac1" => teams.iter().all(|team| {
                team.pointer("/claim/observed").and_then(Value::as_bool) == Some(true)
                    && team
                        .pointer("/reinforcement/observed")
                        .and_then(Value::as_bool)
                        == Some(true)
                    && team
                        .pointer("/reinforcement/distinctAttesters")
                        .and_then(Value::as_bool)
                        == Some(true)
            }),
            "m3-22-ac2" => teams.iter().any(|team| {
                team.pointer("/backoff/observed").and_then(Value::as_bool) == Some(true)
                    && team
                        .pointer("/backoff/winnerScoreGreater")
                        .and_then(Value::as_bool)
                        == Some(true)
                    && team
                        .pointer("/backoff/losingRoleReinforced")
                        .and_then(Value::as_bool)
                        == Some(true)
            }),
            "m3-22-ac3" => teams.iter().any(|team| {
                [
                    "expiryTickObserved",
                    "hashReconciled",
                    "removedFromActive",
                    "retainedInHistory",
                    "runtimeHashesEmitted",
                ]
                .iter()
                .all(|field| {
                    team.pointer(&format!("/contradictionDecay/{field}"))
                        .and_then(Value::as_bool)
                        == Some(true)
                })
            }),
            "m3-22-ac4" => teams.iter().all(|team| {
                ["candidateBound", "organizationBound", "toolBound"]
                    .iter()
                    .all(|field| {
                        team.pointer(&format!("/isolation/{field}"))
                            .and_then(Value::as_bool)
                            == Some(true)
                    })
            }),
            _ => false,
        };
        if !valid {
            return Err(RetainedFailure {
                code: DiagnosticCode::ContradictoryEvidence,
                fact_id: match criterion_id {
                    "m3-22-ac1" => "teamClaimReinforcement",
                    "m3-22-ac2" => "teamBackoff",
                    "m3-22-ac3" => "teamContradictionDecay",
                    _ => "teamIsolation",
                },
                expected: "verified retained team fact",
                observed: vec!["false".into()],
            });
        }
    }
    Ok(())
}

fn canonical_jsonl_record_count(bytes: &[u8]) -> Result<usize, RetainedFailure> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid_artifact())?;
    if text.is_empty() {
        return Err(invalid_artifact());
    }
    let mut records = 0;
    for line in text.lines() {
        let value: Value = serde_json::from_str(line).map_err(|_| invalid_artifact())?;
        if value.get("event").is_some() {
            records += 1;
        }
    }
    Ok(records)
}

fn integrity_failure(fact_id: &'static str) -> RetainedFailure {
    RetainedFailure {
        code: DiagnosticCode::IntegrityMismatch,
        fact_id,
        expected: "verified retained artifact",
        observed: vec!["mismatch".into()],
    }
}

fn artifact_value(
    artifacts: &BTreeMap<String, Vec<u8>>,
    path: &str,
) -> Result<Value, RetainedFailure> {
    let bytes = artifacts.get(path).ok_or_else(invalid_artifact)?;
    serde_json::from_slice(bytes).map_err(|_| invalid_artifact())
}

fn artifact_json(
    artifacts: &BTreeMap<String, Vec<u8>>,
    path: &str,
) -> Result<Value, RetainedFailure> {
    let bytes = artifacts.get(path).ok_or_else(invalid_artifact)?;
    let value: Value = serde_json::from_slice(bytes).map_err(|_| invalid_artifact())?;
    if canonical(&value).map_err(|_| invalid_artifact())? != *bytes {
        return Err(invalid_artifact());
    }
    Ok(value)
}

#[allow(clippy::too_many_lines)]
fn validate_criteria_evidence(value: &Value) -> Result<(), RetainedFailure> {
    exact_value_keys(
        value,
        &[
            "runId",
            "scenario",
            "schemaVersion",
            "seed",
            "sourceRecords",
            "teams",
        ],
    )?;
    if value["schemaVersion"] != "operational-lifeline-criteria-evidence/1"
        || value["runId"] != RUN_ID
        || value["seed"] != SEED
    {
        return Err(invalid_artifact());
    }
    exact_value_keys(
        &value["scenario"],
        &[
            "concurrentInitialTasks",
            "failureRecovery",
            "fallbackIdentity",
            "identityReconciliation",
            "loopbackRoutingOnly",
            "primaryFinalState",
            "rootContextRestarts",
        ],
    )?;
    exact_value_keys(
        &value["scenario"]["concurrentInitialTasks"],
        &["observed", "sourceRecordDigest"],
    )?;
    exact_value_keys(
        &value["scenario"]["fallbackIdentity"],
        &["distinctTaskId", "replacementBound", "sameRootContext"],
    )?;
    exact_value_keys(
        &value["scenario"]["identityReconciliation"],
        &[
            "captureIdentitySetDigest",
            "matched",
            "sourceEventBindings",
            "sourceIdentitySetDigest",
            "unavailableIds",
        ],
    )?;
    let identity = &value["scenario"]["identityReconciliation"];
    if !valid_digest_value(&identity["captureIdentitySetDigest"])
        || !valid_digest_value(&identity["sourceIdentitySetDigest"])
        || !identity["unavailableIds"].is_null()
    {
        return Err(invalid_artifact());
    }
    let bindings = identity["sourceEventBindings"]
        .as_array()
        .ok_or_else(invalid_artifact)?;
    if bindings.len() != 19
        || bindings.iter().any(|binding| {
            exact_value_keys(binding, &["captureEventId", "sourceRecordDigest"]).is_err()
                || !valid_digest_value(&binding["captureEventId"])
                || !valid_digest_value(&binding["sourceRecordDigest"])
        })
    {
        return Err(invalid_artifact());
    }
    exact_value_keys(
        &value["sourceRecords"],
        &["failureRecordCount", "failureSourceDigest", "teamCount"],
    )?;
    let teams = value["teams"].as_array().ok_or_else(invalid_artifact)?;
    if teams.len() != 5 {
        return Err(invalid_artifact());
    }
    let mut ids = BTreeSet::new();
    for team in teams {
        exact_value_keys(
            team,
            &[
                "backoff",
                "claim",
                "contradictionDecay",
                "isolation",
                "reinforcement",
                "runtimeJournalDigest",
                "sourceJournalDigest",
                "sourceRecordDigests",
                "teamId",
            ],
        )?;
        exact_value_keys(
            &team["backoff"],
            &["losingRoleReinforced", "observed", "winnerScoreGreater"],
        )?;
        exact_value_keys(&team["claim"], &["observed", "recordCount"])?;
        exact_value_keys(
            &team["contradictionDecay"],
            &[
                "expiryTickObserved",
                "hashReconciled",
                "removedFromActive",
                "retainedInHistory",
                "runtimeHashesEmitted",
            ],
        )?;
        exact_value_keys(
            &team["isolation"],
            &["candidateBound", "organizationBound", "toolBound"],
        )?;
        exact_value_keys(&team["reinforcement"], &["distinctAttesters", "observed"])?;
        exact_value_keys(
            &team["sourceRecordDigests"],
            &["backoff", "contradiction", "decay", "reinforcement"],
        )?;
        let id = team["teamId"].as_str().ok_or_else(invalid_artifact)?;
        if !ids.insert(id) || !["atlas", "harbor", "helix", "meridian", "sentinel"].contains(&id) {
            return Err(invalid_artifact());
        }
    }
    Ok(())
}

fn valid_digest_value(value: &Value) -> bool {
    value.as_str().is_some_and(|digest| {
        digest.len() == 71
            && digest.starts_with("sha256:")
            && digest[7..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn exact_value_keys(value: &Value, expected: &[&str]) -> Result<(), RetainedFailure> {
    let object = value.as_object().ok_or_else(invalid_artifact)?;
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return Err(invalid_artifact());
    }
    Ok(())
}

fn invalid_artifact() -> RetainedFailure {
    RetainedFailure {
        code: DiagnosticCode::InvalidEvidence,
        fact_id: "artifactSchema",
        expected: "closed canonical artifact",
        observed: vec!["invalid".into()],
    }
}

fn diagnostic(
    code: DiagnosticCode,
    criterion_id: &str,
    fact_id: &str,
    expected: &str,
    observed: Vec<String>,
    evidence_refs: Vec<EvidenceRef>,
) -> AcceptanceDiagnostic {
    AcceptanceDiagnostic {
        code,
        criterion_id: criterion_id.into(),
        evidence_refs,
        expected: expected.into(),
        fact_id: fact_id.into(),
        observed,
    }
}

fn valid_evidence_ref(reference: &EvidenceRef) -> bool {
    !reference.artifact.is_empty()
        && reference.artifact.len() <= 256
        && reference.selector.starts_with('/')
        && reference.selector.len() <= 512
        && reference.event_ids.len() <= 128
        && reference.artifact_digest.len() == 71
        && reference.artifact_digest.starts_with("sha256:")
        && reference.artifact_digest[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn repository_owned_artifacts() -> BTreeMap<String, Vec<u8>> {
    let mut artifacts = BTreeMap::new();
    macro_rules! retained {
        ($path:literal) => {
            artifacts.insert(
                $path.into(),
                include_bytes!(concat!("../demo/fixtures/operational-lifeline-v1/", $path))
                    .to_vec(),
            );
        };
    }
    retained!("actors.json");
    retained!("browser-bootstrap.json");
    retained!("editorial.json");
    retained!("package.jsonl");
    retained!("public-manifest.json");
    retained!("receipt.json");
    retained!("restricted/canonical-capture.jsonl");
    retained!("restricted/causal-source.jsonl");
    retained!("restricted/criteria-evidence.json");
    retained!("restricted/decision-receipt.json");
    retained!("restricted/evidence-manifest.json");
    retained!("restricted/privacy-manifest.json");
    retained!("restricted/redaction-log.json");
    retained!("restricted/replay-receipt.json");
    retained!("restricted/review-packet.json");
    retained!("restricted/review-receipt.json");
    retained!("restricted/sealed-replay.jsonl");
    retained!("restricted/source-facts.json");
    artifacts.insert(
        "acceptance/lifeline-criteria.json".into(),
        include_bytes!("../acceptance/lifeline-criteria.json").to_vec(),
    );
    artifacts
}

fn input_set_digest(
    artifacts: &BTreeMap<String, Vec<u8>>,
) -> Result<String, AcceptanceInfrastructureError> {
    let input_set = GENERATED_ARTIFACTS
        .iter()
        .filter_map(|path| {
            artifacts.get(*path).map(|bytes| {
                json!({
                    "byteLength": bytes.len().to_string(),
                    "digest": hash("operational-lifeline-acceptance-artifact", &[bytes]),
                    "path": path,
                })
            })
        })
        .collect::<Vec<_>>();
    let input_set_bytes = canonical(&Value::Array(input_set))
        .map_err(|_| AcceptanceInfrastructureError::Malformed)?;
    Ok(hash(
        "operational-lifeline-acceptance-input-set",
        &[&input_set_bytes],
    ))
}

fn load_package(
    package: &Path,
) -> Result<BTreeMap<String, Vec<u8>>, AcceptanceInfrastructureError> {
    let mut found = BTreeSet::new();
    for (directory, prefix) in [(package, ""), (&package.join("restricted"), "restricted/")] {
        let entries =
            std::fs::read_dir(directory).map_err(|_| AcceptanceInfrastructureError::Io)?;
        for entry in entries {
            let entry = entry.map_err(|_| AcceptanceInfrastructureError::Io)?;
            let file_type = entry
                .file_type()
                .map_err(|_| AcceptanceInfrastructureError::Io)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| AcceptanceInfrastructureError::UnexpectedArtifact)?;
            if prefix.is_empty() && name == "restricted" && file_type.is_dir() {
                continue;
            }
            if prefix.is_empty() && name == "README.md" && file_type.is_file() {
                continue;
            }
            if !file_type.is_file() {
                return Err(AcceptanceInfrastructureError::UnexpectedArtifact);
            }
            let path = format!("{prefix}{name}");
            if !GENERATED_ARTIFACTS.contains(&path.as_str()) || !found.insert(path) {
                return Err(AcceptanceInfrastructureError::UnexpectedArtifact);
            }
        }
    }
    let mut artifacts = BTreeMap::new();
    let mut total = 0_usize;
    for path in GENERATED_ARTIFACTS {
        let full = package.join(path);
        if !full.is_file() {
            continue;
        }
        let bytes = std::fs::read(full).map_err(|_| AcceptanceInfrastructureError::Io)?;
        total = total.saturating_add(bytes.len());
        if bytes.len() > 16 * 1024 * 1024 || total > 32 * 1024 * 1024 {
            return Err(AcceptanceInfrastructureError::Malformed);
        }
        artifacts.insert(path.into(), bytes);
    }
    Ok(artifacts)
}
