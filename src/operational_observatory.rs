use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

use crate::full_matrix_replay::{canonical, hash, valid_identifier, validate_digest};
use crate::{
    CaptureGapReason, CaptureKind, HybridLogicalClock, ProducerKind, ProjectionReceipt,
    ReplayError, verify_replay_receipt,
};

pub const OPERATIONAL_OBSERVATORY_SCHEMA_VERSION: &str = "operational-observatory/1";
pub const OPERATIONAL_ACTOR_MANIFEST_SCHEMA_VERSION: &str = "operational-observatory-actors/1";
pub const OPERATIONAL_EDITORIAL_OVERLAY_SCHEMA_VERSION: &str =
    "operational-observatory-editorial/1";
pub const OPERATIONAL_SOURCE_FACTS_SCHEMA_VERSION: &str = "operational-observatory-source-facts/1";
pub const OPERATIONAL_OBSERVATORY_PROJECTOR_ID: &str = "smesh-operational-observatory";
pub const OPERATIONAL_OBSERVATORY_PROJECTOR_VERSION: &str = "1";

const HARD_MAX_BYTES: usize = 16 * 1024 * 1024;
const HARD_MAX_LINE_BYTES: usize = 64 * 1024;
const HARD_MAX_EVENTS: usize = 100_000;
const HARD_MAX_ACTORS: usize = 1_024;
const HARD_MAX_SITES: usize = 1_024;
const HARD_MAX_TEXT_BYTES: usize = 4_096;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OperationalProjectionError {
    #[error("verified replay input is invalid")]
    Replay,
    #[error("operational projection input is malformed")]
    Malformed,
    #[error("operational projection schema is unsupported")]
    UnsupportedSchema,
    #[error("operational projection capacity is exhausted")]
    CapacityExhausted,
    #[error("operational projection contains a duplicate or conflicting identity")]
    DuplicateConflict,
    #[error("operational projection input order is noncanonical")]
    InvalidOrder,
    #[error("operational projection reference is missing or restricted")]
    InvalidReference,
}

impl From<ReplayError> for OperationalProjectionError {
    fn from(_: ReplayError) -> Self {
        Self::Replay
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationalProjectionLimits {
    pub max_output_bytes: usize,
    pub max_line_bytes: usize,
    pub max_events: usize,
    pub max_actors: usize,
    pub max_sites: usize,
    pub max_text_bytes: usize,
}

impl Default for OperationalProjectionLimits {
    fn default() -> Self {
        Self {
            max_output_bytes: HARD_MAX_BYTES,
            max_line_bytes: HARD_MAX_LINE_BYTES,
            max_events: HARD_MAX_EVENTS,
            max_actors: HARD_MAX_ACTORS,
            max_sites: HARD_MAX_SITES,
            max_text_bytes: HARD_MAX_TEXT_BYTES,
        }
    }
}

impl OperationalProjectionLimits {
    fn validate(self) -> Result<Self, OperationalProjectionError> {
        if self.max_output_bytes == 0
            || self.max_line_bytes == 0
            || self.max_events == 0
            || self.max_actors == 0
            || self.max_sites == 0
            || self.max_text_bytes == 0
            || self.max_output_bytes > HARD_MAX_BYTES
            || self.max_line_bytes > HARD_MAX_LINE_BYTES
            || self.max_events > HARD_MAX_EVENTS
            || self.max_actors > HARD_MAX_ACTORS
            || self.max_sites > HARD_MAX_SITES
            || self.max_text_bytes > HARD_MAX_TEXT_BYTES
        {
            return Err(OperationalProjectionError::CapacityExhausted);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OperationalVisibility {
    Visible,
    Restricted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationalSite {
    pub display_name: String,
    pub site_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationalProducer {
    pub id: String,
    pub instance_id: String,
    pub kind: ProducerKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationalActor {
    pub actor_id: String,
    pub display_name: String,
    pub producer: OperationalProducer,
    pub site_id: String,
    pub visibility: OperationalVisibility,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationalActorManifest {
    pub actors: Vec<OperationalActor>,
    pub schema_version: String,
    pub sites: Vec<OperationalSite>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EditorialCue {
    Clear,
    Focus,
    Follow,
    Hold,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EditorialEntry {
    pub cue: EditorialCue,
    pub event_id: String,
    pub narration: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationalEditorialOverlay {
    pub entries: Vec<EditorialEntry>,
    pub schema_version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationalFailureKind {
    SiblingSubmitted,
    PrimarySubmitted,
    PrimaryOutageObserved,
    PrimaryStreamFailed,
    CancelRequested,
    LateOutputFenced,
    InternalProcessorStopped,
    CancelConfirmed,
    SiblingCompleted,
    FallbackSelected,
    FallbackSubmitted,
    FallbackCompleted,
    ReviewCompleted,
    PrimaryFinalReconciled,
    ScenarioCompleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationalFailureOutcome {
    Submitted,
    Unavailable,
    Error,
    Requested,
    Fenced,
    CooperativeStop,
    Canceled,
    Completed,
    Selected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OperationalRestrictedField {
    SubjectId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OperationalRestrictionReason {
    SourceIdentifierUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationalFieldRestriction {
    pub field: OperationalRestrictedField,
    pub reason: OperationalRestrictionReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationalSourceFact {
    pub event_id: String,
    pub failure_kind: Option<OperationalFailureKind>,
    pub field_restrictions: Vec<OperationalFieldRestriction>,
    pub outcome: Option<OperationalFailureOutcome>,
    pub source_content_digest: String,
    pub source_schema_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationalSourceFactsManifest {
    pub entries: Vec<OperationalSourceFact>,
    pub schema_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationalProjection {
    package_jsonl: Vec<u8>,
    receipt: ProjectionReceipt,
    receipt_json: Vec<u8>,
    event_ranges: BTreeMap<String, (usize, usize)>,
}

impl OperationalProjection {
    #[must_use]
    pub fn package_jsonl(&self) -> &[u8] {
        &self.package_jsonl
    }

    #[must_use]
    pub fn receipt(&self) -> &ProjectionReceipt {
        &self.receipt
    }

    #[must_use]
    pub fn receipt_json(&self) -> &[u8] {
        &self.receipt_json
    }

    #[must_use]
    pub fn record_json(&self, event_id: &str) -> Option<&[u8]> {
        self.event_ranges
            .get(event_id)
            .map(|(start, end)| &self.package_jsonl[*start..*end])
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReplayContent {
    byte_length: String,
    digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReplayProducer {
    id: String,
    instance_id: String,
    kind: ProducerKind,
    source_sequence: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReplayCaptureEvent {
    content: ReplayContent,
    context_id: Option<String>,
    event_id: String,
    interaction_id: String,
    kind: CaptureKind,
    parent: Value,
    peer_id: String,
    producer: ReplayProducer,
    source_sequence: String,
    subject_id: Option<String>,
    task_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReplayCausal {
    event: ReplayCaptureEvent,
    hlc: HybridLogicalClock,
    lamport: String,
    producer_hash: String,
    producer_previous: Option<String>,
    recorded_decision: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReplayEventRecord {
    causal: ReplayCausal,
    merge_sequence: String,
    record_type: String,
}

fn canonical_input<T>(bytes: &[u8], max: usize) -> Result<(T, Vec<u8>), OperationalProjectionError>
where
    T: for<'de> Deserialize<'de>,
{
    if bytes.is_empty() || bytes.len() > max {
        return Err(OperationalProjectionError::CapacityExhausted);
    }
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| OperationalProjectionError::Malformed)?;
    let encoded = canonical(&value).map_err(|_| OperationalProjectionError::Malformed)?;
    if encoded != bytes {
        return Err(OperationalProjectionError::Malformed);
    }
    let parsed =
        serde_json::from_value(value).map_err(|_| OperationalProjectionError::Malformed)?;
    Ok((parsed, encoded))
}

fn valid_text(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .chars()
            .all(|character| !character.is_control() || matches!(character, '\n' | '\t'))
}

fn producer_key(producer: &OperationalProducer) -> (String, String, String) {
    (
        producer_kind_name(producer.kind).to_owned(),
        producer.id.clone(),
        producer.instance_id.clone(),
    )
}

fn producer_kind_name(kind: ProducerKind) -> &'static str {
    match kind {
        ProducerKind::A2a => "a2a",
        ProducerKind::Smesh => "smesh",
        ProducerKind::Tool => "tool",
        ProducerKind::Artifact => "artifact",
        ProducerKind::Human => "human",
    }
}

fn channel(kind: CaptureKind) -> &'static str {
    match kind {
        CaptureKind::A2aSend | CaptureKind::A2aReceive => "a2a",
        CaptureKind::SmeshSignalEmitted
        | CaptureKind::SmeshSignalSent
        | CaptureKind::SmeshSignalReinforced
        | CaptureKind::SmeshSignalReceived
        | CaptureKind::SmeshSignalExpired
        | CaptureKind::SmeshTickCompleted
        | CaptureKind::SmeshPeerConnected
        | CaptureKind::SmeshPeerDisconnected => "smesh",
        CaptureKind::ToolCall | CaptureKind::ToolResult | CaptureKind::ToolFailed => "tool",
        CaptureKind::ArtifactProduced | CaptureKind::ArtifactConsumed => "artifact",
        CaptureKind::HumanPrompt | CaptureKind::HumanDecision | CaptureKind::HumanFailed => "human",
    }
}

fn validate_manifest(
    manifest: &OperationalActorManifest,
    limits: OperationalProjectionLimits,
) -> Result<BTreeMap<(String, String, String), &OperationalActor>, OperationalProjectionError> {
    if manifest.schema_version != OPERATIONAL_ACTOR_MANIFEST_SCHEMA_VERSION {
        return Err(OperationalProjectionError::UnsupportedSchema);
    }
    if manifest.actors.is_empty()
        || manifest.actors.len() > limits.max_actors
        || manifest.sites.is_empty()
        || manifest.sites.len() > limits.max_sites
    {
        return Err(OperationalProjectionError::CapacityExhausted);
    }
    let mut sites = BTreeSet::new();
    let mut previous_site = None;
    for site in &manifest.sites {
        if !valid_identifier(&site.site_id)
            || !valid_text(&site.display_name, limits.max_text_bytes)
        {
            return Err(OperationalProjectionError::Malformed);
        }
        if previous_site
            .as_deref()
            .is_some_and(|previous| previous >= site.site_id.as_str())
        {
            return Err(if sites.contains(&site.site_id) {
                OperationalProjectionError::DuplicateConflict
            } else {
                OperationalProjectionError::InvalidOrder
            });
        }
        sites.insert(site.site_id.clone());
        previous_site = Some(site.site_id.clone());
    }
    let mut actors = BTreeMap::new();
    let mut actor_ids = BTreeSet::new();
    let mut previous_key = None;
    for actor in &manifest.actors {
        let key = producer_key(&actor.producer);
        if !valid_identifier(&actor.actor_id)
            || !valid_identifier(&actor.producer.id)
            || !valid_identifier(&actor.producer.instance_id)
            || !valid_text(&actor.display_name, limits.max_text_bytes)
            || !sites.contains(&actor.site_id)
        {
            return Err(OperationalProjectionError::Malformed);
        }
        if previous_key
            .as_ref()
            .is_some_and(|previous| previous >= &key)
        {
            return Err(if actors.contains_key(&key) {
                OperationalProjectionError::DuplicateConflict
            } else {
                OperationalProjectionError::InvalidOrder
            });
        }
        if !actor_ids.insert(actor.actor_id.clone()) || actors.insert(key.clone(), actor).is_some()
        {
            return Err(OperationalProjectionError::DuplicateConflict);
        }
        previous_key = Some(key);
    }
    Ok(actors)
}

fn validate_overlay<'a>(
    overlay: &'a OperationalEditorialOverlay,
    events: &BTreeMap<String, OperationalVisibility>,
    limits: OperationalProjectionLimits,
) -> Result<BTreeMap<String, &'a EditorialEntry>, OperationalProjectionError> {
    if overlay.schema_version != OPERATIONAL_EDITORIAL_OVERLAY_SCHEMA_VERSION {
        return Err(OperationalProjectionError::UnsupportedSchema);
    }
    if overlay.entries.len() > limits.max_events {
        return Err(OperationalProjectionError::CapacityExhausted);
    }
    let mut entries = BTreeMap::new();
    let mut previous = None;
    for entry in &overlay.entries {
        validate_digest(&entry.event_id).map_err(|_| OperationalProjectionError::Malformed)?;
        if !valid_text(&entry.narration, limits.max_text_bytes) {
            return Err(OperationalProjectionError::Malformed);
        }
        if previous
            .as_deref()
            .is_some_and(|value| value >= entry.event_id.as_str())
        {
            return Err(if entries.contains_key(&entry.event_id) {
                OperationalProjectionError::DuplicateConflict
            } else {
                OperationalProjectionError::InvalidOrder
            });
        }
        if events.get(&entry.event_id) != Some(&OperationalVisibility::Visible) {
            return Err(OperationalProjectionError::InvalidReference);
        }
        entries.insert(entry.event_id.clone(), entry);
        previous = Some(entry.event_id.clone());
    }
    Ok(entries)
}

fn valid_failure_pair(kind: OperationalFailureKind, outcome: OperationalFailureOutcome) -> bool {
    matches!(
        (kind, outcome),
        (
            OperationalFailureKind::SiblingSubmitted
                | OperationalFailureKind::PrimarySubmitted
                | OperationalFailureKind::FallbackSubmitted,
            OperationalFailureOutcome::Submitted
        ) | (
            OperationalFailureKind::PrimaryOutageObserved,
            OperationalFailureOutcome::Unavailable
        ) | (
            OperationalFailureKind::PrimaryStreamFailed,
            OperationalFailureOutcome::Error
        ) | (
            OperationalFailureKind::CancelRequested,
            OperationalFailureOutcome::Requested
        ) | (
            OperationalFailureKind::LateOutputFenced,
            OperationalFailureOutcome::Fenced
        ) | (
            OperationalFailureKind::InternalProcessorStopped,
            OperationalFailureOutcome::CooperativeStop
        ) | (
            OperationalFailureKind::CancelConfirmed
                | OperationalFailureKind::PrimaryFinalReconciled,
            OperationalFailureOutcome::Canceled
        ) | (
            OperationalFailureKind::SiblingCompleted
                | OperationalFailureKind::FallbackCompleted
                | OperationalFailureKind::ReviewCompleted
                | OperationalFailureKind::ScenarioCompleted,
            OperationalFailureOutcome::Completed
        ) | (
            OperationalFailureKind::FallbackSelected,
            OperationalFailureOutcome::Selected
        )
    )
}

fn validate_source_facts(
    manifest: &OperationalSourceFactsManifest,
    limits: OperationalProjectionLimits,
) -> Result<BTreeMap<String, &OperationalSourceFact>, OperationalProjectionError> {
    if manifest.schema_version != OPERATIONAL_SOURCE_FACTS_SCHEMA_VERSION {
        return Err(OperationalProjectionError::UnsupportedSchema);
    }
    if manifest.entries.len() > limits.max_events {
        return Err(OperationalProjectionError::CapacityExhausted);
    }
    let mut entries = BTreeMap::new();
    let mut previous = None;
    for entry in &manifest.entries {
        validate_digest(&entry.event_id).map_err(|_| OperationalProjectionError::Malformed)?;
        validate_digest(&entry.source_content_digest)
            .map_err(|_| OperationalProjectionError::Malformed)?;
        let source_shape_valid = match entry.source_schema_version.as_str() {
            "lifeline-failure-scenario/1" => {
                entry.field_restrictions.is_empty()
                    && entry
                        .failure_kind
                        .zip(entry.outcome)
                        .is_some_and(|(kind, outcome)| valid_failure_pair(kind, outcome))
            }
            "lifeline-runtime-trace/1" => {
                entry.failure_kind.is_none()
                    && entry.outcome.is_none()
                    && entry.field_restrictions.len() == 1
            }
            _ => false,
        };
        if !source_shape_valid {
            return Err(OperationalProjectionError::Malformed);
        }
        let mut prior_field = None;
        for restriction in &entry.field_restrictions {
            if prior_field.is_some_and(|prior| prior >= restriction.field) {
                return Err(OperationalProjectionError::DuplicateConflict);
            }
            prior_field = Some(restriction.field);
        }
        if previous
            .as_deref()
            .is_some_and(|value| value >= entry.event_id.as_str())
        {
            return Err(if entries.contains_key(&entry.event_id) {
                OperationalProjectionError::DuplicateConflict
            } else {
                OperationalProjectionError::InvalidOrder
            });
        }
        entries.insert(entry.event_id.clone(), entry);
        previous = Some(entry.event_id.clone());
    }
    Ok(entries)
}

fn append_line(
    output: &mut Vec<u8>,
    value: &Value,
    limits: OperationalProjectionLimits,
) -> Result<(usize, usize), OperationalProjectionError> {
    let line = canonical(value).map_err(|_| OperationalProjectionError::Malformed)?;
    if line.len() > limits.max_line_bytes
        || line.len().saturating_add(1) > limits.max_output_bytes.saturating_sub(output.len())
    {
        return Err(OperationalProjectionError::CapacityExhausted);
    }
    let start = output.len();
    output.extend_from_slice(&line);
    let end = output.len();
    output.push(b'\n');
    Ok((start, end))
}

fn exact_keys(value: &Value, keys: &[&str]) -> Result<(), OperationalProjectionError> {
    let object = value
        .as_object()
        .ok_or(OperationalProjectionError::Malformed)?;
    if object.len() != keys.len() || !keys.iter().all(|key| object.contains_key(*key)) {
        return Err(OperationalProjectionError::Malformed);
    }
    Ok(())
}

fn decimal(value: Option<&Value>) -> Result<u64, OperationalProjectionError> {
    let text = value
        .and_then(Value::as_str)
        .ok_or(OperationalProjectionError::Malformed)?;
    if text.is_empty()
        || text.len() > 20
        || text != "0" && text.starts_with('0')
        || !text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(OperationalProjectionError::Malformed);
    }
    text.parse()
        .map_err(|_| OperationalProjectionError::Malformed)
}

fn package_lines(bytes: &[u8]) -> Result<Vec<&[u8]>, OperationalProjectionError> {
    if bytes.is_empty() || bytes.len() > HARD_MAX_BYTES || !bytes.ends_with(b"\n") {
        return Err(OperationalProjectionError::CapacityExhausted);
    }
    let mut lines = Vec::new();
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        if line.is_empty() {
            return Err(OperationalProjectionError::Malformed);
        }
        if line.len() > HARD_MAX_LINE_BYTES || lines.len() > HARD_MAX_EVENTS {
            return Err(OperationalProjectionError::CapacityExhausted);
        }
        lines.push(line);
    }
    if lines.len() < 2 {
        return Err(OperationalProjectionError::Malformed);
    }
    Ok(lines)
}

/// Verifies a closed operational package and its projection receipt without external callbacks.
///
/// # Errors
/// Rejects noncanonical bytes, unknown fields or kinds, duplicate IDs, invalid ordering,
/// malformed references, bounds, receipt mismatches, and digest mismatches.
#[allow(clippy::too_many_lines)]
pub fn verify_operational_projection(
    package_jsonl: &[u8],
    receipt_json: &[u8],
    expected_input_digest: &str,
) -> Result<ProjectionReceipt, OperationalProjectionError> {
    validate_digest(expected_input_digest).map_err(|_| OperationalProjectionError::Malformed)?;
    let (receipt, _): (ProjectionReceipt, _) = canonical_input(receipt_json, HARD_MAX_LINE_BYTES)?;
    if receipt.projector_id != OPERATIONAL_OBSERVATORY_PROJECTOR_ID
        || receipt.projector_version != OPERATIONAL_OBSERVATORY_PROJECTOR_VERSION
        || receipt.input_digest != expected_input_digest
        || receipt.output_byte_length != package_jsonl.len() as u64
        || validate_digest(&receipt.output_digest).is_err()
        || receipt.output_digest != hash("operational-observatory-output", &[package_jsonl])
    {
        return Err(OperationalProjectionError::Replay);
    }
    let lines = package_lines(package_jsonl)?;
    let mut values = Vec::with_capacity(lines.len());
    for line in lines {
        let value: Value =
            serde_json::from_slice(line).map_err(|_| OperationalProjectionError::Malformed)?;
        if canonical(&value).map_err(|_| OperationalProjectionError::Malformed)? != line {
            return Err(OperationalProjectionError::Malformed);
        }
        values.push(value);
    }
    exact_keys(
        &values[0],
        &[
            "actorManifestDigest",
            "editorialOverlayDigest",
            "inputReplayDigest",
            "inputRunSeal",
            "recordType",
            "runId",
            "schemaVersion",
            "sourceFactsDigest",
        ],
    )?;
    let header = values[0]
        .as_object()
        .ok_or(OperationalProjectionError::Malformed)?;
    if header.get("recordType").and_then(Value::as_str) != Some("package") {
        return Err(OperationalProjectionError::Malformed);
    }
    if header.get("schemaVersion").and_then(Value::as_str)
        != Some(OPERATIONAL_OBSERVATORY_SCHEMA_VERSION)
    {
        return Err(OperationalProjectionError::UnsupportedSchema);
    }
    for key in [
        "actorManifestDigest",
        "editorialOverlayDigest",
        "inputReplayDigest",
        "inputRunSeal",
        "sourceFactsDigest",
    ] {
        validate_digest(
            header
                .get(key)
                .and_then(Value::as_str)
                .ok_or(OperationalProjectionError::Malformed)?,
        )
        .map_err(|_| OperationalProjectionError::Malformed)?;
    }
    if !valid_identifier(
        header
            .get("runId")
            .and_then(Value::as_str)
            .ok_or(OperationalProjectionError::Malformed)?,
    ) {
        return Err(OperationalProjectionError::Malformed);
    }
    let mut saw_event = false;
    let mut expected_merge = 0_u64;
    let mut previous_time = 0_u64;
    let mut event_ids = BTreeSet::new();
    let mut verified_source_facts = Vec::<OperationalSourceFact>::new();
    let mut gap_children = Vec::new();
    let mut claimed_gap_children = BTreeSet::new();
    let mut gap_claims = BTreeMap::<String, BTreeSet<String>>::new();
    let mut matched_gap_children = BTreeSet::new();
    for value in &values[1..] {
        let object = value
            .as_object()
            .ok_or(OperationalProjectionError::Malformed)?;
        match object.get("recordType").and_then(Value::as_str) {
            Some("gap") => {
                if saw_event {
                    return Err(OperationalProjectionError::InvalidOrder);
                }
                exact_keys(
                    value,
                    &[
                        "children",
                        "expectedEventId",
                        "reason",
                        "recordId",
                        "recordType",
                    ],
                )?;
                if object.get("reason").and_then(Value::as_str) != Some("unresolvedAtSeal") {
                    return Err(OperationalProjectionError::Malformed);
                }
                for key in ["expectedEventId", "recordId"] {
                    validate_digest(
                        object
                            .get(key)
                            .and_then(Value::as_str)
                            .ok_or(OperationalProjectionError::Malformed)?,
                    )
                    .map_err(|_| OperationalProjectionError::Malformed)?;
                }
                let children = object
                    .get("children")
                    .and_then(Value::as_array)
                    .ok_or(OperationalProjectionError::Malformed)?;
                let expected_event_id = object["expectedEventId"]
                    .as_str()
                    .ok_or(OperationalProjectionError::Malformed)?
                    .to_owned();
                let mut previous = None;
                let mut claimed_children = BTreeSet::new();
                for child in children {
                    let child = child
                        .as_str()
                        .ok_or(OperationalProjectionError::Malformed)?;
                    validate_digest(child).map_err(|_| OperationalProjectionError::Malformed)?;
                    if previous.is_some_and(|prior| prior >= child)
                        || !claimed_gap_children.insert(child.to_owned())
                    {
                        return Err(OperationalProjectionError::InvalidOrder);
                    }
                    gap_children.push(child.to_owned());
                    claimed_children.insert(child.to_owned());
                    previous = Some(child);
                }
                if claimed_children.is_empty()
                    || gap_claims
                        .insert(expected_event_id, claimed_children)
                        .is_some()
                {
                    return Err(OperationalProjectionError::InvalidReference);
                }
            }
            Some("event" | "restricted") => {
                saw_event = true;
                let restricted =
                    object.get("recordType").and_then(Value::as_str) == Some("restricted");
                let expected = if restricted {
                    vec![
                        "actorId",
                        "channel",
                        "eventId",
                        "kind",
                        "mergeIndex",
                        "parent",
                        "producer",
                        "recordType",
                        "restrictionReason",
                        "runRelativeNs",
                        "siteId",
                    ]
                } else {
                    vec![
                        "actorId",
                        "channel",
                        "content",
                        "contextId",
                        "editorial",
                        "eventId",
                        "interactionId",
                        "kind",
                        "mergeIndex",
                        "parent",
                        "peerId",
                        "producer",
                        "recordType",
                        "runRelativeNs",
                        "siteId",
                        "sourceFacts",
                        "subjectId",
                        "taskId",
                    ]
                };
                exact_keys(value, &expected)?;
                if restricted
                    && object.get("restrictionReason").and_then(Value::as_str)
                        != Some("actorManifest")
                {
                    return Err(OperationalProjectionError::Malformed);
                }
                let event_id = object
                    .get("eventId")
                    .and_then(Value::as_str)
                    .ok_or(OperationalProjectionError::Malformed)?;
                validate_digest(event_id).map_err(|_| OperationalProjectionError::Malformed)?;
                if event_ids.contains(event_id) {
                    return Err(OperationalProjectionError::DuplicateConflict);
                }
                if decimal(object.get("mergeIndex"))? != expected_merge {
                    return Err(OperationalProjectionError::InvalidOrder);
                }
                expected_merge += 1;
                let time = decimal(object.get("runRelativeNs"))?;
                if time < previous_time {
                    return Err(OperationalProjectionError::InvalidOrder);
                }
                previous_time = time;
                for key in ["actorId", "siteId"] {
                    if !valid_identifier(
                        object
                            .get(key)
                            .and_then(Value::as_str)
                            .ok_or(OperationalProjectionError::Malformed)?,
                    ) {
                        return Err(OperationalProjectionError::Malformed);
                    }
                }
                let kind: CaptureKind = serde_json::from_value(
                    object
                        .get("kind")
                        .cloned()
                        .ok_or(OperationalProjectionError::Malformed)?,
                )
                .map_err(|_| OperationalProjectionError::Malformed)?;
                if object.get("channel").and_then(Value::as_str) != Some(channel(kind)) {
                    return Err(OperationalProjectionError::Malformed);
                }
                let parent = object
                    .get("parent")
                    .ok_or(OperationalProjectionError::Malformed)?;
                match parent.get("kind").and_then(Value::as_str) {
                    Some("root") => exact_keys(parent, &["kind"]),
                    Some("event") => {
                        exact_keys(parent, &["eventId", "kind"])?;
                        let parent_id = parent["eventId"].as_str().unwrap_or("");
                        validate_digest(parent_id)
                            .map_err(|_| OperationalProjectionError::Malformed)?;
                        if !event_ids.contains(parent_id) {
                            return Err(OperationalProjectionError::InvalidReference);
                        }
                        Ok(())
                    }
                    Some("missing") => {
                        exact_keys(parent, &["expectedEventId", "kind", "reason"])?;
                        let expected_event_id = parent["expectedEventId"].as_str().unwrap_or("");
                        validate_digest(expected_event_id)
                            .map_err(|_| OperationalProjectionError::Malformed)?;
                        let _: CaptureGapReason = serde_json::from_value(parent["reason"].clone())
                            .map_err(|_| OperationalProjectionError::Malformed)?;
                        if !gap_claims
                            .get(expected_event_id)
                            .is_some_and(|children| children.contains(event_id))
                        {
                            return Err(OperationalProjectionError::InvalidReference);
                        }
                        matched_gap_children.insert(event_id.to_owned());
                        Ok(())
                    }
                    _ => Err(OperationalProjectionError::Malformed),
                }?;
                event_ids.insert(event_id.to_owned());
                exact_keys(
                    object
                        .get("producer")
                        .ok_or(OperationalProjectionError::Malformed)?,
                    &["id", "instanceId", "kind", "sourceSequence"],
                )?;
                let producer = object["producer"]
                    .as_object()
                    .ok_or(OperationalProjectionError::Malformed)?;
                let producer_kind: ProducerKind = serde_json::from_value(
                    producer
                        .get("kind")
                        .cloned()
                        .ok_or(OperationalProjectionError::Malformed)?,
                )
                .map_err(|_| OperationalProjectionError::Malformed)?;
                if producer_kind_name(producer_kind) != channel(kind)
                    || !valid_identifier(producer.get("id").and_then(Value::as_str).unwrap_or(""))
                    || !valid_identifier(
                        producer
                            .get("instanceId")
                            .and_then(Value::as_str)
                            .unwrap_or(""),
                    )
                {
                    return Err(OperationalProjectionError::Malformed);
                }
                decimal(producer.get("sourceSequence"))?;
                let source_fact = if restricted || object["sourceFacts"].is_null() {
                    None
                } else {
                    let fact: OperationalSourceFact =
                        serde_json::from_value(object["sourceFacts"].clone())
                            .map_err(|_| OperationalProjectionError::Malformed)?;
                    validate_source_facts(
                        &OperationalSourceFactsManifest {
                            entries: vec![fact.clone()],
                            schema_version: OPERATIONAL_SOURCE_FACTS_SCHEMA_VERSION.into(),
                        },
                        OperationalProjectionLimits::default(),
                    )?;
                    if fact.event_id != event_id {
                        return Err(OperationalProjectionError::InvalidReference);
                    }
                    Some(fact)
                };
                if !restricted {
                    for key in ["interactionId", "peerId"] {
                        if !object
                            .get(key)
                            .and_then(Value::as_str)
                            .is_some_and(valid_identifier)
                        {
                            return Err(OperationalProjectionError::Malformed);
                        }
                    }
                    for key in ["contextId", "taskId", "subjectId"] {
                        let value = object
                            .get(key)
                            .ok_or(OperationalProjectionError::Malformed)?;
                        if !value.is_null() && !value.as_str().is_some_and(valid_identifier) {
                            return Err(OperationalProjectionError::Malformed);
                        }
                    }
                    exact_keys(
                        object
                            .get("content")
                            .ok_or(OperationalProjectionError::Malformed)?,
                        &["byteLength", "digest"],
                    )?;
                    let content = object["content"]
                        .as_object()
                        .ok_or(OperationalProjectionError::Malformed)?;
                    decimal(content.get("byteLength"))?;
                    validate_digest(content.get("digest").and_then(Value::as_str).unwrap_or(""))
                        .map_err(|_| OperationalProjectionError::Malformed)?;
                    if source_fact.as_ref().is_some_and(|fact| {
                        fact.source_content_digest
                            != content.get("digest").and_then(Value::as_str).unwrap_or("")
                            || !fact.field_restrictions.is_empty() && !object["subjectId"].is_null()
                    }) {
                        return Err(OperationalProjectionError::InvalidReference);
                    }
                    if !object["editorial"].is_null() {
                        exact_keys(&object["editorial"], &["cue", "narration"])?;
                        let _: EditorialCue =
                            serde_json::from_value(object["editorial"]["cue"].clone())
                                .map_err(|_| OperationalProjectionError::Malformed)?;
                        if !valid_text(
                            object["editorial"]["narration"].as_str().unwrap_or(""),
                            HARD_MAX_TEXT_BYTES,
                        ) {
                            return Err(OperationalProjectionError::Malformed);
                        }
                    }
                }
                if let Some(fact) = source_fact {
                    verified_source_facts.push(fact);
                }
            }
            _ => return Err(OperationalProjectionError::Malformed),
        }
    }
    if expected_merge == 0
        || gap_claims
            .keys()
            .any(|expected| event_ids.contains(expected))
        || gap_children.iter().any(|child| !event_ids.contains(child))
        || gap_children
            .iter()
            .any(|child| !matched_gap_children.contains(child))
    {
        return Err(OperationalProjectionError::InvalidReference);
    }
    verified_source_facts.sort_by(|a, b| a.event_id.cmp(&b.event_id));
    let source_manifest = serde_json::to_value(OperationalSourceFactsManifest {
        entries: verified_source_facts,
        schema_version: OPERATIONAL_SOURCE_FACTS_SCHEMA_VERSION.into(),
    })
    .map_err(|_| OperationalProjectionError::Malformed)?;
    let source_bytes =
        canonical(&source_manifest).map_err(|_| OperationalProjectionError::Malformed)?;
    if header.get("sourceFactsDigest").and_then(Value::as_str)
        != Some(hash("operational-source-facts", &[&source_bytes]).as_str())
    {
        return Err(OperationalProjectionError::InvalidReference);
    }
    Ok(receipt)
}

/// Verifies a sealed replay and its pinned receipt, then projects only recorded facts.
///
/// The function is pure and has no clock, randomness, URL, network, filesystem, model,
/// tool, or policy callback. Actor/site labels and editorial narration are separately
/// versioned local inputs and cannot add event identity, timing, or causality.
///
/// # Errors
/// Fails closed for any replay, receipt, schema, bound, ordering, identity, or reference error.
#[allow(clippy::too_many_lines)]
pub fn project_operational_observatory(
    replay_bundle: &[u8],
    replay_receipt: &[u8],
    expected_run_seal: &str,
    actor_manifest: &[u8],
    editorial_overlay: &[u8],
    limits: OperationalProjectionLimits,
) -> Result<OperationalProjection, OperationalProjectionError> {
    project_operational_observatory_with_source_facts(
        replay_bundle,
        replay_receipt,
        expected_run_seal,
        actor_manifest,
        editorial_overlay,
        br#"{"entries":[],"schemaVersion":"operational-observatory-source-facts/1"}"#,
        limits,
    )
}

/// Projects a replay with closed, digest-bound public-safe source facts.
///
/// # Errors
/// Fails closed for invalid replay authority, facts, references, bounds, or output encoding.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn project_operational_observatory_with_source_facts(
    replay_bundle: &[u8],
    replay_receipt: &[u8],
    expected_run_seal: &str,
    actor_manifest: &[u8],
    editorial_overlay: &[u8],
    source_facts: &[u8],
    limits: OperationalProjectionLimits,
) -> Result<OperationalProjection, OperationalProjectionError> {
    let limits = limits.validate()?;
    let verified = verify_replay_receipt(replay_bundle, replay_receipt, Some(expected_run_seal))?;
    let (manifest, manifest_bytes): (OperationalActorManifest, _) =
        canonical_input(actor_manifest, HARD_MAX_BYTES)?;
    let actors = validate_manifest(&manifest, limits)?;
    let (facts_manifest, facts_bytes): (OperationalSourceFactsManifest, _) =
        canonical_input(source_facts, HARD_MAX_BYTES)?;
    let facts = validate_source_facts(&facts_manifest, limits)?;

    let mut replay_events = Vec::new();
    let mut gap_values = Vec::new();
    let lines: Vec<_> = replay_bundle[..replay_bundle.len() - 1]
        .split(|byte| *byte == b'\n')
        .collect();
    for line in &lines[..lines.len() - 1] {
        let value: Value =
            serde_json::from_slice(line).map_err(|_| OperationalProjectionError::Replay)?;
        match value.get("recordType").and_then(Value::as_str) {
            Some("event") => {
                let record: ReplayEventRecord = serde_json::from_value(value)
                    .map_err(|_| OperationalProjectionError::Replay)?;
                replay_events.push(record);
            }
            Some("missingParent") => gap_values.push(value),
            _ => return Err(OperationalProjectionError::Replay),
        }
    }
    if replay_events.len() > limits.max_events {
        return Err(OperationalProjectionError::CapacityExhausted);
    }
    let mut event_visibility = BTreeMap::new();
    let mut used_actor_keys = BTreeSet::new();
    for record in &replay_events {
        let identity = &record.causal.event.producer;
        let key = (
            producer_kind_name(identity.kind).to_owned(),
            identity.id.clone(),
            identity.instance_id.clone(),
        );
        let actor = actors
            .get(&key)
            .ok_or(OperationalProjectionError::InvalidReference)?;
        used_actor_keys.insert(key);
        if event_visibility
            .insert(record.causal.event.event_id.clone(), actor.visibility)
            .is_some()
        {
            return Err(OperationalProjectionError::DuplicateConflict);
        }
    }
    for fact in facts.values() {
        let event = replay_events
            .iter()
            .find(|record| record.causal.event.event_id == fact.event_id)
            .ok_or(OperationalProjectionError::InvalidReference)?;
        if event_visibility.get(&fact.event_id) != Some(&OperationalVisibility::Visible)
            || event.causal.event.content.digest != fact.source_content_digest
            || !fact.field_restrictions.is_empty() && event.causal.event.subject_id.is_some()
        {
            return Err(OperationalProjectionError::InvalidReference);
        }
    }
    if used_actor_keys.len() != actors.len() {
        return Err(OperationalProjectionError::InvalidReference);
    }
    let (overlay, overlay_bytes): (OperationalEditorialOverlay, _) =
        canonical_input(editorial_overlay, HARD_MAX_BYTES)?;
    let entries = validate_overlay(&overlay, &event_visibility, limits)?;

    let mut output = Vec::new();
    let manifest_digest = hash("operational-actor-manifest", &[&manifest_bytes]);
    let overlay_digest = hash("operational-editorial-overlay", &[&overlay_bytes]);
    let facts_digest = hash("operational-source-facts", &[&facts_bytes]);
    append_line(
        &mut output,
        &json!({
            "actorManifestDigest": manifest_digest,
            "editorialOverlayDigest": overlay_digest,
            "inputReplayDigest": verified.normalized_output_digest,
            "inputRunSeal": verified.run_seal,
            "recordType": "package",
            "runId": verified.run_id,
            "schemaVersion": OPERATIONAL_OBSERVATORY_SCHEMA_VERSION,
            "sourceFactsDigest": facts_digest,
        }),
        limits,
    )?;
    for gap in gap_values {
        let object = gap.as_object().ok_or(OperationalProjectionError::Replay)?;
        append_line(
            &mut output,
            &json!({
                "children": object.get("children").ok_or(OperationalProjectionError::Replay)?,
                "expectedEventId": object.get("expectedEventId").ok_or(OperationalProjectionError::Replay)?,
                "recordId": object.get("recordId").ok_or(OperationalProjectionError::Replay)?,
                "recordType": "gap",
                "reason": "unresolvedAtSeal",
            }),
            limits,
        )?;
    }
    let first_physical = replay_events
        .first()
        .ok_or(OperationalProjectionError::Replay)?
        .causal
        .hlc
        .physical_ns;
    let mut event_ranges = BTreeMap::new();
    for record in replay_events {
        if record.record_type != "event" {
            return Err(OperationalProjectionError::Replay);
        }
        let event = &record.causal.event;
        let identity = &event.producer;
        let key = (
            producer_kind_name(identity.kind).to_owned(),
            identity.id.clone(),
            identity.instance_id.clone(),
        );
        let actor = actors
            .get(&key)
            .ok_or(OperationalProjectionError::InvalidReference)?;
        let run_relative = record
            .causal
            .hlc
            .physical_ns
            .checked_sub(first_physical)
            .ok_or(OperationalProjectionError::Replay)?;
        let parent = event.parent.clone();
        let common = json!({
            "actorId": actor.actor_id,
            "channel": channel(event.kind),
            "eventId": event.event_id,
            "kind": event.kind,
            "mergeIndex": record.merge_sequence,
            "parent": parent,
            "producer": {
                "id": identity.id,
                "instanceId": identity.instance_id,
                "kind": identity.kind,
                "sourceSequence": identity.source_sequence,
            },
            "runRelativeNs": run_relative.to_string(),
            "siteId": actor.site_id,
        });
        let value = match actor.visibility {
            OperationalVisibility::Restricted => {
                let mut value = common;
                let object = value
                    .as_object_mut()
                    .ok_or(OperationalProjectionError::Malformed)?;
                object.insert("recordType".into(), Value::String("restricted".into()));
                object.insert(
                    "restrictionReason".into(),
                    Value::String("actorManifest".into()),
                );
                value
            }
            OperationalVisibility::Visible => {
                let mut value = common;
                let object = value
                    .as_object_mut()
                    .ok_or(OperationalProjectionError::Malformed)?;
                object.insert(
                    "content".into(),
                    json!({
                        "byteLength": event.content.byte_length,
                        "digest": event.content.digest,
                    }),
                );
                object.insert("contextId".into(), json!(event.context_id));
                object.insert(
                    "editorial".into(),
                    entries.get(&event.event_id).map_or(Value::Null, |entry| {
                        json!({
                            "cue": entry.cue,
                            "narration": entry.narration,
                        })
                    }),
                );
                object.insert("interactionId".into(), json!(event.interaction_id));
                object.insert("peerId".into(), json!(event.peer_id));
                object.insert("recordType".into(), Value::String("event".into()));
                object.insert("sourceFacts".into(), json!(facts.get(&event.event_id)));
                object.insert("subjectId".into(), json!(event.subject_id));
                object.insert("taskId".into(), json!(event.task_id));
                value
            }
        };
        let range = append_line(&mut output, &value, limits)?;
        event_ranges.insert(event.event_id.clone(), range);
        let _ = (
            &event.source_sequence,
            &record.causal.lamport,
            &record.causal.producer_hash,
            &record.causal.producer_previous,
            &record.causal.recorded_decision,
        );
    }
    let receipt = ProjectionReceipt {
        projector_id: OPERATIONAL_OBSERVATORY_PROJECTOR_ID.into(),
        projector_version: OPERATIONAL_OBSERVATORY_PROJECTOR_VERSION.into(),
        input_digest: verified.input_jsonl_digest,
        output_digest: hash("operational-observatory-output", &[&output]),
        output_byte_length: u64::try_from(output.len())
            .map_err(|_| OperationalProjectionError::CapacityExhausted)?,
    };
    let receipt_value =
        serde_json::to_value(&receipt).map_err(|_| OperationalProjectionError::Malformed)?;
    let receipt_json =
        canonical(&receipt_value).map_err(|_| OperationalProjectionError::Malformed)?;
    Ok(OperationalProjection {
        package_jsonl: output,
        receipt,
        receipt_json,
        event_ranges,
    })
}
