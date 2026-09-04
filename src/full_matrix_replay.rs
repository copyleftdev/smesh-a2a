use crate::{CaptureEvent, CaptureGapReason, CaptureParent, ProducerKind};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
#[cfg(unix)]
use std::fs::{self, OpenOptions};
#[cfg(unix)]
use std::io::Write;
use std::path::Path;

use thiserror::Error;

pub const FULL_MATRIX_REPLAY_SCHEMA_VERSION: &str = "full-matrix-replay/1";
pub const CAUSAL_SOURCE_SCHEMA_VERSION: &str = "full-matrix-causal-source/1";
pub const REPLAY_RECEIPT_SCHEMA_VERSION: &str = "full-matrix-replay-receipt/1";
pub const CANONICALIZATION: &str = "RFC8785-JCS-restricted-no-numbers/1";
const MAX_SOURCES: usize = 1_024;
const MAX_EVENTS: usize = 100_000;
const MAX_EDGES: usize = 100_000;
const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_LINE: usize = 64 * 1024;
const MAX_PROJECTIONS: usize = 128;
const MAX_CANONICAL_DEPTH: usize = 64;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReplayError {
    #[error("replay identifier or digest is invalid")]
    InvalidIdentifier,
    #[error("causal source or replay bundle is malformed")]
    Malformed,
    #[error("causal source schema is unsupported")]
    UnsupportedSchema,
    #[error("replay capacity is exhausted")]
    CapacityExhausted,
    #[error("duplicate event envelope conflicts")]
    DuplicateConflict,
    #[error("producer sequence has a gap, regression, or splice")]
    SequenceGap,
    #[error("producer chain is invalid")]
    ProducerChain,
    #[error("a declared missing parent is present")]
    MissingClaimConflict,
    #[error("unresolved parents: {0:?}")]
    MissingParents(Vec<String>),
    #[error("causal graph contains a cycle: {0:?}")]
    Cycle(Vec<String>),
    #[error("HLC or Lamport causality is invalid")]
    ClockCausalityViolation,
    #[error("projection receipt is invalid")]
    ProjectionMismatch,
    #[error("replay integrity verification failed")]
    Integrity,
    #[error("replay persistence failed")]
    Persistence,
    #[error("private replay temporary file requires cleanup; token: {0}")]
    CleanupRequired(String),
    #[error("destination was published but its temporary hard link requires cleanup; token: {0}")]
    PublishedCleanupRequired(String),
    #[error("destination already exists")]
    AlreadyExists,
    #[error("destination was published but final durability could not be confirmed")]
    Published,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HybridLogicalClock {
    #[serde(with = "decimal")]
    pub physical_ns: u64,
    #[serde(with = "decimal")]
    pub logical: u64,
}

/// An in-memory causal event. The closed causal-source wire format is emitted
/// only by [`capture_causal_source_jsonl`]; this type deliberately has no
/// general-purpose Serde representation.
///
/// ```compile_fail
/// use smesh_a2a::CausalSourceEvent;
///
/// fn requires_wire_serde<T: serde::Serialize + for<'de> serde::Deserialize<'de>>() {}
/// requires_wire_serde::<CausalSourceEvent>();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CausalSourceEvent {
    pub event: CaptureEvent,
    pub hlc: HybridLogicalClock,
    pub lamport: u64,
    pub recorded_decision: Option<Value>,
    pub producer_previous: Option<String>,
    pub producer_hash: String,
}

impl CausalSourceEvent {
    /// Creates the first event in a producer chain.
    ///
    /// # Errors
    /// Returns an error when the event, decision, or chain root is malformed.
    pub fn new(
        event: CaptureEvent,
        hlc: HybridLogicalClock,
        lamport: u64,
        recorded_decision: Option<Value>,
    ) -> Result<Self, ReplayError> {
        Self::new_chained(event, hlc, lamport, recorded_decision, None)
    }

    /// Creates an event with an optional producer-chain predecessor.
    ///
    /// # Errors
    /// Returns an error when identifiers, decisions, or chain framing are invalid.
    pub fn new_chained(
        event: CaptureEvent,
        hlc: HybridLogicalClock,
        lamport: u64,
        mut recorded_decision: Option<Value>,
        producer_previous: Option<String>,
    ) -> Result<Self, ReplayError> {
        if let Some(value) = &recorded_decision
            && let Err(error) = canonical_bounded(value, MAX_LINE)
        {
            drop_json_value_iteratively(recorded_decision.take().ok_or(ReplayError::Malformed)?);
            return Err(error);
        }
        validate_event(&event, None)?;
        if event.producer.sequence == 0 && producer_previous.is_some()
            || event.producer.sequence != 0 && producer_previous.is_none()
        {
            return Err(ReplayError::ProducerChain);
        }
        if let Some(previous) = &producer_previous {
            decode_digest(previous)?;
        }
        let mut source = Self {
            event,
            hlc,
            lamport,
            recorded_decision,
            producer_previous,
            producer_hash: String::new(),
        };
        source.producer_hash = compute_producer_hash(&source)?;
        Ok(source)
    }

    #[must_use]
    pub fn producer_hash(&self) -> &str {
        &self.producer_hash
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingParentPolicy {
    Reject,
    Record,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MergeLimits {
    pub max_sources: usize,
    pub max_events: usize,
    pub max_edges: usize,
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
    pub max_line_bytes: usize,
}

impl Default for MergeLimits {
    fn default() -> Self {
        Self {
            max_sources: MAX_SOURCES,
            max_events: MAX_EVENTS,
            max_edges: MAX_EDGES,
            max_input_bytes: MAX_BYTES,
            max_output_bytes: MAX_BYTES,
            max_line_bytes: MAX_LINE,
        }
    }
}

impl MergeLimits {
    fn validate(self) -> Result<Self, ReplayError> {
        if self.max_sources == 0
            || self.max_events == 0
            || self.max_edges == 0
            || self.max_input_bytes == 0
            || self.max_output_bytes == 0
            || self.max_line_bytes == 0
            || self.max_sources > MAX_SOURCES
            || self.max_events > MAX_EVENTS
            || self.max_edges > MAX_EDGES
            || self.max_input_bytes > MAX_BYTES
            || self.max_output_bytes > MAX_BYTES
            || self.max_line_bytes > MAX_LINE
        {
            return Err(ReplayError::CapacityExhausted);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectionReceipt {
    pub projector_id: String,
    pub projector_version: String,
    pub input_digest: String,
    pub output_digest: String,
    #[serde(with = "decimal")]
    pub output_byte_length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplaySealInput {
    pub artifact_manifest_digest: String,
    pub projections: Vec<ProjectionReceipt>,
}

impl ReplaySealInput {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            artifact_manifest_digest: hash("artifact-manifest", &[b"[]"]),
            projections: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReplayReceipt {
    pub schema_version: String,
    pub run_id: String,
    pub run_seal: String,
    pub input_jsonl_digest: String,
    pub merkle_root: String,
    #[serde(with = "decimal")]
    pub replayed_event_count: u64,
    pub decision_mode: String,
    pub recorded_decision_set_digest: String,
    pub projections: Vec<ProjectionReceipt>,
    pub normalized_output_digest: String,
    pub receipt_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedReplay {
    bundle_jsonl: Vec<u8>,
    receipt: ReplayReceipt,
    receipt_json: Vec<u8>,
}

impl SealedReplay {
    #[must_use]
    pub fn bundle_jsonl(&self) -> &[u8] {
        &self.bundle_jsonl
    }
    #[must_use]
    pub fn receipt(&self) -> &ReplayReceipt {
        &self.receipt
    }
    #[must_use]
    pub fn receipt_json(&self) -> &[u8] {
        &self.receipt_json
    }

    /// Persists on Unix to a new absolute path in an owner-private, owner-owned parent.
    ///
    /// All parent ancestors are part of the caller's trust boundary. `Published`
    /// means the destination exists but directory durability could not be proven.
    /// Unsupported non-Unix platforms fail closed without creating a file.
    ///
    /// # Errors
    /// Returns `AlreadyExists`, `Persistence` before publication,
    /// `CleanupRequired` with the bounded same-directory temporary token when
    /// pre-publication cleanup fails, `PublishedCleanupRequired` with that
    /// token when post-publication temporary cleanup fails, or `Published`
    /// after publication when final verification or directory sync fails.
    pub fn persist_new(&self, path: &Path) -> Result<(), ReplayError> {
        persist_bytes_new(path, &self.bundle_jsonl)
    }
}

pub struct CausalMerger {
    run_id: String,
    limits: MergeLimits,
    missing_policy: MissingParentPolicy,
    events: HashMap<String, CausalSourceEvent>,
    slots: HashMap<(String, String, String, u64), String>,
    missing_claims: HashSet<String>,
    edges: HashSet<(String, String)>,
    sources: usize,
    input_bytes: usize,
    source_fingerprints: HashMap<String, usize>,
}

impl CausalMerger {
    /// Creates a bounded merger for one run.
    ///
    /// # Errors
    /// Returns an error for an invalid run identifier or unsupported limits.
    pub fn new(
        run_id: impl Into<String>,
        limits: MergeLimits,
        missing_policy: MissingParentPolicy,
    ) -> Result<Self, ReplayError> {
        let run_id = run_id.into();
        if !valid_identifier(&run_id) {
            return Err(ReplayError::InvalidIdentifier);
        }
        Ok(Self {
            run_id,
            limits: limits.validate()?,
            missing_policy,
            events: HashMap::new(),
            slots: HashMap::new(),
            missing_claims: HashSet::new(),
            edges: HashSet::new(),
            sources: 0,
            input_bytes: 0,
            source_fingerprints: HashMap::new(),
        })
    }

    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.events.values().filter(|e| matches!(&e.event.parent, CaptureParent::Event(id) if !self.events.contains_key(id))).count()
    }

    /// Atomically admits one closed causal-source envelope.
    ///
    /// # Errors
    /// Returns an error for malformed, conflicting, forged, or over-limit input.
    pub fn ingest_source_jsonl(&mut self, bytes: &[u8]) -> Result<usize, ReplayError> {
        if bytes.len() > self.limits.max_input_bytes {
            return Err(ReplayError::CapacityExhausted);
        }
        let fingerprint = hash("source-envelope", &[bytes]);
        if let Some(event_count) = self.source_fingerprints.get(&fingerprint) {
            return Ok(*event_count);
        }
        if self.sources == self.limits.max_sources
            || bytes.len() > self.limits.max_input_bytes.saturating_sub(self.input_bytes)
        {
            return Err(ReplayError::CapacityExhausted);
        }
        let batch = parse_source(
            bytes,
            &self.run_id,
            self.limits.max_line_bytes,
            self.limits.max_events,
        )?;
        for source in &batch {
            validate_source_event(source, Some(&self.run_id))?;
        }
        let batch_ids: HashSet<_> = batch.iter().map(|e| e.event.event_id.as_str()).collect();
        let new_event_count = batch_ids
            .iter()
            .filter(|id| !self.events.contains_key(**id))
            .count();
        if self.events.len().saturating_add(new_event_count) > self.limits.max_events {
            return Err(ReplayError::CapacityExhausted);
        }
        let mut pending_events = HashMap::new();
        let mut pending_slots = HashMap::new();
        let mut pending_missing = HashSet::new();
        for source in &batch {
            let id = source.event.event_id.clone();
            if self.missing_claims.contains(&id) || pending_missing.contains(&id) {
                return Err(ReplayError::MissingClaimConflict);
            }
            if let CaptureParent::Missing {
                expected_event_id, ..
            } = &source.event.parent
            {
                if self.events.contains_key(expected_event_id)
                    || batch_ids.contains(expected_event_id.as_str())
                {
                    return Err(ReplayError::MissingClaimConflict);
                }
                pending_missing.insert(expected_event_id.clone());
            }
            if let Some(existing) = self.events.get(&id).or_else(|| pending_events.get(&id)) {
                if canonical_source_event(existing)? != canonical_source_event(source)? {
                    return Err(ReplayError::DuplicateConflict);
                }
                continue;
            }
            let key = producer_slot(source);
            if let Some(existing_id) = pending_slots.get(&key).or_else(|| self.slots.get(&key))
                && existing_id != &id
            {
                return Err(ReplayError::SequenceGap);
            }
            pending_slots.insert(key, id.clone());
            pending_events.insert(id, source.clone());
        }
        let pending_edges = self.incremental_edges(&pending_events, &pending_slots);
        if self.edges.len().saturating_add(pending_edges.len()) > self.limits.max_edges {
            return Err(ReplayError::CapacityExhausted);
        }
        self.events.extend(pending_events);
        self.slots.extend(pending_slots);
        self.missing_claims.extend(pending_missing);
        self.edges.extend(pending_edges);
        self.sources += 1;
        self.input_bytes += bytes.len();
        self.source_fingerprints.insert(fingerprint, batch.len());
        Ok(batch.len())
    }

    fn incremental_edges(
        &self,
        pending_events: &HashMap<String, CausalSourceEvent>,
        pending_slots: &HashMap<(String, String, String, u64), String>,
    ) -> HashSet<(String, String)> {
        let mut edges = HashSet::new();
        for event in pending_events.values() {
            let child = event.event.event_id.as_str();
            let producer = &event.event.producer.identity;
            let producer_key = |sequence| {
                (
                    kind_name(producer.kind).into(),
                    producer.id.clone(),
                    producer.instance_id.clone(),
                    sequence,
                )
            };
            if event.event.producer.sequence > 0 {
                let key = producer_key(event.event.producer.sequence - 1);
                if let Some(previous) = pending_slots.get(&key).or_else(|| self.slots.get(&key)) {
                    edges.insert((previous.clone(), child.to_owned()));
                }
            }
            if let Some(sequence) = event.event.producer.sequence.checked_add(1) {
                let key = producer_key(sequence);
                if let Some(successor) = pending_slots.get(&key).or_else(|| self.slots.get(&key)) {
                    edges.insert((child.to_owned(), successor.clone()));
                }
            }
            if let CaptureParent::Event(parent) = &event.event.parent {
                edges.insert((parent.clone(), child.to_owned()));
            }
        }
        edges.retain(|edge| !self.edges.contains(edge));
        edges
    }

    /// Derives the deterministic replay bundle and receipt without live callbacks.
    ///
    /// # Errors
    /// Returns an error when causal, chain, missing-parent, projection, or size
    /// invariants cannot be satisfied.
    #[allow(clippy::too_many_lines)] // Claim construction is kept visibly ordered.
    pub fn finalize(&self, input: ReplaySealInput) -> Result<SealedReplay, ReplayError> {
        if self.events.is_empty() {
            return Err(ReplayError::Malformed);
        }
        validate_digest(&input.artifact_manifest_digest)?;
        let mut projections = input.projections;
        validate_projections(&mut projections)?;
        self.validate_producers()?;
        let unresolved = unresolved_map(&self.events);
        if !unresolved.is_empty() && self.missing_policy == MissingParentPolicy::Reject {
            return Err(ReplayError::MissingParents(
                unresolved.keys().cloned().collect(),
            ));
        }
        let (ordered, missing_records) = self.topological_order(&unresolved)?;
        let mut lines = Vec::new();
        let mut merged = Vec::new();
        for (missing, children) in &missing_records {
            let line = canonical(&missing_record(&self.run_id, missing, children))?;
            append_bounded_line(
                &mut lines,
                &mut merged,
                line,
                self.limits.max_line_bytes,
                self.limits.max_output_bytes,
            )?;
        }
        let mut decision_refs = Vec::new();
        for (merge_sequence, id) in ordered.iter().enumerate() {
            let source = &self.events[id];
            let record = merged_record(source, merge_sequence)?;
            if let Some(decision) = &source.recorded_decision {
                let d = canonical(decision)?;
                decision_refs.push(object(vec![
                    (
                        "decisionDigest",
                        Value::String(hash("recorded-decision", &[&d])),
                    ),
                    ("eventId", Value::String(id.clone())),
                ]));
            }
            let line = canonical(&record)?;
            append_bounded_line(
                &mut lines,
                &mut merged,
                line,
                self.limits.max_line_bytes,
                self.limits.max_output_bytes,
            )?;
        }
        let merged_digest = hash("merged-jsonl", &[&merged]);
        if projections
            .iter()
            .any(|projection| projection.input_digest != merged_digest)
        {
            return Err(ReplayError::ProjectionMismatch);
        }
        let merkle_root = merkle_root(&lines)?;
        let decision_bytes = canonical(&Value::Array(decision_refs))?;
        let decision_digest = hash("decision-set", &[&decision_bytes]);
        let heads = producer_heads(&self.events)?;
        let claims = object(vec![
            (
                "artifactManifestDigest",
                Value::String(input.artifact_manifest_digest),
            ),
            ("canonicalization", Value::String(CANONICALIZATION.into())),
            ("eventCount", Value::String(ordered.len().to_string())),
            (
                "hashFraming",
                Value::String("SMESH-A2A-length-prefixed-v1".into()),
            ),
            ("mergedJsonlDigest", Value::String(merged_digest.clone())),
            ("merkleRoot", Value::String(merkle_root.clone())),
            ("missingParents", missing_claims_value(&missing_records)),
            ("producerHeads", Value::Array(heads)),
            (
                "projections",
                serde_json::to_value(&projections).map_err(|_| ReplayError::Malformed)?,
            ),
            ("recordCount", Value::String(lines.len().to_string())),
            (
                "recordedDecisionSetDigest",
                Value::String(decision_digest.clone()),
            ),
            ("runId", Value::String(self.run_id.clone())),
            (
                "schemaVersion",
                Value::String(FULL_MATRIX_REPLAY_SCHEMA_VERSION.into()),
            ),
        ]);
        let claims_bytes = canonical(&claims)?;
        let seal = hash("run-seal", &[&claims_bytes]);
        let terminal = object(vec![
            ("claims", claims),
            ("recordType", Value::String("seal".into())),
            ("sealDigest", Value::String(seal.clone())),
        ]);
        let terminal_bytes = canonical(&terminal)?;
        if terminal_bytes.len() > self.limits.max_line_bytes
            || terminal_bytes.len().saturating_add(1)
                > self.limits.max_output_bytes.saturating_sub(merged.len())
        {
            return Err(ReplayError::CapacityExhausted);
        }
        let mut bundle = merged;
        bundle.extend_from_slice(&terminal_bytes);
        bundle.push(b'\n');
        let normalized = hash("replay-output", &[&bundle]);
        let mut receipt = ReplayReceipt {
            schema_version: REPLAY_RECEIPT_SCHEMA_VERSION.into(),
            run_id: self.run_id.clone(),
            run_seal: seal,
            input_jsonl_digest: merged_digest,
            merkle_root,
            replayed_event_count: ordered.len() as u64,
            decision_mode: "recordedOnly".into(),
            recorded_decision_set_digest: decision_digest,
            projections,
            normalized_output_digest: normalized,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt_digest(&receipt)?;
        let receipt_json =
            canonical(&serde_json::to_value(&receipt).map_err(|_| ReplayError::Malformed)?)?;
        Ok(SealedReplay {
            bundle_jsonl: bundle,
            receipt,
            receipt_json,
        })
    }

    fn validate_producers(&self) -> Result<(), ReplayError> {
        let mut groups: BTreeMap<(String, String, String), Vec<&CausalSourceEvent>> =
            BTreeMap::new();
        for event in self.events.values() {
            let p = &event.event.producer.identity;
            groups
                .entry((
                    kind_name(p.kind).into(),
                    p.id.clone(),
                    p.instance_id.clone(),
                ))
                .or_default()
                .push(event);
        }
        for events in groups.values_mut() {
            events.sort_by_key(|e| e.event.producer.sequence);
            for (expected, event) in events.iter().enumerate() {
                if event.event.producer.sequence != expected as u64 {
                    return Err(ReplayError::SequenceGap);
                }
                let expected_prev = if expected == 0 {
                    None
                } else {
                    Some(events[expected - 1].producer_hash.as_str())
                };
                if event.producer_previous.as_deref() != expected_prev
                    || compute_producer_hash(event)? != event.producer_hash
                {
                    return Err(ReplayError::ProducerChain);
                }
                if expected > 0 && !clock_lt(events[expected - 1], event) {
                    return Err(ReplayError::ClockCausalityViolation);
                }
            }
        }
        Ok(())
    }

    fn topological_order(
        &self,
        unresolved: &BTreeMap<String, Vec<String>>,
    ) -> Result<(Vec<String>, MissingRecords), ReplayError> {
        let mut outgoing: HashMap<String, BTreeSet<String>> = HashMap::new();
        let mut indegree: HashMap<String, usize> =
            self.events.keys().map(|id| (id.clone(), 0)).collect();
        for event in self.events.values() {
            let child = event.event.event_id.clone();
            if event.event.producer.sequence > 0 {
                let p = &event.event.producer.identity;
                let prev = self
                    .slots
                    .get(&(
                        kind_name(p.kind).into(),
                        p.id.clone(),
                        p.instance_id.clone(),
                        event.event.producer.sequence - 1,
                    ))
                    .ok_or(ReplayError::SequenceGap)?;
                add_edge(prev, &child, &mut outgoing, &mut indegree);
            }
            if let CaptureParent::Event(parent) = &event.event.parent
                && self.events.contains_key(parent)
            {
                add_edge(parent, &child, &mut outgoing, &mut indegree);
            }
        }
        let mut ready = BTreeSet::new();
        for (id, degree) in &indegree {
            if *degree == 0 {
                ready.insert(merge_key(&self.events[id]));
            }
        }
        let mut ordered = Vec::with_capacity(self.events.len());
        while let Some(key) = ready.pop_first() {
            let id = key.6.clone();
            ordered.push(id.clone());
            if let Some(children) = outgoing.get(&id) {
                for child in children {
                    let degree = indegree.get_mut(child).ok_or(ReplayError::Malformed)?;
                    *degree -= 1;
                    if *degree == 0 {
                        ready.insert(merge_key(&self.events[child]));
                    }
                }
            }
        }
        if ordered.len() != self.events.len() {
            let mut residual: Vec<_> = indegree
                .into_iter()
                .filter_map(|(id, d)| (d > 0).then_some(id))
                .collect();
            residual.sort();
            return Err(ReplayError::Cycle(residual));
        }
        for event in self.events.values() {
            if let CaptureParent::Event(parent) = &event.event.parent
                && let Some(parent_event) = self.events.get(parent)
                && !clock_lt(parent_event, event)
            {
                return Err(ReplayError::ClockCausalityViolation);
            }
        }
        Ok((
            ordered,
            unresolved
                .iter()
                .map(|(a, b)| (a.clone(), b.clone()))
                .collect(),
        ))
    }
}

/// Serializes a closed, bounded causal-source envelope.
///
/// # Errors
/// Returns an error for malformed events or an over-limit envelope.
pub fn capture_causal_source_jsonl(
    run_id: &str,
    events: &[CausalSourceEvent],
) -> Result<Vec<u8>, ReplayError> {
    if !valid_identifier(run_id) || events.is_empty() || events.len() > MAX_EVENTS {
        return Err(ReplayError::Malformed);
    }
    let mut out = Vec::new();
    for event in events {
        validate_source_event(event, Some(run_id))?;
        let line = object(vec![
            ("event", source_event_value(event)?),
            ("recordType", Value::String("causalEvent".into())),
            ("runId", Value::String(run_id.into())),
            (
                "schemaVersion",
                Value::String(CAUSAL_SOURCE_SCHEMA_VERSION.into()),
            ),
        ]);
        let bytes = canonical(&line)?;
        if bytes.len() > MAX_LINE
            || bytes.len().saturating_add(1) > MAX_BYTES.saturating_sub(out.len())
        {
            return Err(ReplayError::CapacityExhausted);
        }
        out.extend(bytes);
        out.push(b'\n');
    }
    let terminal = canonical(&object(vec![
        ("eventCount", Value::String(events.len().to_string())),
        ("recordType", Value::String("complete".into())),
        ("runId", Value::String(run_id.into())),
        (
            "schemaVersion",
            Value::String(CAUSAL_SOURCE_SCHEMA_VERSION.into()),
        ),
    ]))?;
    if terminal.len().saturating_add(1) > MAX_BYTES.saturating_sub(out.len()) {
        return Err(ReplayError::CapacityExhausted);
    }
    out.extend(terminal);
    out.push(b'\n');
    Ok(out)
}

/// Merges complete source envelopes and derives a sealed replay.
///
/// # Errors
/// Returns an error when admission or final causal validation fails.
pub fn merge_and_seal_jsonl(
    run_id: &str,
    sources: &[&[u8]],
    limits: MergeLimits,
    policy: MissingParentPolicy,
    input: ReplaySealInput,
) -> Result<SealedReplay, ReplayError> {
    let mut merger = CausalMerger::new(run_id, limits, policy)?;
    for source in sources {
        merger.ingest_source_jsonl(source)?;
    }
    merger.finalize(input)
}

/// Fully reconstructs and verifies a closed replay bundle.
///
/// # Errors
/// Returns an error for unsupported schemas, bounds, canonicalization,
/// identities, chains, causal order, missing records, claims, or seal mismatch.
#[allow(clippy::too_many_lines)] // Closed-schema verification is intentionally contiguous.
pub fn verify_sealed_replay(bytes: &[u8]) -> Result<ReplayReceipt, ReplayError> {
    if bytes.len() > MAX_BYTES {
        return Err(ReplayError::CapacityExhausted);
    }
    let lines = strict_lines(bytes, MAX_LINE, MAX_EVENTS.saturating_add(1))?;
    if lines.len() < 2 {
        return Err(ReplayError::Malformed);
    }
    if lines.len() - 1 > MAX_EVENTS {
        return Err(ReplayError::CapacityExhausted);
    }
    let mut values = Vec::with_capacity(lines.len());
    for line in &lines {
        let value: Value = serde_json::from_slice(line).map_err(|_| ReplayError::Malformed)?;
        if canonical(&value)? != *line {
            return Err(ReplayError::Integrity);
        }
        values.push(value);
    }
    let terminal = values
        .last()
        .and_then(Value::as_object)
        .ok_or(ReplayError::Malformed)?;
    exact_keys(terminal, &["claims", "recordType", "sealDigest"])?;
    if terminal.get("recordType").and_then(Value::as_str) != Some("seal") {
        return Err(ReplayError::Malformed);
    }
    let claims = terminal.get("claims").ok_or(ReplayError::Malformed)?;
    let claims_bytes = canonical(claims)?;
    let seal = terminal
        .get("sealDigest")
        .and_then(Value::as_str)
        .ok_or(ReplayError::Malformed)?;
    if hash("run-seal", &[&claims_bytes]) != seal {
        return Err(ReplayError::Integrity);
    }
    let claims_obj = claims.as_object().ok_or(ReplayError::Malformed)?;
    exact_keys(
        claims_obj,
        &[
            "artifactManifestDigest",
            "canonicalization",
            "eventCount",
            "hashFraming",
            "mergedJsonlDigest",
            "merkleRoot",
            "missingParents",
            "producerHeads",
            "projections",
            "recordCount",
            "recordedDecisionSetDigest",
            "runId",
            "schemaVersion",
        ],
    )?;
    if claims_obj.get("schemaVersion").and_then(Value::as_str)
        != Some(FULL_MATRIX_REPLAY_SCHEMA_VERSION)
    {
        return Err(ReplayError::UnsupportedSchema);
    }
    if claims_obj.get("canonicalization").and_then(Value::as_str) != Some(CANONICALIZATION)
        || claims_obj.get("hashFraming").and_then(Value::as_str)
            != Some("SMESH-A2A-length-prefixed-v1")
    {
        return Err(ReplayError::Integrity);
    }
    let run_id = claims_obj
        .get("runId")
        .and_then(Value::as_str)
        .ok_or(ReplayError::Malformed)?;
    if !valid_identifier(run_id) {
        return Err(ReplayError::InvalidIdentifier);
    }
    validate_digest(
        claims_obj
            .get("artifactManifestDigest")
            .and_then(Value::as_str)
            .ok_or(ReplayError::Malformed)?,
    )?;
    let data_lines = &lines[..lines.len() - 1];
    let mut merged_bytes = Vec::new();
    for line in data_lines {
        merged_bytes.extend_from_slice(line);
        merged_bytes.push(b'\n');
    }
    if claims_obj.get("mergedJsonlDigest").and_then(Value::as_str)
        != Some(hash("merged-jsonl", &[&merged_bytes]).as_str())
        || claims_obj.get("merkleRoot").and_then(Value::as_str)
            != Some(merkle_root(data_lines)?.as_str())
        || claims_obj.get("recordCount").and_then(Value::as_str)
            != Some(data_lines.len().to_string().as_str())
    {
        return Err(ReplayError::Integrity);
    }
    let event_count = decimal_value(claims_obj.get("eventCount"))?;
    let actual_events = values[..values.len() - 1]
        .iter()
        .filter(|v| v.get("recordType").and_then(Value::as_str) == Some("event"))
        .count() as u64;
    if event_count != actual_events {
        return Err(ReplayError::Integrity);
    }
    let mut projections: Vec<ProjectionReceipt> = serde_json::from_value(
        claims_obj
            .get("projections")
            .cloned()
            .ok_or(ReplayError::Malformed)?,
    )
    .map_err(|_| ReplayError::Malformed)?;
    validate_projections(&mut projections).map_err(|_| ReplayError::Integrity)?;
    let merged_digest = claims_obj
        .get("mergedJsonlDigest")
        .and_then(Value::as_str)
        .ok_or(ReplayError::Malformed)?;
    if projections
        .iter()
        .any(|projection| projection.input_digest != merged_digest)
    {
        return Err(ReplayError::Integrity);
    }
    let mut merger =
        CausalMerger::new(run_id, MergeLimits::default(), MissingParentPolicy::Record)?;
    let mut saw_event = false;
    let mut expected_merge_sequence = 0_u64;
    for value in &values[..values.len() - 1] {
        let object = value.as_object().ok_or(ReplayError::Malformed)?;
        match object.get("recordType").and_then(Value::as_str) {
            Some("missingParent") => {
                if saw_event {
                    return Err(ReplayError::Integrity);
                }
                exact_keys(
                    object,
                    &["children", "expectedEventId", "recordId", "recordType"],
                )?;
                let expected_id = string(object, "expectedEventId")?;
                validate_digest(expected_id)?;
                if string(object, "recordId")?
                    != hash(
                        "missing-parent",
                        &[run_id.as_bytes(), expected_id.as_bytes()],
                    )
                {
                    return Err(ReplayError::Integrity);
                }
                let children = object
                    .get("children")
                    .and_then(Value::as_array)
                    .ok_or(ReplayError::Malformed)?;
                let parsed: Vec<&str> = children
                    .iter()
                    .map(|child| child.as_str().ok_or(ReplayError::Malformed))
                    .collect::<Result<_, _>>()?;
                if parsed.is_empty()
                    || parsed.windows(2).any(|pair| pair[0] >= pair[1])
                    || parsed.iter().any(|child| decode_digest(child).is_err())
                {
                    return Err(ReplayError::Integrity);
                }
            }
            Some("event") => {
                saw_event = true;
                exact_keys(object, &["causal", "mergeSequence", "recordType"])?;
                if decimal_value(object.get("mergeSequence"))? != expected_merge_sequence {
                    return Err(ReplayError::Integrity);
                }
                expected_merge_sequence += 1;
                let source =
                    parse_source_event(object.get("causal").ok_or(ReplayError::Malformed)?)?;
                validate_source_event(&source, Some(run_id))?;
                let id = source.event.event_id.clone();
                if merger.events.contains_key(&id) {
                    return Err(ReplayError::DuplicateConflict);
                }
                if merger.missing_claims.contains(&id) {
                    return Err(ReplayError::MissingClaimConflict);
                }
                if let CaptureParent::Missing {
                    expected_event_id, ..
                } = &source.event.parent
                    && merger.events.contains_key(expected_event_id)
                {
                    return Err(ReplayError::MissingClaimConflict);
                }
                let slot = producer_slot(&source);
                if merger.slots.insert(slot, id.clone()).is_some() {
                    return Err(ReplayError::SequenceGap);
                }
                if let CaptureParent::Missing {
                    expected_event_id, ..
                } = &source.event.parent
                {
                    merger.missing_claims.insert(expected_event_id.clone());
                }
                merger.events.insert(id, source);
            }
            _ => return Err(ReplayError::Malformed),
        }
    }
    if expected_merge_sequence != event_count {
        return Err(ReplayError::Integrity);
    }
    let rebuilt = merger.finalize(ReplaySealInput {
        artifact_manifest_digest: string(claims_obj, "artifactManifestDigest")?.into(),
        projections,
    })?;
    if rebuilt.bundle_jsonl() != bytes {
        return Err(ReplayError::Integrity);
    }
    Ok(rebuilt.receipt().clone())
}

/// Verifies supplied receipt bytes against a reconstructed bundle and pin.
///
/// # Errors
/// Returns an error for malformed/canonical receipt bytes, any bundle mismatch,
/// or a supplied seal pin that does not equal the verified run seal.
pub fn verify_replay_receipt(
    bundle: &[u8],
    receipt_bytes: &[u8],
    pinned_seal: Option<&str>,
) -> Result<ReplayReceipt, ReplayError> {
    if receipt_bytes.is_empty() || receipt_bytes.len() > MAX_BYTES {
        return Err(ReplayError::CapacityExhausted);
    }
    let value: Value = serde_json::from_slice(receipt_bytes).map_err(|_| ReplayError::Malformed)?;
    if canonical(&value)? != receipt_bytes {
        return Err(ReplayError::Integrity);
    }
    let receipt: ReplayReceipt =
        serde_json::from_value(value).map_err(|_| ReplayError::Malformed)?;
    if receipt.schema_version != REPLAY_RECEIPT_SCHEMA_VERSION
        || receipt.decision_mode != "recordedOnly"
        || !valid_identifier(&receipt.run_id)
        || decode_digest(&receipt.run_seal).is_err()
        || decode_digest(&receipt.input_jsonl_digest).is_err()
        || decode_digest(&receipt.merkle_root).is_err()
        || decode_digest(&receipt.recorded_decision_set_digest).is_err()
        || decode_digest(&receipt.normalized_output_digest).is_err()
        || decode_digest(&receipt.receipt_digest).is_err()
        || receipt_digest(&receipt)? != receipt.receipt_digest
    {
        return Err(ReplayError::Integrity);
    }
    if let Some(expected) = pinned_seal {
        validate_digest(expected)?;
        if receipt.run_seal != expected {
            return Err(ReplayError::Integrity);
        }
    }
    let expected = verify_sealed_replay(bundle)?;
    if receipt != expected {
        return Err(ReplayError::Integrity);
    }
    Ok(receipt)
}

fn parse_source(
    bytes: &[u8],
    run_id: &str,
    max_line: usize,
    max_events: usize,
) -> Result<Vec<CausalSourceEvent>, ReplayError> {
    let lines = strict_lines(bytes, max_line, max_events.saturating_add(1))?;
    if lines.len() < 2 {
        return Err(ReplayError::Malformed);
    }
    let mut events = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let value: Value = serde_json::from_slice(line).map_err(|_| ReplayError::Malformed)?;
        if canonical(&value)? != *line {
            return Err(ReplayError::Malformed);
        }
        let obj = value.as_object().ok_or(ReplayError::Malformed)?;
        let record_type = obj
            .get("recordType")
            .and_then(Value::as_str)
            .ok_or(ReplayError::Malformed)?;
        if obj.get("schemaVersion").and_then(Value::as_str) != Some(CAUSAL_SOURCE_SCHEMA_VERSION) {
            return Err(ReplayError::UnsupportedSchema);
        }
        if obj.get("runId").and_then(Value::as_str) != Some(run_id) {
            return Err(ReplayError::InvalidIdentifier);
        }
        if index + 1 == lines.len() {
            exact_keys(obj, &["eventCount", "recordType", "runId", "schemaVersion"])?;
            if record_type != "complete"
                || decimal_value(obj.get("eventCount"))? != events.len() as u64
            {
                return Err(ReplayError::Malformed);
            }
        } else {
            exact_keys(obj, &["event", "recordType", "runId", "schemaVersion"])?;
            if record_type != "causalEvent" {
                return Err(ReplayError::Malformed);
            }
            events.push(parse_source_event(
                obj.get("event").ok_or(ReplayError::Malformed)?,
            )?);
        }
    }
    if events.is_empty() {
        return Err(ReplayError::Malformed);
    }
    Ok(events)
}

fn source_event_value(source: &CausalSourceEvent) -> Result<Value, ReplayError> {
    let event = event_value(&source.event);
    Ok(object(vec![
        ("event", event),
        (
            "hlc",
            serde_json::to_value(source.hlc).map_err(|_| ReplayError::Malformed)?,
        ),
        ("lamport", Value::String(source.lamport.to_string())),
        ("producerHash", Value::String(source.producer_hash.clone())),
        (
            "producerPrevious",
            source
                .producer_previous
                .clone()
                .map_or(Value::Null, Value::String),
        ),
        (
            "recordedDecision",
            source.recorded_decision.clone().unwrap_or(Value::Null),
        ),
    ]))
}

fn parse_source_event(value: &Value) -> Result<CausalSourceEvent, ReplayError> {
    let obj = value.as_object().ok_or(ReplayError::Malformed)?;
    exact_keys(
        obj,
        &[
            "event",
            "hlc",
            "lamport",
            "producerHash",
            "producerPrevious",
            "recordedDecision",
        ],
    )?;
    let event = parse_event(obj.get("event").ok_or(ReplayError::Malformed)?)?;
    let hlc: HybridLogicalClock =
        serde_json::from_value(obj.get("hlc").cloned().ok_or(ReplayError::Malformed)?)
            .map_err(|_| ReplayError::Malformed)?;
    let lamport = decimal_value(obj.get("lamport"))?;
    let producer_previous = match obj.get("producerPrevious") {
        Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        _ => return Err(ReplayError::Malformed),
    };
    let recorded_decision = match obj.get("recordedDecision") {
        Some(Value::Null) => None,
        Some(v) => Some(v.clone()),
        None => return Err(ReplayError::Malformed),
    };
    Ok(CausalSourceEvent {
        event,
        hlc,
        lamport,
        recorded_decision,
        producer_previous,
        producer_hash: obj
            .get("producerHash")
            .and_then(Value::as_str)
            .ok_or(ReplayError::Malformed)?
            .into(),
    })
}

fn event_value(event: &CaptureEvent) -> Value {
    let p = &event.producer.identity;
    let parent = match &event.parent {
        CaptureParent::Root => object(vec![("kind", Value::String("root".into()))]),
        CaptureParent::Event(id) => object(vec![
            ("eventId", Value::String(id.clone())),
            ("kind", Value::String("event".into())),
        ]),
        CaptureParent::Missing {
            expected_event_id,
            reason,
        } => object(vec![
            ("expectedEventId", Value::String(expected_event_id.clone())),
            ("kind", Value::String("missing".into())),
            ("reason", Value::String(gap_name(*reason).into())),
        ]),
    };
    object(vec![
        (
            "content",
            object(vec![
                (
                    "byteLength",
                    Value::String(event.content.byte_length.to_string()),
                ),
                ("digest", Value::String(event.content.digest.clone())),
            ]),
        ),
        ("contextId", option_string(event.context_id.as_deref())),
        ("eventId", Value::String(event.event_id.clone())),
        ("interactionId", Value::String(event.interaction_id.clone())),
        ("kind", Value::String(capture_kind_name(event.kind).into())),
        ("parent", parent),
        ("peerId", Value::String(event.peer_id.clone())),
        (
            "producer",
            object(vec![
                ("id", Value::String(p.id.clone())),
                ("instanceId", Value::String(p.instance_id.clone())),
                ("kind", Value::String(kind_name(p.kind).into())),
                (
                    "sourceSequence",
                    Value::String(event.producer.sequence.to_string()),
                ),
            ]),
        ),
        ("sourceSequence", Value::String(event.sequence.to_string())),
        ("subjectId", option_string(event.subject_id.as_deref())),
        ("taskId", option_string(event.task_id.as_deref())),
    ])
}

fn parse_event(value: &Value) -> Result<CaptureEvent, ReplayError> {
    let o = value.as_object().ok_or(ReplayError::Malformed)?;
    exact_keys(
        o,
        &[
            "content",
            "contextId",
            "eventId",
            "interactionId",
            "kind",
            "parent",
            "peerId",
            "producer",
            "sourceSequence",
            "subjectId",
            "taskId",
        ],
    )?;
    let po = o
        .get("producer")
        .and_then(Value::as_object)
        .ok_or(ReplayError::Malformed)?;
    exact_keys(po, &["id", "instanceId", "kind", "sourceSequence"])?;
    let kind = parse_producer_kind(string(po, "kind")?)?;
    let identity = crate::ProducerIdentity::new(kind, string(po, "id")?, string(po, "instanceId")?)
        .map_err(|_| ReplayError::InvalidIdentifier)?;
    let content = o
        .get("content")
        .and_then(Value::as_object)
        .ok_or(ReplayError::Malformed)?;
    exact_keys(content, &["byteLength", "digest"])?;
    let parent_o = o
        .get("parent")
        .and_then(Value::as_object)
        .ok_or(ReplayError::Malformed)?;
    let parent = match string(parent_o, "kind")? {
        "root" => {
            exact_keys(parent_o, &["kind"])?;
            CaptureParent::Root
        }
        "event" => {
            exact_keys(parent_o, &["eventId", "kind"])?;
            CaptureParent::Event(string(parent_o, "eventId")?.into())
        }
        "missing" => {
            exact_keys(parent_o, &["expectedEventId", "kind", "reason"])?;
            CaptureParent::Missing {
                expected_event_id: string(parent_o, "expectedEventId")?.into(),
                reason: parse_gap(string(parent_o, "reason")?)?,
            }
        }
        _ => return Err(ReplayError::Malformed),
    };
    let event = CaptureEvent {
        event_id: string(o, "eventId")?.into(),
        sequence: decimal_value(o.get("sourceSequence"))?,
        producer: crate::CaptureProducer {
            identity,
            sequence: decimal_value(po.get("sourceSequence"))?,
        },
        kind: parse_capture_kind(string(o, "kind")?)?,
        interaction_id: string(o, "interactionId")?.into(),
        peer_id: string(o, "peerId")?.into(),
        task_id: optional_string(o.get("taskId"))?,
        context_id: optional_string(o.get("contextId"))?,
        subject_id: optional_string(o.get("subjectId"))?,
        parent,
        content: crate::CapturedContent {
            digest: string(content, "digest")?.into(),
            byte_length: decimal_value(content.get("byteLength"))?,
        },
    };
    validate_event(&event, None)?;
    Ok(event)
}

fn merged_record(source: &CausalSourceEvent, sequence: usize) -> Result<Value, ReplayError> {
    Ok(object(vec![
        ("causal", source_event_value(source)?),
        ("mergeSequence", Value::String(sequence.to_string())),
        ("recordType", Value::String("event".into())),
    ]))
}
fn missing_record(run: &str, id: &str, children: &[String]) -> Value {
    object(vec![
        (
            "children",
            Value::Array(children.iter().cloned().map(Value::String).collect()),
        ),
        ("expectedEventId", Value::String(id.into())),
        (
            "recordId",
            Value::String(hash("missing-parent", &[run.as_bytes(), id.as_bytes()])),
        ),
        ("recordType", Value::String("missingParent".into())),
    ])
}
fn missing_claims_value(records: &[(String, Vec<String>)]) -> Value {
    Value::Array(
        records
            .iter()
            .map(|(id, c)| {
                object(vec![
                    (
                        "children",
                        Value::Array(c.iter().cloned().map(Value::String).collect()),
                    ),
                    ("expectedEventId", Value::String(id.clone())),
                ])
            })
            .collect(),
    )
}

fn unresolved_map(events: &HashMap<String, CausalSourceEvent>) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for event in events.values() {
        if let CaptureParent::Event(parent) = &event.event.parent
            && !events.contains_key(parent)
        {
            out.entry(parent.clone())
                .or_default()
                .push(event.event.event_id.clone());
        }
    }
    for c in out.values_mut() {
        c.sort();
        c.dedup();
    }
    out
}
fn add_edge(
    parent: &str,
    child: &str,
    out: &mut HashMap<String, BTreeSet<String>>,
    indegree: &mut HashMap<String, usize>,
) {
    if out.entry(parent.into()).or_default().insert(child.into()) {
        *indegree.get_mut(child).expect("known child") += 1;
    }
}

type MergeKey = (u64, u64, String, String, String, u64, String);
type MissingRecords = Vec<(String, Vec<String>)>;
fn merge_key(e: &CausalSourceEvent) -> MergeKey {
    let p = &e.event.producer.identity;
    (
        e.hlc.physical_ns,
        e.hlc.logical,
        kind_name(p.kind).into(),
        p.id.clone(),
        p.instance_id.clone(),
        e.event.producer.sequence,
        e.event.event_id.clone(),
    )
}
fn clock_lt(a: &CausalSourceEvent, b: &CausalSourceEvent) -> bool {
    (a.hlc.physical_ns, a.hlc.logical) < (b.hlc.physical_ns, b.hlc.logical) && a.lamport < b.lamport
}
fn producer_slot(e: &CausalSourceEvent) -> (String, String, String, u64) {
    let p = &e.event.producer.identity;
    (
        kind_name(p.kind).into(),
        p.id.clone(),
        p.instance_id.clone(),
        e.event.producer.sequence,
    )
}

fn producer_heads(events: &HashMap<String, CausalSourceEvent>) -> Result<Vec<Value>, ReplayError> {
    let mut groups: BTreeMap<(String, String, String), Vec<&CausalSourceEvent>> = BTreeMap::new();
    for e in events.values() {
        let p = &e.event.producer.identity;
        groups
            .entry((
                kind_name(p.kind).into(),
                p.id.clone(),
                p.instance_id.clone(),
            ))
            .or_default()
            .push(e);
    }
    let mut out = Vec::new();
    for ((kind, id, instance), mut es) in groups {
        es.sort_by_key(|e| e.event.producer.sequence);
        let head = es.last().ok_or(ReplayError::Malformed)?;
        out.push(object(vec![
            ("eventCount", Value::String(es.len().to_string())),
            ("headHash", Value::String(head.producer_hash.clone())),
            ("producerId", Value::String(id)),
            ("producerInstanceId", Value::String(instance)),
            ("producerKind", Value::String(kind)),
        ]));
    }
    Ok(out)
}

fn compute_producer_hash(source: &CausalSourceEvent) -> Result<String, ReplayError> {
    let previous = source
        .producer_previous
        .as_ref()
        .map_or(Ok([0u8; 32]), |s| decode_digest(s))?;
    let core = source_core(source)?;
    Ok(hash("producer-chain", &[&previous, &core]))
}
fn source_core(source: &CausalSourceEvent) -> Result<Vec<u8>, ReplayError> {
    let mut out = CanonicalBuffer::new(MAX_LINE);
    out.extend(b"{\"event\":")?;
    write_canonical(&event_value(&source.event), &mut out, 1)?;
    out.extend(b",\"hlc\":")?;
    write_canonical(
        &serde_json::to_value(source.hlc).map_err(|_| ReplayError::Malformed)?,
        &mut out,
        1,
    )?;
    out.extend(b",\"lamport\":")?;
    write_canonical(&Value::String(source.lamport.to_string()), &mut out, 1)?;
    out.extend(b",\"recordedDecision\":")?;
    write_canonical(
        source.recorded_decision.as_ref().unwrap_or(&Value::Null),
        &mut out,
        1,
    )?;
    out.extend(b"}")?;
    Ok(out.into_inner())
}
fn canonical_source_event(source: &CausalSourceEvent) -> Result<Vec<u8>, ReplayError> {
    let mut out = CanonicalBuffer::new(MAX_LINE);
    out.extend(b"{\"event\":")?;
    write_canonical(&event_value(&source.event), &mut out, 1)?;
    out.extend(b",\"hlc\":")?;
    write_canonical(
        &serde_json::to_value(source.hlc).map_err(|_| ReplayError::Malformed)?,
        &mut out,
        1,
    )?;
    out.extend(b",\"lamport\":")?;
    write_canonical(&Value::String(source.lamport.to_string()), &mut out, 1)?;
    out.extend(b",\"producerHash\":")?;
    write_canonical(&Value::String(source.producer_hash.clone()), &mut out, 1)?;
    out.extend(b",\"producerPrevious\":")?;
    write_canonical(
        &source
            .producer_previous
            .as_ref()
            .map_or(Value::Null, |value| Value::String(value.clone())),
        &mut out,
        1,
    )?;
    out.extend(b",\"recordedDecision\":")?;
    write_canonical(
        source.recorded_decision.as_ref().unwrap_or(&Value::Null),
        &mut out,
        1,
    )?;
    out.extend(b"}")?;
    Ok(out.into_inner())
}

fn merkle_root<T: AsRef<[u8]>>(lines: &[T]) -> Result<String, ReplayError> {
    if lines.is_empty() {
        return Err(ReplayError::Malformed);
    }
    let mut level: Vec<[u8; 32]> = lines
        .iter()
        .map(|line| hash_raw("merkle-leaf", &[line.as_ref()]))
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            if pair.len() == 1 {
                next.push(pair[0]);
            } else {
                next.push(hash_raw("merkle-node", &[&pair[0], &pair[1]]));
            }
        }
        level = next;
    }
    Ok(format_digest(&level[0]))
}

fn receipt_digest(r: &ReplayReceipt) -> Result<String, ReplayError> {
    let mut v = serde_json::to_value(r).map_err(|_| ReplayError::Malformed)?;
    v.as_object_mut()
        .ok_or(ReplayError::Malformed)?
        .remove("receiptDigest");
    Ok(hash("replay-receipt", &[&canonical(&v)?]))
}
fn validate_projections(p: &mut [ProjectionReceipt]) -> Result<(), ReplayError> {
    if p.len() > MAX_PROJECTIONS
        || p.iter().fold(0_usize, |total, projection| {
            total
                .saturating_add(projection.projector_id.len())
                .saturating_add(projection.projector_version.len())
                .saturating_add(projection.input_digest.len())
                .saturating_add(projection.output_digest.len())
        }) > MAX_BYTES
    {
        return Err(ReplayError::CapacityExhausted);
    }
    for x in p.iter() {
        if !valid_identifier(&x.projector_id)
            || !valid_identifier(&x.projector_version)
            || decode_digest(&x.input_digest).is_err()
            || decode_digest(&x.output_digest).is_err()
        {
            return Err(ReplayError::ProjectionMismatch);
        }
    }
    p.sort_by(|a, b| {
        (&a.projector_id, &a.projector_version).cmp(&(&b.projector_id, &b.projector_version))
    });
    if p.windows(2).any(|w| {
        w[0].projector_id == w[1].projector_id && w[0].projector_version == w[1].projector_version
    }) {
        return Err(ReplayError::ProjectionMismatch);
    }
    Ok(())
}

fn validate_source_event(s: &CausalSourceEvent, run_id: Option<&str>) -> Result<(), ReplayError> {
    validate_event(&s.event, run_id)?;
    if let Some(v) = &s.recorded_decision {
        canonical_bounded(v, MAX_LINE)?;
    }
    decode_digest(&s.producer_hash)?;
    if let Some(p) = &s.producer_previous {
        decode_digest(p)?;
    }
    if s.event.producer.sequence == 0 && s.producer_previous.is_some()
        || s.event.producer.sequence > 0 && s.producer_previous.is_none()
    {
        return Err(ReplayError::ProducerChain);
    }
    if compute_producer_hash(s)? != s.producer_hash {
        return Err(ReplayError::ProducerChain);
    }
    Ok(())
}
fn validate_event(e: &CaptureEvent, run_id: Option<&str>) -> Result<(), ReplayError> {
    validate_digest(&e.event_id)?;
    validate_digest(&e.content.digest)?;
    if !valid_identifier(&e.interaction_id)
        || !valid_identifier(&e.peer_id)
        || !valid_identifier(&e.producer.identity.id)
        || !valid_identifier(&e.producer.identity.instance_id)
        || e.task_id.as_deref().is_some_and(|id| !valid_identifier(id))
        || e.context_id
            .as_deref()
            .is_some_and(|id| !valid_identifier(id))
        || e.subject_id
            .as_deref()
            .is_some_and(|id| !valid_identifier(id))
    {
        return Err(ReplayError::InvalidIdentifier);
    }
    match &e.parent {
        CaptureParent::Event(id) => {
            validate_digest(id)?;
            if id == &e.event_id {
                return Err(ReplayError::Cycle(vec![id.clone()]));
            }
        }
        CaptureParent::Missing {
            expected_event_id, ..
        } => validate_digest(expected_event_id)?,
        CaptureParent::Root => {}
    }
    let kind_matches = matches!(
        (e.producer.identity.kind, e.kind),
        (
            ProducerKind::A2a,
            crate::CaptureKind::A2aSend | crate::CaptureKind::A2aReceive
        ) | (
            ProducerKind::Smesh,
            crate::CaptureKind::SmeshSignalEmitted
                | crate::CaptureKind::SmeshSignalSent
                | crate::CaptureKind::SmeshSignalReinforced
                | crate::CaptureKind::SmeshSignalReceived
                | crate::CaptureKind::SmeshSignalExpired
                | crate::CaptureKind::SmeshTickCompleted
                | crate::CaptureKind::SmeshPeerConnected
                | crate::CaptureKind::SmeshPeerDisconnected
        ) | (
            ProducerKind::Tool,
            crate::CaptureKind::ToolCall
                | crate::CaptureKind::ToolResult
                | crate::CaptureKind::ToolFailed
        ) | (
            ProducerKind::Artifact,
            crate::CaptureKind::ArtifactProduced | crate::CaptureKind::ArtifactConsumed
        ) | (
            ProducerKind::Human,
            crate::CaptureKind::HumanPrompt
                | crate::CaptureKind::HumanDecision
                | crate::CaptureKind::HumanFailed
        )
    );
    if !kind_matches {
        return Err(ReplayError::Malformed);
    }
    if let Some(run_id) = run_id {
        let expected = crate::full_matrix_capture::capture_event_id(
            run_id,
            &e.producer.identity,
            e.producer.sequence,
            e.kind,
            &e.interaction_id,
            &e.peer_id,
            e.task_id.as_deref(),
            e.context_id.as_deref(),
            e.subject_id.as_deref(),
            &e.parent,
            &e.content,
        );
        if e.event_id != expected {
            return Err(ReplayError::InvalidIdentifier);
        }
    }
    Ok(())
}
fn strict_lines(
    bytes: &[u8],
    max_line: usize,
    max_lines: usize,
) -> Result<Vec<&[u8]>, ReplayError> {
    if bytes.is_empty()
        || bytes.last() != Some(&b'\n')
        || bytes.contains(&b'\r')
        || bytes.starts_with(&[0xef, 0xbb, 0xbf])
    {
        return Err(ReplayError::Malformed);
    }
    let mut out = Vec::new();
    for line in bytes[..bytes.len() - 1].split(|b| *b == b'\n') {
        if out.len() == max_lines {
            return Err(ReplayError::CapacityExhausted);
        }
        if line.is_empty() || line.len() > max_line {
            return Err(ReplayError::Malformed);
        }
        out.push(line);
    }
    Ok(out)
}

fn canonical(v: &Value) -> Result<Vec<u8>, ReplayError> {
    canonical_bounded(v, MAX_BYTES)
}

fn canonical_bounded(v: &Value, limit: usize) -> Result<Vec<u8>, ReplayError> {
    let mut out = CanonicalBuffer::new(limit);
    write_canonical(v, &mut out, 0)?;
    Ok(out.into_inner())
}

struct CanonicalBuffer {
    bytes: Vec<u8>,
    limit: usize,
    capacity_exhausted: bool,
}

impl CanonicalBuffer {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            capacity_exhausted: false,
        }
    }

    fn extend(&mut self, bytes: &[u8]) -> Result<(), ReplayError> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.capacity_exhausted = true;
            return Err(ReplayError::CapacityExhausted);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl std::io::Write for CanonicalBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.extend(bytes)
            .map_err(|_| std::io::Error::other("canonical capacity exhausted"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn append_bounded_line(
    lines: &mut Vec<Vec<u8>>,
    merged: &mut Vec<u8>,
    line: Vec<u8>,
    max_line_bytes: usize,
    max_output_bytes: usize,
) -> Result<(), ReplayError> {
    if line.len() > max_line_bytes
        || line.len().saturating_add(1) > max_output_bytes.saturating_sub(merged.len())
    {
        return Err(ReplayError::CapacityExhausted);
    }
    merged.extend_from_slice(&line);
    merged.push(b'\n');
    lines.push(line);
    Ok(())
}

fn write_canonical(v: &Value, out: &mut CanonicalBuffer, depth: usize) -> Result<(), ReplayError> {
    if depth > MAX_CANONICAL_DEPTH {
        return Err(ReplayError::Malformed);
    }
    match v {
        Value::Null => out.extend(b"null")?,
        Value::Bool(b) => out.extend(if *b { &b"true"[..] } else { &b"false"[..] })?,
        Value::String(s) => serde_json::to_writer(&mut *out, s).map_err(|error| {
            if out.capacity_exhausted {
                ReplayError::CapacityExhausted
            } else {
                let _ = error;
                ReplayError::Malformed
            }
        })?,
        Value::Array(a) => {
            out.extend(b"[")?;
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.extend(b",")?;
                }
                write_canonical(x, out, depth + 1)?;
            }
            out.extend(b"]")?;
        }
        Value::Object(o) => {
            out.extend(b"{")?;
            if o.len() > out.limit.saturating_sub(out.bytes.len()) / 4 {
                return Err(ReplayError::CapacityExhausted);
            }
            let mut keys: Vec<_> = o.keys().collect();
            keys.sort_by(|a, b| utf16_cmp(a, b));
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.extend(b",")?;
                }
                serde_json::to_writer(&mut *out, *k).map_err(|_| ReplayError::CapacityExhausted)?;
                out.extend(b":")?;
                write_canonical(&o[*k], out, depth + 1)?;
            }
            out.extend(b"}")?;
        }
        Value::Number(_) => return Err(ReplayError::Malformed),
    }
    Ok(())
}

fn drop_json_value_iteratively(value: Value) {
    enum Children {
        Array(std::vec::IntoIter<Value>),
        Object(serde_json::map::IntoIter),
    }

    impl Children {
        fn next(&mut self) -> Option<Value> {
            match self {
                Self::Array(values) => values.next(),
                Self::Object(values) => values.next().map(|(_, value)| value),
            }
        }
    }

    let mut pending = Some(value);
    let mut ancestors = Vec::new();
    loop {
        if let Some(value) = pending.take() {
            match value {
                Value::Array(values) => ancestors.push(Children::Array(values.into_iter())),
                Value::Object(values) => ancestors.push(Children::Object(values.into_iter())),
                _ => {}
            }
        }
        match ancestors.last_mut().and_then(Children::next) {
            Some(value) => pending = Some(value),
            None if ancestors.pop().is_some() => {}
            None => break,
        }
    }
}
fn utf16_cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}
fn object(entries: Vec<(&str, Value)>) -> Value {
    Value::Object(entries.into_iter().map(|(k, v)| (k.into(), v)).collect())
}
fn exact_keys(o: &Map<String, Value>, keys: &[&str]) -> Result<(), ReplayError> {
    if o.len() != keys.len() || !keys.iter().all(|k| o.contains_key(*k)) {
        Err(ReplayError::Malformed)
    } else {
        Ok(())
    }
}
fn string<'a>(o: &'a Map<String, Value>, k: &str) -> Result<&'a str, ReplayError> {
    o.get(k)
        .and_then(Value::as_str)
        .ok_or(ReplayError::Malformed)
}
fn optional_string(v: Option<&Value>) -> Result<Option<String>, ReplayError> {
    match v {
        Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        _ => Err(ReplayError::Malformed),
    }
}
fn option_string(v: Option<&str>) -> Value {
    v.map_or(Value::Null, |value| Value::String(value.into()))
}
fn decimal_value(v: Option<&Value>) -> Result<u64, ReplayError> {
    let s = v.and_then(Value::as_str).ok_or(ReplayError::Malformed)?;
    if s != "0" && (s.starts_with('0') || s.is_empty()) || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ReplayError::Malformed);
    }
    s.parse().map_err(|_| ReplayError::Malformed)
}
fn valid_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':' | b'/'))
}
fn validate_digest(s: &str) -> Result<(), ReplayError> {
    decode_digest(s).map(|_| ())
}
fn decode_digest(s: &str) -> Result<[u8; 32], ReplayError> {
    let h = s
        .strip_prefix("sha256:")
        .ok_or(ReplayError::InvalidIdentifier)?;
    if h.len() != 64
        || !h
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ReplayError::InvalidIdentifier);
    }
    let mut out = [0; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16)
            .map_err(|_| ReplayError::InvalidIdentifier)?;
    }
    Ok(out)
}
fn format_digest(d: &[u8; 32]) -> String {
    let mut s = String::with_capacity(71);
    s.push_str("sha256:");
    for b in d {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}
fn hash(label: &str, parts: &[&[u8]]) -> String {
    format_digest(&hash_raw(label, parts))
}
fn hash_raw(label: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"SMESH-A2A\0");
    h.update(label.as_bytes());
    h.update(b"\0v1\0");
    for p in parts {
        h.update((p.len() as u64).to_be_bytes());
        h.update(p);
    }
    h.finalize().into()
}

fn kind_name(k: ProducerKind) -> &'static str {
    match k {
        ProducerKind::A2a => "a2a",
        ProducerKind::Smesh => "smesh",
        ProducerKind::Tool => "tool",
        ProducerKind::Artifact => "artifact",
        ProducerKind::Human => "human",
    }
}
fn parse_producer_kind(s: &str) -> Result<ProducerKind, ReplayError> {
    match s {
        "a2a" => Ok(ProducerKind::A2a),
        "smesh" => Ok(ProducerKind::Smesh),
        "tool" => Ok(ProducerKind::Tool),
        "artifact" => Ok(ProducerKind::Artifact),
        "human" => Ok(ProducerKind::Human),
        _ => Err(ReplayError::Malformed),
    }
}
fn gap_name(r: CaptureGapReason) -> &'static str {
    match r {
        CaptureGapReason::ExternalBoundary => "externalBoundary",
        CaptureGapReason::CaptureStartedLate => "captureStartedLate",
        CaptureGapReason::ProducerRestart => "producerRestart",
    }
}
fn parse_gap(s: &str) -> Result<CaptureGapReason, ReplayError> {
    match s {
        "externalBoundary" => Ok(CaptureGapReason::ExternalBoundary),
        "captureStartedLate" => Ok(CaptureGapReason::CaptureStartedLate),
        "producerRestart" => Ok(CaptureGapReason::ProducerRestart),
        _ => Err(ReplayError::Malformed),
    }
}
fn capture_kind_name(k: crate::CaptureKind) -> &'static str {
    #[allow(clippy::enum_glob_use)] // Exhaustive variant table is clearer without prefixes.
    use crate::CaptureKind::*;
    match k {
        A2aSend => "a2aSend",
        A2aReceive => "a2aReceive",
        SmeshSignalEmitted => "smeshSignalEmitted",
        SmeshSignalSent => "smeshSignalSent",
        SmeshSignalReinforced => "smeshSignalReinforced",
        SmeshSignalReceived => "smeshSignalReceived",
        SmeshSignalExpired => "smeshSignalExpired",
        SmeshTickCompleted => "smeshTickCompleted",
        SmeshPeerConnected => "smeshPeerConnected",
        SmeshPeerDisconnected => "smeshPeerDisconnected",
        ToolCall => "toolCall",
        ToolResult => "toolResult",
        ToolFailed => "toolFailed",
        ArtifactProduced => "artifactProduced",
        ArtifactConsumed => "artifactConsumed",
        HumanPrompt => "humanPrompt",
        HumanDecision => "humanDecision",
        HumanFailed => "humanFailed",
    }
}
fn parse_capture_kind(s: &str) -> Result<crate::CaptureKind, ReplayError> {
    #[allow(clippy::enum_glob_use)] // Mirrors the exhaustive wire-name table above.
    use crate::CaptureKind::*;
    match s {
        "a2aSend" => Ok(A2aSend),
        "a2aReceive" => Ok(A2aReceive),
        "smeshSignalEmitted" => Ok(SmeshSignalEmitted),
        "smeshSignalSent" => Ok(SmeshSignalSent),
        "smeshSignalReinforced" => Ok(SmeshSignalReinforced),
        "smeshSignalReceived" => Ok(SmeshSignalReceived),
        "smeshSignalExpired" => Ok(SmeshSignalExpired),
        "smeshTickCompleted" => Ok(SmeshTickCompleted),
        "smeshPeerConnected" => Ok(SmeshPeerConnected),
        "smeshPeerDisconnected" => Ok(SmeshPeerDisconnected),
        "toolCall" => Ok(ToolCall),
        "toolResult" => Ok(ToolResult),
        "toolFailed" => Ok(ToolFailed),
        "artifactProduced" => Ok(ArtifactProduced),
        "artifactConsumed" => Ok(ArtifactConsumed),
        "humanPrompt" => Ok(HumanPrompt),
        "humanDecision" => Ok(HumanDecision),
        "humanFailed" => Ok(HumanFailed),
        _ => Err(ReplayError::Malformed),
    }
}

#[cfg(not(unix))]
fn persist_bytes_new(_path: &Path, _bytes: &[u8]) -> Result<(), ReplayError> {
    Err(ReplayError::Persistence)
}

#[cfg(not(unix))]
pub fn reconcile_unpublished_replay_temporary(
    _path: &Path,
    _token: &str,
) -> Result<(), ReplayError> {
    Err(ReplayError::Persistence)
}

#[cfg(not(unix))]
pub fn reconcile_published_replay_temporary(_path: &Path, _token: &str) -> Result<(), ReplayError> {
    Err(ReplayError::Persistence)
}

/// Removes a private temporary replay name named by a
/// [`ReplayError::CleanupRequired`] token.
///
/// # Errors
/// Returns an error for an invalid token, untrusted path, unexpected inode, or
/// failed unlink/directory synchronization.
#[cfg(unix)]
pub fn reconcile_unpublished_replay_temporary(path: &Path, token: &str) -> Result<(), ReplayError> {
    reconcile_replay_temporary(path, token, false)
}

/// Removes a private temporary replay name named by a
/// [`ReplayError::PublishedCleanupRequired`] token while requiring the
/// published destination to survive.
///
/// Use this conservative operation when only a crash-left temporary filename
/// is available: it never deletes a lone temporary that may be the only
/// surviving copy of published replay bytes.
///
/// # Errors
/// Returns an error for an invalid token, untrusted path, missing or unexpected
/// destination, unexpected inode, or failed unlink/directory synchronization.
#[cfg(unix)]
pub fn reconcile_published_replay_temporary(path: &Path, token: &str) -> Result<(), ReplayError> {
    reconcile_replay_temporary(path, token, true)
}

#[cfg(unix)]
fn reconcile_replay_temporary(
    path: &Path,
    token: &str,
    expected_published: bool,
) -> Result<(), ReplayError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if !path.is_absolute()
        || token.len() != 32
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ReplayError::Persistence);
    }
    let parent = path.parent().ok_or(ReplayError::Persistence)?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(ReplayError::Persistence)?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|_| ReplayError::Persistence)?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.file_type().is_symlink()
        || parent_metadata.uid() != rustix::process::geteuid().as_raw()
        || parent_metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ReplayError::Persistence);
    }
    let temporary = parent.join(format!(".{name}.{token}.tmp"));
    let temporary_metadata = match fs::symlink_metadata(&temporary) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if expected_published {
                let destination =
                    fs::symlink_metadata(path).map_err(|_| ReplayError::Persistence)?;
                if !destination.file_type().is_file()
                    || destination.uid() != rustix::process::geteuid().as_raw()
                    || destination.permissions().mode() & 0o777 != 0o600
                    || destination.nlink() != 1
                {
                    return Err(ReplayError::Persistence);
                }
            }
            sync_parent_directory(parent)?;
            return Ok(());
        }
        Err(_) => return Err(ReplayError::Persistence),
    };
    if !temporary_metadata.file_type().is_file()
        || temporary_metadata.uid() != rustix::process::geteuid().as_raw()
        || temporary_metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(ReplayError::Persistence);
    }
    if expected_published {
        match temporary_metadata.nlink() {
            2 => match fs::symlink_metadata(path) {
                Ok(destination_metadata)
                    if destination_metadata.file_type().is_file()
                        && destination_metadata.dev() == temporary_metadata.dev()
                        && destination_metadata.ino() == temporary_metadata.ino() => {}
                _ => return Err(ReplayError::Persistence),
            },
            _ => return Err(ReplayError::Persistence),
        }
    } else if temporary_metadata.nlink() != 1 {
        return Err(ReplayError::Persistence);
    }
    fs::remove_file(&temporary).map_err(|_| reconciliation_error(token, expected_published))?;
    sync_parent_directory(parent).map_err(|_| reconciliation_error(token, expected_published))
}

#[cfg(unix)]
fn reconciliation_error(token: &str, published: bool) -> ReplayError {
    if published {
        ReplayError::PublishedCleanupRequired(token.into())
    } else {
        ReplayError::CleanupRequired(token.into())
    }
}

#[cfg(unix)]
fn persist_bytes_new(path: &Path, bytes: &[u8]) -> Result<(), ReplayError> {
    if !path.is_absolute() {
        return Err(ReplayError::Persistence);
    }
    if fs::symlink_metadata(path).is_ok() {
        return Err(ReplayError::AlreadyExists);
    }
    let parent = path.parent().ok_or(ReplayError::Persistence)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = fs::symlink_metadata(parent).map_err(|_| ReplayError::Persistence)?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(ReplayError::Persistence);
        }
    }
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(ReplayError::Persistence)?;
    let mut opened = None;
    for _ in 0..16 {
        let token = format!("{:032x}", rand::random::<u128>());
        let candidate = parent.join(format!(".{name}.{token}.tmp"));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&candidate) {
            Ok(file) => {
                if force_private_mode(&file).is_err() {
                    cleanup_unpublished_temp(&candidate, &token)?;
                    return Err(ReplayError::Persistence);
                }
                opened = Some((candidate, file, token));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(ReplayError::Persistence),
        }
    }
    let (temp, mut file, token) = opened.ok_or(ReplayError::Persistence)?;
    let mut published = false;
    let result = (|| {
        file.write_all(bytes)
            .map_err(|_| ReplayError::Persistence)?;
        file.sync_all().map_err(|_| ReplayError::Persistence)?;
        fs::hard_link(&temp, path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                ReplayError::AlreadyExists
            } else {
                ReplayError::Persistence
            }
        })?;
        published = true;
        cleanup_published_temp(&temp, &token)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let metadata = fs::symlink_metadata(path).map_err(|_| ReplayError::Published)?;
            if !metadata.file_type().is_file()
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.permissions().mode() & 0o777 != 0o600
                || metadata.nlink() != 1
                || fs::read(path).map_err(|_| ReplayError::Published)? != bytes
            {
                return Err(ReplayError::Published);
            }
        }
        OpenOptions::new()
            .read(true)
            .open(parent)
            .and_then(|parent_file| parent_file.sync_all())
            .map_err(|_| ReplayError::Published)?;
        Ok(())
    })();
    if result.is_err() && !published {
        cleanup_unpublished_temp(&temp, &token)?;
    }
    result
}

#[cfg(unix)]
fn cleanup_unpublished_temp(temp: &Path, token: &str) -> Result<(), ReplayError> {
    cleanup_temporary(temp, token, false)
}

#[cfg(unix)]
fn force_private_mode(file: &fs::File) -> Result<(), ReplayError> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| ReplayError::Persistence)
}

#[cfg(unix)]
fn cleanup_published_temp(temp: &Path, token: &str) -> Result<(), ReplayError> {
    cleanup_temporary(temp, token, true)
}

#[cfg(unix)]
fn cleanup_temporary(temp: &Path, token: &str, published: bool) -> Result<(), ReplayError> {
    let cleanup_error = || {
        if published {
            ReplayError::PublishedCleanupRequired(token.into())
        } else {
            ReplayError::CleanupRequired(token.into())
        }
    };
    fs::remove_file(temp).map_err(|_| cleanup_error())?;
    let parent = temp.parent().ok_or_else(cleanup_error)?;
    sync_parent_directory(parent).map_err(|_| cleanup_error())
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> Result<(), ReplayError> {
    OpenOptions::new()
        .read(true)
        .open(parent)
        .and_then(|parent_file| parent_file.sync_all())
        .map_err(|_| ReplayError::Persistence)
}

#[cfg(all(test, unix))]
mod tests {
    use super::{
        ReplayError, cleanup_published_temp, cleanup_unpublished_temp, force_private_mode,
    };
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[test]
    fn failed_unpublished_cleanup_returns_the_bounded_reconciliation_token() {
        let token = format!("{:032x}", rand::random::<u128>());
        let root = std::env::temp_dir().join(format!(
            "smesh-replay-cleanup-test-{}-{token}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let temp = root.join(format!(".bundle.jsonl.{token}.tmp"));
        std::fs::write(&temp, b"private replay bytes").unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o500)).unwrap();

        let result = cleanup_unpublished_temp(&temp, &token);

        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(result, Err(ReplayError::CleanupRequired(token)));
    }

    #[test]
    fn failed_published_cleanup_reports_publication_and_reconciliation_token() {
        let token = "0123456789abcdef0123456789abcdef";
        let missing = std::env::temp_dir().join(format!(
            "smesh-replay-missing-published-temp-{}",
            std::process::id()
        ));

        assert_eq!(
            cleanup_published_temp(&missing, token),
            Err(ReplayError::PublishedCleanupRequired(token.into()))
        );
    }

    #[test]
    fn private_mode_is_forced_after_restrictive_creation_mode() {
        let token = format!("{:032x}", rand::random::<u128>());
        let path = std::env::temp_dir().join(format!(
            "smesh-replay-private-mode-{}-{token}",
            std::process::id()
        ));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o000)
            .open(&path)
            .unwrap();

        force_private_mode(&file).unwrap();

        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        std::fs::remove_file(path).unwrap();
    }
}

mod decimal {
    use serde::{Deserialize, Deserializer, Serializer};
    #[allow(clippy::trivially_copy_pass_by_ref)] // Serde's `with` contract requires `&u64`.
    pub fn serialize<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        let s = String::deserialize(d)?;
        if s != "0" && (s.starts_with('0') || s.is_empty())
            || !s.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(serde::de::Error::custom("non-canonical decimal"));
        }
        s.parse().map_err(serde::de::Error::custom)
    }
}
