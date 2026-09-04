use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::content_digest;

pub const FULL_MATRIX_CAPTURE_SCHEMA_VERSION: &str = "full-matrix-capture/1";
const MAX_CAPTURE_BYTES: usize = 16 * 1024 * 1024;
const MAX_CAPTURE_LINE_BYTES: usize = 64 * 1024;
const MAX_REPLAY_EVENTS: usize = 100_000;
const CAPTURE_LIFECYCLE_HEADROOM: usize = 2 * MAX_CAPTURE_LINE_BYTES;
const MAX_CAPTURE_EVENT_BYTES: usize = MAX_CAPTURE_BYTES - CAPTURE_LIFECYCLE_HEADROOM;
const MAX_HUMAN_DECISION_BYTES: usize = 64 * 1024;

struct BoundedJsonWriter {
    bytes: Vec<u8>,
}

impl std::io::Write for BoundedJsonWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.bytes.len().saturating_add(bytes.len()) > MAX_CAPTURE_LINE_BYTES {
            return Err(std::io::Error::other("capture JSON exceeds bound"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn bounded_serialize<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    let mut writer = BoundedJsonWriter {
        bytes: Vec::with_capacity(1024),
    };
    serde_json::to_writer(&mut writer, value)?;
    Ok(writer.bytes)
}

fn bounded_json(value: &serde_json::Value) -> Result<Vec<u8>, serde_json::Error> {
    bounded_serialize(value)
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CaptureError {
    #[error("capture identifier is invalid")]
    InvalidIdentifier,
    #[error("capture producer kind does not match adapter")]
    ProducerKindMismatch,
    #[error("capture mutex is poisoned")]
    Poisoned,
    #[error("required capture capacity is exhausted")]
    CapacityExhausted,
    #[error("capture adapter does not support this observation")]
    UnsupportedObservation,
    #[error("human console I/O failed")]
    ConsoleIo,
    #[error("captured stream is invalid")]
    CaptureInvalid,
    #[error("captured stream is malformed")]
    MalformedReplay,
    #[error("captured stream schema is unsupported")]
    UnsupportedSchema,
    #[error("capture persistence failed")]
    Persistence,
    #[error("capture interaction binding conflicts with an earlier observation")]
    InteractionConflict,
    #[error("capture producer sequence has a gap or regression")]
    SequenceGap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CaptureFailure {
    CapacityExhausted,
    Persistence,
    UnclosedInteraction,
    SequenceGap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CaptureGapReason {
    ExternalBoundary,
    CaptureStartedLate,
    ProducerRestart,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProducerKind {
    A2a,
    Smesh,
    Tool,
    Artifact,
    Human,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProducerIdentity {
    pub kind: ProducerKind,
    pub id: String,
    pub instance_id: String,
}

impl ProducerIdentity {
    /// Builds one stable producer/process identity.
    ///
    /// # Errors
    /// Returns [`CaptureError::InvalidIdentifier`] for an empty, oversized, or non-ASCII-safe ID.
    pub fn new(
        kind: ProducerKind,
        id: impl Into<String>,
        instance_id: impl Into<String>,
    ) -> Result<Self, CaptureError> {
        let identity = Self {
            kind,
            id: id.into(),
            instance_id: instance_id.into(),
        };
        if !valid_identifier(&identity.id) || !valid_identifier(&identity.instance_id) {
            return Err(CaptureError::InvalidIdentifier);
        }
        Ok(identity)
    }

    fn key(&self) -> String {
        format!("{:?}\0{}\0{}", self.kind, self.id, self.instance_id)
    }

    fn validate(&self) -> Result<(), CaptureError> {
        if valid_identifier(&self.id) && valid_identifier(&self.instance_id) {
            Ok(())
        } else {
            Err(CaptureError::InvalidIdentifier)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CaptureKind {
    A2aSend,
    A2aReceive,
    SmeshSignalEmitted,
    SmeshSignalSent,
    SmeshSignalReinforced,
    SmeshSignalReceived,
    SmeshSignalExpired,
    SmeshTickCompleted,
    SmeshPeerConnected,
    SmeshPeerDisconnected,
    ToolCall,
    ToolResult,
    ToolFailed,
    ArtifactProduced,
    ArtifactConsumed,
    HumanPrompt,
    HumanDecision,
    HumanFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "eventId",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum CaptureParent {
    Root,
    Event(String),
    Missing {
        expected_event_id: String,
        reason: CaptureGapReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapturedContent {
    pub digest: String,
    pub byte_length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureProducer {
    pub identity: ProducerIdentity,
    pub sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureEvent {
    pub event_id: String,
    pub sequence: u64,
    pub producer: CaptureProducer,
    pub kind: CaptureKind,
    pub interaction_id: String,
    pub peer_id: String,
    pub task_id: Option<String>,
    pub context_id: Option<String>,
    pub subject_id: Option<String>,
    pub parent: CaptureParent,
    pub content: CapturedContent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureStream {
    pub schema_version: String,
    pub run_id: String,
    pub capture_valid: bool,
    pub failure: Option<CaptureFailure>,
    pub events: Vec<CaptureEvent>,
}

#[cfg_attr(test, allow(clippy::struct_excessive_bools))]
struct CaptureState {
    events: Vec<CaptureEvent>,
    event_ids: HashSet<String>,
    missing_claims: HashSet<String>,
    producer_sequences: HashMap<String, u64>,
    interactions: HashMap<String, InteractionBinding>,
    reserved_slots: usize,
    raw_hook_reserved_slots: usize,
    reserved_spool_bytes: usize,
    spool: Option<std::fs::File>,
    spool_bytes: usize,
    capture_valid: bool,
    failure: Option<CaptureFailure>,
    next_interaction: u64,
    completed: bool,
    #[cfg(test)]
    fail_sync_after_next_write: bool,
    #[cfg(test)]
    reject_writes_after_failed_sync: bool,
}

#[derive(Clone)]
struct InteractionBinding {
    participants: HashMap<ProducerKind, [String; 2]>,
    task_id: Option<String>,
    context_id: Option<String>,
    observations: HashMap<CaptureKind, (Option<String>, CapturedContent)>,
    paired_subjects: HashMap<ProducerKind, Option<String>>,
    artifact_contract: Option<(Option<String>, CapturedContent)>,
}

pub struct CanonicalCapture {
    run_id: String,
    capacity: usize,
    state: Mutex<CaptureState>,
}

impl CanonicalCapture {
    /// Creates an in-memory capture collector for tests and schema work.
    ///
    /// # Errors
    /// Returns [`CaptureError::InvalidIdentifier`] for an invalid run ID or zero capacity. Caller
    /// capacity is limited to the global replay bound.
    pub fn new(run_id: impl Into<String>, capacity: usize) -> Result<Self, CaptureError> {
        let run_id = run_id.into();
        if !valid_identifier(&run_id) || capacity == 0 {
            return Err(CaptureError::InvalidIdentifier);
        }
        Ok(Self {
            run_id,
            capacity: capacity.min(MAX_REPLAY_EVENTS),
            state: Mutex::new(CaptureState {
                events: Vec::new(),
                event_ids: HashSet::new(),
                missing_claims: HashSet::new(),
                producer_sequences: HashMap::new(),
                interactions: HashMap::new(),
                reserved_slots: 0,
                raw_hook_reserved_slots: 0,
                reserved_spool_bytes: 0,
                spool: None,
                spool_bytes: 0,
                capture_valid: true,
                failure: None,
                next_interaction: 0,
                completed: false,
                #[cfg(test)]
                fail_sync_after_next_write: false,
                #[cfg(test)]
                reject_writes_after_failed_sync: false,
            }),
        })
    }

    /// Creates a new private durable JSONL spool without replacing an existing path.
    ///
    /// # Errors
    /// Returns validation errors from [`Self::new`] or [`CaptureError::Persistence`] when creation fails.
    pub fn create_spool(
        run_id: impl Into<String>,
        capacity: usize,
        path: &std::path::Path,
    ) -> Result<Self, CaptureError> {
        let mut capture = Self::new(run_id, capacity)?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options.open(path).map_err(|_| CaptureError::Persistence)?;
        #[cfg(unix)]
        if sync_parent_directory(path).is_err() {
            drop(file);
            let _ = std::fs::remove_file(path);
            return Err(CaptureError::Persistence);
        }
        capture
            .state
            .get_mut()
            .map_err(|_| CaptureError::Poisoned)?
            .spool = Some(file);
        Ok(capture)
    }

    fn next_interaction_id(
        &self,
        identity: &ProducerIdentity,
        method: &str,
        content: &[u8],
    ) -> Result<String, CaptureError> {
        let mut state = self.state.lock().map_err(|_| CaptureError::Poisoned)?;
        let nonce = state.next_interaction;
        state.next_interaction = nonce
            .checked_add(1)
            .ok_or(CaptureError::CapacityExhausted)?;
        Ok(content_digest(
            format!(
                "full-matrix-interaction/v1\0{}\0{}\0{method}\0{nonce}\0{}",
                self.run_id,
                identity.key(),
                content_digest(content)
            )
            .as_bytes(),
        ))
    }

    // The closed event schema is clearer here than an untyped options bag.
    #[allow(clippy::too_many_arguments)]
    fn record(
        &self,
        identity: &ProducerIdentity,
        kind: CaptureKind,
        interaction_id: &str,
        peer_id: &str,
        task_id: Option<&str>,
        context_id: Option<&str>,
        subject_id: Option<&str>,
        content: &[u8],
        parent: CaptureParent,
    ) -> Result<CaptureReceipt, CaptureError> {
        self.record_inner(
            identity,
            kind,
            interaction_id,
            peer_id,
            task_id,
            context_id,
            subject_id,
            content,
            parent,
            None,
        )
    }

    // Keep validation, durable append, and sequence advancement in one linearization point.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn record_inner(
        &self,
        identity: &ProducerIdentity,
        kind: CaptureKind,
        interaction_id: &str,
        peer_id: &str,
        task_id: Option<&str>,
        context_id: Option<&str>,
        subject_id: Option<&str>,
        content: &[u8],
        parent: CaptureParent,
        reservation_kind: Option<ReservationKind>,
    ) -> Result<CaptureReceipt, CaptureError> {
        if identity.validate().is_err()
            || !valid_identifier(interaction_id)
            || !valid_identifier(peer_id)
            || task_id.is_some_and(|value| !valid_identifier(value))
            || context_id.is_some_and(|value| !valid_identifier(value))
            || subject_id.is_some_and(|value| !valid_identifier(value))
        {
            return Err(CaptureError::InvalidIdentifier);
        }
        let mut state = self.state.lock().map_err(|_| CaptureError::Poisoned)?;
        if !state.capture_valid
            || state.completed
            || (reservation_kind.is_none() && state.raw_hook_reserved_slots != 0)
        {
            return Err(CaptureError::CaptureInvalid);
        }
        let parent_valid = match &parent {
            CaptureParent::Root => true,
            CaptureParent::Event(parent_id) => {
                canonical_digest(parent_id) && state.event_ids.contains(parent_id)
            }
            CaptureParent::Missing {
                expected_event_id, ..
            } => {
                canonical_digest(expected_event_id) && !state.event_ids.contains(expected_event_id)
            }
        };
        if !parent_valid {
            return Err(CaptureError::MalformedReplay);
        }
        let captured_content = CapturedContent {
            digest: content_digest(content),
            byte_length: u64::try_from(content.len()).unwrap_or(u64::MAX),
        };
        let binding = interaction_binding(
            identity,
            peer_id,
            task_id,
            context_id,
            kind,
            subject_id,
            &captured_content,
        );
        if state
            .interactions
            .get(interaction_id)
            .is_some_and(|existing| !binding_compatible(existing, &binding, kind))
        {
            return Err(CaptureError::InteractionConflict);
        }
        let unavailable = if reservation_kind.is_some() {
            state.reserved_slots == 0
        } else {
            state
                .events
                .len()
                .checked_add(state.reserved_slots)
                .is_none_or(|used| used >= self.capacity)
        };
        if unavailable {
            invalidate_capture(&mut state, &self.run_id, CaptureFailure::CapacityExhausted);
            return Err(CaptureError::CapacityExhausted);
        }
        if reservation_kind.is_some() && state.reserved_slots == 0 {
            invalidate_capture(&mut state, &self.run_id, CaptureFailure::CapacityExhausted);
            return Err(CaptureError::CapacityExhausted);
        }
        let producer_sequence = *state.producer_sequences.get(&identity.key()).unwrap_or(&0);
        let sequence =
            u64::try_from(state.events.len()).map_err(|_| CaptureError::CapacityExhausted)?;
        let event_id = capture_event_id(
            &self.run_id,
            identity,
            producer_sequence,
            kind,
            interaction_id,
            peer_id,
            task_id,
            context_id,
            subject_id,
            &parent,
            &captured_content,
        );
        if state.missing_claims.contains(&event_id) {
            invalidate_capture(&mut state, &self.run_id, CaptureFailure::SequenceGap);
            return Err(CaptureError::CaptureInvalid);
        }
        let event = CaptureEvent {
            event_id: event_id.clone(),
            sequence,
            producer: CaptureProducer {
                identity: identity.clone(),
                sequence: producer_sequence,
            },
            kind,
            interaction_id: interaction_id.to_owned(),
            peer_id: peer_id.to_owned(),
            task_id: task_id.map(str::to_owned),
            context_id: context_id.map(str::to_owned),
            subject_id: subject_id.map(str::to_owned),
            parent,
            content: captured_content,
        };
        append_spool(&mut state, &self.run_id, &event, reservation_kind.is_some())?;
        if let Some(kind) = reservation_kind {
            state.reserved_slots -= 1;
            if kind == ReservationKind::RawHook {
                state.raw_hook_reserved_slots -= 1;
            }
        }
        if let CaptureParent::Missing {
            expected_event_id, ..
        } = &event.parent
        {
            state.missing_claims.insert(expected_event_id.clone());
        }
        state.event_ids.insert(event_id.clone());
        state.events.push(event);
        match state.interactions.get_mut(interaction_id) {
            Some(existing) => {
                existing.participants.extend(binding.participants.clone());
                existing
                    .paired_subjects
                    .extend(binding.paired_subjects.clone());
                if existing.artifact_contract.is_none() {
                    existing
                        .artifact_contract
                        .clone_from(&binding.artifact_contract);
                }
                existing
                    .observations
                    .entry(kind)
                    .or_insert_with(|| binding.observations[&kind].clone());
            }
            None => {
                state
                    .interactions
                    .insert(interaction_id.to_owned(), binding);
            }
        }
        state.producer_sequences.insert(
            identity.key(),
            producer_sequence
                .checked_add(1)
                .ok_or(CaptureError::CapacityExhausted)?,
        );
        Ok(CaptureReceipt { event_id })
    }

    fn reserve_required(
        self: &Arc<Self>,
        count: usize,
        kind: ReservationKind,
    ) -> Result<CaptureReservation, CaptureError> {
        let mut state = self.state.lock().map_err(|_| CaptureError::Poisoned)?;
        if !state.capture_valid || state.completed || state.raw_hook_reserved_slots != 0 {
            return Err(CaptureError::CaptureInvalid);
        }
        let spool_reservation = if state.spool.is_some() {
            count
                .checked_mul(MAX_CAPTURE_LINE_BYTES)
                .ok_or(CaptureError::CapacityExhausted)?
        } else {
            0
        };
        let reserved_slots = state
            .events
            .len()
            .checked_add(state.reserved_slots)
            .and_then(|used| used.checked_add(count));
        let reserved_spool_bytes = state
            .spool_bytes
            .checked_add(state.reserved_spool_bytes)
            .and_then(|used| used.checked_add(spool_reservation));
        if reserved_slots.is_none_or(|used| used > self.capacity)
            || reserved_spool_bytes.is_none_or(|used| used > MAX_CAPTURE_EVENT_BYTES)
        {
            invalidate_capture(&mut state, &self.run_id, CaptureFailure::CapacityExhausted);
            return Err(CaptureError::CapacityExhausted);
        }
        state.reserved_slots = state
            .reserved_slots
            .checked_add(count)
            .ok_or(CaptureError::CapacityExhausted)?;
        if kind == ReservationKind::RawHook {
            state.raw_hook_reserved_slots = state
                .raw_hook_reserved_slots
                .checked_add(count)
                .ok_or(CaptureError::CapacityExhausted)?;
        }
        state.reserved_spool_bytes = state
            .reserved_spool_bytes
            .checked_add(spool_reservation)
            .ok_or(CaptureError::CapacityExhausted)?;
        Ok(CaptureReservation {
            capture: Arc::clone(self),
            remaining: count,
            kind,
        })
    }

    /// Validates and durably appends one source-local JSONL spool in caller-declared order.
    ///
    /// # Errors
    /// Returns a schema, validation, sequence, capacity, or persistence error without accepting an
    /// invalid event.
    // Keep all ingest validation ahead of the first durable canonical append.
    #[allow(clippy::too_many_lines)]
    pub fn ingest_jsonl(&self, bytes: &[u8]) -> Result<(), CaptureError> {
        if bytes.is_empty() || bytes.len() > MAX_CAPTURE_BYTES {
            return Err(CaptureError::MalformedReplay);
        }
        let source = parse_persisted_capture(bytes, true)?;
        if source.run_id != self.run_id {
            return Err(CaptureError::MalformedReplay);
        }
        let source_events = source.events;

        for (index, event) in source_events.iter().enumerate() {
            let expected_sequence =
                u64::try_from(index).map_err(|_| CaptureError::MalformedReplay)?;
            if event.sequence != expected_sequence {
                return Err(CaptureError::MalformedReplay);
            }
        }

        let mut state = self.state.lock().map_err(|_| CaptureError::Poisoned)?;
        if !state.capture_valid || state.completed || state.reserved_slots != 0 {
            return Err(CaptureError::CaptureInvalid);
        }
        if state.spool.is_none() {
            return Err(CaptureError::Persistence);
        }
        let existing_events_by_id = state
            .events
            .iter()
            .cloned()
            .map(|event| (event.event_id.clone(), event))
            .collect::<HashMap<_, _>>();
        let mut accepted: Vec<CaptureEvent> = Vec::new();
        let mut accepted_event_ids = HashMap::<String, usize>::new();
        let mut next_producer_sequences = state.producer_sequences.clone();
        for mut event in source_events {
            if let Some(existing) = existing_events_by_id.get(event.event_id.as_str()) {
                event.sequence = existing.sequence;
                if event == *existing {
                    continue;
                }
                return Err(CaptureError::MalformedReplay);
            }
            if let Some(index) = accepted_event_ids.get(&event.event_id).copied() {
                let existing = &accepted[index];
                event.sequence = existing.sequence;
                if event == *existing {
                    continue;
                }
                return Err(CaptureError::MalformedReplay);
            }
            let producer_key = event.producer.identity.key();
            let expected = next_producer_sequences
                .get(&producer_key)
                .copied()
                .unwrap_or(0);
            if event.producer.sequence != expected {
                invalidate_capture(&mut state, &self.run_id, CaptureFailure::SequenceGap);
                return Err(CaptureError::SequenceGap);
            }
            event.sequence = u64::try_from(
                state
                    .events
                    .len()
                    .checked_add(accepted.len())
                    .ok_or(CaptureError::CapacityExhausted)?,
            )
            .map_err(|_| CaptureError::CapacityExhausted)?;
            next_producer_sequences.insert(
                producer_key,
                expected.checked_add(1).ok_or(CaptureError::SequenceGap)?,
            );
            accepted_event_ids.insert(event.event_id.clone(), accepted.len());
            accepted.push(event);
        }
        if state
            .events
            .len()
            .checked_add(state.reserved_slots)
            .and_then(|used| used.checked_add(accepted.len()))
            .is_none_or(|used| used > self.capacity)
        {
            invalidate_capture(&mut state, &self.run_id, CaptureFailure::CapacityExhausted);
            return Err(CaptureError::CapacityExhausted);
        }
        let mut candidate_event_ids = state.event_ids.clone();
        candidate_event_ids.extend(accepted.iter().map(|event| event.event_id.clone()));
        let mut candidate_missing_claims = state.missing_claims.clone();
        candidate_missing_claims.extend(accepted.iter().filter_map(|event| match &event.parent {
            CaptureParent::Missing {
                expected_event_id, ..
            } => Some(expected_event_id.clone()),
            CaptureParent::Root | CaptureParent::Event(_) => None,
        }));
        if candidate_missing_claims
            .iter()
            .any(|claim| candidate_event_ids.contains(claim))
        {
            return Err(CaptureError::MalformedReplay);
        }
        let mut candidate_events = state.events.clone();
        candidate_events.extend(accepted.iter().cloned());
        validate_replay_events(&CaptureStream {
            schema_version: FULL_MATRIX_CAPTURE_SCHEMA_VERSION.to_owned(),
            run_id: self.run_id.clone(),
            capture_valid: true,
            failure: None,
            events: candidate_events,
        })?;
        let mut accepted_bytes = 0usize;
        let mut encoded: Vec<Vec<u8>> = Vec::with_capacity(accepted.len());
        for event in &accepted {
            let line = lifecycle_line(&PersistedCaptureRecord::Event {
                schema_version: FULL_MATRIX_CAPTURE_SCHEMA_VERSION,
                run_id: &self.run_id,
                event,
            })?;
            accepted_bytes = accepted_bytes
                .checked_add(line.len())
                .ok_or(CaptureError::CapacityExhausted)?;
            encoded.push(line);
        }
        if state
            .spool_bytes
            .saturating_add(state.reserved_spool_bytes)
            .saturating_add(accepted_bytes)
            > MAX_CAPTURE_EVENT_BYTES
        {
            invalidate_capture(&mut state, &self.run_id, CaptureFailure::CapacityExhausted);
            return Err(CaptureError::CapacityExhausted);
        }

        for (event, line) in accepted.into_iter().zip(encoded) {
            if write_spool_line(&mut state, &line).is_err() {
                invalidate_capture(&mut state, &self.run_id, CaptureFailure::Persistence);
                return Err(CaptureError::Persistence);
            }
            state.spool_bytes += line.len();
            let producer_key = event.producer.identity.key();
            state.producer_sequences.insert(
                producer_key,
                event
                    .producer
                    .sequence
                    .checked_add(1)
                    .ok_or(CaptureError::SequenceGap)?,
            );
            let binding = interaction_binding(
                &event.producer.identity,
                &event.peer_id,
                event.task_id.as_deref(),
                event.context_id.as_deref(),
                event.kind,
                event.subject_id.as_deref(),
                &event.content,
            );
            match state.interactions.get_mut(&event.interaction_id) {
                Some(existing) => {
                    existing.participants.extend(binding.participants.clone());
                    existing
                        .paired_subjects
                        .extend(binding.paired_subjects.clone());
                    if existing.artifact_contract.is_none() {
                        existing
                            .artifact_contract
                            .clone_from(&binding.artifact_contract);
                    }
                    existing
                        .observations
                        .entry(event.kind)
                        .or_insert_with(|| binding.observations[&event.kind].clone());
                }
                None => {
                    state
                        .interactions
                        .insert(event.interaction_id.clone(), binding);
                }
            }
            if let CaptureParent::Missing {
                expected_event_id, ..
            } = &event.parent
            {
                state.missing_claims.insert(expected_event_id.clone());
            }
            state.event_ids.insert(event.event_id.clone());
            state.events.push(event);
        }
        Ok(())
    }

    /// Returns the current in-memory view of accepted events and capture health.
    ///
    /// # Errors
    /// Returns [`CaptureError::Poisoned`] if another thread poisoned the capture lock.
    pub fn snapshot(&self) -> Result<CaptureStream, CaptureError> {
        let state = self.state.lock().map_err(|_| CaptureError::Poisoned)?;
        let reservation_open = state.reserved_slots != 0;
        Ok(CaptureStream {
            schema_version: FULL_MATRIX_CAPTURE_SCHEMA_VERSION.to_owned(),
            run_id: self.run_id.clone(),
            capture_valid: state.capture_valid && !reservation_open,
            failure: if reservation_open {
                Some(state.failure.unwrap_or(CaptureFailure::UnclosedInteraction))
            } else {
                state.failure
            },
            events: state.events.clone(),
        })
    }

    /// Durably closes a live spool. Only closed spools are accepted by JSONL replay or ingestion.
    ///
    /// Completion first synchronizes the event prefix, records its exact file offset, then appends
    /// and synchronizes the terminal record. If terminal synchronization fails, completion
    /// truncates back to the synchronized prefix and synchronizes that truncation before returning
    /// an error. If truncation cannot be confirmed, it overwrites the terminal record's first byte
    /// with invalid JSON and synchronizes that fail-closed marker. The file is abandoned if both
    /// recovery operations fail; as with every portable `fsync` protocol, an I/O error cannot prove
    /// what reached faulty storage, but no further writes are attempted through this capture.
    ///
    /// # Errors
    /// Returns [`CaptureError::CaptureInvalid`] while an interaction is open, after failure, or
    /// after the spool has already been closed, and [`CaptureError::Persistence`] on sync failure.
    pub fn complete(&self) -> Result<(), CaptureError> {
        use std::io::Seek as _;

        let mut state = self.state.lock().map_err(|_| CaptureError::Poisoned)?;
        if !state.capture_valid
            || state.reserved_slots != 0
            || state.completed
            || state.spool.is_none()
        {
            return Err(CaptureError::CaptureInvalid);
        }
        if state
            .events
            .iter()
            .any(|event| state.missing_claims.contains(&event.event_id))
        {
            invalidate_capture(&mut state, &self.run_id, CaptureFailure::SequenceGap);
            return Err(CaptureError::CaptureInvalid);
        }
        let candidate = CaptureStream {
            schema_version: FULL_MATRIX_CAPTURE_SCHEMA_VERSION.to_owned(),
            run_id: self.run_id.clone(),
            capture_valid: true,
            failure: None,
            events: state.events.clone(),
        };
        if validate_replay_events(&candidate).is_err() {
            invalidate_capture(&mut state, &self.run_id, CaptureFailure::SequenceGap);
            return Err(CaptureError::CaptureInvalid);
        }
        let event_count =
            u64::try_from(state.events.len()).map_err(|_| CaptureError::CapacityExhausted)?;
        let line = lifecycle_line(&PersistedCaptureRecord::Complete {
            schema_version: FULL_MATRIX_CAPTURE_SCHEMA_VERSION,
            run_id: &self.run_id,
            event_count,
        })?;
        if state.spool_bytes.saturating_add(line.len()) > MAX_CAPTURE_BYTES {
            invalidate_capture(&mut state, &self.run_id, CaptureFailure::CapacityExhausted);
            return Err(CaptureError::CapacityExhausted);
        }
        let prefix_offset = {
            let Some(spool) = state.spool.as_mut() else {
                state.capture_valid = false;
                state.failure = Some(CaptureFailure::Persistence);
                return Err(CaptureError::Persistence);
            };
            if spool.sync_all().is_err() {
                invalidate_capture(&mut state, &self.run_id, CaptureFailure::Persistence);
                return Err(CaptureError::Persistence);
            }
            let Ok(offset) = spool.seek(std::io::SeekFrom::End(0)) else {
                invalidate_capture(&mut state, &self.run_id, CaptureFailure::Persistence);
                return Err(CaptureError::Persistence);
            };
            offset
        };
        if write_spool_line(&mut state, &line).is_err() {
            if rollback_terminal_record(&mut state, prefix_offset).is_err()
                && render_terminal_record_malformed(&mut state, prefix_offset).is_err()
            {
                state.spool.take();
            }
            state.capture_valid = false;
            state.failure = Some(CaptureFailure::Persistence);
            return Err(CaptureError::Persistence);
        }
        state.spool_bytes += line.len();
        state.completed = true;
        Ok(())
    }

    /// Parses and validates the bounded single-object capture representation without side effects.
    ///
    /// # Errors
    /// Returns a schema, malformed-input, or invalid-capture error.
    pub fn replay(bytes: &[u8]) -> Result<CaptureStream, CaptureError> {
        const MAX_REPLAY_BYTES: usize = 16 * 1024 * 1024;
        const MAX_REPLAY_EVENTS: usize = 100_000;
        if bytes.len() > MAX_REPLAY_BYTES {
            return Err(CaptureError::MalformedReplay);
        }
        let stream: CaptureStream =
            serde_json::from_slice(bytes).map_err(|_| CaptureError::MalformedReplay)?;
        if stream.schema_version != FULL_MATRIX_CAPTURE_SCHEMA_VERSION {
            return Err(CaptureError::UnsupportedSchema);
        }
        if !stream.capture_valid || stream.failure.is_some() {
            return Err(CaptureError::CaptureInvalid);
        }
        if !valid_identifier(&stream.run_id) || stream.events.len() > MAX_REPLAY_EVENTS {
            return Err(CaptureError::MalformedReplay);
        }
        validate_replay_events(&stream)?;
        Ok(stream)
    }

    /// Exports a valid in-memory capture to a new private JSONL path.
    ///
    /// # Errors
    /// Returns [`CaptureError::CaptureInvalid`] for an empty/invalid capture or a persistence error.
    pub fn persist_new(&self, path: &std::path::Path) -> Result<(), CaptureError> {
        use std::io::Write as _;

        let stream = self.snapshot()?;
        if !stream.capture_valid
            || stream.failure.is_some()
            || stream.events.is_empty()
            || stream.events.len() > MAX_REPLAY_EVENTS
        {
            return Err(CaptureError::CaptureInvalid);
        }
        validate_replay_events(&stream)?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(path).map_err(|_| CaptureError::Persistence)?;
        let result = (|| {
            let mut total = 0usize;
            for event in &stream.events {
                let line = lifecycle_line(&PersistedCaptureRecord::Event {
                    schema_version: FULL_MATRIX_CAPTURE_SCHEMA_VERSION,
                    run_id: &stream.run_id,
                    event,
                })?;
                total = total
                    .checked_add(line.len())
                    .ok_or(CaptureError::CapacityExhausted)?;
                if total > MAX_CAPTURE_EVENT_BYTES {
                    return Err(CaptureError::CapacityExhausted);
                }
                file.write_all(&line)
                    .map_err(|_| CaptureError::Persistence)?;
            }
            let line = lifecycle_line(&PersistedCaptureRecord::Complete {
                schema_version: FULL_MATRIX_CAPTURE_SCHEMA_VERSION,
                run_id: &stream.run_id,
                event_count: u64::try_from(stream.events.len())
                    .map_err(|_| CaptureError::CapacityExhausted)?,
            })?;
            if total.saturating_add(line.len()) > MAX_CAPTURE_BYTES {
                return Err(CaptureError::CapacityExhausted);
            }
            file.write_all(&line)
                .map_err(|_| CaptureError::Persistence)?;
            file.sync_all().map_err(|_| CaptureError::Persistence)?;
            #[cfg(unix)]
            sync_parent_directory(path)?;
            Ok(())
        })();
        if result.is_err() {
            drop(file);
            let _ = std::fs::remove_file(path);
            #[cfg(unix)]
            let _ = sync_parent_directory(path);
        }
        result
    }

    /// Parses and validates a bounded JSONL capture without side effects.
    ///
    /// # Errors
    /// Returns a schema or malformed-input error when any line or relationship is invalid.
    pub fn replay_jsonl(bytes: &[u8]) -> Result<CaptureStream, CaptureError> {
        parse_persisted_capture(bytes, true)
    }
}

fn parse_persisted_capture(
    bytes: &[u8],
    validate_events: bool,
) -> Result<CaptureStream, CaptureError> {
    if bytes.is_empty() || bytes.len() > MAX_CAPTURE_BYTES || bytes.last() != Some(&b'\n') {
        return Err(CaptureError::MalformedReplay);
    }
    let records = &bytes[..bytes.len() - 1];
    if records.is_empty() {
        return Err(CaptureError::MalformedReplay);
    }
    let mut run_id: Option<String> = None;
    let mut events = Vec::new();
    let mut terminal = false;
    for line in records.split(|byte| *byte == b'\n') {
        if line.is_empty() || line.len() > MAX_CAPTURE_LINE_BYTES || terminal {
            return Err(CaptureError::MalformedReplay);
        }
        let record: OwnedPersistedCaptureRecord =
            serde_json::from_slice(line).map_err(|_| CaptureError::MalformedReplay)?;
        let (schema_version, record_run_id) = record.header();
        if schema_version != FULL_MATRIX_CAPTURE_SCHEMA_VERSION {
            return Err(CaptureError::UnsupportedSchema);
        }
        if let Some(existing) = &run_id {
            if existing != record_run_id {
                return Err(CaptureError::MalformedReplay);
            }
        } else if valid_identifier(record_run_id) {
            run_id = Some(record_run_id.to_owned());
        } else {
            return Err(CaptureError::MalformedReplay);
        }
        match record {
            OwnedPersistedCaptureRecord::Event { event, .. } => {
                if events.len() >= MAX_REPLAY_EVENTS {
                    return Err(CaptureError::MalformedReplay);
                }
                events.push(*event);
            }
            OwnedPersistedCaptureRecord::Failure { failure, .. } => {
                let _ = failure;
                return Err(CaptureError::CaptureInvalid);
            }
            OwnedPersistedCaptureRecord::Complete { event_count, .. } => {
                if event_count != u64::try_from(events.len()).unwrap_or(u64::MAX) {
                    return Err(CaptureError::MalformedReplay);
                }
                terminal = true;
            }
        }
    }
    if !terminal {
        return Err(CaptureError::MalformedReplay);
    }
    let stream = CaptureStream {
        schema_version: FULL_MATRIX_CAPTURE_SCHEMA_VERSION.to_owned(),
        run_id: run_id.ok_or(CaptureError::MalformedReplay)?,
        capture_valid: true,
        failure: None,
        events,
    };
    if validate_events {
        validate_replay_events(&stream)?;
    }
    Ok(stream)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReservationKind {
    Wrapper,
    RawHook,
}

struct CaptureReservation {
    capture: Arc<CanonicalCapture>,
    remaining: usize,
    kind: ReservationKind,
}

impl CaptureReservation {
    // A reservation records the same closed event fields as the canonical collector.
    #[allow(clippy::too_many_arguments)]
    fn record(
        &mut self,
        identity: &ProducerIdentity,
        kind: CaptureKind,
        interaction_id: &str,
        peer_id: &str,
        task_id: Option<&str>,
        context_id: Option<&str>,
        subject_id: Option<&str>,
        content: &[u8],
        parent: CaptureParent,
    ) -> Result<CaptureReceipt, CaptureError> {
        let receipt = self.capture.record_inner(
            identity,
            kind,
            interaction_id,
            peer_id,
            task_id,
            context_id,
            subject_id,
            content,
            parent,
            Some(self.kind),
        )?;
        self.remaining -= 1;
        Ok(receipt)
    }
}

impl Drop for CaptureReservation {
    fn drop(&mut self) {
        if self.remaining == 0 {
            return;
        }
        if let Ok(mut state) = self.capture.state.lock() {
            state.reserved_slots = state.reserved_slots.saturating_sub(self.remaining);
            if self.kind == ReservationKind::RawHook {
                state.raw_hook_reserved_slots =
                    state.raw_hook_reserved_slots.saturating_sub(self.remaining);
            }
            let remaining_bytes = if state.spool.is_some() {
                self.remaining.saturating_mul(MAX_CAPTURE_LINE_BYTES)
            } else {
                0
            };
            state.reserved_spool_bytes = state.reserved_spool_bytes.saturating_sub(remaining_bytes);
            invalidate_capture(
                &mut state,
                &self.capture.run_id,
                CaptureFailure::UnclosedInteraction,
            );
        }
    }
}

#[derive(Serialize)]
#[serde(
    tag = "recordType",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum PersistedCaptureRecord<'a> {
    Event {
        schema_version: &'a str,
        run_id: &'a str,
        event: &'a CaptureEvent,
    },
    Failure {
        schema_version: &'a str,
        run_id: &'a str,
        failure: CaptureFailure,
    },
    Complete {
        schema_version: &'a str,
        run_id: &'a str,
        event_count: u64,
    },
}

#[cfg(unix)]
fn sync_parent_directory(path: &std::path::Path) -> Result<(), CaptureError> {
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| CaptureError::Persistence)
}

fn append_spool(
    state: &mut CaptureState,
    run_id: &str,
    event: &CaptureEvent,
    reserved_slot: bool,
) -> Result<(), CaptureError> {
    if state.spool.is_none() {
        return Ok(());
    }
    let line = lifecycle_line(&PersistedCaptureRecord::Event {
        schema_version: FULL_MATRIX_CAPTURE_SCHEMA_VERSION,
        run_id,
        event,
    })?;
    let reserved_bytes = if reserved_slot {
        MAX_CAPTURE_LINE_BYTES
    } else {
        0
    };
    if state.reserved_spool_bytes < reserved_bytes
        || state
            .spool_bytes
            .saturating_add(state.reserved_spool_bytes - reserved_bytes)
            .saturating_add(line.len())
            > MAX_CAPTURE_EVENT_BYTES
    {
        invalidate_capture(state, run_id, CaptureFailure::CapacityExhausted);
        return Err(CaptureError::CapacityExhausted);
    }
    if write_spool_line(state, &line).is_err() {
        invalidate_capture(state, run_id, CaptureFailure::Persistence);
        return Err(CaptureError::Persistence);
    }
    state.spool_bytes += line.len();
    state.reserved_spool_bytes -= reserved_bytes;
    Ok(())
}

fn lifecycle_line<T: Serialize>(record: &T) -> Result<Vec<u8>, CaptureError> {
    let mut line = bounded_serialize(record).map_err(|_| CaptureError::Persistence)?;
    if line.len().saturating_add(1) > MAX_CAPTURE_LINE_BYTES {
        return Err(CaptureError::CapacityExhausted);
    }
    line.push(b'\n');
    Ok(line)
}

fn write_spool_line(state: &mut CaptureState, line: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    #[cfg(test)]
    if state.reject_writes_after_failed_sync {
        return Err(std::io::Error::other(
            "injected write failure after sync failure",
        ));
    }
    state
        .spool
        .as_mut()
        .expect("spool presence checked")
        .write_all(line)
        .and_then(|()| {
            #[cfg(test)]
            if state.fail_sync_after_next_write {
                state.fail_sync_after_next_write = false;
                state.reject_writes_after_failed_sync = true;
                return Err(std::io::Error::other("injected sync failure"));
            }
            state
                .spool
                .as_mut()
                .expect("spool presence checked")
                .sync_all()
        })
}

fn rollback_terminal_record(state: &mut CaptureState, prefix_offset: u64) -> std::io::Result<()> {
    use std::io::{Seek as _, SeekFrom};

    let spool = state.spool.as_mut().expect("spool presence checked");
    spool.set_len(prefix_offset)?;
    spool.seek(SeekFrom::Start(prefix_offset))?;
    spool.sync_all()?;
    state.spool_bytes = usize::try_from(prefix_offset)
        .map_err(|_| std::io::Error::other("capture offset exceeds address space"))?;
    Ok(())
}

fn render_terminal_record_malformed(
    state: &mut CaptureState,
    prefix_offset: u64,
) -> std::io::Result<()> {
    use std::io::{Seek as _, SeekFrom, Write as _};

    let spool = state.spool.as_mut().expect("spool presence checked");
    spool.seek(SeekFrom::Start(prefix_offset))?;
    spool.write_all(b"!")?;
    spool.sync_all()
}

fn invalidate_capture(state: &mut CaptureState, run_id: &str, failure: CaptureFailure) {
    if !state.capture_valid {
        return;
    }
    state.capture_valid = false;
    state.failure = Some(failure);
    if state.spool.is_none() || state.completed {
        return;
    }
    let Ok(line) = lifecycle_line(&PersistedCaptureRecord::Failure {
        schema_version: FULL_MATRIX_CAPTURE_SCHEMA_VERSION,
        run_id,
        failure,
    }) else {
        return;
    };
    if state.spool_bytes.saturating_add(line.len()) <= MAX_CAPTURE_BYTES
        && write_spool_line(state, &line).is_ok()
    {
        state.spool_bytes += line.len();
    }
}

#[derive(Deserialize)]
#[serde(
    tag = "recordType",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum OwnedPersistedCaptureRecord {
    Event {
        schema_version: String,
        run_id: String,
        event: Box<CaptureEvent>,
    },
    Failure {
        schema_version: String,
        run_id: String,
        failure: CaptureFailure,
    },
    Complete {
        schema_version: String,
        run_id: String,
        event_count: u64,
    },
}

impl OwnedPersistedCaptureRecord {
    fn header(&self) -> (&str, &str) {
        match self {
            Self::Event {
                schema_version,
                run_id,
                ..
            }
            | Self::Failure {
                schema_version,
                run_id,
                ..
            }
            | Self::Complete {
                schema_version,
                run_id,
                ..
            } => (schema_version, run_id),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureReceipt {
    event_id: String,
}

impl CaptureReceipt {
    #[must_use]
    pub fn event_id(&self) -> &str {
        &self.event_id
    }
}

struct PendingA2aCapture {
    reservation: CaptureReservation,
    parent_event_id: String,
}

struct PendingA2aGuard<'a> {
    adapter: &'a A2aCaptureAdapter,
    interaction_id: String,
    armed: bool,
}

impl Drop for PendingA2aGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(mut pending) = self.adapter.pending.lock() {
            pending.remove(&self.interaction_id);
        }
    }
}

pub struct A2aCaptureAdapter {
    capture: Arc<CanonicalCapture>,
    identity: ProducerIdentity,
    pending: Mutex<HashMap<String, PendingA2aCapture>>,
}

impl A2aCaptureAdapter {
    /// Binds an A2A producer to the shared capture.
    ///
    /// # Errors
    /// Returns a kind mismatch or invalid-identifier error for an unusable A2A identity.
    pub fn new(
        capture: Arc<CanonicalCapture>,
        identity: ProducerIdentity,
    ) -> Result<Self, CaptureError> {
        if identity.kind != ProducerKind::A2a {
            return Err(CaptureError::ProducerKindMismatch);
        }
        identity.validate()?;
        Ok(Self {
            capture,
            identity,
            pending: Mutex::new(HashMap::new()),
        })
    }

    /// Records one outbound A2A observation.
    ///
    /// # Errors
    /// Returns validation, interaction-binding, capacity, lock, or persistence errors.
    pub fn send(
        &self,
        interaction_id: &str,
        peer_id: &str,
        task_id: Option<&str>,
        context_id: Option<&str>,
        content: &[u8],
        parent: CaptureParent,
    ) -> Result<CaptureReceipt, CaptureError> {
        self.capture.record(
            &self.identity,
            CaptureKind::A2aSend,
            interaction_id,
            peer_id,
            task_id,
            context_id,
            None,
            content,
            parent,
        )
    }

    /// Records one inbound A2A observation.
    ///
    /// # Errors
    /// Returns validation, interaction-binding, capacity, lock, or persistence errors.
    pub fn receive(
        &self,
        interaction_id: &str,
        peer_id: &str,
        task_id: Option<&str>,
        context_id: Option<&str>,
        content: &[u8],
        parent: CaptureParent,
    ) -> Result<CaptureReceipt, CaptureError> {
        self.capture.record(
            &self.identity,
            CaptureKind::A2aReceive,
            interaction_id,
            peer_id,
            task_id,
            context_id,
            None,
            content,
            parent,
        )
    }

    fn begin_intercepted_capture(
        &self,
        context: &mut a2a_server::CallContext,
        request: &serde_json::Value,
        reservation_kind: ReservationKind,
    ) -> Result<(), a2a::A2AError> {
        let encoded = bounded_json(request)
            .map_err(|_| a2a::A2AError::internal("A2A capture encoding failed"))?;
        let interaction_id = self
            .capture
            .next_interaction_id(&self.identity, &context.method, &encoded)
            .map_err(|_| a2a::A2AError::internal("A2A capture failed"))?;
        let mut reservation = self
            .capture
            .reserve_required(2, reservation_kind)
            .map_err(|_| a2a::A2AError::internal("A2A capture failed"))?;
        let receipt = reservation
            .record(
                &self.identity,
                CaptureKind::A2aReceive,
                &interaction_id,
                "external-a2a-peer",
                None,
                None,
                Some(A2A_HOOK_SUBJECT),
                &encoded,
                CaptureParent::Missing {
                    expected_event_id: content_digest(
                        format!("external-a2a-send/v1\0{interaction_id}").as_bytes(),
                    ),
                    reason: CaptureGapReason::ExternalBoundary,
                },
            )
            .map_err(|_| a2a::A2AError::internal("A2A capture failed"))?;
        let parent_event_id = receipt.event_id().to_owned();
        self.pending
            .lock()
            .map_err(|_| a2a::A2AError::internal("A2A capture failed"))?
            .insert(
                interaction_id.clone(),
                PendingA2aCapture {
                    reservation,
                    parent_event_id: parent_event_id.clone(),
                },
            );
        context
            .service_params
            .insert(A2A_INTERACTION_PARAM.to_owned(), vec![interaction_id]);
        context
            .service_params
            .insert(A2A_PARENT_PARAM.to_owned(), vec![parent_event_id]);
        Ok(())
    }

    /// Captures one unary dispatch and invalidates its reservation if the future is cancelled or panics.
    ///
    /// # Errors
    /// Returns the dispatch error or a capture error represented by the interceptor contract.
    pub async fn capture_unary<F>(
        &self,
        context: &mut a2a_server::CallContext,
        request: &serde_json::Value,
        dispatch: F,
    ) -> Result<serde_json::Value, a2a::A2AError>
    where
        F: std::future::Future<Output = Result<serde_json::Value, a2a::A2AError>>,
    {
        self.begin_intercepted_capture(context, request, ReservationKind::Wrapper)?;
        let [interaction_id] = context
            .service_params
            .get(A2A_INTERACTION_PARAM)
            .map(Vec::as_slice)
            .unwrap_or_default()
        else {
            return Err(a2a::A2AError::internal("A2A capture interaction is absent"));
        };
        let mut guard = PendingA2aGuard {
            adapter: self,
            interaction_id: interaction_id.clone(),
            armed: true,
        };
        let result = dispatch.await;
        guard.armed = false;
        drop(guard);
        <Self as a2a_server::CallInterceptor>::after(self, context, &result).await?;
        result
    }
}

const A2A_INTERACTION_PARAM: &str = "x-smesh-capture-interaction-id";
const A2A_PARENT_PARAM: &str = "smesh-internal-capture-parent-event";
const A2A_HOOK_SUBJECT: &str = "a2a.interceptor";

#[async_trait::async_trait]
impl a2a_server::CallInterceptor for A2aCaptureAdapter {
    async fn before(
        &self,
        context: &mut a2a_server::CallContext,
        request: &serde_json::Value,
    ) -> Result<(), a2a::A2AError> {
        self.begin_intercepted_capture(context, request, ReservationKind::RawHook)
    }

    async fn after(
        &self,
        context: &a2a_server::CallContext,
        result: &Result<serde_json::Value, a2a::A2AError>,
    ) -> Result<(), a2a::A2AError> {
        let [interaction_id] = context
            .service_params
            .get(A2A_INTERACTION_PARAM)
            .map(Vec::as_slice)
            .unwrap_or_default()
        else {
            return Err(a2a::A2AError::internal("A2A capture interaction is absent"));
        };
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| a2a::A2AError::internal("A2A capture failed"))?
            .remove(interaction_id)
            .ok_or_else(|| a2a::A2AError::internal("A2A capture interaction is absent"))?;
        let encoded = match result {
            Ok(value) => bounded_json(value)
                .map_err(|_| a2a::A2AError::internal("A2A capture encoding failed"))?,
            Err(_) => b"a2a-error".to_vec(),
        };
        pending
            .reservation
            .record(
                &self.identity,
                CaptureKind::A2aSend,
                interaction_id,
                "external-a2a-peer",
                None,
                None,
                Some(A2A_HOOK_SUBJECT),
                &encoded,
                CaptureParent::Event(pending.parent_event_id),
            )
            .map_err(|_| a2a::A2AError::internal("A2A capture failed"))?;
        Ok(())
    }
}

pub struct SmeshJournalCaptureAdapter {
    capture: Arc<CanonicalCapture>,
    identity: ProducerIdentity,
}

pub struct ArtifactCaptureAdapter {
    capture: Arc<CanonicalCapture>,
    identity: ProducerIdentity,
}

pub struct HumanConsoleCaptureAdapter {
    capture: Arc<CanonicalCapture>,
    identity: ProducerIdentity,
}

impl HumanConsoleCaptureAdapter {
    /// Binds a human-console producer to the shared capture.
    ///
    /// # Errors
    /// Returns a kind mismatch or invalid-identifier error for an unusable human identity.
    pub fn new(
        capture: Arc<CanonicalCapture>,
        identity: ProducerIdentity,
    ) -> Result<Self, CaptureError> {
        if identity.kind != ProducerKind::Human {
            return Err(CaptureError::ProducerKindMismatch);
        }
        identity.validate()?;
        Ok(Self { capture, identity })
    }

    /// Durably records a prompt, performs bounded console I/O, and records its terminal outcome.
    ///
    /// # Errors
    /// Returns capture errors before I/O or [`CaptureError::ConsoleIo`] after recording an I/O,
    /// EOF, or oversize terminal observation.
    // Console boundary fields remain explicit and typed at the call site.
    #[allow(clippy::too_many_arguments)]
    pub fn prompt_and_read<R, W>(
        &self,
        interaction_id: &str,
        prompt_id: &str,
        task_id: Option<&str>,
        context_id: Option<&str>,
        prompt: &[u8],
        parent: CaptureParent,
        input: &mut R,
        output: &mut W,
    ) -> Result<Vec<u8>, CaptureError>
    where
        R: std::io::BufRead,
        W: std::io::Write,
    {
        let mut reservation = self.capture.reserve_required(2, ReservationKind::Wrapper)?;
        let prompt_receipt = reservation.record(
            &self.identity,
            CaptureKind::HumanPrompt,
            interaction_id,
            &self.identity.id,
            task_id,
            context_id,
            Some(prompt_id),
            prompt,
            parent,
        )?;
        if output
            .write_all(prompt)
            .and_then(|()| output.flush())
            .is_err()
        {
            reservation.record(
                &self.identity,
                CaptureKind::HumanFailed,
                interaction_id,
                &self.identity.id,
                task_id,
                context_id,
                Some(prompt_id),
                b"console-write-failed",
                CaptureParent::Event(prompt_receipt.event_id),
            )?;
            return Err(CaptureError::ConsoleIo);
        }
        let mut decision = Vec::new();
        let mut limited = std::io::Read::take(input, (MAX_HUMAN_DECISION_BYTES + 1) as u64);
        let Ok(read) = std::io::BufRead::read_until(&mut limited, b'\n', &mut decision) else {
            reservation.record(
                &self.identity,
                CaptureKind::HumanFailed,
                interaction_id,
                &self.identity.id,
                task_id,
                context_id,
                Some(prompt_id),
                b"console-read-failed",
                CaptureParent::Event(prompt_receipt.event_id),
            )?;
            return Err(CaptureError::ConsoleIo);
        };
        if decision.len() > MAX_HUMAN_DECISION_BYTES {
            reservation.record(
                &self.identity,
                CaptureKind::HumanFailed,
                interaction_id,
                &self.identity.id,
                task_id,
                context_id,
                Some(prompt_id),
                b"console-decision-oversize",
                CaptureParent::Event(prompt_receipt.event_id),
            )?;
            return Err(CaptureError::ConsoleIo);
        }
        if read == 0 {
            reservation.record(
                &self.identity,
                CaptureKind::HumanFailed,
                interaction_id,
                &self.identity.id,
                task_id,
                context_id,
                Some(prompt_id),
                b"console-eof",
                CaptureParent::Event(prompt_receipt.event_id),
            )?;
            return Err(CaptureError::ConsoleIo);
        }
        reservation.record(
            &self.identity,
            CaptureKind::HumanDecision,
            interaction_id,
            &self.identity.id,
            task_id,
            context_id,
            Some(prompt_id),
            &decision,
            CaptureParent::Event(prompt_receipt.event_id),
        )?;
        Ok(decision)
    }
}

impl ArtifactCaptureAdapter {
    /// Binds an artifact producer to the shared capture.
    ///
    /// # Errors
    /// Returns a kind mismatch or invalid-identifier error for an unusable artifact identity.
    pub fn new(
        capture: Arc<CanonicalCapture>,
        identity: ProducerIdentity,
    ) -> Result<Self, CaptureError> {
        if identity.kind != ProducerKind::Artifact {
            return Err(CaptureError::ProducerKindMismatch);
        }
        identity.validate()?;
        Ok(Self { capture, identity })
    }

    /// Records artifact production from the supplied artifact bytes.
    ///
    /// # Errors
    /// Returns validation, interaction-binding, capacity, lock, or persistence errors.
    pub fn produced(
        &self,
        interaction_id: &str,
        artifact_id: &str,
        task_id: Option<&str>,
        context_id: Option<&str>,
        content: &[u8],
        parent: CaptureParent,
    ) -> Result<CaptureReceipt, CaptureError> {
        self.record_artifact(
            CaptureKind::ArtifactProduced,
            interaction_id,
            artifact_id,
            task_id,
            context_id,
            content,
            parent,
        )
    }

    /// Records artifact consumption from the supplied artifact bytes.
    ///
    /// # Errors
    /// Returns validation, interaction-binding, capacity, lock, or persistence errors.
    pub fn consumed(
        &self,
        interaction_id: &str,
        artifact_id: &str,
        task_id: Option<&str>,
        context_id: Option<&str>,
        content: &[u8],
        parent: CaptureParent,
    ) -> Result<CaptureReceipt, CaptureError> {
        self.record_artifact(
            CaptureKind::ArtifactConsumed,
            interaction_id,
            artifact_id,
            task_id,
            context_id,
            content,
            parent,
        )
    }

    // Artifact observations use the same closed correlation tuple as all adapters.
    #[allow(clippy::too_many_arguments)]
    fn record_artifact(
        &self,
        kind: CaptureKind,
        interaction_id: &str,
        artifact_id: &str,
        task_id: Option<&str>,
        context_id: Option<&str>,
        content: &[u8],
        parent: CaptureParent,
    ) -> Result<CaptureReceipt, CaptureError> {
        self.capture.record(
            &self.identity,
            kind,
            interaction_id,
            &self.identity.id,
            task_id,
            context_id,
            Some(artifact_id),
            content,
            parent,
        )
    }
}

#[derive(Debug, Error)]
pub enum ToolCaptureError<E> {
    #[error("tool capture failed: {0}")]
    Capture(#[from] CaptureError),
    #[error("wrapped tool failed")]
    Tool(E),
}

pub struct ToolMcpCaptureAdapter {
    capture: Arc<CanonicalCapture>,
    identity: ProducerIdentity,
}

impl ToolMcpCaptureAdapter {
    /// Binds a tool/MCP producer to the shared capture.
    ///
    /// # Errors
    /// Returns a kind mismatch or invalid-identifier error for an unusable tool identity.
    pub fn new(
        capture: Arc<CanonicalCapture>,
        identity: ProducerIdentity,
    ) -> Result<Self, CaptureError> {
        if identity.kind != ProducerKind::Tool {
            return Err(CaptureError::ProducerKindMismatch);
        }
        identity.validate()?;
        Ok(Self { capture, identity })
    }

    /// Records a call before executing a real closure and records its result or failure.
    ///
    /// # Errors
    /// Returns [`ToolCaptureError::Capture`] for capture failure and [`ToolCaptureError::Tool`]
    /// when the wrapped closure fails after its terminal failure observation is durable.
    // The wrapper keeps the operation adjacent to its complete capture context.
    #[allow(clippy::too_many_arguments)]
    pub fn execute<E, F>(
        &self,
        interaction_id: &str,
        tool_id: &str,
        task_id: Option<&str>,
        context_id: Option<&str>,
        input: &[u8],
        parent: CaptureParent,
        operation: F,
    ) -> Result<Vec<u8>, ToolCaptureError<E>>
    where
        F: FnOnce() -> Result<Vec<u8>, E>,
    {
        let mut reservation = self.capture.reserve_required(2, ReservationKind::Wrapper)?;
        let call = reservation.record(
            &self.identity,
            CaptureKind::ToolCall,
            interaction_id,
            tool_id,
            task_id,
            context_id,
            Some(tool_id),
            input,
            parent,
        )?;
        let output = match operation() {
            Ok(output) => output,
            Err(error) => {
                reservation.record(
                    &self.identity,
                    CaptureKind::ToolFailed,
                    interaction_id,
                    tool_id,
                    task_id,
                    context_id,
                    Some(tool_id),
                    b"tool-operation-failed",
                    CaptureParent::Event(call.event_id),
                )?;
                return Err(ToolCaptureError::Tool(error));
            }
        };
        reservation.record(
            &self.identity,
            CaptureKind::ToolResult,
            interaction_id,
            tool_id,
            task_id,
            context_id,
            Some(tool_id),
            &output,
            CaptureParent::Event(call.event_id),
        )?;
        Ok(output)
    }
}

impl SmeshJournalCaptureAdapter {
    /// Binds a pinned SMESH runtime producer to the shared capture.
    ///
    /// # Errors
    /// Returns a kind mismatch or invalid-identifier error for an unusable SMESH identity.
    pub fn new(
        capture: Arc<CanonicalCapture>,
        identity: ProducerIdentity,
    ) -> Result<Self, CaptureError> {
        if identity.kind != ProducerKind::Smesh {
            return Err(CaptureError::ProducerKindMismatch);
        }
        identity.validate()?;
        Ok(Self { capture, identity })
    }

    /// Normalizes one supported pinned `JournalEvent` into the capture schema.
    ///
    /// # Errors
    /// Returns validation, unsupported-kind, capacity, lock, or persistence errors.
    pub fn record_journal(
        &self,
        interaction_id: &str,
        task_id: Option<&str>,
        context_id: Option<&str>,
        event: &smesh_runtime::JournalEvent,
        parent: CaptureParent,
    ) -> Result<CaptureReceipt, CaptureError> {
        if event.node != self.identity.id {
            return Err(CaptureError::InvalidIdentifier);
        }
        let kind = match event.kind.as_str() {
            "signal_sent" => CaptureKind::SmeshSignalSent,
            _ => return Err(CaptureError::UnsupportedObservation),
        };
        let subject_id = event
            .data
            .get("hash")
            .and_then(serde_json::Value::as_str)
            .ok_or(CaptureError::InvalidIdentifier)?;
        if !valid_identifier(subject_id) {
            return Err(CaptureError::InvalidIdentifier);
        }
        let encoded = bounded_serialize(event).map_err(|_| CaptureError::UnsupportedObservation)?;
        self.capture.record(
            &self.identity,
            kind,
            interaction_id,
            &self.identity.id,
            task_id,
            context_id,
            Some(subject_id),
            &encoded,
            parent,
        )
    }

    /// Normalizes one pinned `RuntimeEvent` into the capture schema.
    ///
    /// # Errors
    /// Returns validation, encoding, capacity, lock, or persistence errors.
    pub fn record(
        &self,
        interaction_id: &str,
        task_id: Option<&str>,
        context_id: Option<&str>,
        event: smesh_runtime::RuntimeEvent,
        parent: CaptureParent,
    ) -> Result<CaptureReceipt, CaptureError> {
        let (kind, subject_id, details) = match event {
            smesh_runtime::RuntimeEvent::SignalEmitted { hash } => {
                require_identifier(&hash)?;
                (CaptureKind::SmeshSignalEmitted, Some(hash), Vec::new())
            }
            smesh_runtime::RuntimeEvent::SignalReinforced { hash, count } => {
                require_identifier(&hash)?;
                (
                    CaptureKind::SmeshSignalReinforced,
                    Some(hash),
                    bounded_serialize(&serde_json::json!({ "count": count }))
                        .map_err(|_| CaptureError::UnsupportedObservation)?,
                )
            }
            smesh_runtime::RuntimeEvent::SignalReceived { hash, from, hops } => {
                require_identifier(&hash)?;
                require_identifier(&from)?;
                (
                    CaptureKind::SmeshSignalReceived,
                    Some(hash),
                    bounded_serialize(&serde_json::json!({
                        "from": from,
                        "hops": hops,
                    }))
                    .map_err(|_| CaptureError::UnsupportedObservation)?,
                )
            }
            smesh_runtime::RuntimeEvent::SignalExpired { hash } => {
                require_identifier(&hash)?;
                (CaptureKind::SmeshSignalExpired, Some(hash), Vec::new())
            }
            smesh_runtime::RuntimeEvent::TickCompleted {
                tick,
                active_signals,
                expired,
            } => (
                CaptureKind::SmeshTickCompleted,
                None,
                bounded_serialize(&serde_json::json!({
                    "tick": tick,
                    "activeSignals": active_signals,
                    "expired": expired,
                }))
                .map_err(|_| CaptureError::UnsupportedObservation)?,
            ),
            smesh_runtime::RuntimeEvent::PeerConnected { peer_id } => {
                require_identifier(&peer_id)?;
                (CaptureKind::SmeshPeerConnected, Some(peer_id), Vec::new())
            }
            smesh_runtime::RuntimeEvent::PeerDisconnected { peer_id } => {
                require_identifier(&peer_id)?;
                (
                    CaptureKind::SmeshPeerDisconnected,
                    Some(peer_id),
                    Vec::new(),
                )
            }
        };
        self.capture.record(
            &self.identity,
            kind,
            interaction_id,
            &self.identity.id,
            task_id,
            context_id,
            subject_id.as_deref(),
            &details,
            parent,
        )
    }
}

fn interaction_binding(
    identity: &ProducerIdentity,
    peer_id: &str,
    task_id: Option<&str>,
    context_id: Option<&str>,
    kind: CaptureKind,
    subject_id: Option<&str>,
    content: &CapturedContent,
) -> InteractionBinding {
    let mut participants = [identity.id.clone(), peer_id.to_owned()];
    participants.sort();
    InteractionBinding {
        participants: HashMap::from([(identity.kind, participants)]),
        task_id: task_id.map(str::to_owned),
        context_id: context_id.map(str::to_owned),
        observations: HashMap::from([(kind, (subject_id.map(str::to_owned), content.clone()))]),
        paired_subjects: matches!(
            kind,
            CaptureKind::ToolCall
                | CaptureKind::ToolResult
                | CaptureKind::ToolFailed
                | CaptureKind::HumanPrompt
                | CaptureKind::HumanDecision
                | CaptureKind::HumanFailed
        )
        .then(|| (identity.kind, subject_id.map(str::to_owned)))
        .into_iter()
        .collect(),
        artifact_contract: matches!(
            kind,
            CaptureKind::ArtifactProduced | CaptureKind::ArtifactConsumed
        )
        .then(|| (subject_id.map(str::to_owned), content.clone())),
    }
}

fn binding_compatible(
    existing: &InteractionBinding,
    candidate: &InteractionBinding,
    kind: CaptureKind,
) -> bool {
    candidate.participants.iter().all(|(kind, participants)| {
        existing
            .participants
            .get(kind)
            .is_none_or(|existing| existing == participants)
    }) && candidate.paired_subjects.iter().all(|(kind, subject)| {
        existing
            .paired_subjects
            .get(kind)
            .is_none_or(|existing| existing == subject)
    }) && existing.task_id == candidate.task_id
        && existing.context_id == candidate.context_id
        && (existing.artifact_contract.is_none()
            || candidate.artifact_contract.is_none()
            || existing.artifact_contract == candidate.artifact_contract)
        && (!binding_kind_is_one_to_one(kind)
            || existing.observations.get(&kind).is_none_or(|observation| {
                candidate
                    .observations
                    .get(&kind)
                    .is_some_and(|candidate| candidate == observation)
            }))
}

fn binding_kind_is_one_to_one(kind: CaptureKind) -> bool {
    matches!(
        kind,
        CaptureKind::A2aSend
            | CaptureKind::A2aReceive
            | CaptureKind::ToolCall
            | CaptureKind::ToolResult
            | CaptureKind::ToolFailed
            | CaptureKind::ArtifactProduced
            | CaptureKind::ArtifactConsumed
            | CaptureKind::HumanPrompt
            | CaptureKind::HumanDecision
            | CaptureKind::HumanFailed
    )
}

// The digest preimage names every schema field explicitly; an options bag would weaken review.
#[allow(clippy::too_many_arguments)]
fn capture_event_id(
    run_id: &str,
    identity: &ProducerIdentity,
    producer_sequence: u64,
    kind: CaptureKind,
    interaction_id: &str,
    peer_id: &str,
    task_id: Option<&str>,
    context_id: Option<&str>,
    subject_id: Option<&str>,
    parent: &CaptureParent,
    content: &CapturedContent,
) -> String {
    let parent = match parent {
        CaptureParent::Root => "root".to_owned(),
        CaptureParent::Event(event_id) => format!("event:{event_id}"),
        CaptureParent::Missing {
            expected_event_id,
            reason,
        } => format!("missing:{expected_event_id}:{reason:?}"),
    };
    content_digest(
        format!(
            "full-matrix-event/v1\0{run_id}\0{}\0{producer_sequence}\0{kind:?}\0{interaction_id}\0{peer_id}\0{}\0{}\0{}\0{parent}\0{}\0{}",
            identity.key(),
            task_id.unwrap_or(""),
            context_id.unwrap_or(""),
            subject_id.unwrap_or(""),
            content.digest,
            content.byte_length,
        )
        .as_bytes(),
    )
}

// One pass validates sequence, kind, identity, causality, binding, and event ID together.
#[allow(clippy::too_many_lines)]
fn validate_replay_events(stream: &CaptureStream) -> Result<(), CaptureError> {
    let all_event_ids = stream
        .events
        .iter()
        .map(|event| event.event_id.as_str())
        .collect::<std::collections::HashSet<_>>();
    let mut event_ids = std::collections::HashSet::new();
    let mut producer_sequences = HashMap::new();
    let mut interactions: HashMap<String, InteractionBinding> = HashMap::new();
    let mut open_paired_interactions: HashMap<String, (CaptureKind, String)> = HashMap::new();
    for (index, event) in stream.events.iter().enumerate() {
        let expected_sequence = u64::try_from(index).map_err(|_| CaptureError::MalformedReplay)?;
        let producer_key = event.producer.identity.key();
        let expected_producer_sequence = *producer_sequences.get(&producer_key).unwrap_or(&0);
        let identifiers_valid = valid_identifier(&event.producer.identity.id)
            && valid_identifier(&event.producer.identity.instance_id)
            && valid_identifier(&event.interaction_id)
            && valid_identifier(&event.peer_id)
            && event.task_id.as_deref().is_none_or(valid_identifier)
            && event.context_id.as_deref().is_none_or(valid_identifier)
            && event.subject_id.as_deref().is_none_or(valid_identifier)
            && canonical_digest(&event.content.digest);
        let kind_matches = matches!(
            (event.producer.identity.kind, event.kind),
            (
                ProducerKind::A2a,
                CaptureKind::A2aSend | CaptureKind::A2aReceive
            ) | (
                ProducerKind::Smesh,
                CaptureKind::SmeshSignalEmitted
                    | CaptureKind::SmeshSignalSent
                    | CaptureKind::SmeshSignalReinforced
                    | CaptureKind::SmeshSignalReceived
                    | CaptureKind::SmeshSignalExpired
                    | CaptureKind::SmeshTickCompleted
                    | CaptureKind::SmeshPeerConnected
                    | CaptureKind::SmeshPeerDisconnected
            ) | (
                ProducerKind::Tool,
                CaptureKind::ToolCall | CaptureKind::ToolResult | CaptureKind::ToolFailed
            ) | (
                ProducerKind::Artifact,
                CaptureKind::ArtifactProduced | CaptureKind::ArtifactConsumed
            ) | (
                ProducerKind::Human,
                CaptureKind::HumanPrompt | CaptureKind::HumanDecision | CaptureKind::HumanFailed
            )
        );
        let parent_valid = match &event.parent {
            CaptureParent::Root => true,
            CaptureParent::Event(parent_id) => {
                canonical_digest(parent_id) && event_ids.contains(parent_id)
            }
            CaptureParent::Missing {
                expected_event_id, ..
            } => {
                canonical_digest(expected_event_id)
                    && !all_event_ids.contains(expected_event_id.as_str())
            }
        };
        let expected_id = capture_event_id(
            &stream.run_id,
            &event.producer.identity,
            event.producer.sequence,
            event.kind,
            &event.interaction_id,
            &event.peer_id,
            event.task_id.as_deref(),
            event.context_id.as_deref(),
            event.subject_id.as_deref(),
            &event.parent,
            &event.content,
        );
        let binding = interaction_binding(
            &event.producer.identity,
            &event.peer_id,
            event.task_id.as_deref(),
            event.context_id.as_deref(),
            event.kind,
            event.subject_id.as_deref(),
            &event.content,
        );
        let interaction_valid = interactions
            .get(&event.interaction_id)
            .is_none_or(|existing| binding_compatible(existing, &binding, event.kind));
        if event.sequence != expected_sequence
            || event.producer.sequence != expected_producer_sequence
            || !identifiers_valid
            || !kind_matches
            || !parent_valid
            || event.event_id != expected_id
            || !interaction_valid
            || !event_ids.insert(event.event_id.clone())
        {
            return Err(CaptureError::MalformedReplay);
        }
        match event.kind {
            CaptureKind::A2aReceive if event.subject_id.as_deref() == Some(A2A_HOOK_SUBJECT) => {
                if open_paired_interactions
                    .insert(
                        event.interaction_id.clone(),
                        (event.kind, event.event_id.clone()),
                    )
                    .is_some()
                {
                    return Err(CaptureError::MalformedReplay);
                }
            }
            CaptureKind::A2aSend if event.subject_id.as_deref() == Some(A2A_HOOK_SUBJECT) => {
                let Some((CaptureKind::A2aReceive, opener_id)) =
                    open_paired_interactions.remove(&event.interaction_id)
                else {
                    return Err(CaptureError::MalformedReplay);
                };
                if event.parent != CaptureParent::Event(opener_id) {
                    return Err(CaptureError::MalformedReplay);
                }
            }
            CaptureKind::ToolCall | CaptureKind::HumanPrompt => {
                if open_paired_interactions
                    .insert(
                        event.interaction_id.clone(),
                        (event.kind, event.event_id.clone()),
                    )
                    .is_some()
                {
                    return Err(CaptureError::MalformedReplay);
                }
            }
            CaptureKind::ToolResult | CaptureKind::ToolFailed => {
                let Some((CaptureKind::ToolCall, opener_id)) =
                    open_paired_interactions.remove(&event.interaction_id)
                else {
                    return Err(CaptureError::MalformedReplay);
                };
                if event.parent != CaptureParent::Event(opener_id) {
                    return Err(CaptureError::MalformedReplay);
                }
            }
            CaptureKind::HumanDecision | CaptureKind::HumanFailed => {
                let Some((CaptureKind::HumanPrompt, opener_id)) =
                    open_paired_interactions.remove(&event.interaction_id)
                else {
                    return Err(CaptureError::MalformedReplay);
                };
                if event.parent != CaptureParent::Event(opener_id) {
                    return Err(CaptureError::MalformedReplay);
                }
            }
            _ => {}
        }
        match interactions.get_mut(&event.interaction_id) {
            Some(existing) => {
                existing.participants.extend(binding.participants.clone());
                existing
                    .paired_subjects
                    .extend(binding.paired_subjects.clone());
                if existing.artifact_contract.is_none() {
                    existing
                        .artifact_contract
                        .clone_from(&binding.artifact_contract);
                }
                existing
                    .observations
                    .entry(event.kind)
                    .or_insert_with(|| binding.observations[&event.kind].clone());
            }
            None => {
                interactions.insert(event.interaction_id.clone(), binding);
            }
        }
        producer_sequences.insert(
            producer_key,
            expected_producer_sequence
                .checked_add(1)
                .ok_or(CaptureError::MalformedReplay)?,
        );
    }
    if !open_paired_interactions.is_empty() {
        return Err(CaptureError::MalformedReplay);
    }
    Ok(())
}

fn canonical_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn require_identifier(value: &str) -> Result<(), CaptureError> {
    if valid_identifier(value) {
        Ok(())
    } else {
        Err(CaptureError::InvalidIdentifier)
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn failed_terminal_sync_cannot_leave_a_replayable_spool() {
        let path = std::env::temp_dir().join(format!(
            "smesh-complete-sync-failure-{}-{}.jsonl",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = std::fs::remove_file(&path);
        let capture =
            CanonicalCapture::create_spool("run-complete-sync-failure", 1, &path).unwrap();
        let identity = ProducerIdentity::new(ProducerKind::Smesh, "runtime", "process").unwrap();
        capture
            .record(
                &identity,
                CaptureKind::SmeshSignalEmitted,
                "interaction",
                "runtime",
                None,
                None,
                Some("signal"),
                b"signal",
                CaptureParent::Root,
            )
            .unwrap();
        capture.state.lock().unwrap().fail_sync_after_next_write = true;

        assert_eq!(capture.complete(), Err(CaptureError::Persistence));
        assert_eq!(
            capture.snapshot().unwrap().failure,
            Some(CaptureFailure::Persistence)
        );
        assert_eq!(capture.complete(), Err(CaptureError::CaptureInvalid));
        drop(capture);
        let persisted = std::fs::read(&path).unwrap();
        assert_eq!(
            CanonicalCapture::replay_jsonl(&persisted),
            Err(CaptureError::MalformedReplay)
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn live_record_rejects_forged_oversized_identity_before_durable_append() {
        let path =
            std::env::temp_dir().join(format!("smesh-invalid-live-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let capture = CanonicalCapture::create_spool("run-invalid-live", 1, &path).unwrap();
        let identity = ProducerIdentity {
            kind: ProducerKind::Smesh,
            id: "x".repeat(257),
            instance_id: "process".to_owned(),
        };

        assert_eq!(
            capture.record(
                &identity,
                CaptureKind::SmeshSignalEmitted,
                "interaction",
                "runtime",
                None,
                None,
                Some("signal"),
                b"signal",
                CaptureParent::Root,
            ),
            Err(CaptureError::InvalidIdentifier)
        );
        assert!(capture.snapshot().unwrap().events.is_empty());
        assert!(capture.snapshot().unwrap().capture_valid);
        assert!(std::fs::read(&path).unwrap().is_empty());
        drop(capture);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn complete_rejects_a_corrupted_missing_claim_conflict() {
        let path = std::env::temp_dir().join(format!(
            "smesh-missing-defense-{}-{}.jsonl",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = std::fs::remove_file(&path);
        let capture = CanonicalCapture::create_spool("run-missing-defense", 2, &path).unwrap();
        let identity = ProducerIdentity::new(ProducerKind::Smesh, "runtime", "process").unwrap();
        let receipt = capture
            .record(
                &identity,
                CaptureKind::SmeshSignalEmitted,
                "interaction",
                "runtime",
                None,
                None,
                Some("signal"),
                b"signal",
                CaptureParent::Root,
            )
            .unwrap();
        capture
            .state
            .lock()
            .unwrap()
            .missing_claims
            .insert(receipt.event_id().to_owned());

        assert_eq!(capture.complete(), Err(CaptureError::CaptureInvalid));
        assert!(!capture.snapshot().unwrap().capture_valid);
        drop(capture);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn complete_rejects_corrupted_protocol_without_terminal_record() {
        let path = std::env::temp_dir().join(format!(
            "smesh-protocol-defense-{}-{}.jsonl",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = std::fs::remove_file(&path);
        let capture = CanonicalCapture::create_spool("run-protocol-defense", 2, &path).unwrap();
        let identity = ProducerIdentity::new(ProducerKind::Smesh, "runtime", "process").unwrap();
        capture
            .record(
                &identity,
                CaptureKind::SmeshSignalEmitted,
                "interaction",
                "runtime",
                None,
                None,
                Some("signal"),
                b"signal",
                CaptureParent::Root,
            )
            .unwrap();
        let mut duplicate = capture.snapshot().unwrap().events.remove(0);
        duplicate.sequence = 1;
        capture.state.lock().unwrap().events.push(duplicate);

        assert_eq!(capture.complete(), Err(CaptureError::CaptureInvalid));
        assert!(!capture.snapshot().unwrap().capture_valid);
        let persisted = std::fs::read_to_string(&path).unwrap();
        assert!(!persisted.contains("\"recordType\":\"complete\""));
        assert_eq!(
            CanonicalCapture::replay_jsonl(persisted.as_bytes()),
            Err(CaptureError::CaptureInvalid)
        );
        drop(capture);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn ingest_admission_has_no_per_event_prefix_scans() {
        let source = include_str!("full_matrix_capture.rs");
        let nested_duplicate_scan = ["chain(accepted.", "iter())"].concat();
        let nested_sequence_scan = ["accepted", ".iter()", ".filter("].concat();

        assert!(!source.contains(&nested_duplicate_scan));
        assert!(!source.contains(&nested_sequence_scan));
        assert!(source.contains("accepted_event_ids"));
        assert!(source.contains("next_producer_sequences"));
    }

    #[test]
    fn later_event_matching_a_missing_parent_claim_invalidates_without_append() {
        let capture = CanonicalCapture::new("run-missing-claim", 3).unwrap();
        let identity = ProducerIdentity::new(ProducerKind::Smesh, "runtime", "process").unwrap();
        let later_content = CapturedContent {
            digest: content_digest(b"later"),
            byte_length: 5,
        };
        let claimed_event_id = capture_event_id(
            "run-missing-claim",
            &identity,
            1,
            CaptureKind::SmeshSignalEmitted,
            "later-interaction",
            "runtime",
            None,
            None,
            Some("later-signal"),
            &CaptureParent::Root,
            &later_content,
        );
        capture
            .record(
                &identity,
                CaptureKind::SmeshSignalEmitted,
                "claim-interaction",
                "runtime",
                None,
                None,
                Some("claim-signal"),
                b"claim",
                CaptureParent::Missing {
                    expected_event_id: claimed_event_id,
                    reason: CaptureGapReason::ExternalBoundary,
                },
            )
            .unwrap();

        assert_eq!(
            capture.record(
                &identity,
                CaptureKind::SmeshSignalEmitted,
                "later-interaction",
                "runtime",
                None,
                None,
                Some("later-signal"),
                b"later",
                CaptureParent::Root,
            ),
            Err(CaptureError::CaptureInvalid)
        );
        let stream = capture.snapshot().unwrap();
        assert_eq!(stream.events.len(), 1);
        assert!(!stream.capture_valid);
        assert_eq!(stream.failure, Some(CaptureFailure::SequenceGap));
    }

    #[test]
    fn caller_capacity_is_limited_to_global_replay_event_bound() {
        let boundary = CanonicalCapture::new("run-capacity-boundary", MAX_REPLAY_EVENTS).unwrap();
        let capture = CanonicalCapture::new("run-capacity-boundary", usize::MAX).unwrap();
        let path = std::env::temp_dir().join(format!(
            "smesh-capacity-boundary-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let spool =
            CanonicalCapture::create_spool("run-capacity-spool", usize::MAX, &path).unwrap();

        assert_eq!(boundary.capacity, MAX_REPLAY_EVENTS);
        assert_eq!(capture.capacity, MAX_REPLAY_EVENTS);
        assert_eq!(spool.capacity, MAX_REPLAY_EVENTS);
        assert!(capture.snapshot().unwrap().events.len() <= MAX_REPLAY_EVENTS);
        drop(spool);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn persist_new_validates_protocol_before_creating_file() {
        let capture = Arc::new(CanonicalCapture::new("run-persist-validation", 2).unwrap());
        let first = A2aCaptureAdapter::new(
            Arc::clone(&capture),
            ProducerIdentity::new(ProducerKind::A2a, "gateway-a", "process-a").unwrap(),
        )
        .unwrap()
        .send(
            "first-persist-interaction",
            "peer",
            None,
            None,
            b"first",
            CaptureParent::Root,
        )
        .unwrap();
        let source = Arc::new(CanonicalCapture::new("run-persist-validation", 1).unwrap());
        A2aCaptureAdapter::new(
            Arc::clone(&source),
            ProducerIdentity::new(ProducerKind::A2a, "gateway-b", "process-b").unwrap(),
        )
        .unwrap()
        .send(
            "second-persist-interaction",
            "peer",
            None,
            None,
            b"second",
            CaptureParent::Missing {
                expected_event_id: first.event_id().to_owned(),
                reason: CaptureGapReason::ExternalBoundary,
            },
        )
        .unwrap();
        let mut conflicting = source.snapshot().unwrap().events.remove(0);
        conflicting.sequence = 1;
        capture.state.lock().unwrap().events.push(conflicting);
        let path =
            std::env::temp_dir().join(format!("smesh-persist-invalid-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);

        assert_eq!(
            capture.persist_new(&path),
            Err(CaptureError::MalformedReplay)
        );
        assert!(!path.exists());
    }

    #[test]
    fn canonical_digest_rejects_uppercase_hex() {
        assert!(!canonical_digest(
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn spool_parent_directory_sync_helper_accepts_created_entry() {
        let root = std::env::temp_dir().join(format!("smesh-parent-sync-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let path = root.join("capture.jsonl");
        std::fs::write(&path, b"").unwrap();

        assert_eq!(sync_parent_directory(&path), Ok(()));

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn paired_tool_and_human_kinds_bind_the_same_subject() {
        for (producer_kind, opener, closer) in [
            (
                ProducerKind::Tool,
                CaptureKind::ToolCall,
                CaptureKind::ToolResult,
            ),
            (
                ProducerKind::Human,
                CaptureKind::HumanPrompt,
                CaptureKind::HumanDecision,
            ),
        ] {
            let capture = CanonicalCapture::new("run-paired-subject", 2).unwrap();
            let identity = ProducerIdentity::new(producer_kind, "producer", "process").unwrap();
            let first = capture
                .record(
                    &identity,
                    opener,
                    "interaction",
                    "peer",
                    None,
                    None,
                    Some("subject-a"),
                    b"open",
                    CaptureParent::Root,
                )
                .unwrap();
            assert_eq!(
                capture.record(
                    &identity,
                    closer,
                    "interaction",
                    "peer",
                    None,
                    None,
                    Some("subject-b"),
                    b"close",
                    CaptureParent::Event(first.event_id().to_owned()),
                ),
                Err(CaptureError::InteractionConflict)
            );
        }
    }

    #[test]
    fn ingest_pre_admits_the_entire_serialized_batch() {
        let root = std::env::temp_dir().join(format!(
            "smesh-ingest-byte-admission-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let source_path = root.join("source.jsonl");
        let destination_path = root.join("destination.jsonl");
        let source = Arc::new(CanonicalCapture::new("run-byte-admission", 2).unwrap());
        let adapter = A2aCaptureAdapter::new(
            Arc::clone(&source),
            ProducerIdentity::new(ProducerKind::A2a, "source", "process").unwrap(),
        )
        .unwrap();
        adapter
            .send("one", "peer", None, None, b"one", CaptureParent::Root)
            .unwrap();
        adapter
            .send("two", "peer", None, None, b"two", CaptureParent::Root)
            .unwrap();
        source.persist_new(&source_path).unwrap();
        let source_bytes = std::fs::read(&source_path).unwrap();
        let event_bytes = source_bytes
            .split_inclusive(|byte| *byte == b'\n')
            .take(2)
            .map(<[u8]>::len)
            .sum::<usize>();

        let destination =
            CanonicalCapture::create_spool("run-byte-admission", 2, &destination_path).unwrap();
        destination.state.lock().unwrap().spool_bytes = MAX_CAPTURE_EVENT_BYTES - event_bytes + 1;

        assert_eq!(
            destination.ingest_jsonl(&source_bytes),
            Err(CaptureError::CapacityExhausted)
        );
        let written = std::fs::read_to_string(&destination_path).unwrap();
        assert!(!written.contains("\"recordType\":\"event\""));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn paired_reservation_claims_worst_case_spool_bytes_before_effect() {
        let path = std::env::temp_dir().join(format!("smesh-byte-reserve-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let capture =
            Arc::new(CanonicalCapture::create_spool("run-byte-reserve", 2, &path).unwrap());
        capture.state.lock().unwrap().spool_bytes = MAX_CAPTURE_BYTES - MAX_CAPTURE_LINE_BYTES;
        let tool = ToolMcpCaptureAdapter::new(
            Arc::clone(&capture),
            ProducerIdentity::new(ProducerKind::Tool, "tool", "process").unwrap(),
        )
        .unwrap();
        let invocations = AtomicUsize::new(0);

        let result = tool.execute(
            "interaction",
            "tool",
            None,
            None,
            b"input",
            CaptureParent::Root,
            || {
                invocations.fetch_add(1, Ordering::SeqCst);
                Ok::<_, std::convert::Infallible>(Vec::new())
            },
        );

        assert!(matches!(
            result,
            Err(ToolCaptureError::Capture(CaptureError::CapacityExhausted))
        ));
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
        drop(tool);
        drop(capture);
        std::fs::remove_file(path).unwrap();
    }
}
