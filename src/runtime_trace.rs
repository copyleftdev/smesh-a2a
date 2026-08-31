use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use smesh_runtime::RuntimeEvent;
use thiserror::Error;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::{
    CompletionEvidence, DispatchError, RuntimeEventSink, RuntimeTask, RuntimeTaskProcessor,
    content_digest,
};

const RUNTIME_TRACE_SCHEMA_V1: &str = "runtime-trace/1";
const RUNTIME_TRACE_SCHEMA_V2: &str = "runtime-trace/2";
const RUNTIME_TRACE_SCHEMA: &str = "runtime-trace/3";
const MAX_REPLAY_BYTES: usize = 16 * 1024 * 1024;
const MAX_REPLAY_EVENTS: usize = 100_000;
const MAX_CAPTURE_EVENTS: usize = 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RuntimeTraceKind {
    SignalEmitted,
    SignalReinforced,
    SignalReceived,
    SignalExpired,
    PeerConnected,
    PeerDisconnected,
    TickCompleted,
    Claim,
    Contradiction,
    TerminalOutput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RuntimeClaimKind {
    Review,
    Test,
    Attestation,
    Ratification,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RuntimeTerminalState {
    Completed,
    Failed,
    Canceled,
    InputRequired,
    Rejected,
}

/// How a requested cancellation reached its public terminal state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum RuntimeCancellationOutcome {
    CooperativeStop,
    ForcedAbort,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum RuntimeTraceDetails {
    None,
    Reinforcement {
        count: u32,
    },
    Receipt {
        hops: u32,
    },
    Tick {
        tick: u64,
        active_signals: usize,
        expired: usize,
    },
    Claim {
        claim_kind: RuntimeClaimKind,
        evidence_id: Option<String>,
        subject_digest: Option<String>,
        asserted_outcome: Option<bool>,
    },
    Contradiction {
        evidence_id: String,
        subject_digest: String,
        blocking: bool,
    },
    TerminalOutput {
        state: RuntimeTerminalState,
        artifact_digests: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cancellation_outcome: Option<RuntimeCancellationOutcome>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeTraceEvent {
    pub sequence: u64,
    pub monotonic_micros: u64,
    pub kind: RuntimeTraceKind,
    pub task_id: Option<String>,
    pub context_id: Option<String>,
    pub signal_hash: Option<String>,
    pub details: RuntimeTraceDetails,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeTrace {
    pub schema_version: String,
    pub capture_valid: bool,
    pub events: Vec<RuntimeTraceEvent>,
    pub dropped_optional: u64,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RuntimeTraceError {
    #[error("runtime trace capacity must be non-zero")]
    ZeroCapacity,
    #[error("required runtime trace capacity exhausted")]
    RequiredCapacityExhausted,
    #[error("invalid runtime trace correlation")]
    InvalidCorrelation,
    #[error("runtime trace correlation conflicts with an existing binding")]
    CorrelationConflict,
    #[error("runtime trace sequence exhausted")]
    SequenceOverflow,
    #[error("runtime trace schema is unsupported")]
    UnsupportedSchema,
    #[error("runtime trace persistence failed")]
    Persistence,
    #[error("runtime trace capture is invalid")]
    CaptureInvalid,
    #[error("runtime trace replay is malformed: {0}")]
    MalformedReplay(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Correlation {
    task_id: String,
    context_id: String,
}

struct RetainedRuntimeEvent {
    event: RuntimeTraceEvent,
    workload: Option<String>,
}

struct CaptureState {
    started: Instant,
    next_sequence: u64,

    required: VecDeque<RetainedRuntimeEvent>,
    optional: Vec<RuntimeTraceEvent>,
    required_capacity: usize,
    optional_capacity: usize,
    dropped_optional: u64,
    retired_required: u64,
    per_workload_capacity: usize,
    correlations: HashMap<String, Correlation>,
    workload_aliases: HashMap<String, String>,
    seen_hashes: std::collections::HashSet<String>,
    ambiguous_hashes: std::collections::HashSet<String>,
    hash_history_saturated: bool,
}

pub struct RuntimeEventCapture {
    state: Mutex<CaptureState>,
    failure: CancellationToken,
    telemetry: Option<crate::telemetry::TelemetryHandle>,
}

pub struct CorrelatingRuntimeProcessor<P> {
    inner: P,
    capture: Arc<RuntimeEventCapture>,
}

impl<P> CorrelatingRuntimeProcessor<P> {
    #[must_use]
    pub fn new(inner: P, capture: Arc<RuntimeEventCapture>) -> Self {
        Self { inner, capture }
    }
}

#[async_trait::async_trait]
impl<P> RuntimeTaskProcessor for CorrelatingRuntimeProcessor<P>
where
    P: RuntimeTaskProcessor,
{
    async fn process(
        &self,
        task: RuntimeTask,
        cancellation: CancellationToken,
        events: RuntimeEventSink,
    ) -> Result<(), DispatchError> {
        self.capture
            .register_correlation(
                &task.signal_hash,
                &task.request.task_id,
                &task.request.context_id,
            )
            .await
            .map_err(|error| DispatchError::Message(error.to_string()))?;
        self.inner.process(task, cancellation, events).await
    }
}

impl RuntimeEventCapture {
    #[must_use]
    pub fn new(required_capacity: usize, optional_capacity: usize) -> Self {
        Self::new_with_retention(
            required_capacity,
            optional_capacity,
            required_capacity.min(256),
        )
    }

    /// Construct a capture with a bounded process window and per-workload share.
    #[must_use]
    pub fn new_with_retention(
        required_capacity: usize,
        optional_capacity: usize,
        per_workload_capacity: usize,
    ) -> Self {
        let required_capacity = if required_capacity == 0 {
            0
        } else {
            required_capacity.clamp(2, MAX_CAPTURE_EVENTS)
        };
        let optional_capacity = optional_capacity.min(MAX_CAPTURE_EVENTS - required_capacity);
        Self {
            state: Mutex::new(CaptureState {
                started: Instant::now(),
                next_sequence: 0,

                required: VecDeque::new(),
                optional: Vec::new(),
                required_capacity,
                optional_capacity,
                dropped_optional: 0,
                retired_required: 0,
                per_workload_capacity: if required_capacity == 0 {
                    0
                } else {
                    per_workload_capacity.clamp(2, required_capacity)
                },
                correlations: HashMap::new(),
                workload_aliases: HashMap::new(),
                seen_hashes: std::collections::HashSet::new(),
                ambiguous_hashes: std::collections::HashSet::new(),
                hash_history_saturated: false,
            }),
            failure: CancellationToken::new(),
            telemetry: None,
        }
    }

    #[must_use]
    pub fn with_telemetry(mut self, telemetry: Option<crate::telemetry::TelemetryHandle>) -> Self {
        self.telemetry = telemetry;
        self
    }

    #[must_use]
    pub fn failure_token(&self) -> CancellationToken {
        self.failure.clone()
    }

    pub fn invalidate(&self) {
        self.failure.cancel();
    }

    fn fail<T>(&self, error: RuntimeTraceError) -> Result<T, RuntimeTraceError> {
        self.failure.cancel();
        Err(error)
    }

    /// Bind a runtime signal hash to its authoritative A2A task and context.
    ///
    /// # Errors
    ///
    /// Returns an error for empty/oversized fields, a conflicting binding, or a full active map.
    pub async fn register_correlation(
        &self,
        signal_hash: &str,
        task_id: &str,
        context_id: &str,
    ) -> Result<(), RuntimeTraceError> {
        if [signal_hash, task_id, context_id]
            .iter()
            .any(|value| !bounded_public_value(value))
        {
            return Err(RuntimeTraceError::InvalidCorrelation);
        }
        let mut state = self.state.lock().await;
        if state.required_capacity == 0 {
            return Err(RuntimeTraceError::ZeroCapacity);
        }
        let correlation = Correlation {
            task_id: task_id.to_owned(),
            context_id: context_id.to_owned(),
        };
        if let Some(existing) = state.correlations.get(signal_hash) {
            if existing.task_id != correlation.task_id
                || existing.context_id != correlation.context_id
            {
                return Err(RuntimeTraceError::CorrelationConflict);
            }
            return Ok(());
        }
        if state.correlations.len() >= state.required_capacity {
            return Err(RuntimeTraceError::RequiredCapacityExhausted);
        }
        let workload = runtime_workload_key(task_id, context_id);
        if state
            .workload_aliases
            .get(signal_hash)
            .is_some_and(|existing| existing != &workload)
        {
            return Err(RuntimeTraceError::CorrelationConflict);
        }
        let reused_hash = state.hash_history_saturated || state.seen_hashes.contains(signal_hash);
        if state.seen_hashes.len() < MAX_CAPTURE_EVENTS {
            state.seen_hashes.insert(signal_hash.to_owned());
        } else {
            state.hash_history_saturated = true;
        }
        if reused_hash {
            state.ambiguous_hashes.insert(signal_hash.to_owned());
        }
        state
            .workload_aliases
            .insert(signal_hash.to_owned(), workload.clone());
        state
            .correlations
            .insert(signal_hash.to_owned(), correlation.clone());
        for retained in &mut state.required {
            if retained.event.signal_hash.as_deref() == Some(signal_hash) {
                retained.workload = Some(workload.clone());
                if retained.event.kind == RuntimeTraceKind::SignalEmitted
                    && retained.event.task_id.is_none()
                {
                    retained.event.task_id = Some(correlation.task_id.clone());
                    retained.event.context_id = Some(correlation.context_id.clone());
                }
            }
        }
        for event in &mut state.optional {
            if event.kind == RuntimeTraceKind::SignalEmitted
                && event.signal_hash.as_deref() == Some(signal_hash)
                && event.task_id.is_none()
            {
                event.task_id = Some(correlation.task_id.clone());
                event.context_id = Some(correlation.context_id.clone());
            }
        }
        enforce_workload_limit(&mut state, &workload);
        Ok(())
    }

    #[doc(hidden)]
    pub async fn correlation_count_for_test(&self) -> usize {
        self.state.lock().await.correlations.len()
    }

    #[doc(hidden)]
    pub async fn retention_stats_for_test(&self) -> (u64, usize, usize, usize) {
        let state = self.state.lock().await;
        (
            state.retired_required,
            state.required_capacity,
            state.optional_capacity,
            state.workload_aliases.len() + state.ambiguous_hashes.len() + state.seen_hashes.len(),
        )
    }

    /// Record one genuine runtime event using only allowlisted, non-payload details.
    ///
    /// # Errors
    ///
    /// Required history retires within the configured process/per-workload RPO window.
    pub async fn record(&self, event: RuntimeEvent) -> Result<(), RuntimeTraceError> {
        let mut state = self.state.lock().await;
        if state.required_capacity == 0 {
            return self.fail(RuntimeTraceError::ZeroCapacity);
        }
        let (kind, signal_hash, required, details) = adapt_event(event);
        if signal_hash
            .as_deref()
            .is_some_and(|hash| !bounded_public_value(hash))
        {
            return self.fail(RuntimeTraceError::InvalidCorrelation);
        }

        if required
            && kind != RuntimeTraceKind::SignalEmitted
            && signal_hash.as_deref().is_some_and(|hash| {
                state.hash_history_saturated
                    || state.ambiguous_hashes.contains(hash)
                    || state.seen_hashes.contains(hash)
                        && !state.workload_aliases.contains_key(hash)
            })
        {
            state.retired_required = state.retired_required.saturating_add(1);
            return Ok(());
        }

        if !required && state.optional.len() >= state.optional_capacity {
            state.dropped_optional = state.dropped_optional.saturating_add(1);
            return Ok(());
        }
        let correlation = (kind == RuntimeTraceKind::SignalEmitted)
            .then(|| {
                signal_hash
                    .as_deref()
                    .and_then(|hash| state.correlations.get(hash))
                    .cloned()
            })
            .flatten();
        let trace_event = RuntimeTraceEvent {
            sequence: state.next_sequence,
            monotonic_micros: u64::try_from(state.started.elapsed().as_micros())
                .unwrap_or(u64::MAX),
            kind,
            task_id: correlation.as_ref().map(|value| value.task_id.clone()),
            context_id: correlation.as_ref().map(|value| value.context_id.clone()),
            signal_hash,
            details,
        };
        state.next_sequence = match state.next_sequence.checked_add(1) {
            Some(next) => next,
            None => return self.fail(RuntimeTraceError::SequenceOverflow),
        };
        let projection = (
            trace_event.kind,
            trace_event.task_id.clone(),
            trace_event.context_id.clone(),
            trace_event.signal_hash.clone(),
        );
        if required {
            push_required(&mut state, trace_event);
        } else {
            state.optional.push(trace_event);
        }

        drop(state);
        if let Some(telemetry) = &self.telemetry {
            let (name, reason) = match projection.0 {
                RuntimeTraceKind::Claim => (crate::telemetry::EventName::RuntimeClaim, "claim"),
                RuntimeTraceKind::Contradiction => (
                    crate::telemetry::EventName::RuntimeContradiction,
                    "contradiction",
                ),
                RuntimeTraceKind::TerminalOutput => {
                    (crate::telemetry::EventName::RuntimeTerminal, "terminal")
                }
                RuntimeTraceKind::TickCompleted => {
                    (crate::telemetry::EventName::RuntimeLifecycle, "tick")
                }
                _ => (crate::telemetry::EventName::RuntimeLifecycle, "lifecycle"),
            };
            telemetry.runtime_event(
                name,
                reason,
                projection.1.as_deref(),
                projection.2.as_deref(),
                projection.3.as_deref(),
            );
        }
        Ok(())
    }

    /// Record an untrusted gateway claim without copying raw evidence bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identifiers or exhausted required capacity.
    pub async fn record_evidence(
        &self,
        task_id: &str,
        context_id: &str,
        evidence: &CompletionEvidence,
    ) -> Result<(), RuntimeTraceError> {
        let (kind, details) = match evidence {
            CompletionEvidence::Review {
                id,
                subject_digest,
                approved,
                ..
            } => (
                RuntimeTraceKind::Claim,
                RuntimeTraceDetails::Claim {
                    claim_kind: RuntimeClaimKind::Review,
                    evidence_id: Some(content_digest(id.as_bytes())),
                    subject_digest: Some(subject_digest.clone()),
                    asserted_outcome: Some(*approved),
                },
            ),
            CompletionEvidence::Test {
                id,
                subject_digest,
                passed,
                ..
            } => (
                RuntimeTraceKind::Claim,
                RuntimeTraceDetails::Claim {
                    claim_kind: RuntimeClaimKind::Test,
                    evidence_id: Some(content_digest(id.as_bytes())),
                    subject_digest: Some(subject_digest.clone()),
                    asserted_outcome: Some(*passed),
                },
            ),
            CompletionEvidence::Attestation {
                id, subject_digest, ..
            } => (
                RuntimeTraceKind::Claim,
                RuntimeTraceDetails::Claim {
                    claim_kind: RuntimeClaimKind::Attestation,
                    evidence_id: Some(content_digest(id.as_bytes())),
                    subject_digest: Some(subject_digest.clone()),
                    asserted_outcome: None,
                },
            ),
            CompletionEvidence::Contradiction {
                id,
                subject_digest,
                blocking,
                ..
            } => (
                RuntimeTraceKind::Contradiction,
                RuntimeTraceDetails::Contradiction {
                    evidence_id: content_digest(id.as_bytes()),
                    subject_digest: subject_digest.clone(),
                    blocking: *blocking,
                },
            ),
            CompletionEvidence::Ratification(receipt) => (
                RuntimeTraceKind::Claim,
                RuntimeTraceDetails::Claim {
                    claim_kind: RuntimeClaimKind::Ratification,
                    evidence_id: None,
                    subject_digest: Some(receipt.statement.artifact_set_digest.clone()),
                    asserted_outcome: Some(receipt.statement.approved),
                },
            ),
        };
        self.record_required_gateway(task_id, context_id, kind, details)
            .await
    }

    /// Record a public terminal outcome using only artifact digests.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identifiers/digests or exhausted required capacity.
    pub async fn record_terminal(
        &self,
        task_id: &str,
        context_id: &str,
        state: RuntimeTerminalState,
        artifact_digests: Vec<String>,
    ) -> Result<(), RuntimeTraceError> {
        if state == RuntimeTerminalState::Canceled
            || artifact_digests.len() > 16
            || artifact_digests
                .iter()
                .any(|digest| !bounded_public_value(digest))
        {
            return self.fail(RuntimeTraceError::InvalidCorrelation);
        }
        self.record_required_gateway(
            task_id,
            context_id,
            RuntimeTraceKind::TerminalOutput,
            RuntimeTraceDetails::TerminalOutput {
                state,
                artifact_digests,
                cancellation_outcome: None,
            },
        )
        .await
    }

    /// Record a terminal cancellation and how local processor containment ended.
    ///
    /// # Errors
    ///
    /// Returns an error for inconsistent state/outcome pairs, invalid identifiers, or exhausted
    /// required capacity.
    pub async fn record_cancellation_terminal(
        &self,
        task_id: &str,
        context_id: &str,
        state: RuntimeTerminalState,
        outcome: RuntimeCancellationOutcome,
    ) -> Result<(), RuntimeTraceError> {
        let valid = matches!(
            (state, outcome),
            (
                RuntimeTerminalState::Canceled,
                RuntimeCancellationOutcome::CooperativeStop
            ) | (
                RuntimeTerminalState::Failed,
                RuntimeCancellationOutcome::ForcedAbort | RuntimeCancellationOutcome::Failed
            )
        );
        if !valid {
            return self.fail(RuntimeTraceError::InvalidCorrelation);
        }
        self.record_required_gateway(
            task_id,
            context_id,
            RuntimeTraceKind::TerminalOutput,
            RuntimeTraceDetails::TerminalOutput {
                state,
                artifact_digests: Vec::new(),
                cancellation_outcome: Some(outcome),
            },
        )
        .await
    }

    async fn record_required_gateway(
        &self,
        task_id: &str,
        context_id: &str,
        kind: RuntimeTraceKind,
        details: RuntimeTraceDetails,
    ) -> Result<(), RuntimeTraceError> {
        if !bounded_public_value(task_id)
            || !bounded_public_value(context_id)
            || !details_are_bounded(&details, false)
        {
            return Err(RuntimeTraceError::InvalidCorrelation);
        }
        let mut state = self.state.lock().await;
        if state.required_capacity == 0 {
            return self.fail(RuntimeTraceError::ZeroCapacity);
        }
        let event = RuntimeTraceEvent {
            sequence: state.next_sequence,
            monotonic_micros: u64::try_from(state.started.elapsed().as_micros())
                .unwrap_or(u64::MAX),
            kind,
            task_id: Some(task_id.to_owned()),
            context_id: Some(context_id.to_owned()),
            signal_hash: None,
            details,
        };
        state.next_sequence = match state.next_sequence.checked_add(1) {
            Some(next) => next,
            None => return self.fail(RuntimeTraceError::SequenceOverflow),
        };
        let event_name = match event.kind {
            RuntimeTraceKind::Claim => crate::telemetry::EventName::RuntimeClaim,
            RuntimeTraceKind::Contradiction => crate::telemetry::EventName::RuntimeContradiction,
            RuntimeTraceKind::TerminalOutput => crate::telemetry::EventName::RuntimeTerminal,
            _ => crate::telemetry::EventName::RuntimeLifecycle,
        };
        push_required(&mut state, event);
        if kind == RuntimeTraceKind::TerminalOutput {
            state.correlations.retain(|_, correlation| {
                correlation.task_id != task_id || correlation.context_id != context_id
            });
        }
        drop(state);
        if let Some(telemetry) = &self.telemetry {
            telemetry.runtime_event(
                event_name,
                match kind {
                    RuntimeTraceKind::Claim => "claim",
                    RuntimeTraceKind::Contradiction => "contradiction",
                    RuntimeTraceKind::TerminalOutput => "terminal",
                    _ => "lifecycle",
                },
                Some(task_id),
                Some(context_id),
                None,
            );
        }
        Ok(())
    }

    pub async fn snapshot(&self) -> RuntimeTrace {
        let state = self.state.lock().await;
        let mut events = state
            .required
            .iter()
            .map(|retained| retained.event.clone())
            .collect::<Vec<_>>();
        events.extend(state.optional.clone());
        events.sort_by_key(|event| event.sequence);
        for (sequence, event) in events.iter_mut().enumerate() {
            event.sequence = u64::try_from(sequence).unwrap_or(u64::MAX);
        }
        RuntimeTrace {
            schema_version: RUNTIME_TRACE_SCHEMA.to_owned(),
            capture_valid: !self.failure.is_cancelled(),
            events,
            dropped_optional: state.dropped_optional,
        }
    }

    /// Persist one immutable trace artifact with create-new semantics.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding, secure file creation, writing, or syncing fails.
    pub async fn persist_new(&self, path: impl AsRef<Path>) -> Result<(), RuntimeTraceError> {
        if self.failure.is_cancelled() {
            return Err(RuntimeTraceError::CaptureInvalid);
        }
        let path: PathBuf = path.as_ref().to_path_buf();
        let mut encoded = serde_json::to_vec(&self.snapshot().await)
            .map_err(|_| RuntimeTraceError::Persistence)?;
        encoded.push(b'\n');
        tokio::task::spawn_blocking(move || {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(path)
                .map_err(|_| RuntimeTraceError::Persistence)?;
            file.write_all(&encoded)
                .map_err(|_| RuntimeTraceError::Persistence)?;
            file.sync_all().map_err(|_| RuntimeTraceError::Persistence)
        })
        .await
        .map_err(|_| RuntimeTraceError::Persistence)?
    }

    /// Decode a captured trace without accessing live runtime state.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed JSON, duplicate/non-monotonic sequences, or time regression.
    pub fn replay(bytes: &[u8]) -> Result<RuntimeTrace, RuntimeTraceError> {
        if bytes.len() > MAX_REPLAY_BYTES {
            return Err(RuntimeTraceError::MalformedReplay(
                "trace exceeds replay byte limit".to_owned(),
            ));
        }
        let trace: RuntimeTrace = serde_json::from_slice(bytes)
            .map_err(|error| RuntimeTraceError::MalformedReplay(error.to_string()))?;
        let legacy_v1 = trace.schema_version == RUNTIME_TRACE_SCHEMA_V1;
        let legacy_v2 = trace.schema_version == RUNTIME_TRACE_SCHEMA_V2;
        if !legacy_v1 && !legacy_v2 && trace.schema_version != RUNTIME_TRACE_SCHEMA {
            return Err(RuntimeTraceError::UnsupportedSchema);
        }

        if !trace.capture_valid {
            return Err(RuntimeTraceError::CaptureInvalid);
        }
        if trace.events.len() > MAX_REPLAY_EVENTS {
            return Err(RuntimeTraceError::MalformedReplay(
                "trace exceeds replay event limit".to_owned(),
            ));
        }
        for (index, event) in trace.events.iter().enumerate() {
            if event.sequence != u64::try_from(index).unwrap_or(u64::MAX)
                || index > 0 && trace.events[index - 1].monotonic_micros > event.monotonic_micros
                || !trace_event_is_valid(event, legacy_v1)
            {
                return Err(RuntimeTraceError::MalformedReplay(
                    "trace ordering regressed".to_owned(),
                ));
            }
        }
        Ok(trace)
    }
}

fn runtime_workload_key(task_id: &str, context_id: &str) -> String {
    content_digest(format!("runtime-trace-workload/v1\0{task_id}\0{context_id}").as_bytes())
}

fn workload_for_event(state: &CaptureState, event: &RuntimeTraceEvent) -> Option<String> {
    if let Some(hash) = event.signal_hash.as_deref() {
        return state
            .workload_aliases
            .get(hash)
            .cloned()
            .or_else(|| Some(hash.to_owned()));
    }
    event
        .task_id
        .as_deref()
        .zip(event.context_id.as_deref())
        .map(|(task, context)| runtime_workload_key(task, context))
}

fn workload_matches(retained: &RetainedRuntimeEvent, workload: &str) -> bool {
    retained.workload.as_deref() == Some(workload)
}

fn is_boundary(retained: &RetainedRuntimeEvent) -> bool {
    matches!(
        retained.event.kind,
        RuntimeTraceKind::SignalEmitted | RuntimeTraceKind::TerminalOutput
    )
}

fn workload_is_completed(state: &CaptureState, workload: &str) -> bool {
    state.required.iter().any(|retained| {
        workload_matches(retained, workload)
            && retained.event.kind == RuntimeTraceKind::TerminalOutput
    })
}

fn retirement_index(state: &CaptureState, workload: &str) -> Option<usize> {
    state
        .required
        .iter()
        .position(|retained| workload_matches(retained, workload) && !is_boundary(retained))
        .or_else(|| {
            workload_is_completed(state, workload).then(|| {
                state
                    .required
                    .iter()
                    .position(|retained| workload_matches(retained, workload))
            })?
        })
        .or_else(|| {
            state
                .required
                .iter()
                .position(|retained| workload_matches(retained, workload))
        })
}

fn prune_workload_aliases(state: &mut CaptureState) {
    let retained_hashes = state
        .required
        .iter()
        .filter_map(|retained| retained.event.signal_hash.clone())
        .chain(state.correlations.keys().cloned())
        .collect::<std::collections::HashSet<_>>();
    state
        .workload_aliases
        .retain(|hash, _| retained_hashes.contains(hash));
    state
        .ambiguous_hashes
        .retain(|hash| retained_hashes.contains(hash));
}

fn enforce_workload_limit(state: &mut CaptureState, workload: &str) {
    while state
        .required
        .iter()
        .filter(|retained| workload_matches(retained, workload))
        .count()
        > state.per_workload_capacity
    {
        let Some(index) = retirement_index(state, workload) else {
            break;
        };
        state.required.remove(index);
        state.retired_required = state.retired_required.saturating_add(1);
    }
    prune_workload_aliases(state);
}

fn push_required(state: &mut CaptureState, event: RuntimeTraceEvent) {
    if state.required_capacity == 0 {
        return;
    }
    let workload = workload_for_event(state, &event);
    let retained = RetainedRuntimeEvent { event, workload };
    if let Some(workload) = retained.workload.as_deref() {
        let workload_count = state
            .required
            .iter()
            .filter(|existing| workload_matches(existing, workload))
            .count();
        let has_retirable_intermediate = state
            .required
            .iter()
            .any(|existing| workload_matches(existing, workload) && !is_boundary(existing));
        if workload_count >= state.per_workload_capacity
            && !is_boundary(&retained)
            && !has_retirable_intermediate
        {
            state.retired_required = state.retired_required.saturating_add(1);
            prune_workload_aliases(state);
            return;
        }
        while state
            .required
            .iter()
            .filter(|existing| workload_matches(existing, workload))
            .count()
            >= state.per_workload_capacity
        {
            let Some(index) = retirement_index(state, workload) else {
                break;
            };
            state.required.remove(index);
            state.retired_required = state.retired_required.saturating_add(1);
        }
    }
    while state.required.len() >= state.required_capacity {
        let completed_workload = state
            .required
            .iter()
            .filter_map(|candidate| candidate.workload.clone())
            .find(|workload| workload_is_completed(state, workload));
        if let Some(completed_workload) = completed_workload {
            let indexes = state
                .required
                .iter()
                .enumerate()
                .filter_map(|(index, candidate)| {
                    workload_matches(candidate, &completed_workload).then_some(index)
                })
                .collect::<Vec<_>>();
            for index in indexes.iter().rev() {
                state.required.remove(*index);
            }
            state.retired_required = state
                .retired_required
                .saturating_add(u64::try_from(indexes.len()).unwrap_or(u64::MAX));
            prune_workload_aliases(state);
            continue;
        }
        let non_boundary = state
            .required
            .iter()
            .position(|candidate| !is_boundary(candidate));
        state.required.remove(non_boundary.unwrap_or(0));
        state.retired_required = state.retired_required.saturating_add(1);
    }
    state.required.push_back(retained);
    prune_workload_aliases(state);
}

fn bounded_public_value(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
}

fn canonical_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn trace_event_is_valid(event: &RuntimeTraceEvent, legacy_v1: bool) -> bool {
    let identifiers_valid = event.task_id.as_deref().is_none_or(bounded_public_value)
        && event.context_id.as_deref().is_none_or(bounded_public_value)
        && event
            .signal_hash
            .as_deref()
            .is_none_or(bounded_public_value);
    let correlation_pair = event.task_id.is_some() == event.context_id.is_some();
    let shape_valid = match (&event.kind, &event.details) {
        (
            RuntimeTraceKind::SignalEmitted | RuntimeTraceKind::SignalExpired,
            RuntimeTraceDetails::None,
        )
        | (RuntimeTraceKind::SignalReinforced, RuntimeTraceDetails::Reinforcement { .. })
        | (RuntimeTraceKind::SignalReceived, RuntimeTraceDetails::Receipt { .. }) => {
            event.signal_hash.is_some() && correlation_pair
        }
        (
            RuntimeTraceKind::PeerConnected | RuntimeTraceKind::PeerDisconnected,
            RuntimeTraceDetails::None,
        )
        | (RuntimeTraceKind::TickCompleted, RuntimeTraceDetails::Tick { .. }) => {
            event.signal_hash.is_none() && event.task_id.is_none() && event.context_id.is_none()
        }
        (RuntimeTraceKind::Claim, RuntimeTraceDetails::Claim { .. })
        | (RuntimeTraceKind::Contradiction, RuntimeTraceDetails::Contradiction { .. })
        | (RuntimeTraceKind::TerminalOutput, RuntimeTraceDetails::TerminalOutput { .. }) => {
            event.signal_hash.is_none() && event.task_id.is_some() && event.context_id.is_some()
        }
        _ => false,
    };
    identifiers_valid && shape_valid && details_are_bounded(&event.details, legacy_v1)
}

fn details_are_bounded(details: &RuntimeTraceDetails, legacy_v1: bool) -> bool {
    match details {
        RuntimeTraceDetails::Claim {
            claim_kind,
            evidence_id,
            subject_digest,
            asserted_outcome,
        } => match claim_kind {
            RuntimeClaimKind::Review | RuntimeClaimKind::Test => {
                evidence_id.as_deref().is_some_and(canonical_sha256)
                    && subject_digest.as_deref().is_some_and(canonical_sha256)
                    && asserted_outcome.is_some()
            }
            RuntimeClaimKind::Attestation => {
                evidence_id.as_deref().is_some_and(canonical_sha256)
                    && subject_digest.as_deref().is_some_and(canonical_sha256)
                    && asserted_outcome.is_none()
            }
            RuntimeClaimKind::Ratification => {
                evidence_id.is_none()
                    && subject_digest.as_deref().is_some_and(canonical_sha256)
                    && asserted_outcome.is_some()
            }
        },
        RuntimeTraceDetails::Contradiction {
            evidence_id,
            subject_digest,
            ..
        } => canonical_sha256(evidence_id) && canonical_sha256(subject_digest),
        RuntimeTraceDetails::TerminalOutput {
            state,
            artifact_digests,
            cancellation_outcome,
        } => {
            let cancellation_valid = match cancellation_outcome {
                None => legacy_v1 || *state != RuntimeTerminalState::Canceled,
                Some(RuntimeCancellationOutcome::CooperativeStop) => {
                    !legacy_v1 && *state == RuntimeTerminalState::Canceled
                }
                Some(
                    RuntimeCancellationOutcome::ForcedAbort | RuntimeCancellationOutcome::Failed,
                ) => !legacy_v1 && *state == RuntimeTerminalState::Failed,
            };
            cancellation_valid
                && artifact_digests.len() <= 16
                && artifact_digests.iter().all(|value| canonical_sha256(value))
        }
        RuntimeTraceDetails::None
        | RuntimeTraceDetails::Reinforcement { .. }
        | RuntimeTraceDetails::Receipt { .. }
        | RuntimeTraceDetails::Tick { .. } => true,
    }
}

fn adapt_event(
    event: RuntimeEvent,
) -> (RuntimeTraceKind, Option<String>, bool, RuntimeTraceDetails) {
    match event {
        RuntimeEvent::SignalEmitted { hash } => (
            RuntimeTraceKind::SignalEmitted,
            Some(hash),
            true,
            RuntimeTraceDetails::None,
        ),
        RuntimeEvent::SignalReinforced { hash, count } => (
            RuntimeTraceKind::SignalReinforced,
            Some(hash),
            true,
            RuntimeTraceDetails::Reinforcement { count },
        ),
        RuntimeEvent::SignalReceived { hash, hops, .. } => (
            RuntimeTraceKind::SignalReceived,
            Some(hash),
            true,
            RuntimeTraceDetails::Receipt { hops },
        ),
        RuntimeEvent::SignalExpired { hash } => (
            RuntimeTraceKind::SignalExpired,
            Some(hash),
            true,
            RuntimeTraceDetails::None,
        ),
        RuntimeEvent::PeerConnected { .. } => (
            RuntimeTraceKind::PeerConnected,
            None,
            true,
            RuntimeTraceDetails::None,
        ),
        RuntimeEvent::PeerDisconnected { .. } => (
            RuntimeTraceKind::PeerDisconnected,
            None,
            true,
            RuntimeTraceDetails::None,
        ),
        RuntimeEvent::TickCompleted {
            tick,
            active_signals,
            expired,
        } => (
            RuntimeTraceKind::TickCompleted,
            None,
            false,
            RuntimeTraceDetails::Tick {
                tick,
                active_signals,
                expired,
            },
        ),
    }
}
