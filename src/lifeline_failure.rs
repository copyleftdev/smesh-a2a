use std::collections::HashSet;
use std::io::{Read as _, Seek as _, Write as _};
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const LIFELINE_FAILURE_TRACE_SCHEMA_VERSION: &str = "lifeline-failure-scenario/1";
const MAX_EVENTS: usize = 64;
const MAX_LINE_BYTES: usize = 8 * 1024;
const MAX_TOTAL_BYTES: usize = 256 * 1024;

#[derive(Debug, Error)]
pub enum LifelineFailureError {
    #[error("failure scenario trace I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("failure scenario trace JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("failure scenario trace invariant failed: {0}")]
    Invariant(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LifelineFailureEventKind {
    PrimarySubmitted,
    SiblingSubmitted,
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

impl LifelineFailureEventKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PrimarySubmitted => "primary-submitted",
            Self::SiblingSubmitted => "sibling-submitted",
            Self::PrimaryOutageObserved => "primary-outage-observed",
            Self::PrimaryStreamFailed => "primary-stream-failed",
            Self::CancelRequested => "cancel-requested",
            Self::LateOutputFenced => "late-output-fenced",
            Self::InternalProcessorStopped => "internal-processor-stopped",
            Self::CancelConfirmed => "cancel-confirmed",
            Self::SiblingCompleted => "sibling-completed",
            Self::FallbackSelected => "fallback-selected",
            Self::FallbackSubmitted => "fallback-submitted",
            Self::FallbackCompleted => "fallback-completed",
            Self::ReviewCompleted => "review-completed",
            Self::PrimaryFinalReconciled => "primary-final-reconciled",
            Self::ScenarioCompleted => "scenario-completed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifelineFailureEvent {
    schema_version: String,
    sequence: u64,
    event_id: String,
    parent_event_id: Option<String>,
    kind: LifelineFailureEventKind,
    operation_id: String,
    gateway_id: String,
    context_id: String,
    task_id: Option<String>,
    message_id: Option<String>,
    attempt: u32,
    outcome: String,
    replaces_task_id: Option<String>,
}

impl LifelineFailureEvent {
    #[must_use]
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        self.kind.as_str()
    }
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
    #[must_use]
    pub fn gateway_id(&self) -> &str {
        &self.gateway_id
    }
    #[must_use]
    pub fn context_id(&self) -> &str {
        &self.context_id
    }
    #[must_use]
    pub fn task_id(&self) -> Option<&str> {
        self.task_id.as_deref()
    }
    #[must_use]
    pub fn message_id(&self) -> Option<&str> {
        self.message_id.as_deref()
    }
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.attempt
    }
    #[must_use]
    pub fn outcome(&self) -> &str {
        &self.outcome
    }
    #[must_use]
    pub fn replaces_task_id(&self) -> Option<&str> {
        self.replaces_task_id.as_deref()
    }
}

#[derive(Clone, Copy)]
pub struct LifelineFailureTransition<'a> {
    pub kind: LifelineFailureEventKind,
    pub operation_id: &'a str,
    pub gateway_id: &'a str,
    pub context_id: &'a str,
    pub task_id: Option<&'a str>,
    pub message_id: Option<&'a str>,
    pub attempt: u32,
    pub outcome: &'a str,
    pub replaces_task_id: Option<&'a str>,
}

struct TraceState {
    file: std::fs::File,
    events: Vec<LifelineFailureEvent>,
    bytes: usize,
    terminal_prefix_bytes: Option<usize>,
    failed: bool,
    #[cfg(test)]
    faults: TraceFaults,
}

#[cfg(test)]
#[derive(Default)]
#[allow(clippy::struct_excessive_bools)] // Independent one-shot persistence fault points.
struct TraceFaults {
    write: bool,
    sync_data: bool,
    sync_all: bool,
    rollback: bool,
}

#[derive(Clone)]
pub struct LifelineFailureTrace {
    state: Arc<Mutex<TraceState>>,
}

impl LifelineFailureTrace {
    /// Creates one private, create-new restricted JSONL trace.
    ///
    /// # Errors
    /// Returns an error if the destination exists or cannot be created privately.
    pub fn create(path: &Path) -> Result<Self, LifelineFailureError> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        Ok(Self {
            state: Arc::new(Mutex::new(TraceState {
                file: options.open(path)?,
                events: Vec::new(),
                bytes: 0,
                terminal_prefix_bytes: None,
                failed: false,
                #[cfg(test)]
                faults: TraceFaults::default(),
            })),
        })
    }

    /// Records a transition at its live linearization point and durably appends it.
    ///
    /// # Errors
    /// Returns an error for invalid fields, exhausted bounds, or persistence failure.
    pub fn record(
        &self,
        transition: LifelineFailureTransition<'_>,
    ) -> Result<(), LifelineFailureError> {
        validate_identifier(transition.operation_id)?;
        validate_identifier(transition.gateway_id)?;
        validate_identifier(transition.context_id)?;
        if let Some(value) = transition.task_id {
            validate_identifier(value)?;
        }
        if let Some(value) = transition.message_id {
            validate_identifier(value)?;
        }
        if let Some(value) = transition.replaces_task_id {
            validate_identifier(value)?;
        }
        validate_identifier(transition.outcome)?;
        if transition.attempt != 1 {
            return Err(invariant("attempt is outside the closed protocol"));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| invariant("trace lock poisoned"))?;
        if state.failed {
            return Err(invariant("trace writer is abandoned"));
        }
        if state.events.len() >= MAX_EVENTS {
            return Err(invariant("event count exceeds bound"));
        }
        let sequence =
            u64::try_from(state.events.len() + 1).map_err(|_| invariant("sequence overflow"))?;
        let event = LifelineFailureEvent {
            schema_version: LIFELINE_FAILURE_TRACE_SCHEMA_VERSION.to_owned(),
            sequence,
            event_id: format!("event-{sequence}"),
            parent_event_id: state.events.last().map(|event| event.event_id.clone()),
            kind: transition.kind,
            operation_id: transition.operation_id.to_owned(),
            gateway_id: transition.gateway_id.to_owned(),
            context_id: transition.context_id.to_owned(),
            task_id: transition.task_id.map(str::to_owned),
            message_id: transition.message_id.map(str::to_owned),
            attempt: transition.attempt,
            outcome: transition.outcome.to_owned(),
            replaces_task_id: transition.replaces_task_id.map(str::to_owned),
        };
        verify_live_append(&state.events, &event)?;
        let mut line = serde_json::to_vec(&event)?;
        line.push(b'\n');
        if line.len() > MAX_LINE_BYTES || state.bytes + line.len() > MAX_TOTAL_BYTES {
            return Err(invariant("trace byte bound exceeded"));
        }
        let prefix_bytes = state.bytes;
        let terminal = event.kind == LifelineFailureEventKind::ScenarioCompleted;
        let write_result = if trace_fault(&mut state, TraceFaultPoint::Write) {
            let partial = line.len().saturating_div(2).max(1);
            state
                .file
                .write_all(&line[..partial])
                .and_then(|()| Err(std::io::Error::other("injected trace write failure")))
        } else {
            state.file.write_all(&line)
        };
        if let Err(error) = write_result {
            return Err(abandon_trace_writer(
                &mut state,
                prefix_bytes,
                terminal,
                error,
            ));
        }
        let sync_result = if trace_fault(&mut state, TraceFaultPoint::SyncData) {
            Err(std::io::Error::other("injected trace data sync failure"))
        } else {
            state.file.sync_data()
        };
        if let Err(error) = sync_result {
            return Err(abandon_trace_writer(
                &mut state,
                prefix_bytes,
                terminal,
                error,
            ));
        }
        if event.kind == LifelineFailureEventKind::ScenarioCompleted {
            state.terminal_prefix_bytes = Some(prefix_bytes);
        }
        state.bytes += line.len();
        state.events.push(event);
        Ok(())
    }

    /// # Errors
    /// Returns an error when the restricted trace cannot be durably synchronized.
    pub fn sync(&self) -> Result<(), LifelineFailureError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| invariant("trace lock poisoned"))?;
        if state.failed {
            return Err(invariant("trace writer is abandoned"));
        }
        let result = if trace_fault(&mut state, TraceFaultPoint::SyncAll) {
            Err(std::io::Error::other("injected trace full sync failure"))
        } else {
            state.file.sync_all()
        };
        match result {
            Ok(()) => Ok(()),
            Err(error) => {
                state.failed = true;
                if let Some(prefix) = state.terminal_prefix_bytes
                    && rollback_trace(&mut state, prefix).is_err()
                {
                    invalidate_terminal_record(&mut state, prefix).map_err(|_| {
                        invariant(
                            "trace terminal rollback and invalidation failed; writer abandoned",
                        )
                    })?;
                    return Err(invariant(
                        "trace terminal rollback failed; terminal invalidated and writer abandoned",
                    ));
                }
                Err(error.into())
            }
        }
    }
}

#[derive(Clone, Copy)]
enum TraceFaultPoint {
    Write,
    SyncData,
    SyncAll,
    Rollback,
}

fn trace_fault(state: &mut TraceState, point: TraceFaultPoint) -> bool {
    #[cfg(test)]
    {
        let fault = match point {
            TraceFaultPoint::Write => &mut state.faults.write,
            TraceFaultPoint::SyncData => &mut state.faults.sync_data,
            TraceFaultPoint::SyncAll => &mut state.faults.sync_all,
            TraceFaultPoint::Rollback => &mut state.faults.rollback,
        };
        std::mem::take(fault)
    }
    #[cfg(not(test))]
    {
        let _ = (state, point);
        false
    }
}

fn rollback_trace(state: &mut TraceState, prefix_bytes: usize) -> Result<(), std::io::Error> {
    if trace_fault(state, TraceFaultPoint::Rollback) {
        return Err(std::io::Error::other("injected trace rollback failure"));
    }
    let offset = u64::try_from(prefix_bytes)
        .map_err(|_| std::io::Error::other("trace rollback offset overflow"))?;
    state.file.set_len(offset)?;
    state.file.seek(std::io::SeekFrom::Start(offset))?;
    state.file.sync_data()
}

fn invalidate_terminal_record(
    state: &mut TraceState,
    prefix_bytes: usize,
) -> Result<(), std::io::Error> {
    let offset = u64::try_from(prefix_bytes)
        .map_err(|_| std::io::Error::other("trace invalidation offset overflow"))?;
    state.file.seek(std::io::SeekFrom::Start(offset))?;
    state.file.write_all(b"!")?;
    state.file.sync_data()
}

fn abandon_trace_writer(
    state: &mut TraceState,
    prefix_bytes: usize,
    terminal: bool,
    error: std::io::Error,
) -> LifelineFailureError {
    state.failed = true;
    if rollback_trace(state, prefix_bytes).is_err() {
        if terminal && invalidate_terminal_record(state, prefix_bytes).is_ok() {
            invariant("trace rollback failed; terminal invalidated and writer abandoned")
        } else {
            invariant("trace rollback failed; writer abandoned")
        }
    } else {
        error.into()
    }
}

fn verify_live_append(
    prefix: &[LifelineFailureEvent],
    next: &LifelineFailureEvent,
) -> Result<(), LifelineFailureError> {
    use LifelineFailureEventKind as Kind;

    if prefix
        .last()
        .is_some_and(|event| event.kind == Kind::ScenarioCompleted)
    {
        return Err(invariant("scenario completion is terminal"));
    }
    let singleton = !matches!(next.kind, Kind::SiblingSubmitted | Kind::SiblingCompleted);
    if singleton && prefix.iter().any(|event| event.kind == next.kind) {
        return Err(invariant("live transition is duplicated"));
    }
    let has = |kind| prefix.iter().any(|event| event.kind == kind);
    let requires = |predecessor| {
        if has(predecessor) {
            Ok(())
        } else {
            Err(invariant("live transition predecessor is missing"))
        }
    };
    match next.kind {
        Kind::PrimarySubmitted => {}
        Kind::SiblingSubmitted => {
            if has(Kind::FallbackSelected)
                || prefix
                    .iter()
                    .filter(|event| event.kind == Kind::SiblingSubmitted)
                    .count()
                    >= 3
                || prefix.iter().any(|event| {
                    event.kind == Kind::SiblingSubmitted
                        && event.operation_id == next.operation_id
                        && event.gateway_id == next.gateway_id
                })
            {
                return Err(invariant("live sibling submission is invalid"));
            }
        }
        Kind::PrimaryOutageObserved => requires(Kind::PrimarySubmitted)?,
        Kind::PrimaryStreamFailed => requires(Kind::PrimaryOutageObserved)?,
        Kind::CancelRequested => requires(Kind::PrimaryStreamFailed)?,
        Kind::LateOutputFenced => requires(Kind::CancelRequested)?,
        Kind::InternalProcessorStopped => requires(Kind::LateOutputFenced)?,
        Kind::CancelConfirmed => requires(Kind::InternalProcessorStopped)?,
        Kind::FallbackSelected => {
            requires(Kind::CancelConfirmed)?;
            if prefix
                .iter()
                .filter(|event| event.kind == Kind::SiblingSubmitted)
                .count()
                != 3
            {
                return Err(invariant("fallback preceded sibling submissions"));
            }
            if prefix
                .iter()
                .filter(|event| event.kind == Kind::SiblingCompleted)
                .count()
                != 3
            {
                return Err(invariant("fallback preceded sibling continuity"));
            }
        }
        Kind::FallbackSubmitted => requires(Kind::FallbackSelected)?,
        Kind::SiblingCompleted => {
            if has(Kind::FallbackSelected)
                || prefix
                    .iter()
                    .filter(|event| event.kind == Kind::SiblingCompleted)
                    .count()
                    >= 3
                || !prefix.iter().any(|event| {
                    event.kind == Kind::SiblingSubmitted
                        && event.operation_id == next.operation_id
                        && event.gateway_id == next.gateway_id
                })
                || prefix.iter().any(|event| {
                    event.kind == Kind::SiblingCompleted
                        && event.operation_id == next.operation_id
                        && event.gateway_id == next.gateway_id
                })
            {
                return Err(invariant("live sibling completion is invalid"));
            }
        }
        Kind::FallbackCompleted => {
            requires(Kind::FallbackSubmitted)?;
        }
        Kind::ReviewCompleted => requires(Kind::FallbackCompleted)?,
        Kind::PrimaryFinalReconciled => requires(Kind::ReviewCompleted)?,
        Kind::ScenarioCompleted => {
            requires(Kind::PrimaryFinalReconciled)?;
            let mut completed = prefix.to_vec();
            completed.push(next.clone());
            verify_lifeline_failure_events(&completed)?;
        }
    }
    verify_live_event_semantics(prefix, next)
}

#[allow(clippy::too_many_lines)] // Mirrors the closed wire protocol at append admission.
fn verify_live_event_semantics(
    prefix: &[LifelineFailureEvent],
    next: &LifelineFailureEvent,
) -> Result<(), LifelineFailureError> {
    use LifelineFailureEventKind as Kind;

    let primary = prefix
        .iter()
        .find(|event| event.kind == Kind::PrimarySubmitted)
        .or_else(|| (next.kind == Kind::PrimarySubmitted).then_some(next));
    let no_replacement = next.replaces_task_id.is_none();
    match next.kind {
        Kind::PrimarySubmitted => {
            if next.operation_id != "shipment-routing"
                || next.gateway_id != "atlas-primary"
                || prefix
                    .iter()
                    .any(|event| event.context_id != next.context_id)
                || next.task_id.is_none()
                || next.message_id.is_none()
                || next.outcome != "submitted"
                || !no_replacement
            {
                return Err(invariant("live primary submission is invalid"));
            }
        }
        Kind::PrimaryOutageObserved
        | Kind::PrimaryStreamFailed
        | Kind::CancelRequested
        | Kind::LateOutputFenced
        | Kind::InternalProcessorStopped
        | Kind::CancelConfirmed
        | Kind::PrimaryFinalReconciled => {
            let primary = primary.ok_or_else(|| invariant("live primary binding is missing"))?;
            let expected_outcome = match next.kind {
                Kind::PrimaryOutageObserved => "unavailable",
                Kind::PrimaryStreamFailed => "error",
                Kind::CancelRequested => "requested",
                Kind::LateOutputFenced => "fenced",
                Kind::InternalProcessorStopped => "cooperative-stop",
                Kind::CancelConfirmed | Kind::PrimaryFinalReconciled => "canceled",
                _ => unreachable!(),
            };
            if next.operation_id != primary.operation_id
                || next.gateway_id != "atlas-primary"
                || next.context_id != primary.context_id
                || next.task_id != primary.task_id
                || next.message_id != primary.message_id
                || next.outcome != expected_outcome
                || !no_replacement
            {
                return Err(invariant("live primary transition binding is invalid"));
            }
        }
        Kind::SiblingSubmitted | Kind::SiblingCompleted => {
            let expected = HashSet::from([
                ("lot-genealogy", "meridian"),
                ("recall-criteria", "helix"),
                ("exposure-cohort", "harbor"),
            ]);
            let identity_is_valid = match next.kind {
                Kind::SiblingSubmitted => next.task_id.is_none() && next.message_id.is_none(),
                Kind::SiblingCompleted => next.task_id.is_some() && next.message_id.is_some(),
                _ => unreachable!(),
            };
            if !expected.contains(&(next.operation_id.as_str(), next.gateway_id.as_str()))
                || primary.is_some_and(|primary| next.context_id != primary.context_id)
                || !identity_is_valid
                || next.outcome
                    != if next.kind == Kind::SiblingSubmitted {
                        "submitted"
                    } else {
                        "completed"
                    }
                || !no_replacement
            {
                return Err(invariant("live sibling transition binding is invalid"));
            }
        }
        Kind::FallbackSelected | Kind::FallbackSubmitted | Kind::FallbackCompleted => {
            let primary = primary.ok_or_else(|| invariant("live primary binding is missing"))?;
            let expected_outcome = match next.kind {
                Kind::FallbackSelected => "selected",
                Kind::FallbackSubmitted => "submitted",
                Kind::FallbackCompleted => "completed",
                _ => unreachable!(),
            };
            let identity_is_valid = match next.kind {
                Kind::FallbackSelected => next.task_id.is_none() && next.message_id.is_none(),
                Kind::FallbackSubmitted => next.task_id.is_none() && next.message_id.is_some(),
                Kind::FallbackCompleted => {
                    let submitted = prefix
                        .iter()
                        .find(|event| event.kind == Kind::FallbackSubmitted)
                        .ok_or_else(|| invariant("live fallback submission is missing"))?;
                    next.task_id.is_some()
                        && next.task_id != primary.task_id
                        && next.message_id.is_some()
                        && next.message_id == submitted.message_id
                }
                _ => unreachable!(),
            };
            if next.operation_id != "shipment-routing-fallback"
                || next.gateway_id != "atlas-fallback"
                || next.context_id != primary.context_id
                || next.replaces_task_id.as_deref() != primary.task_id.as_deref()
                || next.outcome != expected_outcome
                || !identity_is_valid
            {
                return Err(invariant("live fallback transition binding is invalid"));
            }
        }
        Kind::ReviewCompleted => {
            let primary = primary.ok_or_else(|| invariant("live primary binding is missing"))?;
            if next.operation_id != "independent-review"
                || next.gateway_id != "sentinel"
                || next.context_id != primary.context_id
                || next.task_id.is_none()
                || next.message_id.is_none()
                || next.outcome != "completed"
                || !no_replacement
            {
                return Err(invariant("live review transition binding is invalid"));
            }
        }
        Kind::ScenarioCompleted => {}
    }
    Ok(())
}

/// Reads and verifies the closed restricted scenario trace and its causal proof.
///
/// # Errors
/// Returns an error for I/O, malformed JSONL, tampering, gaps, or semantic omissions.
pub fn verify_lifeline_failure_trace(
    path: &Path,
) -> Result<Vec<LifelineFailureEvent>, LifelineFailureError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_TOTAL_BYTES as u64 {
        return Err(invariant("trace is not a bounded regular file"));
    }
    let file = std::fs::File::open(path)?;
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| invariant("trace length does not fit in memory bounds"))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take((MAX_TOTAL_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > MAX_TOTAL_BYTES || !bytes.ends_with(b"\n") {
        return Err(invariant("trace framing or total bound is invalid"));
    }
    let mut events = Vec::new();
    let body = &bytes[..bytes.len() - 1];
    for line in body.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            return Err(invariant("blank JSONL record is invalid"));
        }
        if line.len() > MAX_LINE_BYTES || events.len() >= MAX_EVENTS {
            return Err(invariant("trace line or event bound exceeded"));
        }
        events.push(serde_json::from_slice::<LifelineFailureEvent>(line)?);
    }
    verify_lifeline_failure_events(&events)?;
    Ok(events)
}

#[allow(clippy::too_many_lines)] // One closed verifier keeps the causal proof rules co-located.
pub(crate) fn verify_lifeline_failure_events(
    events: &[LifelineFailureEvent],
) -> Result<(), LifelineFailureError> {
    if events.is_empty() {
        return Err(invariant("trace is empty"));
    }
    for (index, event) in events.iter().enumerate() {
        let sequence = u64::try_from(index + 1).map_err(|_| invariant("sequence overflow"))?;
        let expected_parent = if index == 0 {
            None
        } else {
            Some(format!("event-{index}"))
        };
        if event.schema_version != LIFELINE_FAILURE_TRACE_SCHEMA_VERSION
            || event.sequence != sequence
            || event.event_id != format!("event-{sequence}")
            || event.parent_event_id != expected_parent
            || event.attempt != 1
        {
            return Err(invariant(
                "schema, sequence, parent, event ID, or attempt is invalid",
            ));
        }
        for value in [
            &event.operation_id,
            &event.gateway_id,
            &event.context_id,
            &event.outcome,
        ] {
            validate_identifier(value)?;
        }
        for value in [
            event.task_id.as_deref(),
            event.message_id.as_deref(),
            event.replaces_task_id.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_identifier(value)?;
        }
    }
    let one = |kind| events.iter().filter(|event| event.kind == kind).count() == 1;
    for kind in [
        LifelineFailureEventKind::PrimarySubmitted,
        LifelineFailureEventKind::PrimaryOutageObserved,
        LifelineFailureEventKind::PrimaryStreamFailed,
        LifelineFailureEventKind::CancelRequested,
        LifelineFailureEventKind::LateOutputFenced,
        LifelineFailureEventKind::InternalProcessorStopped,
        LifelineFailureEventKind::CancelConfirmed,
        LifelineFailureEventKind::FallbackSelected,
        LifelineFailureEventKind::FallbackSubmitted,
        LifelineFailureEventKind::FallbackCompleted,
        LifelineFailureEventKind::ReviewCompleted,
        LifelineFailureEventKind::PrimaryFinalReconciled,
        LifelineFailureEventKind::ScenarioCompleted,
    ] {
        if !one(kind) {
            return Err(invariant(
                "required causal transition is missing or duplicated",
            ));
        }
    }
    if events
        .iter()
        .filter(|event| event.kind == LifelineFailureEventKind::SiblingSubmitted)
        .count()
        != 3
        || events
            .iter()
            .filter(|event| event.kind == LifelineFailureEventKind::SiblingCompleted)
            .count()
            != 3
    {
        return Err(invariant("sibling dispatch evidence is incomplete"));
    }
    let event = |kind| {
        events
            .iter()
            .find(|event| event.kind == kind)
            .expect("required event checked")
    };
    let primary = event(LifelineFailureEventKind::PrimarySubmitted);
    let outage = event(LifelineFailureEventKind::PrimaryOutageObserved);
    let stream_failed = event(LifelineFailureEventKind::PrimaryStreamFailed);
    let cancel = event(LifelineFailureEventKind::CancelRequested);
    let fenced = event(LifelineFailureEventKind::LateOutputFenced);
    let stopped = event(LifelineFailureEventKind::InternalProcessorStopped);
    let confirmed = event(LifelineFailureEventKind::CancelConfirmed);
    let selected = event(LifelineFailureEventKind::FallbackSelected);
    let submitted = event(LifelineFailureEventKind::FallbackSubmitted);
    let completed = event(LifelineFailureEventKind::FallbackCompleted);
    let review = event(LifelineFailureEventKind::ReviewCompleted);
    let reconciled = event(LifelineFailureEventKind::PrimaryFinalReconciled);
    let scenario_completed = event(LifelineFailureEventKind::ScenarioCompleted);
    if primary.task_id.is_none() || primary.message_id.is_none() {
        return Err(invariant("primary protocol identity is missing"));
    }
    let same_primary = |candidate: &LifelineFailureEvent| {
        candidate.operation_id == primary.operation_id
            && candidate.gateway_id == "atlas-primary"
            && candidate.context_id == primary.context_id
            && candidate.task_id == primary.task_id
            && candidate.message_id == primary.message_id
    };
    if primary.operation_id != "shipment-routing"
        || primary.gateway_id != "atlas-primary"
        || primary.outcome != "submitted"
        || [
            primary,
            outage,
            stream_failed,
            cancel,
            fenced,
            stopped,
            confirmed,
            reconciled,
        ]
        .iter()
        .any(|event| event.replaces_task_id.is_some())
        || ![
            outage,
            stream_failed,
            cancel,
            fenced,
            stopped,
            confirmed,
            reconciled,
        ]
        .into_iter()
        .all(same_primary)
        || outage.outcome != "unavailable"
        || stream_failed.outcome != "error"
        || cancel.outcome != "requested"
        || fenced.outcome != "fenced"
        || stopped.outcome != "cooperative-stop"
        || confirmed.outcome != "canceled"
        || reconciled.outcome != "canceled"
    {
        return Err(invariant(
            "primary outage/cancellation evidence is inconsistent or downgraded",
        ));
    }
    if scenario_completed.operation_id != "incident-response"
        || scenario_completed.gateway_id != "director"
        || scenario_completed.context_id != primary.context_id
        || scenario_completed.task_id.is_some()
        || scenario_completed.message_id.is_some()
        || scenario_completed.replaces_task_id.is_some()
        || scenario_completed.outcome != "completed"
        || events.last().map(|event| event.kind)
            != Some(LifelineFailureEventKind::ScenarioCompleted)
    {
        return Err(invariant("scenario completion evidence is inconsistent"));
    }
    let pos = |kind| {
        events
            .iter()
            .position(|event| event.kind == kind)
            .expect("required event checked")
    };
    if !(pos(LifelineFailureEventKind::PrimarySubmitted)
        < pos(LifelineFailureEventKind::PrimaryOutageObserved)
        && pos(LifelineFailureEventKind::PrimaryOutageObserved)
            < pos(LifelineFailureEventKind::PrimaryStreamFailed)
        && pos(LifelineFailureEventKind::PrimaryStreamFailed)
            < pos(LifelineFailureEventKind::CancelRequested)
        && pos(LifelineFailureEventKind::CancelRequested)
            < pos(LifelineFailureEventKind::LateOutputFenced)
        && pos(LifelineFailureEventKind::LateOutputFenced)
            < pos(LifelineFailureEventKind::InternalProcessorStopped)
        && pos(LifelineFailureEventKind::InternalProcessorStopped)
            < pos(LifelineFailureEventKind::CancelConfirmed)
        && pos(LifelineFailureEventKind::CancelConfirmed)
            < pos(LifelineFailureEventKind::FallbackSelected)
        && pos(LifelineFailureEventKind::FallbackSelected)
            < pos(LifelineFailureEventKind::FallbackSubmitted)
        && pos(LifelineFailureEventKind::FallbackSubmitted)
            < pos(LifelineFailureEventKind::FallbackCompleted)
        && pos(LifelineFailureEventKind::FallbackCompleted)
            < pos(LifelineFailureEventKind::ReviewCompleted)
        && pos(LifelineFailureEventKind::ReviewCompleted)
            < pos(LifelineFailureEventKind::PrimaryFinalReconciled)
        && pos(LifelineFailureEventKind::PrimaryFinalReconciled)
            < pos(LifelineFailureEventKind::ScenarioCompleted))
    {
        return Err(invariant("causal transition order is invalid"));
    }
    for fallback in [selected, submitted, completed] {
        if fallback.operation_id != "shipment-routing-fallback"
            || fallback.gateway_id != "atlas-fallback"
            || fallback.context_id != primary.context_id
            || fallback.replaces_task_id.as_deref() != primary.task_id.as_deref()
        {
            return Err(invariant("fallback replacement binding is invalid"));
        }
    }
    if selected.task_id.is_some()
        || selected.message_id.is_some()
        || submitted.task_id.is_some()
        || submitted.message_id.is_none()
        || completed.task_id == primary.task_id
        || completed.task_id.is_none()
        || completed.message_id != submitted.message_id
    {
        return Err(invariant("fallback live protocol identity is invalid"));
    }
    if selected.outcome != "selected"
        || submitted.outcome != "submitted"
        || completed.outcome != "completed"
    {
        return Err(invariant("fallback outcome is invalid"));
    }
    if review.operation_id != "independent-review"
        || review.gateway_id != "sentinel"
        || review.context_id != primary.context_id
        || review.outcome != "completed"
        || review.task_id.is_none()
        || review.message_id.is_none()
        || review.replaces_task_id.is_some()
    {
        return Err(invariant("review evidence is invalid"));
    }
    let sibling_submitted = events
        .iter()
        .filter(|event| event.kind == LifelineFailureEventKind::SiblingSubmitted)
        .collect::<Vec<_>>();
    let sibling_completed = events
        .iter()
        .filter(|event| event.kind == LifelineFailureEventKind::SiblingCompleted)
        .collect::<Vec<_>>();
    let expected = HashSet::from([
        ("lot-genealogy", "meridian"),
        ("exposure-cohort", "harbor"),
        ("recall-criteria", "helix"),
    ]);
    if sibling_submitted
        .iter()
        .map(|event| (event.operation_id.as_str(), event.gateway_id.as_str()))
        .collect::<HashSet<_>>()
        != expected
        || sibling_completed
            .iter()
            .map(|event| (event.operation_id.as_str(), event.gateway_id.as_str()))
            .collect::<HashSet<_>>()
            != expected
        || sibling_completed.iter().any(|completed| {
            let submitted = sibling_submitted.iter().find(|submitted| {
                submitted.operation_id == completed.operation_id
                    && submitted.gateway_id == completed.gateway_id
            });
            submitted.is_none_or(|submitted| submitted.sequence >= completed.sequence)
                || completed.sequence >= selected.sequence
                || completed.sequence >= review.sequence
        })
        || sibling_submitted.iter().any(|event| {
            event.outcome != "submitted"
                || event.context_id != primary.context_id
                || event.task_id.is_some()
                || event.message_id.is_some()
                || event.replaces_task_id.is_some()
        })
        || sibling_completed.iter().any(|event| {
            event.outcome != "completed"
                || event.context_id != primary.context_id
                || event.task_id.is_none()
                || event.message_id.is_none()
                || event.replaces_task_id.is_some()
        })
    {
        return Err(invariant("sibling evidence is invalid"));
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), LifelineFailureError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(invariant("identifier violates closed bounds"));
    }
    Ok(())
}

fn invariant(message: impl Into<String>) -> LifelineFailureError {
    LifelineFailureError::Invariant(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace() -> (LifelineFailureTrace, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "smesh-live-trace-fault-{}-{}.jsonl",
            std::process::id(),
            rand::random::<u64>()
        ));
        (LifelineFailureTrace::create(&path).unwrap(), path)
    }

    fn completed_fixture() -> (Vec<u8>, Vec<LifelineFailureEvent>, usize) {
        let bytes = include_bytes!("../tests/fixtures/lifeline-failure-valid.jsonl").to_vec();
        let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/lifeline-failure-valid.jsonl");
        let events = verify_lifeline_failure_trace(&fixture_path).unwrap();
        let terminal_prefix = bytes
            .windows(b"{\"schemaVersion\":\"lifeline-failure-scenario/1\",\"sequence\":19".len())
            .position(|window| {
                window == b"{\"schemaVersion\":\"lifeline-failure-scenario/1\",\"sequence\":19"
            })
            .unwrap();
        (bytes, events, terminal_prefix)
    }

    fn primary_transition(attempt: u32) -> LifelineFailureTransition<'static> {
        LifelineFailureTransition {
            kind: LifelineFailureEventKind::PrimarySubmitted,
            operation_id: "shipment-routing",
            gateway_id: "atlas-primary",
            context_id: "ctx-test",
            task_id: Some("task-test"),
            message_id: Some("message-test"),
            attempt,
            outcome: "submitted",
            replaces_task_id: None,
        }
    }

    #[test]
    fn partial_write_failure_rolls_back_and_abandons_writer() {
        let (trace, path) = trace();
        trace.state.lock().unwrap().faults.write = true;

        assert!(trace.record(primary_transition(1)).is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        assert!(trace.record(primary_transition(1)).is_err());
        assert!(verify_lifeline_failure_trace(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn data_sync_failure_rolls_back_and_abandons_writer() {
        let (trace, path) = trace();
        trace.state.lock().unwrap().faults.sync_data = true;

        assert!(trace.record(primary_transition(1)).is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        assert!(trace.record(primary_transition(1)).is_err());
        assert!(verify_lifeline_failure_trace(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn terminal_sync_failure_removes_replayable_terminal_bytes() {
        let (trace, path) = trace();
        {
            let mut state = trace.state.lock().unwrap();
            state
                .file
                .write_all(b"{\"kind\":\"scenario-completed\"}\n")
                .unwrap();
            state.bytes = 30;
            state.terminal_prefix_bytes = Some(0);
            state.faults.sync_all = true;
        }

        assert!(trace.sync().is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        assert!(trace.sync().is_err());
        assert!(verify_lifeline_failure_trace(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn terminal_data_sync_and_rollback_failure_invalidates_completed_trace() {
        let (bytes, events, terminal_prefix) = completed_fixture();
        let (trace, path) = trace();
        {
            let mut state = trace.state.lock().unwrap();
            state.file.write_all(&bytes[..terminal_prefix]).unwrap();
            state.file.sync_data().unwrap();
            state.bytes = terminal_prefix;
            state.events = events[..events.len() - 1].to_vec();
            state.faults.sync_data = true;
            state.faults.rollback = true;
        }
        let terminal = events.last().unwrap();

        assert!(
            trace
                .record(LifelineFailureTransition {
                    kind: LifelineFailureEventKind::ScenarioCompleted,
                    operation_id: terminal.operation_id(),
                    gateway_id: terminal.gateway_id(),
                    context_id: terminal.context_id(),
                    task_id: terminal.task_id(),
                    message_id: terminal.message_id(),
                    attempt: terminal.attempt(),
                    outcome: terminal.outcome(),
                    replaces_task_id: terminal.replaces_task_id(),
                })
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap()[terminal_prefix], b'!');
        assert!(trace.sync().is_err());
        assert!(verify_lifeline_failure_trace(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn terminal_full_sync_and_rollback_failure_invalidates_completed_trace() {
        let (bytes, events, terminal_prefix) = completed_fixture();
        let (trace, path) = trace();
        {
            let mut state = trace.state.lock().unwrap();
            state.file.write_all(&bytes).unwrap();
            state.file.sync_data().unwrap();
            state.bytes = bytes.len();
            state.events = events;
            state.terminal_prefix_bytes = Some(terminal_prefix);
            state.faults.sync_all = true;
            state.faults.rollback = true;
        }
        assert!(verify_lifeline_failure_trace(&path).is_ok());

        assert!(trace.sync().is_err());
        assert_eq!(std::fs::read(&path).unwrap()[terminal_prefix], b'!');
        assert!(trace.sync().is_err());
        assert!(verify_lifeline_failure_trace(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn rollback_failure_abandons_malformed_partial_file() {
        let (trace, path) = trace();
        {
            let mut state = trace.state.lock().unwrap();
            state.faults.write = true;
            state.faults.rollback = true;
        }

        assert!(trace.record(primary_transition(1)).is_err());
        assert!(std::fs::metadata(&path).unwrap().len() > 0);
        assert!(trace.record(primary_transition(1)).is_err());
        assert!(verify_lifeline_failure_trace(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn live_append_requires_the_replay_attempt() {
        let path = std::env::temp_dir().join(format!(
            "smesh-live-trace-attempt-{}-{}.jsonl",
            std::process::id(),
            rand::random::<u64>()
        ));
        let trace = LifelineFailureTrace::create(&path).unwrap();
        let result = trace.record(LifelineFailureTransition {
            kind: LifelineFailureEventKind::PrimarySubmitted,
            operation_id: "shipment-routing",
            gateway_id: "atlas-primary",
            context_id: "ctx-test",
            task_id: Some("task-test"),
            message_id: Some("message-test"),
            attempt: 2,
            outcome: "submitted",
            replaces_task_id: None,
        });
        assert!(result.is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn live_append_rejects_transition_without_predecessor() {
        let path = std::env::temp_dir().join(format!(
            "smesh-live-trace-{}-{}.jsonl",
            std::process::id(),
            rand::random::<u64>()
        ));
        let trace = LifelineFailureTrace::create(&path).unwrap();
        let result = trace.record(LifelineFailureTransition {
            kind: LifelineFailureEventKind::ScenarioCompleted,
            operation_id: "incident-response",
            gateway_id: "director",
            context_id: "ctx-test",
            task_id: None,
            message_id: None,
            attempt: 1,
            outcome: "completed",
            replaces_task_id: None,
        });
        assert!(result.is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        std::fs::remove_file(path).unwrap();
    }
}
