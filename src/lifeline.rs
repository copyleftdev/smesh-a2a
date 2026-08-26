use std::collections::HashSet;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

const SCHEMA_VERSION: &str = "1.0.0";
const RUN_ID: &str = "lifeline-seed-0047";
const TRACE_ID: &str = "trace-lifeline-0047";

#[derive(Debug, Error)]
pub enum TraceError {
    #[error("trace serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("trace write failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("trace invariant failed: {0}")]
    Invariant(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Geo {
    pub lon: f64,
    pub lat: f64,
    pub alt: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceActor {
    pub id: String,
    pub label: String,
    pub organization: String,
    pub role: String,
    pub endpoint: Option<String>,
    pub geo: Geo,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_field_names)]
pub struct Correlation {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub context_id: Option<String>,
    pub task_id: Option<String>,
    pub signal_id: Option<String>,
    pub artifact_id: Option<String>,
    pub tool_call_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceMessage {
    pub summary: String,
    pub modality: String,
    pub content_hash: Option<String>,
    pub redacted: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TraceMetrics {
    pub intensity: Option<f64>,
    pub confidence: Option<f64>,
    pub trust: Option<f64>,
    pub reinforcement: Option<u32>,
    pub latency_ms: Option<u64>,
    pub payload_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct VisualCue {
    pub importance: f64,
    pub camera_focus: Option<String>,
    pub palette_key: Option<String>,
    pub hold_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NarrationCue {
    pub cue_id: String,
    pub line: String,
    pub voice: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Integrity {
    pub prev_hash: Option<String>,
    pub event_hash: String,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceEvent {
    pub schema_version: String,
    pub run_id: String,
    pub event_id: String,
    pub sequence: u64,
    pub sim_time_ms: u64,
    pub wall_time: Option<String>,
    pub layer: String,
    pub kind: String,
    pub source: TraceActor,
    pub target: Option<TraceActor>,
    pub correlation: Correlation,
    pub message: TraceMessage,
    pub state: Option<String>,
    pub metrics: TraceMetrics,
    pub payload: Value,
    pub visual: VisualCue,
    pub narration: Option<NarrationCue>,
    pub integrity: Integrity,
}

struct TraceBuilder {
    events: Vec<TraceEvent>,
    prev_hash: Option<String>,
}

struct Emit<'a> {
    time_ms: u64,
    layer: &'a str,
    kind: &'a str,
    source: &'a str,
    target: Option<&'a str>,
    state: Option<&'a str>,
    summary: &'a str,
    task_id: Option<&'a str>,
    signal_id: Option<&'a str>,
    artifact_id: Option<&'a str>,
    metrics: TraceMetrics,
    payload: Value,
    importance: f64,
    narration: Option<(&'a str, &'a str)>,
}

impl TraceBuilder {
    fn new() -> Self {
        Self {
            events: Vec::new(),
            prev_hash: None,
        }
    }

    fn emit(&mut self, spec: Emit<'_>) -> Result<(), TraceError> {
        let sequence = u64::try_from(self.events.len())
            .map_err(|_| TraceError::Invariant("event sequence overflow".to_owned()))?;
        let event_id = format!("evt-{sequence:04}");
        let span_id = format!("span-{sequence:04}");
        let mut event = TraceEvent {
            schema_version: SCHEMA_VERSION.to_owned(),
            run_id: RUN_ID.to_owned(),
            event_id,
            sequence,
            sim_time_ms: spec.time_ms,
            wall_time: None,
            layer: spec.layer.to_owned(),
            kind: spec.kind.to_owned(),
            source: actor(spec.source),
            target: spec.target.map(actor),
            correlation: Correlation {
                trace_id: TRACE_ID.to_owned(),
                span_id,
                parent_span_id: (sequence > 0).then(|| format!("span-{:04}", sequence - 1)),
                context_id: Some("incident-lifeline-47".to_owned()),
                task_id: spec.task_id.map(str::to_owned),
                signal_id: spec.signal_id.map(str::to_owned),
                artifact_id: spec.artifact_id.map(str::to_owned),
                tool_call_id: None,
            },
            message: TraceMessage {
                summary: spec.summary.to_owned(),
                modality: modality(spec.layer, spec.kind).to_owned(),
                content_hash: Some(hash_bytes(spec.summary.as_bytes())),
                redacted: spec.layer == "tool",
            },
            state: spec.state.map(str::to_owned),
            metrics: spec.metrics,
            payload: spec.payload,
            visual: VisualCue {
                importance: spec.importance,
                camera_focus: spec.target.or(Some(spec.source)).map(str::to_owned),
                palette_key: Some(spec.layer.to_owned()),
                hold_ms: if spec.importance > 0.85 { 1_200 } else { 320 },
            },
            narration: spec.narration.map(|(cue_id, line)| NarrationCue {
                cue_id: cue_id.to_owned(),
                line: line.to_owned(),
                voice: "lifeline-narrator".to_owned(),
            }),
            integrity: Integrity {
                prev_hash: self.prev_hash.clone(),
                event_hash: String::new(),
                signature: None,
            },
        };
        event.integrity.event_hash = event_hash(&event)?;
        self.prev_hash = Some(event.integrity.event_hash.clone());
        self.events.push(event);
        Ok(())
    }
}

#[allow(clippy::too_many_lines)]
/// Builds the deterministic LIFELINE cinematic fixture.
///
/// # Errors
///
/// Returns an error if an event cannot be serialized or if the completed
/// fixture violates a trace invariant.
pub fn generate_lifeline_trace() -> Result<Vec<TraceEvent>, TraceError> {
    let mut trace = TraceBuilder::new();
    let mut emit = |time_ms,
                    layer,
                    kind,
                    source,
                    target,
                    state,
                    summary,
                    task_id,
                    signal_id,
                    artifact_id,
                    confidence,
                    reinforcement,
                    importance,
                    narration| {
        trace.emit(Emit {
            time_ms,
            layer,
            kind,
            source,
            target,
            state,
            summary,
            task_id,
            signal_id,
            artifact_id,
            metrics: TraceMetrics {
                intensity: confidence,
                confidence,
                trust: confidence.map(|value| (value + 0.08).min(1.0)),
                reinforcement,
                latency_ms: Some(18 + (time_ms % 41)),
                payload_bytes: Some(u64::try_from(summary.len()).unwrap_or(u64::MAX)),
            },
            payload: json!({ "fictional": true }),
            importance,
            narration,
        })
    };

    emit(
        0,
        "system",
        "system.run.started",
        "incident",
        None,
        Some("submitted"),
        "LIFELINE deterministic run begins",
        None,
        None,
        None,
        None,
        None,
        1.0,
        Some((
            "n00",
            "In this fictional exercise: three hospitals. Three countries. The same rare reaction.",
        )),
    )?;
    for (time, source, signal) in [
        (2_000, "hospital-boston", "clinical-event-bos"),
        (5_000, "hospital-rotterdam", "clinical-event-rtm"),
        (8_000, "hospital-singapore", "clinical-event-sin"),
    ] {
        emit(
            time,
            "tool",
            "tool.clinical-event.observed",
            source,
            Some("northstar"),
            Some("emitted"),
            "Rare adverse-event pattern observed; patient data redacted",
            None,
            Some(signal),
            None,
            Some(0.42),
            Some(0),
            0.75,
            None,
        )?;
    }
    for (index, target) in [
        "meridian",
        "atlas",
        "helix",
        "harbor",
        "sentinel",
        "atlas-fallback",
    ]
    .into_iter()
    .enumerate()
    {
        let time = 14_000 + u64::try_from(index).unwrap_or(0) * 1_700;
        emit(
            time,
            "a2a",
            if target == "atlas-fallback" {
                "a2a.agent.fallback-discovered"
            } else {
                "a2a.agent.discovered"
            },
            "northstar",
            Some(target),
            Some("discovered"),
            "Agent Card resolved with capability and modality contract",
            None,
            None,
            None,
            None,
            None,
            0.55,
            (target == "atlas-fallback")
                .then_some(("n06", "A fallback agent is available, but not yet active.")),
        )?;
    }
    emit(
        26_000,
        "a2a",
        "a2a.context.created",
        "northstar",
        None,
        Some("submitted"),
        "Root medication-safety incident context created",
        Some("task-root"),
        None,
        None,
        Some(0.55),
        Some(0),
        0.85,
        Some((
            "n01",
            "Through A2A, the safety agent discovers what each remote agent can do.",
        )),
    )?;
    for (index, (target, task, summary)) in [
        ("meridian", "task-lots", "Trace production-lot genealogy"),
        (
            "harbor",
            "task-exposure",
            "Build de-identified exposure cohort",
        ),
        (
            "atlas",
            "task-shipments",
            "Map global shipment and quarantine routes",
        ),
        (
            "helix",
            "task-threshold",
            "Evaluate fictional recall threshold",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        emit(
            30_000 + u64::try_from(index).unwrap_or(0) * 1_000,
            "a2a",
            "a2a.task.submitted",
            "northstar",
            Some(target),
            Some("submitted"),
            summary,
            Some(task),
            None,
            None,
            Some(0.7),
            None,
            0.72,
            None,
        )?;
    }

    for (time, source, kind, state, summary, signal, confidence, reinforcement) in [
        (
            40_000,
            "meridian",
            "smesh.signal.emitted",
            "emitted",
            "Lot-genealogy task diffuses through the local field",
            "sig-lot-root",
            0.72,
            0,
        ),
        (
            43_000,
            "meridian-manufacturing",
            "smesh.task.claimed",
            "claimed",
            "Manufacturing agent claims lot genealogy",
            "sig-lot-claim-mfg",
            0.91,
            0,
        ),
        (
            44_000,
            "meridian-quality",
            "smesh.task.claimed",
            "claimed",
            "Quality agent independently claims anomaly review",
            "sig-lot-claim-qa",
            0.84,
            0,
        ),
        (
            47_000,
            "meridian-quality",
            "smesh.task.backed-off",
            "backed-off",
            "Quality agent yields lot ownership but continues evidence review",
            "sig-lot-claim-qa",
            0.66,
            0,
        ),
        (
            51_000,
            "meridian-manufacturing",
            "smesh.signal.reinforced",
            "reinforced",
            "Manufacturing telemetry supports lot ZX-472",
            "sig-hypothesis-zx472",
            0.78,
            1,
        ),
        (
            54_000,
            "meridian-quality",
            "smesh.signal.reinforced",
            "reinforced",
            "Independent quality record reinforces ZX-472 hypothesis",
            "sig-hypothesis-zx472",
            0.87,
            2,
        ),
        (
            58_000,
            "sentinel-contradiction",
            "smesh.signal.contested",
            "contested",
            "Auditor reserves judgment pending shipment evidence",
            "sig-hypothesis-zx472",
            0.61,
            2,
        ),
    ] {
        emit(
            time,
            "smesh",
            kind,
            source,
            None,
            Some(state),
            summary,
            Some("task-lots"),
            Some(signal),
            None,
            Some(confidence),
            Some(reinforcement),
            0.74,
            None,
        )?;
    }

    for (index, (public_agent, specialist, task_id, signal_id, summary)) in [
        (
            "northstar",
            "northstar-epidemiology",
            "task-cluster",
            "sig-cluster",
            "Epidemiology swarm corroborates the cross-hospital cluster",
        ),
        (
            "harbor",
            "harbor-claims",
            "task-exposure",
            "sig-exposure",
            "Claims swarm corroborates the de-identified exposure cohort",
        ),
        (
            "atlas",
            "atlas-routing",
            "task-shipments",
            "sig-routes",
            "Routing swarm corroborates the shipment graph",
        ),
        (
            "helix",
            "helix-regulation",
            "task-threshold",
            "sig-threshold",
            "Regulatory swarm corroborates the fictional recall threshold",
        ),
        (
            "sentinel",
            "sentinel-auditor",
            "task-audit",
            "sig-audit",
            "Audit swarm corroborates provenance across artifacts",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let base = 59_000 + u64::try_from(index).unwrap_or(0) * 1_100;
        emit(
            base,
            "smesh",
            "smesh.signal.emitted",
            public_agent,
            None,
            Some("emitted"),
            "A2A task enters the organization-local SMESH field",
            Some(task_id),
            Some(signal_id),
            None,
            Some(0.68),
            Some(0),
            0.62,
            None,
        )?;
        emit(
            base + 300,
            "smesh",
            "smesh.task.claimed",
            specialist,
            None,
            Some("claimed"),
            "Highest-affinity specialist claims the local task",
            Some(task_id),
            Some(signal_id),
            None,
            Some(0.82),
            Some(0),
            0.66,
            None,
        )?;
        emit(
            base + 600,
            "smesh",
            "smesh.signal.reinforced",
            specialist,
            None,
            Some("reinforced"),
            summary,
            Some(task_id),
            Some(signal_id),
            None,
            Some(0.9),
            Some(2),
            0.7,
            None,
        )?;
    }

    emit(
        66_000,
        "artifact",
        "artifact.created",
        "meridian",
        Some("northstar"),
        Some("working"),
        "Initial affected-lot boundary: ZX-472",
        Some("task-lots"),
        None,
        Some("artifact-lots-v1"),
        Some(0.78),
        Some(2),
        0.8,
        Some((
            "n03",
            "Inside each endpoint, SMESH specialists claim, challenge, and reinforce the work.",
        )),
    )?;
    emit(
        74_000,
        "artifact",
        "artifact.created",
        "atlas",
        Some("sentinel"),
        Some("working"),
        "Shipment graph connects adjacent lots to the same thermal excursion",
        Some("task-shipments"),
        None,
        Some("artifact-routes-v1"),
        Some(0.93),
        Some(3),
        0.92,
        Some(("n04", "Then logistics evidence widens the boundary.")),
    )?;
    emit(
        78_000,
        "smesh",
        "smesh.signal.contested",
        "sentinel-contradiction",
        None,
        Some("contested"),
        "ZX-472-only boundary contradicted by route telemetry",
        Some("task-lots"),
        Some("sig-hypothesis-zx472"),
        None,
        Some(0.44),
        Some(1),
        0.95,
        None,
    )?;
    emit(
        82_000,
        "smesh",
        "smesh.signal.decayed",
        "meridian",
        None,
        Some("decayed"),
        "Unsupported narrow-lot hypothesis decays",
        Some("task-lots"),
        Some("sig-hypothesis-zx472"),
        None,
        Some(0.18),
        Some(0),
        0.88,
        None,
    )?;
    emit(
        86_000,
        "a2a",
        "a2a.message.continued",
        "northstar",
        Some("meridian"),
        Some("working"),
        "Continue lot analysis with shipment-graph evidence",
        Some("task-lots"),
        None,
        Some("artifact-routes-v1"),
        Some(0.82),
        None,
        0.78,
        None,
    )?;

    emit(
        101_000,
        "system",
        "system.endpoint.failed",
        "atlas",
        Some("northstar"),
        Some("failed"),
        "Primary logistics endpoint stopped streaming",
        Some("task-shipments"),
        None,
        None,
        Some(0.2),
        None,
        1.0,
        Some((
            "n05",
            "Now the primary logistics endpoint stops responding.",
        )),
    )?;
    emit(
        104_000,
        "a2a",
        "a2a.task.canceled",
        "northstar",
        Some("atlas"),
        Some("canceled"),
        "Stalled logistics task canceled without restarting the incident",
        Some("task-shipments"),
        None,
        None,
        Some(0.5),
        None,
        0.95,
        None,
    )?;
    emit(
        108_000,
        "a2a",
        "a2a.agent.fallback-discovered",
        "northstar",
        Some("atlas-fallback"),
        Some("discovered"),
        "Frankfurt fallback logistics Agent Card selected",
        Some("task-shipments-fallback"),
        None,
        None,
        Some(0.73),
        None,
        0.86,
        None,
    )?;
    emit(
        111_000,
        "a2a",
        "a2a.task.submitted",
        "northstar",
        Some("atlas-fallback"),
        Some("submitted"),
        "Bounded shipment context delegated to fallback",
        Some("task-shipments-fallback"),
        None,
        None,
        Some(0.8),
        None,
        0.88,
        None,
    )?;

    for (time, source, target, task, artifact, summary) in [
        (
            126_000,
            "meridian",
            "northstar",
            "task-lots",
            "artifact-lots-v2",
            "Expanded affected-lot boundary accepted",
        ),
        (
            130_000,
            "harbor",
            "northstar",
            "task-exposure",
            "artifact-exposure",
            "De-identified exposure cohort completed",
        ),
        (
            134_000,
            "atlas-fallback",
            "northstar",
            "task-shipments-fallback",
            "artifact-quarantine",
            "Quarantine and reroute GeoJSON completed",
        ),
        (
            138_000,
            "helix",
            "northstar",
            "task-threshold",
            "artifact-threshold",
            "Fictional recall-threshold memo completed",
        ),
        (
            142_000,
            "sentinel",
            "northstar",
            "task-audit",
            "artifact-contradiction",
            "Independent contradiction report completed",
        ),
    ] {
        emit(
            time,
            "artifact",
            "artifact.accepted",
            source,
            Some(target),
            Some("completed"),
            summary,
            Some(task),
            None,
            Some(artifact),
            Some(0.94),
            Some(3),
            0.82,
            None,
        )?;
    }
    emit(
        150_000,
        "a2a",
        "a2a.task.completed",
        "northstar",
        Some("incident"),
        Some("completed"),
        "Recall evidence packet assembled from linked artifacts",
        Some("task-root"),
        None,
        Some("artifact-recall-packet"),
        Some(0.96),
        Some(5),
        0.96,
        Some((
            "n07",
            "The artifacts converge, but agreement is not authority.",
        )),
    )?;
    emit(
        160_000,
        "human",
        "human.review.opened",
        "commander",
        Some("incident"),
        Some("working"),
        "Incident commander reviews evidence and remaining uncertainty",
        Some("task-root"),
        None,
        Some("artifact-recall-packet"),
        None,
        None,
        1.0,
        None,
    )?;
    emit(
        169_000,
        "human",
        "human.decision.ratified",
        "commander",
        Some("incident"),
        Some("ratified"),
        "Fictional recall action approved by human authority",
        Some("task-root"),
        None,
        Some("artifact-ratification"),
        Some(1.0),
        None,
        1.0,
        Some((
            "n08",
            "The machines moved at network speed. A human made the irreversible decision.",
        )),
    )?;
    emit(
        176_000,
        "system",
        "system.run.completed",
        "incident",
        None,
        Some("completed"),
        "LIFELINE run complete; trace sealed for deterministic replay",
        Some("task-root"),
        None,
        Some("artifact-ratification"),
        Some(1.0),
        Some(6),
        1.0,
        Some(("n09", "A2A between agents. SMESH within the swarm.")),
    )?;

    verify_trace(&trace.events)?;
    Ok(trace.events)
}

/// Verifies ordering, identity, monotonic time, and the event hash chain.
///
/// # Errors
///
/// Returns [`TraceError::Invariant`] for the first invalid event, or a
/// serialization error if an event cannot be normalized for hashing.
pub fn verify_trace(events: &[TraceEvent]) -> Result<(), TraceError> {
    if events.is_empty() {
        return Err(TraceError::Invariant("trace is empty".to_owned()));
    }
    let mut ids = HashSet::new();
    let mut previous_hash: Option<&str> = None;
    let mut previous_time = 0;
    for (index, event) in events.iter().enumerate() {
        if event.sequence != u64::try_from(index).unwrap_or(u64::MAX) {
            return Err(TraceError::Invariant(format!(
                "sequence mismatch at {index}"
            )));
        }
        if event.sim_time_ms < previous_time {
            return Err(TraceError::Invariant(format!("time regressed at {index}")));
        }
        if !ids.insert(event.event_id.as_str()) {
            return Err(TraceError::Invariant(format!(
                "duplicate event id at {index}"
            )));
        }
        if let Some(content_hash) = event.message.content_hash.as_deref()
            && content_hash != hash_bytes(event.message.summary.as_bytes())
        {
            return Err(TraceError::Invariant(format!(
                "content hash mismatch at {index}"
            )));
        }
        if event.integrity.prev_hash.as_deref() != previous_hash {
            return Err(TraceError::Invariant(format!(
                "hash-chain break at {index}"
            )));
        }
        let expected = event_hash(event)?;
        if event.integrity.event_hash != expected {
            return Err(TraceError::Invariant(format!(
                "event hash mismatch at {index}"
            )));
        }
        previous_hash = Some(event.integrity.event_hash.as_str());
        previous_time = event.sim_time_ms;
    }
    Ok(())
}

/// Generates the deterministic fixture and writes it as newline-delimited JSON.
///
/// # Errors
///
/// Returns an error when generation, serialization, file creation, writing, or
/// final flushing fails.
pub fn write_lifeline_trace(path: impl AsRef<Path>) -> Result<Vec<TraceEvent>, TraceError> {
    let events = generate_lifeline_trace()?;
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    for event in &events {
        serde_json::to_writer(&mut writer, event)?;
        writer.write_all(b"\n")?;
    }
    writer.flush()?;
    Ok(events)
}

fn event_hash(event: &TraceEvent) -> Result<String, serde_json::Error> {
    let mut normalized = event.clone();
    normalized.integrity.event_hash.clear();
    Ok(hash_bytes(&serde_json::to_vec(&normalized)?))
}

fn hash_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().fold(
        String::with_capacity(digest.len() * 2),
        |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to a String cannot fail");
            output
        },
    )
}

fn modality(layer: &str, kind: &str) -> &'static str {
    if kind.contains("geo") || kind.contains("shipment") {
        "geojson"
    } else if matches!(layer, "artifact" | "tool") {
        "data"
    } else {
        "text"
    }
}

#[allow(clippy::too_many_lines)]
fn actor(id: &str) -> TraceActor {
    let (label, organization, role, lon, lat, endpoint) = match id {
        "incident" => (
            "LIFELINE Incident",
            "LIFELINE",
            "incident",
            -18.0,
            38.0,
            None,
        ),
        "northstar" => (
            "Clinical Safety Agent",
            "Northstar Hospital Network",
            "a2a-agent",
            -71.0589,
            42.3601,
            Some("http://northstar.invalid/a2a"),
        ),
        "northstar-epidemiology" => (
            "Epidemiology Specialist",
            "Northstar Hospital Network",
            "smesh-agent",
            -71.0589,
            42.3601,
            None,
        ),
        "hospital-boston" => (
            "Boston Hospital",
            "Northstar Hospital Network",
            "clinical-source",
            -71.0589,
            42.3601,
            None,
        ),
        "hospital-rotterdam" => (
            "Rotterdam Hospital",
            "Northstar Hospital Network",
            "clinical-source",
            4.4777,
            51.9244,
            None,
        ),
        "hospital-singapore" => (
            "Singapore Hospital",
            "Northstar Hospital Network",
            "clinical-source",
            103.8198,
            1.3521,
            None,
        ),
        "meridian" => (
            "Pharmacovigilance Agent",
            "Meridian Bio",
            "a2a-agent",
            -74.0060,
            40.7128,
            Some("http://meridian.invalid/a2a"),
        ),
        "meridian-manufacturing" => (
            "Manufacturing Specialist",
            "Meridian Bio",
            "smesh-agent",
            -74.0060,
            40.7128,
            None,
        ),
        "meridian-quality" => (
            "Quality Specialist",
            "Meridian Bio",
            "smesh-agent",
            -74.0060,
            40.7128,
            None,
        ),
        "atlas" => (
            "Logistics Agent",
            "Atlas Cold Chain",
            "a2a-agent",
            103.8,
            1.29,
            Some("http://atlas.invalid/a2a"),
        ),
        "atlas-routing" => (
            "Routing Specialist",
            "Atlas Cold Chain",
            "smesh-agent",
            103.8,
            1.29,
            None,
        ),
        "atlas-fallback" => (
            "Fallback Logistics Agent",
            "Atlas Cold Chain",
            "a2a-agent",
            8.6821,
            50.1109,
            Some("http://atlas-fallback.invalid/a2a"),
        ),
        "helix" => (
            "Recall Authority Agent",
            "Helix Medicines Authority",
            "a2a-agent",
            4.3517,
            50.8503,
            Some("http://helix.invalid/a2a"),
        ),
        "helix-regulation" => (
            "Regulatory Specialist",
            "Helix Medicines Authority",
            "smesh-agent",
            4.3517,
            50.8503,
            None,
        ),
        "harbor" => (
            "Member Safety Agent",
            "Harbor Health",
            "a2a-agent",
            -87.6298,
            41.8781,
            Some("http://harbor.invalid/a2a"),
        ),
        "harbor-claims" => (
            "Claims Specialist",
            "Harbor Health",
            "smesh-agent",
            -87.6298,
            41.8781,
            None,
        ),
        "sentinel" => (
            "Independent Evidence Agent",
            "Sentinel Labs",
            "a2a-agent",
            -0.1276,
            51.5072,
            Some("http://sentinel.invalid/a2a"),
        ),
        "sentinel-auditor" => (
            "Provenance Auditor",
            "Sentinel Labs",
            "smesh-agent",
            -0.1276,
            51.5072,
            None,
        ),
        "sentinel-contradiction" => (
            "Contradiction Specialist",
            "Sentinel Labs",
            "smesh-agent",
            -0.1276,
            51.5072,
            None,
        ),
        "commander" => (
            "Incident Commander",
            "LIFELINE",
            "human",
            2.3522,
            48.8566,
            None,
        ),
        _ => ("Unknown Actor", "Unknown", "unknown", 0.0, 0.0, None),
    };
    TraceActor {
        id: id.to_owned(),
        label: label.to_owned(),
        organization: organization.to_owned(),
        role: role.to_owned(),
        endpoint: endpoint.map(str::to_owned),
        geo: Geo { lon, lat, alt: 0.0 },
    }
}
