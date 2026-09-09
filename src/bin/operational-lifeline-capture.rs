use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::path::Path;
use std::sync::Arc;

use serde_json::{Value, json};
use smesh_a2a::{
    A2aCaptureAdapter, ArtifactCaptureAdapter, CanonicalCapture, CaptureParent, CausalMerger,
    CausalSourceEvent, DataClass, EditorialCue, EditorialEntry, HumanConsoleCaptureAdapter,
    HumanDecision, HybridLogicalClock, LifelineFailureScenarioRun, MergeLimits,
    MissingParentPolicy, OperationalActor, OperationalActorManifest, OperationalEditorialOverlay,
    OperationalProducer, OperationalProjectionLimits, OperationalSite, OperationalVisibility,
    PrivacyPolicy, ProducerIdentity, ProducerKind, ProjectionReceipt, RatificationCommand,
    RatificationLedger, RedactionAction, RedactionRule, ReplaySealInput, ReviewAcknowledgement,
    ReviewArtifact, ReviewPacketInput, RunHmacKey, SmeshJournalCaptureAdapter,
    ToolMcpCaptureAdapter, capture_causal_source_jsonl, content_digest,
    project_operational_observatory_with_source_facts, sanitize_public_trace_with_receipts,
    verify_lifeline_failure_trace, verify_operational_projection, verify_sanitized_trace,
};

const RUN_ID: &str = "lifeline-operational-0047";
const INSTANCE: &str = "lifeline-seed-47";
const CONTEXT: &str = "lifeline-incident-0047";
const GATEWAYS: [(&str, &str); 6] = [
    ("atlas-fallback", "Atlas Cold Chain fallback"),
    ("atlas-primary", "Atlas Cold Chain primary"),
    ("harbor", "Harbor Health"),
    ("helix", "Helix Medicines Authority"),
    ("meridian", "Meridian Bio"),
    ("sentinel", "Sentinel Labs"),
];
const TEAM_SITE: [(&str, &str); 5] = [
    ("atlas", "atlas-primary"),
    ("harbor", "harbor"),
    ("helix", "helix"),
    ("meridian", "meridian"),
    ("sentinel", "sentinel"),
];

struct RatificationArtifacts {
    manifest: Value,
    decision_receipt_bytes: Vec<u8>,
    prompt_bytes: Vec<u8>,
}

#[derive(Clone)]
struct PendingSourceFact {
    failure_kind: Option<String>,
    field_restricted: bool,
    outcome: Option<String>,
    source_schema_version: String,
}

struct ObservedToolCall {
    sequence: u64,
    organization: String,
    role: String,
    tool_id: String,
    task_id: String,
    context_id: String,
    marker: Vec<u8>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os();
    let binary = args
        .next()
        .unwrap_or_else(|| "operational-lifeline-capture".into());
    let source = args.next().ok_or_else(|| usage(&binary))?;
    let output = args.next().ok_or_else(|| usage(&binary))?;
    if args.next().is_some() {
        return Err(usage(&binary).into());
    }
    compose(Path::new(&source), Path::new(&output))?;
    println!("{}", Path::new(&output).join("package.jsonl").display());
    Ok(())
}

fn usage(binary: &std::ffi::OsStr) -> String {
    format!(
        "usage: {} <lifeline-failure-scenario-directory> <new-output-directory>",
        Path::new(binary).display()
    )
}

#[allow(clippy::too_many_lines)] // Linear evidence pipeline keeps every authority transition auditable.
fn compose(source: &Path, output: &Path) -> Result<(), Box<dyn Error>> {
    if output.exists() {
        return Err("output directory already exists".into());
    }
    let run_bytes = read_bounded(&source.join("run.json"), 256 * 1024)?;
    let run: LifelineFailureScenarioRun = serde_json::from_slice(&run_bytes)?;
    let run_value: Value = serde_json::from_slice(&run_bytes)?;
    let agent_cards = verified_agent_cards(&run_value)?;
    let failure_path = source.join("restricted-scenario.jsonl");
    let verified_failure = verify_lifeline_failure_trace(&failure_path)?;
    run.verify(&verified_failure)?;
    let failure_bytes = read_bounded(&failure_path, 256 * 1024)?;

    std::fs::create_dir(output)?;
    set_private_dir(output)?;
    let restricted = output.join("restricted");
    std::fs::create_dir(&restricted)?;
    set_private_dir(&restricted)?;

    let capture = Arc::new(CanonicalCapture::create_spool(
        RUN_ID,
        512,
        &restricted.join("canonical-capture.jsonl"),
    )?);
    let mut labels = HashMap::<String, (String, String)>::new();
    let mut pending_facts = HashMap::<String, PendingSourceFact>::new();
    let mut source_bindings = Vec::<Value>::new();
    capture_failure(&capture, &failure_bytes, &mut labels, &mut pending_facts)?;
    source_bindings.push(source_binding(
        "lifeline-failure-scenario/1",
        "lifeline-failure-adapter/1",
        &failure_bytes,
    ));

    for (team, site) in TEAM_SITE {
        let journal = read_bounded(&source.join(format!("journals/{team}.jsonl")), 256 * 1024)?;
        capture_team_journal(&capture, team, site, &journal, &mut labels)?;
        source_bindings.push(source_binding(
            "lifeline-team-journal/1",
            "lifeline-team-journal-adapter/1",
            &journal,
        ));
        let runtime = read_bounded(
            &source.join(format!("journals/{team}.runtime.jsonl")),
            256 * 1024,
        )?;
        capture_runtime(
            &capture,
            team,
            site,
            &runtime,
            &mut labels,
            &mut pending_facts,
        )?;
        source_bindings.push(source_binding(
            "lifeline-runtime-trace/1",
            "lifeline-runtime-trace-adapter/1",
            &runtime,
        ));
    }

    source_bindings.sort_by_key(|value| {
        format!(
            "{}\0{}",
            value["schemaVersion"].as_str().unwrap_or_default(),
            value["adapterVersion"].as_str().unwrap_or_default()
        )
    });
    let pre_decision = capture.snapshot()?;
    if !pre_decision.capture_valid || pre_decision.events.is_empty() {
        return Err("pre-decision canonical capture is invalid".into());
    }
    let pre_decision_bytes = canonical_value(&serde_json::to_value(&pre_decision)?)?;
    let mut ratification = ratify(
        &restricted,
        &pre_decision_bytes,
        pre_decision.events.len(),
        &source_bindings,
    )?;
    let decision_event_id = capture_human(
        &capture,
        &mut labels,
        &ratification.prompt_bytes,
        &ratification.decision_receipt_bytes,
    )?;
    ratification.manifest["decisionEventId"] = decision_event_id.into();
    ratification.manifest["decisionEventContentDigest"] =
        content_digest(&ratification.decision_receipt_bytes).into();
    capture.complete()?;
    let stream = capture.snapshot()?;
    if !stream.capture_valid || stream.events.is_empty() {
        return Err("canonical capture is invalid".into());
    }
    let mut fact_entries = stream
        .events
        .iter()
        .filter_map(|event| {
            pending_facts.get(&event.interaction_id).map(|fact| {
                json!({
                    "eventId": event.event_id,
                    "failureKind": fact.failure_kind,
                    "fieldRestrictions": if fact.field_restricted {
                        vec![json!({"field":"subjectId","reason":"sourceIdentifierUnavailable"})]
                    } else { Vec::new() },
                    "outcome": fact.outcome,
                    "sourceContentDigest": event.content.digest,
                    "sourceSchemaVersion": fact.source_schema_version,
                })
            })
        })
        .collect::<Vec<_>>();
    fact_entries.sort_by(|a, b| a["eventId"].as_str().cmp(&b["eventId"].as_str()));
    let source_facts_bytes = canonical_value(&json!({
        "entries": fact_entries,
        "schemaVersion": "operational-observatory-source-facts/1",
    }))?;
    write_private(&restricted.join("source-facts.json"), &source_facts_bytes)?;

    let mut prior = HashMap::<(ProducerKind, String, String), String>::new();
    let mut causal = Vec::with_capacity(stream.events.len());
    for (index, event) in stream.events.into_iter().enumerate() {
        let key = (
            event.producer.identity.kind,
            event.producer.identity.id.clone(),
            event.producer.identity.instance_id.clone(),
        );
        let decision = Some(json!({
            "adapterVersion": adapter_version(event.producer.identity.kind),
            "clockAuthority": "adapterOrdinalOnly",
            "sourceSequence": event.producer.sequence.to_string()
        }));
        let item = CausalSourceEvent::new_chained(
            event,
            HybridLogicalClock {
                physical_ns: u64::try_from(index)?.saturating_mul(1_000_000_000),
                logical: 0,
            },
            u64::try_from(index)?,
            decision,
            prior.get(&key).cloned(),
        )?;
        prior.insert(key, item.producer_hash().to_owned());
        causal.push(item);
    }
    let causal_bytes = capture_causal_source_jsonl(RUN_ID, &causal)?;
    write_private(&restricted.join("causal-source.jsonl"), &causal_bytes)?;
    let mut merger =
        CausalMerger::new(RUN_ID, MergeLimits::default(), MissingParentPolicy::Record)?;
    merger.ingest_source_jsonl(&causal_bytes)?;
    let sealed = merger.finalize(ReplaySealInput::empty())?;
    ratification.manifest["finalReplayRunSeal"] = sealed.receipt().run_seal.clone().into();
    write_private(
        &restricted.join("sealed-replay.jsonl"),
        sealed.bundle_jsonl(),
    )?;
    write_private(
        &restricted.join("replay-receipt.json"),
        sealed.receipt_json(),
    )?;

    let (actor_manifest, actor_bytes) = actors(&labels)?;
    let editorial = editorial(&causal);
    let editorial_bytes = canonical_value(&serde_json::to_value(&editorial)?)?;
    let projection = project_operational_observatory_with_source_facts(
        sealed.bundle_jsonl(),
        sealed.receipt_json(),
        &sealed.receipt().run_seal,
        &actor_bytes,
        &editorial_bytes,
        &source_facts_bytes,
        OperationalProjectionLimits::default(),
    )?;
    verify_operational_projection(
        projection.package_jsonl(),
        projection.receipt_json(),
        &projection.receipt().input_digest,
    )?;

    let sanitized = sanitize_package(projection.package_jsonl(), projection.receipt())?;
    if sanitized.public_package != projection.package_jsonl() {
        return Err("privacy projection changed approved public package".into());
    }

    write_public(&output.join("package.jsonl"), &sanitized.public_package)?;
    write_public(&output.join("receipt.json"), projection.receipt_json())?;
    write_public(&output.join("actors.json"), &actor_bytes)?;
    write_public(&output.join("editorial.json"), &editorial_bytes)?;
    let bootstrap = canonical_value(&json!({
        "expectedInputDigest": projection.receipt().input_digest,
        "expectedRunSeal": sealed.receipt().run_seal,
        "finalDurationNs": u64::try_from(causal.len())?.saturating_mul(1_000_000_000).to_string(),
        "schemaVersion": "operational-observatory-browser-bootstrap/1"
    }))?;
    write_public(&output.join("browser-bootstrap.json"), &bootstrap)?;
    write_public(
        &output.join("public-manifest.json"),
        &canonical_value(
            &json!({"manifests":sanitized.public_manifests,"schemaVersion":"operational-lifeline-public-manifests/1"}),
        )?,
    )?;
    write_private(
        &restricted.join("privacy-manifest.json"),
        &canonical_value(
            &json!({"manifests":sanitized.restricted_manifests,"schemaVersion":"operational-lifeline-restricted-manifests/1"}),
        )?,
    )?;
    write_private(
        &restricted.join("redaction-log.json"),
        &canonical_value(&Value::Array(sanitized.action_logs))?,
    )?;

    let gap_count = std::str::from_utf8(sealed.bundle_jsonl())?
        .lines()
        .filter(|line| line.contains("\"recordType\":\"missingParent\""))
        .count();
    let manifest = json!({
        "agentCards": agent_cards,
        "eventCount": causal.len().to_string(),
        "gapCount": gap_count.to_string(),
        "gatewayCount": "6",
        "humanRatification": ratification.manifest,
        "restrictionCount": TEAM_SITE.len().to_string(),
        "sourceClockRestrictionCount": causal.len().to_string(),
        "sourceIdentifierRestrictionCount": TEAM_SITE.len().to_string(),
        "operationalTimeBasis": "adapterOrdinalPresentationOnly; source schemas provide order but no authoritative wall clock",
        "runId": RUN_ID,
        "schemaVersion": "operational-lifeline-evidence/1",
        "sourceSchemas": ["lifeline-failure-scenario/1", "lifeline-runtime-trace/1", "lifeline-team-journal/1"],
        "sources": source_bindings,
    });
    write_private(
        &restricted.join("evidence-manifest.json"),
        &canonical_value(&manifest)?,
    )?;
    let _ = actor_manifest;
    Ok(())
}

fn verified_agent_cards(run: &Value) -> Result<Vec<Value>, Box<dyn Error>> {
    let cards = run
        .pointer("/directorRun/discoveredGateways")
        .and_then(Value::as_array)
        .ok_or("discovered Agent Card evidence is absent")?;
    if cards.len() != GATEWAYS.len() {
        return Err("expected exactly six discovered Agent Cards".into());
    }
    let expected = GATEWAYS
        .iter()
        .map(|(id, _)| *id)
        .collect::<std::collections::BTreeSet<_>>();
    let found = cards
        .iter()
        .filter_map(|card| card["gatewayId"].as_str())
        .collect::<std::collections::BTreeSet<_>>();
    if found != expected {
        return Err("discovered Agent Card topology does not match the six gateways".into());
    }
    cards.iter().map(|card| {
        let discovery = card["discoveryUrl"].as_str().ok_or("Agent Card discovery URL absent")?;
        if !(discovery.starts_with("http://127.0.0.1:") || discovery.starts_with("http://[::1]:")) { return Err("Agent Card discovery escaped loopback".into()); }
        let interfaces = card["interfaces"].as_array().ok_or("Agent Card interfaces absent")?;
        if interfaces.is_empty() || interfaces.iter().any(|interface| {
            interface["url"].as_str().is_none_or(|url| !(url.starts_with("http://127.0.0.1:") || url.starts_with("http://[::1]:")))
        }) { return Err("Agent Card interface escaped loopback".into()); }
        Ok(json!({
            "gatewayId": card["gatewayId"],
            "interfaceProtocols": interfaces.iter().map(|interface| interface["protocolBinding"].clone()).collect::<Vec<_>>(),
            "providerOrganization": card["providerOrganization"],
            "skillIds": card["skillIds"],
            "sourceSchema": "lifeline-failure-scenario-run/1"
        }))
    }).collect()
}

fn capture_failure(
    capture: &Arc<CanonicalCapture>,
    bytes: &[u8],
    labels: &mut HashMap<String, (String, String)>,
    pending_facts: &mut HashMap<String, PendingSourceFact>,
) -> Result<(), Box<dyn Error>> {
    let mut mapped = HashMap::<String, String>::new();
    for line in std::str::from_utf8(bytes)?.lines() {
        let value: Value = serde_json::from_str(line)?;
        let gateway = value["gatewayId"]
            .as_str()
            .ok_or("failure gateway absent")?;
        value["sequence"]
            .as_u64()
            .ok_or("failure sequence absent")?;
        let kind = value["kind"].as_str().ok_or("failure kind absent")?;
        let identity = ProducerIdentity::new(ProducerKind::A2a, gateway, INSTANCE)?;
        let adapter = A2aCaptureAdapter::new(Arc::clone(capture), identity)?;
        labels.insert(
            format!("a2a\0{gateway}\0{INSTANCE}"),
            (
                if gateway == "director" {
                    "LIFELINE director"
                } else {
                    gateway
                }
                .to_owned(),
                if gateway == "director" {
                    "sentinel"
                } else {
                    gateway
                }
                .to_owned(),
            ),
        );
        let parent = value["parentEventId"]
            .as_str()
            .and_then(|id| mapped.get(id))
            .cloned()
            .map_or(CaptureParent::Root, CaptureParent::Event);
        let normalized = canonical_value(&json!({
            "adapterVersion": "lifeline-failure-adapter/1",
            "attempt": value["attempt"],
            "contextId": value["contextId"],
            "kind": kind,
            "messageId": value["messageId"],
            "operationId": value["operationId"],
            "outcome": value["outcome"],
            "replacesTaskId": value["replacesTaskId"],
            "schemaVersion": "lifeline-failure-scenario/1",
            "sourceEventId": value["eventId"],
            "taskId": value["taskId"]
        }))?;
        let interaction_id = value["eventId"]
            .as_str()
            .ok_or("failure interaction identity absent")?;
        let outcome = value["outcome"].as_str().ok_or("failure outcome absent")?;
        if pending_facts
            .insert(
                interaction_id.to_owned(),
                PendingSourceFact {
                    failure_kind: Some(kind.to_owned()),
                    field_restricted: false,
                    outcome: Some(outcome.to_owned()),
                    source_schema_version: "lifeline-failure-scenario/1".into(),
                },
            )
            .is_some()
        {
            return Err("duplicate source fact identity".into());
        }
        let receipt = adapter.send_with_subject(
            interaction_id,
            "lifeline-director",
            value["taskId"].as_str(),
            value["contextId"].as_str(),
            value["replacesTaskId"]
                .as_str()
                .or_else(|| value["messageId"].as_str()),
            &normalized,
            parent,
        )?;
        mapped.insert(
            value["eventId"].as_str().unwrap().to_owned(),
            receipt.event_id().to_owned(),
        );
    }
    Ok(())
}

fn capture_runtime(
    capture: &Arc<CanonicalCapture>,
    team: &str,
    site: &str,
    bytes: &[u8],
    labels: &mut HashMap<String, (String, String)>,
    pending_facts: &mut HashMap<String, PendingSourceFact>,
) -> Result<(), Box<dyn Error>> {
    let id = format!("{team}-runtime");
    let identity = ProducerIdentity::new(ProducerKind::Smesh, &id, INSTANCE)?;
    let adapter = SmeshJournalCaptureAdapter::new(Arc::clone(capture), identity)?;
    labels.insert(
        format!("smesh\0{id}\0{INSTANCE}"),
        (format!("{team} local SMESH runtime"), site.to_owned()),
    );
    let mut parent = CaptureParent::Root;
    let mut saw_signal = false;
    let mut saw_tick = false;
    let mut expected_sequence = 1_u64;
    for line in std::str::from_utf8(bytes)?.lines() {
        let value: Value = serde_json::from_str(line)?;
        if canonical_value(&value)? != line.as_bytes() {
            return Err("runtime source record is not canonical".into());
        }
        let record = source_object(
            &value,
            &["data", "kind", "schemaVersion", "sequence"],
            "runtime source record",
        )?;
        if record.get("schemaVersion").and_then(Value::as_str) != Some("lifeline-runtime-trace/1") {
            return Err("runtime source schema is unsupported".into());
        }
        let sequence = record
            .get("sequence")
            .and_then(Value::as_u64)
            .ok_or("runtime source sequence absent")?;
        if sequence != expected_sequence {
            return Err("runtime source sequence is not contiguous".into());
        }
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or("runtime source sequence overflow")?;
        let kind = record
            .get("kind")
            .and_then(Value::as_str)
            .ok_or("runtime kind absent")?;
        validate_runtime_data(kind, record.get("data").ok_or("runtime data absent")?)?;
        let receipt = match kind {
            "tick_completed" if !saw_tick => {
                saw_tick = true;
                // Tick ordinal and counts are scheduler-dependent presentation data, not
                // authoritative source time or failure facts. Preserve only the observed kind.
                adapter.record(
                    &format!("runtime-{team}-tick-completed"),
                    None,
                    Some(CONTEXT),
                    smesh_runtime::RuntimeEvent::TickCompleted {
                        tick: 0,
                        active_signals: 0,
                        expired: 0,
                    },
                    parent,
                )?
            }
            "signal_emitted" if !saw_signal => {
                saw_signal = true;
                let interaction_id = format!("runtime-{team}-signal-emitted");
                pending_facts.insert(
                    interaction_id.clone(),
                    PendingSourceFact {
                        failure_kind: None,
                        field_restricted: true,
                        outcome: None,
                        source_schema_version: "lifeline-runtime-trace/1".into(),
                    },
                );
                adapter.record_signal_with_unavailable_identifier(
                    &interaction_id,
                    None,
                    Some(CONTEXT),
                    parent,
                )?
            }
            _ => continue,
        };
        parent = CaptureParent::Event(receipt.event_id().to_owned());
    }
    if !saw_signal || !saw_tick {
        return Err("runtime trace lacks signal or tick evidence".into());
    }
    Ok(())
}

fn validate_runtime_data(kind: &str, data: &Value) -> Result<(), Box<dyn Error>> {
    let (keys, string_keys, unsigned_keys): (&[&str], &[&str], &[&str]) = match kind {
        "signal_emitted" | "signal_expired" => (&["hash"], &["hash"], &[]),
        "signal_reinforced" => (&["count", "hash"], &["hash"], &["count"]),
        "signal_received" => (&["from", "hash", "hops"], &["from", "hash"], &["hops"]),
        "tick_completed" => (
            &["active_signals", "expired", "tick"],
            &[],
            &["active_signals", "expired", "tick"],
        ),
        "peer_connected" | "peer_disconnected" => (&["peer_id"], &["peer_id"], &[]),
        _ => return Err("runtime source kind is unsupported".into()),
    };
    let data = source_object(data, keys, "runtime source data")?;
    if string_keys
        .iter()
        .any(|key| data.get(*key).and_then(Value::as_str).is_none())
        || unsigned_keys
            .iter()
            .any(|key| data.get(*key).and_then(Value::as_u64).is_none())
    {
        return Err("runtime source data has an invalid field type".into());
    }
    Ok(())
}

fn source_object<'a>(
    value: &'a Value,
    keys: &[&str],
    label: &str,
) -> Result<&'a serde_json::Map<String, Value>, Box<dyn Error>> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{label} must be an object"))?;
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
        return Err(format!("{label} schema is not closed").into());
    }
    Ok(object)
}

fn source_identifier(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<String, Box<dyn Error>> {
    let value = object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("journal {key} is absent"))?;
    if value.is_empty()
        || value.len() > 256
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    {
        return Err(format!("journal {key} is invalid").into());
    }
    Ok(value.to_owned())
}

fn source_text(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<String, Box<dyn Error>> {
    let value = object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("journal {key} is absent"))?;
    if value.is_empty()
        || value.len() > 4096
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() && !matches!(byte, b'\t' | b'\n' | b'\r'))
    {
        return Err(format!("journal {key} is invalid").into());
    }
    Ok(value.to_owned())
}

#[allow(clippy::too_many_lines)] // Closed journal parsing keeps pair validation adjacent.
fn capture_team_journal(
    capture: &Arc<CanonicalCapture>,
    team: &str,
    site: &str,
    bytes: &[u8],
    labels: &mut HashMap<String, (String, String)>,
) -> Result<(), Box<dyn Error>> {
    let tool_id = format!("{team}-local-tool");
    let artifact_id = format!("{team}-candidate");
    let tool = ToolMcpCaptureAdapter::new(
        Arc::clone(capture),
        ProducerIdentity::new(ProducerKind::Tool, &tool_id, INSTANCE)?,
    )?;
    let artifacts = ArtifactCaptureAdapter::new(
        Arc::clone(capture),
        ProducerIdentity::new(ProducerKind::Artifact, &artifact_id, INSTANCE)?,
    )?;
    labels.insert(
        format!("tool\0{tool_id}\0{INSTANCE}"),
        (format!("{team} observed local tool"), site.to_owned()),
    );
    labels.insert(
        format!("artifact\0{artifact_id}\0{INSTANCE}"),
        (format!("{team} captured candidate"), site.to_owned()),
    );
    let mut pending_call: Option<ObservedToolCall> = None;
    let mut saw_completion = false;
    let mut saw_artifact = false;
    let mut expected_sequence = 1_u64;
    for line in std::str::from_utf8(bytes)?.lines() {
        let value: Value = serde_json::from_str(line)?;
        if canonical_value(&value)? != line.as_bytes() {
            return Err("team journal record is not canonical".into());
        }
        let record = source_object(
            &value,
            &["data", "kind", "schemaVersion", "sequence"],
            "team journal record",
        )?;
        if record.get("schemaVersion").and_then(Value::as_str) != Some("lifeline-team-journal/1") {
            return Err("team journal schema is unsupported".into());
        }
        let sequence = record
            .get("sequence")
            .and_then(Value::as_u64)
            .ok_or("journal sequence absent")?;
        if sequence != expected_sequence {
            return Err("team journal source sequence is not contiguous".into());
        }
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or("team journal source sequence overflow")?;
        let data = record.get("data").ok_or("journal data absent")?;
        match record.get("kind").and_then(Value::as_str) {
            Some("tool_called") => {
                if pending_call.is_some() || saw_completion {
                    return Err("team journal has duplicate tool call".into());
                }
                let data = source_object(
                    data,
                    &[
                        "context_id",
                        "organization",
                        "role",
                        "seed",
                        "task_id",
                        "tool_id",
                    ],
                    "tool call data",
                )?;
                let organization = source_text(data, "organization")?;
                if data.get("seed").and_then(Value::as_u64).is_none() {
                    return Err("tool call organization or seed is invalid".into());
                }
                let role = source_identifier(data, "role")?;
                let observed_tool_id = source_identifier(data, "tool_id")?;
                let task_id = source_identifier(data, "task_id")?;
                let context_id = source_identifier(data, "context_id")?;
                let marker = canonical_value(
                    &json!({"adapterVersion":"lifeline-team-journal-adapter/1","observedKind":"tool_called","schemaVersion":"lifeline-team-journal/1","sourceData":Value::Object(data.clone()),"sourceSequence":sequence.to_string()}),
                )?;
                pending_call = Some(ObservedToolCall {
                    sequence,
                    organization,
                    role,
                    tool_id: observed_tool_id,
                    task_id,
                    context_id,
                    marker,
                });
            }
            Some("tool_completed") => {
                if saw_completion {
                    return Err("team journal has duplicate tool completion".into());
                }
                let observed = pending_call
                    .take()
                    .ok_or("tool completion precedes its call")?;
                if sequence != observed.sequence + 1 {
                    return Err("tool completion does not immediately follow its call".into());
                }
                let data = source_object(
                    data,
                    &[
                        "context_id",
                        "dataset_digest",
                        "organization",
                        "record_count",
                        "role",
                        "task_id",
                        "tool_id",
                    ],
                    "tool completion data",
                )?;
                let completion_digest = source_identifier(data, "dataset_digest")?;
                if !completion_digest.starts_with("sha256:")
                    || completion_digest.len() != 71
                    || !completion_digest[7..]
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                    || data.get("record_count").and_then(Value::as_u64).is_none()
                    || source_text(data, "organization")? != observed.organization
                    || source_identifier(data, "role")? != observed.role
                    || source_identifier(data, "tool_id")? != observed.tool_id
                    || source_identifier(data, "task_id")? != observed.task_id
                    || source_identifier(data, "context_id")? != observed.context_id
                {
                    return Err("tool completion does not match its call".into());
                }
                let result_marker = canonical_value(
                    &json!({"adapterVersion":"lifeline-team-journal-adapter/1","observedKind":"tool_completed","schemaVersion":"lifeline-team-journal/1","sourceData":Value::Object(data.clone()),"sourceSequence":sequence.to_string()}),
                )?;
                tool.record_observed_call_result(
                    &format!("journal-tool-{team}-{}", observed.sequence),
                    &observed.tool_id,
                    Some(&observed.task_id),
                    Some(&observed.context_id),
                    &observed.marker,
                    &result_marker,
                    CaptureParent::Root,
                )?;
                saw_completion = true;
            }
            Some("candidate_built") => {
                if !saw_completion || saw_artifact {
                    return Err("candidate is out of order or duplicated".into());
                }
                let data = source_object(
                    data,
                    &[
                        "bytes",
                        "context_id",
                        "digest",
                        "media_type",
                        "name",
                        "organization",
                        "role",
                        "task_id",
                    ],
                    "candidate data",
                )?;
                if data.get("bytes").and_then(Value::as_u64).is_none() {
                    return Err("candidate data is invalid".into());
                }
                for key in ["context_id", "digest", "role", "task_id"] {
                    source_identifier(data, key)?;
                }
                for key in ["media_type", "name", "organization"] {
                    source_text(data, key)?;
                }
                let marker = canonical_value(
                    &json!({"adapterVersion":"lifeline-team-journal-adapter/1","observedKind":"candidate_built","schemaVersion":"lifeline-team-journal/1","sourceSequence":sequence.to_string()}),
                )?;
                artifacts.produced(
                    &format!("journal-artifact-{team}-{sequence}"),
                    &artifact_id,
                    None,
                    Some(CONTEXT),
                    &marker,
                    CaptureParent::Root,
                )?;
                saw_artifact = true;
            }
            Some(
                "query_retained"
                | "task_claimed"
                | "task_backed_off"
                | "signal_reinforced"
                | "signal_contradicted"
                | "signal_decayed",
            ) => {
                data.as_object().ok_or("journal data must be an object")?;
            }
            Some(_) => return Err("team journal kind is unsupported".into()),
            None => return Err("team journal kind is absent".into()),
        }
    }
    if pending_call.is_some() || !saw_completion || !saw_artifact {
        return Err("team journal lacks a completed tool pair or artifact evidence".into());
    }
    Ok(())
}

fn capture_human(
    capture: &Arc<CanonicalCapture>,
    labels: &mut HashMap<String, (String, String)>,
    prompt_bytes: &[u8],
    decision_receipt_bytes: &[u8],
) -> Result<String, Box<dyn Error>> {
    let id = "scripted-deterministic-test-human";
    let adapter = HumanConsoleCaptureAdapter::new(
        Arc::clone(capture),
        ProducerIdentity::new(ProducerKind::Human, id, INSTANCE)?,
    )?;
    labels.insert(
        format!("human\0{id}\0{INSTANCE}"),
        (
            "Scripted deterministic test-human authority fixture".into(),
            "sentinel".into(),
        ),
    );
    let receipts = adapter.record_scripted_fixture(
        "scripted-test-human-ratification",
        "frozen-evidence-review",
        Some("ratification-task"),
        Some(CONTEXT),
        prompt_bytes,
        decision_receipt_bytes,
        CaptureParent::Root,
    )?;
    Ok(receipts[1].event_id().to_owned())
}

#[allow(clippy::too_many_lines)] // Frozen packet, review, and decision are one audited transaction.
fn ratify(
    restricted: &Path,
    pre_decision_bytes: &[u8],
    pre_decision_event_count: usize,
    source_bindings: &[Value],
) -> Result<RatificationArtifacts, Box<dyn Error>> {
    let pre_decision_digest = content_digest(pre_decision_bytes);
    let candidate_value = json!({
        "eventCount": pre_decision_event_count.to_string(),
        "preDecisionCaptureDigest": pre_decision_digest,
        "runId": RUN_ID,
        "schemaVersion": "operational-lifeline-review-candidate/1",
        "sources": source_bindings,
    });
    let candidate_bytes = canonical_value(&candidate_value)?;
    let candidate_json = String::from_utf8(candidate_bytes.clone())?;
    let published = a2a::Artifact {
        artifact_id: "lifeline-candidate".into(),
        name: Some("lifeline-candidate.json".into()),
        description: None,
        parts: vec![a2a::Part::text(candidate_json).with_media_type("application/json")],
        metadata: None,
        extensions: None,
    };
    let canonical_json = String::from_utf8(canonical_value(&serde_json::to_value(&published)?)?)?;
    let artifact = ReviewArtifact {
        name: "lifeline-candidate.json".into(),
        media_type: "application/json".into(),
        digest: content_digest(canonical_json.as_bytes()),
        canonical_json,
    };
    let artifact_set_bytes = canonical_value(&serde_json::to_value(vec![published])?)?;
    let artifact_set_digest = content_digest(&artifact_set_bytes);
    let evidence = vec![pre_decision_digest.clone()];
    let evidence_hashes = evidence
        .iter()
        .map(|digest| content_digest(digest.as_bytes()))
        .collect();
    let packet_input = ReviewPacketInput {
        task_id: "ratification-task".into(),
        tenant_id: "lifeline-tenant".into(),
        generation: 1,
        task_revision: 1,
        authorization_policy_id: "scripted-fixture-no-live-authorization".into(),
        authorization_policy_revision: 1,
        authorization_policy_digest: content_digest(b"scripted-fixture-no-live-authorization-v1"),
        principal_scope: content_digest(b"scripted-deterministic-test-human"),
        authentication_method: "scripted-deterministic-test-human".into(),
        context_id: CONTEXT.into(),
        request_digest: content_digest(&candidate_bytes),
        idempotency_key_digest: content_digest(b"scripted-fixture-packet"),
        ratification_key_generation: content_digest(b"scripted-fixture-ratification-key-1"),
        checkpoint: "frozen pre-decision operational evidence prefix".into(),
        checkpoint_hash: content_digest(b"frozen pre-decision operational evidence prefix"),
        completion_policy_id: "scripted-fixture-projection".into(),
        completion_policy_version: 1,
        completion_policy_hash: content_digest(b"scripted-fixture-projection-v1"),
        evidence_snapshot_hash: pre_decision_digest.clone(),
        artifact_set_digest,
        evidence,
        evidence_hashes,
        artifacts: vec![artifact],
        approved_task_digest: content_digest(&candidate_bytes),
        approved_result_digest: content_digest(&artifact_set_bytes),
        approved_transcript_digest: content_digest(pre_decision_bytes),
        uncertainty_summary: "Scripted deterministic test-human fixture; no authenticated human, live authorization, or real action authority.".into(),
        created_at_millis: 1_700_000_000_000,
    };
    let ledger = RatificationLedger::open(restricted.join("ratification.sqlite3"), [0x27; 32])?;
    let packet = ledger.freeze_packet(packet_input)?;
    let account = "scripted-deterministic-test-human";
    let scope = content_digest(b"scripted-deterministic-test-human");
    let review = ledger.acknowledge_review(ReviewAcknowledgement {
        tenant_id: packet.tenant_id.clone(),
        task_id: packet.task_id.clone(),
        generation: packet.generation,
        account_id: account.into(),
        authorization_policy_id: packet.authorization_policy_id.clone(),
        authorization_policy_revision: packet.authorization_policy_revision,
        authorization_policy_digest: packet.authorization_policy_digest.clone(),
        principal_scope: scope.clone(),
        authentication_method: "scripted-deterministic-test-human".into(),
        context_id: packet.context_id.clone(),
        request_digest: packet.request_digest.clone(),
        ratification_key_generation: packet.ratification_key_generation.clone(),
        expected_revision: 0,
        checkpoint_hash: packet.checkpoint_hash.clone(),
        packet_hash: packet.packet_hash.clone(),
        evidence_hashes: packet.evidence_hashes.clone(),
        artifact_hashes: packet
            .artifacts
            .iter()
            .map(|artifact| artifact.digest.clone())
            .collect(),
        artifact_manifest_digest: packet.artifact_set_digest.clone(),
        uncertainty_acknowledged: true,
        idempotency_key: "review-frozen-evidence".into(),
        reviewed_at_millis: 1_700_000_000_001,
    })?;
    let decision = ledger.decide(RatificationCommand {
        tenant_id: packet.tenant_id.clone(),
        task_id: packet.task_id.clone(),
        generation: packet.generation,
        account_id: account.into(),
        authorization_policy_id: packet.authorization_policy_id.clone(),
        authorization_policy_revision: packet.authorization_policy_revision,
        authorization_policy_digest: packet.authorization_policy_digest.clone(),
        principal_scope: scope,
        authentication_method: "scripted-deterministic-test-human".into(),
        context_id: packet.context_id.clone(),
        request_digest: packet.request_digest.clone(),
        ratification_key_generation: packet.ratification_key_generation.clone(),
        expected_revision: 1,
        checkpoint_hash: packet.checkpoint_hash.clone(),
        packet_hash: packet.packet_hash.clone(),
        artifact_manifest_digest: packet.artifact_set_digest.clone(),
        idempotency_key: "approve-frozen-evidence".into(),
        decision: HumanDecision::Approve,
        rationale:
            "Scripted test-human fixture approves only the exact frozen pre-decision candidate."
                .into(),
        decided_at_millis: 1_700_000_000_002,
    })?;
    if !ledger.verify_receipt(&review) || !ledger.verify_receipt(&decision) {
        return Err("ratification receipt verification failed".into());
    }
    let packet_bytes = canonical_value(&serde_json::to_value(&packet)?)?;
    let review_bytes = canonical_value(&serde_json::to_value(&review)?)?;
    let decision_bytes = canonical_value(&serde_json::to_value(&decision)?)?;
    write_private(&restricted.join("review-packet.json"), &packet_bytes)?;
    write_private(&restricted.join("review-receipt.json"), &review_bytes)?;
    write_private(&restricted.join("decision-receipt.json"), &decision_bytes)?;
    let prompt_bytes = canonical_value(&json!({
        "packetHash": packet.packet_hash,
        "reviewReceiptHash": review.receipt_hash,
        "schemaVersion": "operational-lifeline-scripted-review-prompt/1"
    }))?;
    let manifest = json!({
        "authenticated": false,
        "authenticationMethod": "scripted-deterministic-test-human",
        "authorityKind": "scripted-deterministic-test-human-authority-fixture",
        "candidatePublicBeforeDecision": false,
        "decision": "approve",
        "decisionReceiptHash": decision.receipt_hash,
        "packetHash": packet.packet_hash,
        "preDecisionCaptureDigest": pre_decision_digest,
        "preDecisionEventCount": pre_decision_event_count.to_string(),
        "reviewReceiptHash": review.receipt_hash,
    });
    drop(ledger);
    for path in [
        restricted.join("ratification.sqlite3"),
        restricted.join("ratification.sqlite3-wal"),
        restricted.join("ratification.sqlite3-shm"),
    ] {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(RatificationArtifacts {
        manifest,
        decision_receipt_bytes: decision_bytes,
        prompt_bytes,
    })
}

fn actors(
    labels: &HashMap<String, (String, String)>,
) -> Result<(OperationalActorManifest, Vec<u8>), Box<dyn Error>> {
    let mut actors = labels
        .iter()
        .map(|(key, (display, site))| {
            let mut parts = key.split('\0');
            let kind = match parts.next().unwrap() {
                "a2a" => ProducerKind::A2a,
                "artifact" => ProducerKind::Artifact,
                "human" => ProducerKind::Human,
                "smesh" => ProducerKind::Smesh,
                "tool" => ProducerKind::Tool,
                _ => unreachable!(),
            };
            let id = parts.next().unwrap().to_owned();
            let instance_id = parts.next().unwrap().to_owned();
            OperationalActor {
                actor_id: format!("actor-{}-{}", kind_name(kind), id),
                display_name: display.clone(),
                producer: OperationalProducer {
                    id,
                    instance_id,
                    kind,
                },
                site_id: site.clone(),
                visibility: OperationalVisibility::Visible,
            }
        })
        .collect::<Vec<_>>();
    actors.sort_by_key(|actor| {
        format!(
            "{}\0{}\0{}",
            kind_name(actor.producer.kind),
            actor.producer.id,
            actor.producer.instance_id
        )
    });
    let manifest = OperationalActorManifest {
        actors,
        schema_version: "operational-observatory-actors/1".into(),
        sites: GATEWAYS
            .into_iter()
            .map(|(id, name)| OperationalSite {
                display_name: name.into(),
                site_id: id.into(),
            })
            .collect(),
    };
    let bytes = canonical_value(&serde_json::to_value(&manifest)?)?;
    Ok((manifest, bytes))
}

fn editorial(causal: &[CausalSourceEvent]) -> OperationalEditorialOverlay {
    let mut entries = causal
        .iter()
        .filter(|event| {
            let id = &event.event.interaction_id;
            matches!(
                id.as_str(),
                "event-5"
                    | "event-6"
                    | "event-8"
                    | "event-11"
                    | "event-12"
                    | "event-13"
                    | "event-16"
                    | "scripted-test-human-ratification"
            )
        })
        .map(|event| EditorialEntry {
            cue: EditorialCue::Focus,
            event_id: event.event.event_id.clone(),
            narration: format!("Captured source event: {}.", event.event.interaction_id),
        })
        .collect::<Vec<_>>();
    entries.sort_by(|a, b| a.event_id.cmp(&b.event_id));
    OperationalEditorialOverlay {
        entries,
        schema_version: "operational-observatory-editorial/1".into(),
    }
}

struct SanitizedPackage {
    public_package: Vec<u8>,
    public_manifests: Vec<Value>,
    restricted_manifests: Vec<Value>,
    action_logs: Vec<Value>,
}

fn sanitize_package(
    package: &[u8],
    receipt: &ProjectionReceipt,
) -> Result<SanitizedPackage, Box<dyn Error>> {
    let mut public = Vec::new();
    let mut public_manifests = Vec::new();
    let mut restricted_manifests = Vec::new();
    let mut logs = Vec::new();
    for (index, line) in std::str::from_utf8(package)?.lines().enumerate() {
        let value: Value = serde_json::from_str(line)?;
        let mut pointers = Vec::new();
        collect_pointers(&value, "", false, &mut pointers);
        pointers.sort();
        pointers.dedup();
        let rules = pointers
            .into_iter()
            .map(|pointer| RedactionRule {
                pointer,
                class: DataClass::Public,
                action: RedactionAction::Keep,
                stable_identifier: false,
                fictional_provenance: Some("captured:lifeline-loopback".into()),
            })
            .collect();
        let policy =
            PrivacyPolicy::new_versioned(format!("lifeline-public-{index}"), 1, "seed-47", rules)?;
        let sanitized = sanitize_public_trace_with_receipts(
            line.as_bytes(),
            RUN_ID,
            RunHmacKey::new([0x47; 32]),
            &policy,
            vec![receipt.clone()],
        )?;
        verify_sanitized_trace(
            &sanitized,
            line.as_bytes(),
            RUN_ID,
            RunHmacKey::new([0x47; 32]),
            &policy,
            vec![receipt.clone()],
        )?;
        public.extend_from_slice(&sanitized.public_bytes);
        public.push(b'\n');
        public_manifests.push(serde_json::to_value(sanitized.public_manifest)?);
        restricted_manifests.push(serde_json::to_value(sanitized.restricted_manifest)?);
        logs.push(serde_json::from_slice(&sanitized.action_log_bytes)?);
    }
    Ok(SanitizedPackage {
        public_package: public,
        public_manifests,
        restricted_manifests,
        action_logs: logs,
    })
}

fn collect_pointers(value: &Value, pointer: &str, object_member: bool, output: &mut Vec<String>) {
    if object_member || !matches!(value, Value::Object(_) | Value::Array(_)) {
        output.push(pointer.to_owned());
    }
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let escaped = key.replace('~', "~0").replace('/', "~1");
                collect_pointers(child, &format!("{pointer}/{escaped}"), true, output);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                collect_pointers(child, &format!("{pointer}/{index}"), false, output);
            }
        }
        _ => {}
    }
}

fn source_binding(schema: &str, adapter: &str, _bytes: &[u8]) -> Value {
    json!({
        "adapterVersion": adapter,
        "rawSourceCommitment": null,
        "restriction": "raw sources are ephemeral; available source interaction, message, task, context, and replacement identities are preserved exactly, unavailable identities remain null, and the frozen canonical pre-decision capture is the deterministic authority",
        "schemaVersion": schema
    })
}
fn adapter_version(kind: ProducerKind) -> &'static str {
    match kind {
        ProducerKind::A2a => "lifeline-failure-adapter/1",
        ProducerKind::Smesh => "lifeline-runtime-trace-adapter/1",
        ProducerKind::Tool | ProducerKind::Artifact => "lifeline-team-journal-adapter/1",
        ProducerKind::Human => "human-ratification-adapter/1",
    }
}
fn kind_name(kind: ProducerKind) -> &'static str {
    match kind {
        ProducerKind::A2a => "a2a",
        ProducerKind::Smesh => "smesh",
        ProducerKind::Tool => "tool",
        ProducerKind::Artifact => "artifact",
        ProducerKind::Human => "human",
    }
}
fn canonical_value(value: &Value) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(serde_json::to_vec(&sort_value(value))?)
}
fn sort_value(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(sort_value).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, value)| (key.clone(), sort_value(value)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        other => other.clone(),
    }
}
fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > limit as u64 {
        return Err("source is not a bounded regular file".into());
    }
    Ok(std::fs::read(path)?)
}
fn write_public(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    std::fs::write(path, bytes)?;
    Ok(())
}
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn set_private_dir(path: &Path) -> Result<(), Box<dyn Error>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(sequence: u64) -> Value {
        json!({
            "data": {"context_id":"context","organization":"atlas","role":"operator","seed":47,"task_id":"task","tool_id":"atlas-tool"},
            "kind": "tool_called",
            "schemaVersion": "lifeline-team-journal/1",
            "sequence": sequence,
        })
    }

    fn completion(sequence: u64) -> Value {
        json!({
            "data": {"context_id":"context","dataset_digest":format!("sha256:{}", "a".repeat(64)),"organization":"atlas","record_count":3,"role":"operator","task_id":"task","tool_id":"atlas-tool"},
            "kind": "tool_completed",
            "schemaVersion": "lifeline-team-journal/1",
            "sequence": sequence,
        })
    }

    fn candidate(sequence: u64) -> Value {
        json!({
            "data": {"bytes":12,"context_id":"context","digest":format!("sha256:{}", "b".repeat(64)),"media_type":"application/json","name":"candidate.json","organization":"atlas","role":"operator","task_id":"task"},
            "kind": "candidate_built",
            "schemaVersion": "lifeline-team-journal/1",
            "sequence": sequence,
        })
    }

    fn journal(values: &[Value]) -> Vec<u8> {
        let mut bytes = values
            .iter()
            .map(|value| canonical_value(value).unwrap())
            .collect::<Vec<_>>()
            .join(&b'\n');
        bytes.push(b'\n');
        bytes
    }

    fn capture(values: &[Value]) -> Result<smesh_a2a::CaptureStream, Box<dyn Error>> {
        let collector = Arc::new(CanonicalCapture::new("journal-test", 16)?);
        capture_team_journal(
            &collector,
            "atlas",
            "atlas-primary",
            &journal(values),
            &mut HashMap::new(),
        )?;
        Ok(collector.snapshot()?)
    }

    #[test]
    fn observed_team_journal_requires_one_ordered_matching_completion() {
        let mut duplicate = vec![call(1), completion(2), completion(3), candidate(4)];
        let mut mismatched = vec![call(1), completion(2), candidate(3)];
        mismatched[1]["data"]["tool_id"] = "other-tool".into();
        let mut unknown = vec![call(1), completion(2), candidate(3)];
        unknown[1]["unknown"] = true.into();
        let mut invented_kind = call(1);
        invented_kind["kind"] = "invented".into();
        let cases = vec![
            vec![call(1), candidate(2)],
            std::mem::take(&mut duplicate),
            vec![completion(1), call(2), candidate(3)],
            mismatched,
            unknown,
            vec![invented_kind, call(2), completion(3), candidate(4)],
            vec![call(1), completion(3), candidate(4)],
        ];
        for values in cases {
            assert!(
                capture(&values).is_err(),
                "accepted malformed observed journal"
            );
        }
    }

    #[test]
    fn observed_team_journal_preserves_distinct_call_and_completion_markers() {
        let call_record = call(1);
        let completion_record = completion(2);
        let stream =
            capture(&[call_record.clone(), completion_record.clone(), candidate(3)]).unwrap();
        let tools = stream
            .events
            .iter()
            .filter(|event| {
                matches!(
                    event.kind,
                    smesh_a2a::CaptureKind::ToolCall | smesh_a2a::CaptureKind::ToolResult
                )
            })
            .collect::<Vec<_>>();
        let call_marker = canonical_value(&json!({"adapterVersion":"lifeline-team-journal-adapter/1","observedKind":"tool_called","schemaVersion":"lifeline-team-journal/1","sourceData":call_record["data"].clone(),"sourceSequence":"1"})).unwrap();
        let result_marker = canonical_value(&json!({"adapterVersion":"lifeline-team-journal-adapter/1","observedKind":"tool_completed","schemaVersion":"lifeline-team-journal/1","sourceData":completion_record["data"].clone(),"sourceSequence":"2"})).unwrap();
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].content.digest, content_digest(&call_marker));
        assert_eq!(tools[1].content.digest, content_digest(&result_marker));
        assert_ne!(tools[0].content.digest, tools[1].content.digest);
    }
}
