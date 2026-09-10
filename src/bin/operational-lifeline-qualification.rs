use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;
use std::process::{ExitCode, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use smesh_a2a::auth::{
    AuthState, AuthenticationError, BearerVerifier, PresentedBearer, Principal, PrincipalLimits,
};
use smesh_a2a::lifeline_acceptance::{
    AcceptancePlane, DenyEffectBroker, EffectClass, canonical_criteria, criteria_evidence_digest,
    evaluate_operational_lifeline,
};
use smesh_a2a::owned_temp::OwnedTempDir;
use smesh_a2a::{
    A2aCaptureAdapter, ArtifactClassification, AuthorizationPolicy, CanonicalCapture,
    CaptureGapReason, CaptureKind, CaptureParent, CausalMerger, CausalSourceEvent, DataClass,
    DurableLoopbackEndpoint, GatewayConfig, HumanDecision, HybridLogicalClock, InjectedClock,
    LifelineTopologyManifest, MergeLimits, MissingParentPolicy, PrivacyPolicy, ProducerIdentity,
    ProducerKind, RatificationCommand, RatificationLedger, RedactionAction, RedactionRule,
    ReplaySealInput, ReviewAcknowledgement, ReviewArtifact, ReviewPacketInput, RunHmacKey,
    SqliteTaskStore, build_authorized_durable_loopback_gateway_with_ratification_and_telemetry,
    capture_causal_source_jsonl, sanitize_public_trace, verify_operational_projection,
    verify_replay_receipt, verify_sealed_replay,
};
use tower::ServiceExt as _;

const RUN_ID: &str = "lifeline-operational-0047";
const BROWSER_TIMEOUT_SECS: u64 = 90;
const ARTIFACTS: [&str; 18] = [
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

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(1)
        }
    }
}

async fn run() -> Result<(), &'static str> {
    if let Some(error) = unsupported_platform_error() {
        return Err(error);
    }
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.len() != 4 {
        return Err(
            "usage: operational-lifeline-qualification <repo> <generation-a> <generation-b> <new-output.json>",
        );
    }
    let repo_path = Path::new(&args[0])
        .canonicalize()
        .map_err(|_| "repository path invalid")?;
    let repo = repo_path.as_path();
    let first_path = Path::new(&args[1])
        .canonicalize()
        .map_err(|_| "generation A path invalid")?;
    let first = first_path.as_path();
    let second_path = Path::new(&args[2])
        .canonicalize()
        .map_err(|_| "generation B path invalid")?;
    let second = second_path.as_path();
    let output = Path::new(&args[3]);
    if output.exists() || output.symlink_metadata().is_ok() {
        return Err("qualification output exists");
    }

    let mut facts = Vec::<(&str, Value)>::new();
    facts.push(("m3-20-ac4", topology_probe(repo).await?));
    facts.push(("m3-23-ac2", capture_pair_probe()?));
    let (missing, permutations, tamper) = replay_probes(repo, first)?;
    facts.push(("m3-23-ac3", missing));
    facts.push(("m3-24-ac1", permutations));
    facts.push(("m3-24-ac3", tamper));
    let (privacy, deterministic) = privacy_probes()?;
    facts.push(("m3-25-ac2", privacy));
    facts.push(("m3-25-ac3", deterministic));
    let (amendment, unauthorized) = ratification_probes().await?;
    facts.push(("m3-27-ac3", amendment));
    facts.push(("m3-27-ac4", unauthorized));
    facts.push(("m3-28-ac3", invalid_projection_probe(first)?));
    let force_fresh_browser_hang = first == second
        && std::env::var("SMESH_QUALIFICATION_FORCE_FRESH_BROWSER_HANG")
            .is_ok_and(|value| value == "1");
    let browser = browser_probe(repo, force_fresh_browser_hang)?;
    facts.push(("m3-28-ac4", browser["evidence"].clone()));
    facts.push(("m3-29-ac2", missing_diagnostic_probe(first)?));
    facts.push(("m3-29-ac3", reproduction_probe(first, second)?));
    let rust_synthetic_rejected = synthetic_probe(first)?;
    let browser_synthetic_rejected = browser["evidence"]["syntheticRejected"] == true;
    if !rust_synthetic_rejected || !browser_synthetic_rejected {
        return Err("synthetic fixture accepted");
    }
    facts.push(("m3-29-ac4", json!({"browserSyntheticRejected":true,"completeArtifactSet":true,"eventCount":"46","profileMismatch":true,"rustSyntheticRejected":true,"semanticProfileReached":true})));

    let expected = canonical_criteria()
        .map_err(|_| "criteria registry invalid")?
        .into_iter()
        .filter(|criterion| criterion.plane == AcceptancePlane::Qualification)
        .map(|criterion| criterion.id)
        .collect::<Vec<_>>();
    let actual = facts
        .iter()
        .map(|(id, _)| (*id).to_owned())
        .collect::<Vec<_>>();
    if actual != expected || actual.iter().collect::<BTreeSet<_>>().len() != 14 {
        return Err("qualification probe set mismatch");
    }
    let probes = facts.into_iter().map(|(id, fact)| {
        let bytes = serde_json::to_vec(&fact).expect("probe fact serialization");
        json!({"criterionId":id,"evidence":[{"artifact":format!("qualification-probe/{id}"),"artifactDigest":criteria_evidence_digest("operational-lifeline-qualification-evidence",&bytes),"eventIds":[format!("probe-{id}")],"selector":"/facts"}],"facts":fact,"status":"pass"})
    }).collect::<Vec<_>>();
    let document = json!({"probes":probes,"runId":RUN_ID,"schemaVersion":"operational-lifeline-qualification-probes/1","seed":"47"});
    let bytes = serde_json::to_vec(&document).map_err(|_| "qualification encoding failed")?;
    write_new(output, &bytes)
}

#[cfg(target_os = "linux")]
fn unsupported_platform_error() -> Option<&'static str> {
    None
}

#[cfg(not(target_os = "linux"))]
fn unsupported_platform_error() -> Option<&'static str> {
    Some(
        "operational qualification requires Linux bubblewrap, strace, and process groups; no child was launched",
    )
}

async fn topology_probe(repo: &Path) -> Result<Value, &'static str> {
    let text = std::fs::read_to_string(repo.join("deploy/lifeline-topology.json"))
        .map_err(|_| "topology read failed")?;
    let manifest = LifelineTopologyManifest::from_json(&text)
        .map_err(|_| "topology invalid")?
        .with_ephemeral_loopback_ports();
    let topology = tokio::time::timeout(Duration::from_secs(10), manifest.launch())
        .await
        .map_err(|_| "topology launch timeout")?
        .map_err(|_| "topology launch failed")?;
    let endpoints = topology.endpoints().len();
    tokio::time::timeout(Duration::from_secs(5), topology.shutdown())
        .await
        .map_err(|_| "topology shutdown timeout")?
        .map_err(|_| "topology shutdown failed")?;
    if endpoints != 6 {
        return Err("topology listener count mismatch");
    }
    let authority = effect_authority_probe()?;
    Ok(
        json!({"attemptKinds":["liveEffect"],"blockedAttemptCount":authority.0,"bounded":true,"effectBoundaryDenyByDefault":true,"effectClassesAudited":["callback","medical","messaging","model","outreach","quarantine","remoteTool","shipping","url"],"listeners":"6","loopbackOnly":true,"shutdownReaped":true,"successfulRealActions":authority.1}),
    )
}

fn effect_authority_probe() -> Result<(&'static str, &'static str), &'static str> {
    let broker = DenyEffectBroker;
    let mut transports_invoked = 0_u8;
    let denied = EffectClass::ALL
        .into_iter()
        .filter(|class| broker.attempt(*class, || transports_invoked += 1).is_err())
        .count();
    if transports_invoked != 0 || denied != 9 {
        return Err("real-action authority boundary failed");
    }
    Ok(("9", "0"))
}

fn capture_pair_probe() -> Result<Value, &'static str> {
    let capture = Arc::new(
        CanonicalCapture::new("qualification-capture", 4).map_err(|_| "capture create failed")?,
    );
    let sender = A2aCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::A2a, "director", "probe")
            .map_err(|_| "identity failed")?,
    )
    .map_err(|_| "adapter failed")?;
    let receiver = A2aCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::A2a, "gateway", "probe")
            .map_err(|_| "identity failed")?,
    )
    .map_err(|_| "adapter failed")?;
    let sent = sender
        .send(
            "shared-interaction",
            "gateway",
            Some("task"),
            Some("context"),
            b"bounded fictional payload",
            CaptureParent::Root,
        )
        .map_err(|_| "send capture failed")?;
    receiver
        .receive(
            "shared-interaction",
            "director",
            Some("task"),
            Some("context"),
            b"bounded fictional payload",
            CaptureParent::Event(sent.event_id().to_owned()),
        )
        .map_err(|_| "receive capture failed")?;
    let events = capture
        .snapshot()
        .map_err(|_| "capture snapshot failed")?
        .events;
    if events.len() != 2
        || events[0].kind != CaptureKind::A2aSend
        || events[1].kind != CaptureKind::A2aReceive
        || events[0].interaction_id != events[1].interaction_id
        || events[1].parent != CaptureParent::Event(events[0].event_id.clone())
        || events[0].content != events[1].content
    {
        return Err("send receive identity mismatch");
    }
    Ok(
        json!({"eventCount":"2","interactionBound":true,"parentBound":true,"rawPayloadRetained":false}),
    )
}

fn replay_probes(repo: &Path, _package: &Path) -> Result<(Value, Value, Value), &'static str> {
    let a = std::fs::read(repo.join("demo/fixtures/full-matrix-replay-v1/source-a.jsonl"))
        .map_err(|_| "replay source read failed")?;
    let b = std::fs::read(repo.join("demo/fixtures/full-matrix-replay-v1/source-b.jsonl"))
        .map_err(|_| "replay source read failed")?;
    let merge = |order: [&[u8]; 2], policy| -> Result<Vec<u8>, &'static str> {
        let mut m = CausalMerger::new("cross-language-vector", MergeLimits::default(), policy)
            .map_err(|_| "merger create failed")?;
        for source in order {
            m.ingest_source_jsonl(source).map_err(|_| "ingest failed")?;
        }
        Ok(m.finalize(ReplaySealInput::empty())
            .map_err(|_| "finalize failed")?
            .bundle_jsonl()
            .to_vec())
    };
    let left = merge([&a, &b], MissingParentPolicy::Reject)?;
    let right = merge([&b, &a], MissingParentPolicy::Reject)?;
    if left != right {
        return Err("ingestion permutation mismatch");
    }
    let mut strict = CausalMerger::new(
        "cross-language-vector",
        MergeLimits::default(),
        MissingParentPolicy::Reject,
    )
    .map_err(|_| "merger create failed")?;
    strict
        .ingest_source_jsonl(&b)
        .map_err(|_| "ingest failed")?;
    let strict_rejected = matches!(
        strict.finalize(ReplaySealInput::empty()),
        Err(smesh_a2a::ReplayError::MissingParents(_))
    );
    let mut recording = CausalMerger::new(
        "cross-language-vector",
        MergeLimits::default(),
        MissingParentPolicy::Record,
    )
    .map_err(|_| "merger create failed")?;
    recording
        .ingest_source_jsonl(&b)
        .map_err(|_| "ingest failed")?;
    let recorded = recording
        .finalize(ReplaySealInput::empty())
        .map_err(|_| "record missing failed")?;
    let explicit = String::from_utf8_lossy(recorded.bundle_jsonl())
        .contains("\"recordType\":\"missingParent\"");
    let capture_gap = explicit_capture_gap_probe()?;
    if !strict_rejected || !explicit || !capture_gap {
        return Err("gap or missing parent behavior mismatch");
    }
    let original_event = seal_probe_event(b"canonical-causal-value-a")?;
    let replacement_commitment = seal_probe_event(b"canonical-causal-value-b")?;
    let mut tampered_event = original_event.clone();
    tampered_event.content = replacement_commitment.content;
    tampered_event.event_id = replacement_commitment.event_id;
    let original = seal_probe_event_bundle(original_event)?;
    let changed = seal_probe_event_bundle(tampered_event)?;
    let original_receipt = verify_sealed_replay(original.bundle_jsonl())
        .map_err(|_| "original semantic replay invalid")?;
    let changed_receipt = verify_sealed_replay(changed.bundle_jsonl())
        .map_err(|_| "tampered semantic replay invalid")?;
    let original_receipt_and_pin_rejected = verify_replay_receipt(
        changed.bundle_jsonl(),
        original.receipt_json(),
        Some(&original_receipt.run_seal),
    )
    .is_err();
    if original_receipt.run_seal == changed_receipt.run_seal
        || original_receipt.receipt_digest == changed_receipt.receipt_digest
        || original.bundle_jsonl() == changed.bundle_jsonl()
        || !original_receipt_and_pin_rejected
    {
        return Err("semantic tamper did not change seal");
    }
    Ok((
        json!({"captureGapRecorded":true,"missingParentRecorded":true,"strictTypedRejection":true}),
        json!({"byteIdentical":true,"orders":"2"}),
        json!({"attackerControlledChainRebound":true,"derivedReceiptChanged":true,"derivedSealChanged":true,"originalReceiptAndPinRejected":true,"originalReceiptRejected":true,"originalVerified":true,"structurallyValidTamper":true,"tamperedReplayVerified":true}),
    ))
}

fn explicit_capture_gap_probe() -> Result<bool, &'static str> {
    let capture = Arc::new(
        CanonicalCapture::new("qualification-gap", 2).map_err(|_| "gap capture create failed")?,
    );
    let adapter = A2aCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::A2a, "gap-producer", "probe")
            .map_err(|_| "gap identity failed")?,
    )
    .map_err(|_| "gap adapter failed")?;
    let expected = smesh_a2a::content_digest(b"qualification-missing-parent");
    adapter
        .send(
            "gap-interaction",
            "gap-peer",
            None,
            None,
            b"gap payload",
            CaptureParent::Missing {
                expected_event_id: expected.clone(),
                reason: CaptureGapReason::CaptureStartedLate,
            },
        )
        .map_err(|_| "gap capture failed")?;
    let events = capture
        .snapshot()
        .map_err(|_| "gap snapshot failed")?
        .events;
    Ok(events.len() == 1
        && matches!(&events[0].parent,
        CaptureParent::Missing { expected_event_id, reason: CaptureGapReason::CaptureStartedLate }
        if expected_event_id == &expected))
}

fn seal_probe_event(payload: &[u8]) -> Result<smesh_a2a::CaptureEvent, &'static str> {
    let capture = Arc::new(
        CanonicalCapture::new("qualification-seal", 2).map_err(|_| "seal capture create failed")?,
    );
    let adapter = A2aCaptureAdapter::new(
        Arc::clone(&capture),
        ProducerIdentity::new(ProducerKind::A2a, "seal-producer", "probe")
            .map_err(|_| "seal identity failed")?,
    )
    .map_err(|_| "seal adapter failed")?;
    adapter
        .send(
            "seal-interaction",
            "seal-peer",
            None,
            None,
            payload,
            CaptureParent::Root,
        )
        .map_err(|_| "seal capture failed")?;
    let event = capture
        .snapshot()
        .map_err(|_| "seal snapshot failed")?
        .events
        .into_iter()
        .next()
        .ok_or("seal event absent")?;
    Ok(event)
}

fn seal_probe_event_bundle(
    event: smesh_a2a::CaptureEvent,
) -> Result<smesh_a2a::SealedReplay, &'static str> {
    let causal = CausalSourceEvent::new(
        event,
        HybridLogicalClock {
            physical_ns: 47,
            logical: 0,
        },
        0,
        None,
    )
    .map_err(|_| "seal causal event failed")?;
    let source = capture_causal_source_jsonl("qualification-seal", &[causal])
        .map_err(|_| "seal source failed")?;
    let mut merger = CausalMerger::new(
        "qualification-seal",
        MergeLimits::default(),
        MissingParentPolicy::Reject,
    )
    .map_err(|_| "seal merger failed")?;
    merger
        .ingest_source_jsonl(&source)
        .map_err(|_| "seal ingest failed")?;
    merger
        .finalize(ReplaySealInput::empty())
        .map_err(|_| "seal finalize failed")
}

fn privacy_probes() -> Result<(Value, Value), &'static str> {
    const PII: &[u8] = b"planted-person";
    const PHI: &[u8] = b"planted-diagnosis";
    const SECRET: &[u8] = b"planted-secret";
    let source=br#"{"public":"fictional","pii":"planted-person","phi":"planted-diagnosis","secret":"planted-secret"}"#;
    let equivalent=br#"{"secret":"planted-secret","phi":"planted-diagnosis","pii":"planted-person","public":"fictional"}"#;
    let changed=br#"{"public":"changed-control","pii":"planted-person","phi":"planted-diagnosis","secret":"planted-secret"}"#;
    let rule = |pointer: &str, class, action, provenance| RedactionRule {
        pointer: pointer.into(),
        class,
        action,
        stable_identifier: false,
        fictional_provenance: provenance,
    };
    let policy = PrivacyPolicy::new_versioned(
        "qualification-policy",
        1,
        "qualification-key",
        vec![
            rule(
                "/public",
                DataClass::Public,
                RedactionAction::Keep,
                Some("fixture:qualification".into()),
            ),
            rule("/pii", DataClass::Pii, RedactionAction::Placeholder, None),
            rule("/phi", DataClass::Phi, RedactionAction::Placeholder, None),
            rule("/secret", DataClass::Secret, RedactionAction::Drop, None),
        ],
    )
    .map_err(|_| "privacy policy failed")?;
    let one = sanitize_public_trace(
        source,
        "qualification-run",
        RunHmacKey::new([47; 32]),
        &policy,
    )
    .map_err(|_| "privacy projection failed")?;
    let equivalent_projection = sanitize_public_trace(
        equivalent,
        "qualification-run",
        RunHmacKey::new([47; 32]),
        &policy,
    )
    .map_err(|_| "privacy equivalent projection failed")?;
    let changed_projection = sanitize_public_trace(
        changed,
        "qualification-run",
        RunHmacKey::new([47; 32]),
        &policy,
    )
    .map_err(|_| "privacy control projection failed")?;
    let public: Value =
        serde_json::from_slice(&one.public_bytes).map_err(|_| "privacy output invalid")?;
    let surfaces = [
        one.public_bytes.clone(),
        one.action_log_bytes.clone(),
        serde_json::to_vec(&one.public_manifest).map_err(|_| "public manifest encode failed")?,
        serde_json::to_vec(&one.restricted_manifest)
            .map_err(|_| "restricted manifest encode failed")?,
    ];
    let canaries_absent = surfaces.iter().all(|surface| {
        [PII, PHI, SECRET].iter().all(|canary| {
            !surface
                .windows(canary.len())
                .any(|window| window == *canary)
        })
    });
    if public.get("secret").is_some()
        || !canaries_absent
        || one.public_bytes != equivalent_projection.public_bytes
        || one.action_log_bytes != equivalent_projection.action_log_bytes
        || one.public_bytes == changed_projection.public_bytes
        || one.public_manifest.artifact.classification != ArtifactClassification::Public
    {
        return Err("privacy probe mismatch");
    }
    Ok((
        json!({"allPublicSurfacesScanned":true,"canariesAbsent":true,"classesPlanted":"3","secretDropped":true,"surfaceCount":"4"}),
        json!({"actionLogIdentical":true,"changedInputChangedOutput":true,"equivalentInputsCompared":true,"publicBytesIdentical":true}),
    ))
}

fn packet() -> ReviewPacketInput {
    let published_artifact = a2a::Artifact {
        artifact_id: "artifact-result".to_owned(),
        name: Some("result.json".to_owned()),
        description: None,
        parts: vec![a2a::Part::text("result").with_media_type("application/json")],
        metadata: None,
        extensions: None,
    };
    let canonical_json =
        serde_json::to_string(&serde_json::to_value(&published_artifact).unwrap()).unwrap();
    let artifacts = vec![ReviewArtifact {
        name: "result.json".to_owned(),
        media_type: "application/json".to_owned(),
        digest: smesh_a2a::content_digest(canonical_json.as_bytes()),
        canonical_json,
    }];
    let artifact_set_digest = smesh_a2a::content_digest(
        &serde_json::to_vec(&serde_json::to_value(vec![published_artifact]).unwrap()).unwrap(),
    );
    ReviewPacketInput {
        task_id: "task-27".to_owned(),
        tenant_id: "tenant-a".to_owned(),
        generation: 1,
        task_revision: 7,
        authorization_policy_id: "ratification-authz".to_owned(),
        authorization_policy_revision: 1,
        authorization_policy_digest: smesh_a2a::content_digest(b"ratification-authz-v1"),
        principal_scope: smesh_a2a::content_digest(b"ratifier-principal"),
        authentication_method: "bearer-jwt".to_owned(),
        context_id: "context-27".to_owned(),
        request_digest: smesh_a2a::content_digest(b"request-27"),
        idempotency_key_digest: smesh_a2a::content_digest(b"packet-27"),
        ratification_key_generation: smesh_a2a::content_digest(b"ratification-key-1"),
        checkpoint: "checkpoint".to_owned(),
        checkpoint_hash: smesh_a2a::content_digest(b"checkpoint"),
        completion_policy_id: "release-policy".to_owned(),
        completion_policy_version: 7,
        completion_policy_hash: smesh_a2a::content_digest(b"policy"),
        evidence_snapshot_hash: smesh_a2a::content_digest(b"evidence-snapshot"),
        artifact_set_digest,
        evidence: vec!["review-evidence".to_owned()],
        evidence_hashes: vec![smesh_a2a::content_digest(b"review-evidence")],
        artifacts,
        approved_task_digest: smesh_a2a::content_digest(b"approved-task"),
        approved_result_digest: smesh_a2a::content_digest(b"approved-result"),
        approved_transcript_digest: smesh_a2a::content_digest(b"approved-transcript"),
        uncertainty_summary: "One model-derived assertion remains uncertain.".to_owned(),
        created_at_millis: 1_700_000_000_000,
    }
}

#[allow(clippy::too_many_lines)]
async fn ratification_probes() -> Result<(Value, Value), &'static str> {
    let root = TempRoot::new("ratification")?;
    let authority_root = match TempRoot::new("production-ratification") {
        Ok(root) => root,
        Err(primary) => {
            return Err(if root.close().is_ok() {
                primary
            } else {
                "ratification temp creation and cleanup failed"
            });
        }
    };
    let result = ratification_probes_with_roots(&root, &authority_root).await;
    let cleanup_failed = root.close().is_err() | authority_root.close().is_err();
    match (result, cleanup_failed) {
        (Ok(value), false) => Ok(value),
        (Err(primary), false) => Err(primary),
        (Ok(_), true) => Err("ratification temp cleanup failed"),
        (Err(_), true) => Err("ratification probe and temp cleanup failed"),
    }
}

#[allow(clippy::too_many_lines)]
async fn ratification_probes_with_roots(
    root: &TempRoot,
    authority_root: &TempRoot,
) -> Result<(Value, Value), &'static str> {
    let ledger_path = root.database_path();
    let ledger =
        RatificationLedger::open(&ledger_path, [47; 32]).map_err(|_| "ledger open failed")?;
    let frozen = ledger
        .freeze_packet(packet())
        .map_err(|_| "packet freeze failed")?;
    let review = ReviewAcknowledgement {
        tenant_id: frozen.tenant_id.clone(),
        task_id: frozen.task_id.clone(),
        generation: frozen.generation,
        account_id: "ratifier".into(),
        authorization_policy_id: frozen.authorization_policy_id.clone(),
        authorization_policy_revision: frozen.authorization_policy_revision,
        authorization_policy_digest: frozen.authorization_policy_digest.clone(),
        principal_scope: frozen.principal_scope.clone(),
        authentication_method: frozen.authentication_method.clone(),
        context_id: frozen.context_id.clone(),
        request_digest: frozen.request_digest.clone(),
        ratification_key_generation: frozen.ratification_key_generation.clone(),
        expected_revision: 0,
        checkpoint_hash: frozen.checkpoint_hash.clone(),
        packet_hash: frozen.packet_hash.clone(),
        evidence_hashes: frozen.evidence_hashes.clone(),
        artifact_hashes: frozen.artifacts.iter().map(|a| a.digest.clone()).collect(),
        artifact_manifest_digest: frozen.artifact_set_digest.clone(),
        uncertainty_acknowledged: true,
        idempotency_key: "review".into(),
        reviewed_at_millis: 2,
    };
    let reviewed = ledger
        .acknowledge_review(review)
        .map_err(|_| "review failed")?;
    let command = RatificationCommand {
        tenant_id: frozen.tenant_id.clone(),
        task_id: frozen.task_id.clone(),
        generation: frozen.generation,
        account_id: "ratifier".into(),
        authorization_policy_id: frozen.authorization_policy_id.clone(),
        authorization_policy_revision: frozen.authorization_policy_revision,
        authorization_policy_digest: frozen.authorization_policy_digest.clone(),
        principal_scope: frozen.principal_scope.clone(),
        authentication_method: frozen.authentication_method.clone(),
        context_id: frozen.context_id.clone(),
        request_digest: frozen.request_digest.clone(),
        ratification_key_generation: frozen.ratification_key_generation.clone(),
        expected_revision: 1,
        checkpoint_hash: frozen.checkpoint_hash.clone(),
        packet_hash: frozen.packet_hash.clone(),
        artifact_manifest_digest: frozen.artifact_set_digest.clone(),
        idempotency_key: "amend".into(),
        decision: HumanDecision::Amend,
        rationale: "amend fictional assertion".into(),
        decided_at_millis: 3,
    };
    let amended = ledger.decide(command.clone()).map_err(|_| "amend failed")?;
    if amended.revision != 2
        || amended.previous_receipt_hash.as_deref() != Some(&reviewed.receipt_hash)
        || ledger
            .history(&frozen.tenant_id, &frozen.task_id)
            .map_err(|_| "history failed")?
            .len()
            != 2
    {
        return Err("amendment append mismatch");
    }
    let store_path = authority_root.database_path();
    let store = SqliteTaskStore::open_with_ratification_key(
        &store_path,
        16,
        zeroize::Zeroizing::new([47; 32]),
        false,
    )
    .await
    .map_err(|error| {
        eprintln!("production ratification store failed: {error}");
        "production ratification store failed"
    })?;
    let policy=AuthorizationPolicy::from_json(br#"{"schemaVersion":"smesh-authz-policy/v1","policyId":"qualification-authz","revision":1,"tenants":[{"id":"tenant-qualification","enabled":true}],"accounts":[{"id":"viewer","kind":"human","memberships":[{"tenantId":"tenant-qualification","roles":["taskViewer"]}]}],"principalBindings":[{"principal":{"issuer":"qualification","subject":"viewer"},"accountId":"viewer"}]}"#).map_err(|_|"authz policy failed")?;
    let store_probe = store.clone();
    let gateway = build_authorized_durable_loopback_gateway_with_ratification_and_telemetry(
        GatewayConfig::new("http://127.0.0.1:1", "qualification-ratification"),
        store,
        DurableLoopbackEndpoint::new(),
        InjectedClock::new(47),
        AuthState::new(Arc::new(QualificationVerifier), [47; 32]),
        Arc::new(policy),
        None,
    )
    .map_err(|_| "production ratification gateway failed")?;
    let before_count = store_probe
        .authorization_decision_count()
        .await
        .map_err(|_| "authorization count failed")?;
    let before = store_probe
        .ratification_packet("tenant-qualification", "qualification-task")
        .await
        .map_err(|_| "ratification state failed")?;
    let response = gateway
        .router()
        .oneshot(
            Request::post("/ratification/v1/tasks/qualification-task/decision")
                .header("authorization", "Bearer viewer-token")
                .header("origin", "http://127.0.0.1:1")
                .header("content-type", "application/json")
                .header(
                    "if-match",
                    format!("\"ratification-v1:{}\"", "0".repeat(64)),
                )
                .header("idempotency-key", "unauthorized-production-decision")
                .body(Body::from(
                    r#"{"decision":"approve","rationale":"unauthorized"}"#,
                ))
                .map_err(|_| "unauthorized request failed")?,
        )
        .await
        .map_err(|_| "production ratification request failed")?;
    let after = store_probe
        .ratification_packet("tenant-qualification", "qualification-task")
        .await
        .map_err(|_| "ratification state failed")?;
    let after_count = store_probe
        .authorization_decision_count()
        .await
        .map_err(|_| "authorization count failed")?;
    if response.status() != StatusCode::FORBIDDEN
        || before != after
        || before.is_some()
        || before_count != after_count
    {
        return Err("unauthorized mutation probe failed");
    }
    Ok((
        json!({"appendOnly":true,"historyLength":"2","receiptChainBound":true}),
        json!({"authorizationAuditUnchanged":true,"authorizationToLedgerAttempt":true,"historyUnchanged":true,"principalIdentityBound":true,"principalRejected":true,"receiptAbsent":true,"stateUnchanged":true}),
    ))
}

struct QualificationVerifier;

#[async_trait]
impl BearerVerifier for QualificationVerifier {
    async fn verify(&self, token: PresentedBearer<'_>) -> Result<Principal, AuthenticationError> {
        if token.as_str() != "viewer-token" {
            return Err(AuthenticationError::InvalidToken);
        }
        Principal::bearer_for_verifier(
            "qualification".into(),
            "viewer".into(),
            PrincipalLimits::default(),
        )
        .map_err(|_| AuthenticationError::InvalidToken)
    }
}

fn invalid_projection_probe(package: &Path) -> Result<Value, &'static str> {
    let original =
        std::fs::read(package.join("package.jsonl")).map_err(|_| "package read failed")?;
    let original_receipt =
        std::fs::read(package.join("receipt.json")).map_err(|_| "receipt read failed")?;
    let (bytes, receipt, input) = rebound_invalid_projection(package)?;
    if verify_operational_projection(&original, &original_receipt, &input).is_err()
        || verify_operational_projection(&bytes, &receipt, &input).is_ok()
    {
        return Err("invalid operational event accepted or baseline invalid");
    }
    Ok(
        json!({"attackerDigestsRebound":true,"eventSemanticRejection":true,"partialStatePublished":false,"structurallyValidEvent":true}),
    )
}

fn rebound_invalid_projection(package: &Path) -> Result<(Vec<u8>, Vec<u8>, String), &'static str> {
    let original =
        std::fs::read(package.join("package.jsonl")).map_err(|_| "package read failed")?;
    let mut records = original
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<Value>(line).map_err(|_| "package record invalid"))
        .collect::<Result<Vec<_>, _>>()?;
    let event = records
        .iter_mut()
        .find(|record| record["recordType"] == "event")
        .ok_or("operational event absent")?;
    event["parent"] = json!({
        "eventId": smesh_a2a::content_digest(b"attacker-controlled-absent-parent"),
        "kind": "event"
    });
    let mut bytes = Vec::new();
    for record in records {
        bytes.extend_from_slice(&serde_json::to_vec(&record).map_err(|_| "record encode failed")?);
        bytes.push(b'\n');
    }
    let receipt_path = package.join("receipt.json");
    let mut receipt_value: Value =
        serde_json::from_slice(&std::fs::read(receipt_path).map_err(|_| "receipt read failed")?)
            .map_err(|_| "receipt invalid")?;
    let input = receipt_value["inputDigest"]
        .as_str()
        .ok_or("receipt digest missing")?
        .to_owned();
    receipt_value["outputByteLength"] = bytes.len().to_string().into();
    receipt_value["outputDigest"] =
        criteria_evidence_digest("operational-observatory-output", &bytes).into();
    let receipt = serde_json::to_vec(&receipt_value).map_err(|_| "receipt encode failed")?;
    Ok((bytes, receipt, input))
}

fn browser_probe(repo: &Path, force_fresh_hang: bool) -> Result<Value, &'static str> {
    let profile = OwnedTempDir::create("smesh-qualification-browser-profile-")
        .map_err(|_| "browser profile create failed")?;
    let result = browser_probe_with_profile(repo, profile.path(), force_fresh_hang);
    match (result, profile.close()) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(_)) => Err("browser profile cleanup failed"),
        (Err(_), Err(_)) => Err("browser probe failed and profile cleanup failed"),
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_lines)] // Process and bounded pipes share one lifecycle state machine.
fn browser_probe_with_profile(
    repo: &Path,
    profile: &Path,
    force_fresh_hang: bool,
) -> Result<Value, &'static str> {
    use std::os::unix::process::CommandExt as _;
    let mut command = {
        let mut command = std::process::Command::new("bwrap");
        command.args([
            "--unshare-net",
            "--die-with-parent",
            "--dev-bind",
            "/",
            "/",
            "--proc",
            "/proc",
            "--",
            "node",
        ]);
        command
    };

    command
        .arg(repo.join("demo/operational-qualification.mjs"))
        .env("SMESH_QUALIFICATION_BROWSER_PROFILE", profile)
        .current_dir(repo.join("demo"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut owned_roots = Vec::with_capacity(2);
    if let Some(root) = std::env::var_os("SMESH_QUALIFICATION_OWNED_PROBE_ROOT") {
        owned_roots.push(root.to_string_lossy().into_owned());
    }
    owned_roots.push(profile.to_string_lossy().into_owned());
    command.env(
        "SMESH_QUALIFICATION_LIFECYCLE_OWNED_ROOTS",
        serde_json::to_string(&owned_roots).map_err(|_| "owned-root provenance encode failed")?,
    );
    if force_fresh_hang {
        command.env("SMESH_QUALIFICATION_FORCE_BROWSER_HANG", "1");
        if let Some(marker) = std::env::var_os("SMESH_QUALIFICATION_FRESH_LIFECYCLE_MARKER") {
            command.env("SMESH_QUALIFICATION_LIFECYCLE_MARKER", marker);
        }
    }
    command.process_group(0);
    let mut child = command.spawn().map_err(|_| "browser probe spawn failed")?;
    let Some(stdout_pipe) = child.stdout.take() else {
        return Err(if terminate_browser_group(&mut child).is_empty() {
            "browser stdout unavailable"
        } else {
            "browser stdout unavailable and cleanup failed"
        });
    };
    let Ok(mut stdout) = BoundedPipe::new(stdout_pipe, 128 * 1024) else {
        return Err(if terminate_browser_group(&mut child).is_empty() {
            "browser stdout nonblocking setup failed"
        } else {
            "browser stdout nonblocking setup and cleanup failed"
        });
    };
    let Some(stderr_pipe) = child.stderr.take() else {
        return Err(if terminate_browser_group(&mut child).is_empty() {
            "browser stderr unavailable"
        } else {
            "browser stderr unavailable and cleanup failed"
        });
    };
    let Ok(mut stderr) = BoundedPipe::new(stderr_pipe, 32 * 1024) else {
        return Err(if terminate_browser_group(&mut child).is_empty() {
            "browser stderr nonblocking setup failed"
        } else {
            "browser stderr nonblocking setup and cleanup failed"
        });
    };
    let timeout_ms = std::env::var("SMESH_QUALIFICATION_BROWSER_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| (50..=BROWSER_TIMEOUT_SECS * 1_000).contains(value))
        .unwrap_or(BROWSER_TIMEOUT_SECS * 1_000);
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        if stdout.drain().is_err() || stderr.drain().is_err() {
            let cleanup = terminate_browser_group(&mut child);
            let pipe_errors = finish_browser_pipes(&mut stdout, &mut stderr);
            report_browser_failure("browser pipe read failed", None, &cleanup, &stderr.retained);
            return Err(if cleanup.is_empty() && pipe_errors.is_empty() {
                "browser pipe read failed"
            } else {
                "browser pipe read and cleanup failed"
            });
        }
        let exited = match browser_child_exited(&mut child) {
            Ok(exited) => exited,
            Err(error) => {
                let cleanup = terminate_browser_group(&mut child);
                let pipe_errors = finish_browser_pipes(&mut stdout, &mut stderr);
                report_browser_failure(
                    "browser wait failed",
                    Some(&error),
                    &cleanup,
                    &stderr.retained,
                );
                return Err(if !cleanup.is_empty() || !pipe_errors.is_empty() {
                    "browser wait and cleanup failed"
                } else {
                    "browser wait failed"
                });
            }
        };
        if exited {
            let (status, cleanup) = finish_exited_browser_group(&mut child);
            let pipe_errors = finish_browser_pipes(&mut stdout, &mut stderr);
            let cleanup_failed = !cleanup.is_empty();
            for error in cleanup {
                eprintln!("browser cleanup: {error}");
            }
            for error in &pipe_errors {
                eprintln!("browser cleanup: {error}");
            }
            if cleanup_failed || !pipe_errors.is_empty() {
                return Err("browser normal-exit cleanup failed");
            }
            let status = status.map_err(|_| "browser reap failed")?;
            if !status.success() {
                print_browser_stderr(&stderr.retained);
                return Err("browser probe failed");
            }
            return serde_json::from_slice(&stdout.retained)
                .map_err(|_| "browser evidence invalid");
        }
        if Instant::now() >= deadline {
            let cleanup = terminate_browser_group(&mut child);
            let pipe_errors = finish_browser_pipes(&mut stdout, &mut stderr);
            report_browser_failure("browser probe timeout", None, &cleanup, &stderr.retained);
            return Err(if !cleanup.is_empty() || !pipe_errors.is_empty() {
                "browser probe timeout and cleanup failed"
            } else {
                "browser probe timeout"
            });
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(not(target_os = "linux"))]
fn browser_probe_with_profile(
    _repo: &Path,
    _profile: &Path,
    _force_fresh_hang: bool,
) -> Result<Value, &'static str> {
    Err("operational qualification requires Linux; browser child was not launched")
}

#[cfg(target_os = "linux")]
struct BoundedPipe<R> {
    pipe: R,
    retained: Vec<u8>,
    limit: usize,
    eof: bool,
}

#[cfg(target_os = "linux")]
impl<R: Read + std::os::fd::AsFd> BoundedPipe<R> {
    fn new(pipe: R, limit: usize) -> std::io::Result<Self> {
        let flags = rustix::fs::fcntl_getfl(pipe.as_fd())?;
        rustix::fs::fcntl_setfl(pipe.as_fd(), flags | rustix::fs::OFlags::NONBLOCK)?;
        Ok(Self {
            pipe,
            retained: Vec::new(),
            limit,
            eof: false,
        })
    }

    fn drain(&mut self) -> std::io::Result<()> {
        let mut buffer = [0_u8; 4096];
        loop {
            match self.pipe.read(&mut buffer) {
                Ok(0) => {
                    self.eof = true;
                    return Ok(());
                }
                Ok(count) => {
                    let available = self.limit.saturating_sub(self.retained.len());
                    self.retained
                        .extend_from_slice(&buffer[..count.min(available)]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn finish_browser_pipes<O: Read + std::os::fd::AsFd, E: Read + std::os::fd::AsFd>(
    stdout: &mut BoundedPipe<O>,
    stderr: &mut BoundedPipe<E>,
) -> Vec<String> {
    let deadline = Instant::now() + Duration::from_millis(250);
    let mut errors = Vec::new();
    while (!stdout.eof || !stderr.eof) && Instant::now() < deadline {
        if let Err(error) = stdout.drain() {
            errors.push(format!("stdout read failed: {error}"));
        }
        if let Err(error) = stderr.drain() {
            errors.push(format!("stderr read failed: {error}"));
        }
        if !stdout.eof || !stderr.eof {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    if !stdout.eof {
        errors.push("stdout pipe remained open after cleanup".to_owned());
    }
    if !stderr.eof {
        errors.push("stderr pipe remained open after cleanup".to_owned());
    }
    errors
}

#[cfg(target_os = "linux")]
fn print_browser_stderr(stderr: &[u8]) {
    if !stderr.is_empty() {
        let mut digest = Sha256::new();
        digest.update(b"smesh-operational-browser-stderr-v1\0");
        digest.update(stderr);
        eprintln!(
            "browser stderr captured: class=browserProbeFailure bytes={} digest=sha256:{:x}",
            stderr.len(),
            digest.finalize()
        );
    }
}

#[cfg(target_os = "linux")]
fn report_browser_failure(primary: &str, detail: Option<&str>, cleanup: &[String], stderr: &[u8]) {
    print_browser_stderr(stderr);
    match detail {
        Some(detail) => eprintln!("{primary}: {detail}"),
        None => eprintln!("{primary}"),
    }
    for error in cleanup {
        eprintln!("browser cleanup: {error}");
    }
}

#[cfg(target_os = "linux")]
fn browser_child_exited(child: &mut std::process::Child) -> Result<bool, String> {
    let pid = browser_group_pid(child.id())?;
    let options = rustix::process::WaitIdOptions::EXITED
        | rustix::process::WaitIdOptions::NOHANG
        | rustix::process::WaitIdOptions::NOWAIT;
    rustix::process::waitid(rustix::process::WaitId::Pid(pid), options)
        .map(|status| status.is_some())
        .map_err(|error| error.to_string())
}

#[cfg(target_os = "linux")]
fn finish_exited_browser_group(
    child: &mut std::process::Child,
) -> (std::io::Result<std::process::ExitStatus>, Vec<String>) {
    let mut errors = Vec::new();
    let group = browser_group_pid(child.id());
    if let Ok(group) = group {
        if let Err(error) = signal_browser_group(group, rustix::process::Signal::TERM) {
            errors.push(error);
        }
        let deadline = Instant::now() + Duration::from_millis(500);
        while Instant::now() < deadline {
            match browser_group_alive(group) {
                Ok(false) => break,
                Ok(true) => std::thread::sleep(Duration::from_millis(20)),
                Err(error) => {
                    errors.push(error);
                    break;
                }
            }
        }
        if browser_group_alive(group).unwrap_or(true) {
            kill_browser_group_with_direct_fallback(child, group, &mut errors);
        }
        let status = bounded_browser_reap(child);
        verify_browser_group_absent(group, &mut errors);
        (status, errors)
    } else {
        errors.push(group.unwrap_err());
        if let Err(error) = child.kill() {
            errors.push(format!("direct child kill fallback failed: {error}"));
        }
        (bounded_browser_reap(child), errors)
    }
}

#[cfg(target_os = "linux")]
fn bounded_browser_reap(
    child: &mut std::process::Child,
) -> std::io::Result<std::process::ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait()? {
            Some(status) => return Ok(status),
            None if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "browser direct-child reap timed out",
                ));
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn browser_group_pid(group: u32) -> Result<rustix::process::Pid, String> {
    rustix::process::Pid::from_raw(group.cast_signed())
        .ok_or_else(|| format!("invalid browser process-group id {group}"))
}

#[cfg(target_os = "linux")]
fn signal_browser_group(
    group: rustix::process::Pid,
    signal: rustix::process::Signal,
) -> Result<(), String> {
    match rustix::process::kill_process_group(group, signal) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        Err(error) => Err(format!("process-group {signal:?} failed: {error}")),
    }
}

#[cfg(target_os = "linux")]
fn kill_browser_group_with_direct_fallback(
    child: &mut std::process::Child,
    group: rustix::process::Pid,
    errors: &mut Vec<String>,
) {
    if let Err(error) = signal_browser_group(group, rustix::process::Signal::KILL) {
        errors.push(error);
        if let Err(error) = child.kill() {
            errors.push(format!("direct child kill fallback failed: {error}"));
        }
        if let Err(error) = signal_browser_group(group, rustix::process::Signal::KILL) {
            errors.push(format!("fallback {error}"));
        }
    }
}

#[cfg(target_os = "linux")]
fn browser_group_alive(group: rustix::process::Pid) -> Result<bool, String> {
    match rustix::process::test_kill_process_group(group) {
        Ok(()) => Ok(true),
        Err(rustix::io::Errno::SRCH) => Ok(false),
        Err(error) => Err(format!("process-group absence check failed: {error}")),
    }
}

#[cfg(target_os = "linux")]
fn verify_browser_group_absent(group: rustix::process::Pid, errors: &mut Vec<String>) {
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        match browser_group_alive(group) {
            Ok(false) => break,
            Ok(true) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(true) => {
                errors.push("process group remained after KILL and reap".to_owned());
                break;
            }
            Err(error) => {
                errors.push(error);
                break;
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn terminate_browser_group(child: &mut std::process::Child) -> Vec<String> {
    let mut errors = Vec::new();
    let group = match browser_group_pid(child.id()) {
        Ok(group) => group,
        Err(error) => {
            errors.push(error);
            if let Err(error) = child.kill() {
                errors.push(format!("direct child kill failed: {error}"));
            }
            if let Err(error) = bounded_browser_reap(child) {
                errors.push(format!("direct child reap failed: {error}"));
            }
            return errors;
        }
    };
    if let Err(error) = signal_browser_group(group, rustix::process::Signal::TERM) {
        errors.push(error);
    }
    let deadline = Instant::now() + Duration::from_millis(500);
    while Instant::now() < deadline {
        match browser_group_alive(group) {
            Ok(false) => break,
            Ok(true) => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                errors.push(error);
                break;
            }
        }
    }
    match browser_group_alive(group) {
        Ok(false) => {}
        Ok(true) => {
            kill_browser_group_with_direct_fallback(child, group, &mut errors);
        }
        Err(error) => {
            errors.push(error);
            kill_browser_group_with_direct_fallback(child, group, &mut errors);
        }
    }
    if let Err(error) = bounded_browser_reap(child) {
        errors.push(format!("direct child reap failed: {error}"));
    }
    verify_browser_group_absent(group, &mut errors);
    errors
}

fn missing_diagnostic_probe(package: &Path) -> Result<Value, &'static str> {
    let empty=br#"{"probes":[],"runId":"lifeline-operational-0047","schemaVersion":"operational-lifeline-qualification-probes/1","seed":"47"}"#;
    let artifacts = evaluate_operational_lifeline(package, empty)
        .map_err(|_| "diagnostic evaluation failed")?;
    let result = artifacts
        .scorecard
        .results
        .iter()
        .find(|r| r.criterion_id == "m3-20-ac4")
        .ok_or("diagnostic absent")?;
    let diagnostic = result.diagnostics.first().ok_or("diagnostic absent")?;
    let missing = result
        .missing_evidence
        .first()
        .ok_or("missing evidence absent")?;
    if diagnostic.code.as_str() != "missingEvidence"
        || diagnostic.criterion_id != "m3-20-ac4"
        || diagnostic.fact_id != "qualificationProbe"
        || diagnostic.expected != "present"
        || diagnostic.observed != ["missing"]
        || !diagnostic.evidence_refs.is_empty()
        || missing.artifact != "qualification-probes.json"
        || missing.selector != "/probes/m3-20-ac4"
        || missing.expectation != "explicit passing operational qualification probe"
    {
        return Err("missing diagnostic mismatch");
    }
    let raw_values = [
        b"planted-diagnostic-source-value".as_slice(),
        b"planted-diagnostic-secret-value".as_slice(),
    ];
    let planted_facts = json!({
        "secret":"planted-diagnostic-secret-value",
        "source":"planted-diagnostic-source-value"
    });
    let planted_bytes =
        serde_json::to_vec(&planted_facts).map_err(|_| "planted diagnostic encode failed")?;
    let planted = json!({
        "probes":[{
            "criterionId":"m3-20-ac4",
            "evidence":[{
                "artifact":"qualification-probe/m3-20-ac4",
                "artifactDigest":criteria_evidence_digest(
                    "operational-lifeline-qualification-evidence", &planted_bytes),
                "eventIds":["probe-m3-20-ac4"],
                "selector":"/facts"
            }],
            "facts":planted_facts,
            "status":"pass"
        }],
        "runId":RUN_ID,"schemaVersion":"operational-lifeline-qualification-probes/1","seed":"47"
    });
    let planted_artifacts = evaluate_operational_lifeline(
        package,
        &serde_json::to_vec(&planted).map_err(|_| "planted evidence encode failed")?,
    )
    .map_err(|_| "planted diagnostic evaluation failed")?;
    let planted_result = planted_artifacts
        .scorecard
        .results
        .iter()
        .find(|candidate| candidate.criterion_id == "m3-20-ac4")
        .ok_or("planted diagnostic absent")?;
    let diagnostic_bytes =
        serde_json::to_vec(planted_result).map_err(|_| "diagnostic encode failed")?;
    if raw_values.iter().any(|raw| {
        diagnostic_bytes
            .windows(raw.len())
            .any(|window| window == *raw)
    }) {
        return Err("raw diagnostic value disclosed");
    }
    Ok(
        json!({"allDiagnosticFieldsInspected":true,"criterionNamed":true,"expectationNamed":true,"rawValuesAbsent":true,"selectorNamed":true}),
    )
}
fn reproduction_probe(first: &Path, second: &Path) -> Result<Value, &'static str> {
    for path in ARTIFACTS {
        let a = std::fs::read(first.join(path)).map_err(|_| "generation artifact missing")?;
        let b = std::fs::read(second.join(path)).map_err(|_| "reproduction artifact missing")?;
        if a != b {
            return Err("same-seed artifact divergence");
        }
    }
    Ok(json!({"artifactCount":"18","byteIdentical":true,"seed":"47"}))
}
fn synthetic_probe(package: &Path) -> Result<bool, &'static str> {
    let root = TempRoot::new("synthetic-package")?;
    let result = synthetic_probe_in(package, &root);
    match (result, root.close()) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(_)) => Err("synthetic package temp cleanup failed"),
        (Err(_), Err(_)) => Err("synthetic probe and temp cleanup failed"),
    }
}

fn synthetic_probe_in(package: &Path, root: &TempRoot) -> Result<bool, &'static str> {
    let copy = root.path().join("package");
    std::fs::create_dir_all(copy.join("restricted"))
        .map_err(|_| "synthetic package create failed")?;
    for artifact in ARTIFACTS {
        std::fs::copy(package.join(artifact), copy.join(artifact))
            .map_err(|_| "synthetic artifact copy failed")?;
    }
    let mut records = std::fs::read(copy.join("package.jsonl"))
        .map_err(|_| "synthetic package read failed")?
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<Value>(line).map_err(|_| "synthetic record invalid"))
        .collect::<Result<Vec<_>, _>>()?;
    if records.len() != 47 || records[0]["recordType"] != "package" {
        return Err("synthetic package is not the full 46-event profile");
    }
    records[0]["runId"] = "lifeline-substituted-0047".into();
    let mut bytes = Vec::new();
    for record in records {
        bytes.extend_from_slice(
            &serde_json::to_vec(&record).map_err(|_| "synthetic record encode failed")?,
        );
        bytes.push(b'\n');
    }
    let mut receipt_value: Value = serde_json::from_slice(
        &std::fs::read(copy.join("receipt.json")).map_err(|_| "synthetic receipt read failed")?,
    )
    .map_err(|_| "synthetic receipt invalid")?;
    receipt_value["outputByteLength"] = bytes.len().to_string().into();
    receipt_value["outputDigest"] =
        criteria_evidence_digest("operational-observatory-output", &bytes).into();
    let receipt =
        serde_json::to_vec(&receipt_value).map_err(|_| "synthetic receipt encode failed")?;
    std::fs::write(copy.join("package.jsonl"), bytes)
        .map_err(|_| "synthetic package write failed")?;
    std::fs::write(copy.join("receipt.json"), receipt)
        .map_err(|_| "synthetic receipt write failed")?;
    let empty=br#"{"probes":[],"runId":"lifeline-operational-0047","schemaVersion":"operational-lifeline-qualification-probes/1","seed":"47"}"#;
    let artifacts = evaluate_operational_lifeline(&copy, empty)
        .map_err(|_| "synthetic evaluator infrastructure failure")?;
    let result = artifacts
        .scorecard
        .results
        .iter()
        .find(|result| result.criterion_id == "m3-28-ac1")
        .ok_or("synthetic operational criterion absent")?;
    Ok(result.status.as_str() == "fail"
        && result.diagnostics.first().is_some_and(|diagnostic| {
            diagnostic.code.as_str() == "profileMismatch"
                && diagnostic.fact_id == "productionInputSet"
        }))
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), &'static str> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "qualification output create failed")?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| "qualification output write failed")
}
struct TempRoot {
    owned: OwnedTempDir,
}
impl TempRoot {
    fn new(label: &str) -> Result<Self, &'static str> {
        let prefix = format!("smesh-qualification-{label}-");
        let owned = OwnedTempDir::create(&prefix).map_err(|_| "temp create failed")?;
        Ok(Self { owned })
    }

    fn path(&self) -> &Path {
        self.owned.path()
    }

    fn database_path(&self) -> std::path::PathBuf {
        self.path().join("ledger.sqlite3")
    }

    fn close(self) -> std::io::Result<()> {
        self.owned.close()
    }
}
