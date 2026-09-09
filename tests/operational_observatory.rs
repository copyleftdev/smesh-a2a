use sha2::{Digest, Sha256};
use smesh_a2a::{
    CaptureEvent, CaptureGapReason, CaptureKind, CaptureParent, CaptureProducer, CapturedContent,
    CausalMerger, CausalSourceEvent, HybridLogicalClock, MergeLimits, MissingParentPolicy,
    OPERATIONAL_OBSERVATORY_PROJECTOR_ID, OPERATIONAL_OBSERVATORY_PROJECTOR_VERSION,
    OperationalProjectionError, OperationalProjectionLimits, ProducerIdentity, ProducerKind,
    ReplaySealInput, project_operational_observatory,
    project_operational_observatory_with_source_facts, verify_operational_projection,
};

const ROOT: &str = "demo/fixtures/full-matrix-replay-v1";
const FIRST: &str = "sha256:97d139d083022d475e8c960e0ec4cea62c5d54f49c8a9d3bb495bae1ff8b290a";
const SECOND: &str = "sha256:78e975bffcaf2a4f20352337a8873b2820dc99a0da30a6fea96f5d8dc928d9e1";

fn replay() -> (Vec<u8>, Vec<u8>, String) {
    let bundle = std::fs::read(format!("{ROOT}/expected.bundle.jsonl")).unwrap();
    let receipt = std::fs::read(format!("{ROOT}/expected.receipt.json")).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
    (
        bundle,
        receipt,
        value["runSeal"].as_str().unwrap().to_owned(),
    )
}

fn actors() -> Vec<u8> {
    br#"{"actors":[{"actorId":"alpha","displayName":"Alpha","producer":{"id":"alpha","instanceId":"instance","kind":"a2a"},"siteId":"site-alpha","visibility":"visible"},{"actorId":"beta","displayName":"Beta","producer":{"id":"beta","instanceId":"instance","kind":"a2a"},"siteId":"site-beta","visibility":"visible"}],"schemaVersion":"operational-observatory-actors/1","sites":[{"displayName":"Alpha local site","siteId":"site-alpha"},{"displayName":"Beta local site","siteId":"site-beta"}]}"#.to_vec()
}

fn overlay() -> Vec<u8> {
    format!(
        "{{\"entries\":[{{\"cue\":\"follow\",\"eventId\":\"{SECOND}\",\"narration\":\"Captured dependent send.\"}},{{\"cue\":\"focus\",\"eventId\":\"{FIRST}\",\"narration\":\"Captured send.\"}}],\"schemaVersion\":\"operational-observatory-editorial/1\"}}"
    )
    .into_bytes()
}

fn empty_overlay() -> Vec<u8> {
    br#"{"entries":[],"schemaVersion":"operational-observatory-editorial/1"}"#.to_vec()
}

fn project(actor_bytes: &[u8], overlay_bytes: &[u8]) -> smesh_a2a::OperationalProjection {
    let (bundle, receipt, seal) = replay();
    project_operational_observatory(
        &bundle,
        &receipt,
        &seal,
        actor_bytes,
        overlay_bytes,
        OperationalProjectionLimits::default(),
    )
    .unwrap()
}

fn protocol_hash(label: &str, bytes: &[u8]) -> String {
    let mut framed = Vec::new();
    framed.extend_from_slice(b"SMESH-A2A\0");
    framed.extend_from_slice(label.as_bytes());
    framed.extend_from_slice(b"\0v1\0");
    framed.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    framed.extend_from_slice(bytes);
    format!("sha256:{:x}", Sha256::digest(framed))
}

fn rebound_receipt(projection: &smesh_a2a::OperationalProjection, package: &[u8]) -> Vec<u8> {
    let mut receipt: serde_json::Value = serde_json::from_slice(projection.receipt_json()).unwrap();
    receipt["outputByteLength"] = package.len().to_string().into();
    receipt["outputDigest"] = protocol_hash("operational-observatory-output", package).into();
    serde_json::to_vec(&receipt).unwrap()
}

fn mutate_manifest(mutator: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
    let mut value: serde_json::Value = serde_json::from_slice(&actors()).unwrap();
    mutator(&mut value);
    serde_json::to_vec(&value).unwrap()
}

fn bind_event_id(run_id: &str, mut event: CaptureEvent) -> CaptureEvent {
    let parent = match &event.parent {
        CaptureParent::Root => "root".to_owned(),
        CaptureParent::Event(id) => format!("event:{id}"),
        CaptureParent::Missing {
            expected_event_id,
            reason,
        } => format!("missing:{expected_event_id}:{reason:?}"),
    };
    let identity = &event.producer.identity;
    let identity_key = format!(
        "{:?}\0{}\0{}",
        identity.kind, identity.id, identity.instance_id
    );
    let preimage = format!(
        "full-matrix-event/v1\0{run_id}\0{identity_key}\0{}\0{:?}\0{}\0{}\0{}\0{}\0{}\0{parent}\0{}\0{}",
        event.producer.sequence,
        event.kind,
        event.interaction_id,
        event.peer_id,
        event.task_id.as_deref().unwrap_or(""),
        event.context_id.as_deref().unwrap_or(""),
        event.subject_id.as_deref().unwrap_or(""),
        event.content.digest,
        event.content.byte_length,
    );
    event.event_id = smesh_a2a::content_digest(preimage.as_bytes());
    event
}

fn replay_with_parent(parent: CaptureParent) -> smesh_a2a::SealedReplay {
    let run = "observatory-parent-vector";
    let event = CaptureEvent {
        event_id: format!("sha256:{}", "00".repeat(32)),
        sequence: 0,
        producer: CaptureProducer {
            identity: ProducerIdentity::new(ProducerKind::A2a, "alpha", "instance").unwrap(),
            sequence: 0,
        },
        kind: CaptureKind::A2aSend,
        interaction_id: "parent-vector".into(),
        peer_id: "peer".into(),
        task_id: None,
        context_id: None,
        subject_id: None,
        parent,
        content: CapturedContent {
            digest: format!("sha256:{}", "cc".repeat(32)),
            byte_length: 1,
        },
    };
    let causal = CausalSourceEvent::new(
        bind_event_id(run, event),
        HybridLogicalClock {
            physical_ns: 10,
            logical: 0,
        },
        0,
        None,
    )
    .unwrap();
    let source = smesh_a2a::capture_causal_source_jsonl(run, &[causal]).unwrap();
    let mut merger =
        CausalMerger::new(run, MergeLimits::default(), MissingParentPolicy::Record).unwrap();
    merger.ingest_source_jsonl(&source).unwrap();
    merger.finalize(ReplaySealInput::empty()).unwrap()
}

fn one_actor() -> Vec<u8> {
    br#"{"actors":[{"actorId":"alpha","displayName":"Alpha","producer":{"id":"alpha","instanceId":"instance","kind":"a2a"},"siteId":"site-alpha","visibility":"visible"}],"schemaVersion":"operational-observatory-actors/1","sites":[{"displayName":"Alpha local site","siteId":"site-alpha"}]}"#.to_vec()
}

#[test]
fn checked_in_verified_replay_projects_exact_operational_facts() {
    let projection = project(&actors(), &overlay());
    assert_eq!(
        projection.receipt().projector_id,
        OPERATIONAL_OBSERVATORY_PROJECTOR_ID
    );
    assert_eq!(
        projection.receipt().projector_version,
        OPERATIONAL_OBSERVATORY_PROJECTOR_VERSION
    );
    assert_eq!(
        usize::try_from(projection.receipt().output_byte_length).unwrap(),
        projection.package_jsonl().len()
    );
    let text = std::str::from_utf8(projection.package_jsonl()).unwrap();
    assert_eq!(text.matches("\"recordType\":\"event\"").count(), 2);
    assert!(text.contains(&format!("\"eventId\":\"{FIRST}\"")));
    assert!(text.contains(&format!("\"eventId\":\"{SECOND}\"")));
    assert!(text.contains("\"runRelativeNs\":\"0\""));
    assert!(text.contains("\"runRelativeNs\":\"1\""));
    assert_eq!(
        verify_operational_projection(
            projection.package_jsonl(),
            projection.receipt_json(),
            &projection.receipt().input_digest,
        )
        .unwrap(),
        *projection.receipt()
    );
}

#[test]
fn projection_is_repeatable_and_random_access_is_state_independent() {
    let first = project(&actors(), &overlay());
    let second = project(&actors(), &overlay());
    assert_eq!(first.package_jsonl(), second.package_jsonl());
    assert_eq!(first.receipt_json(), second.receipt_json());

    let second_first = first.record_json(SECOND).unwrap().to_vec();
    let first_second = first.record_json(FIRST).unwrap().to_vec();
    assert_eq!(first.record_json(FIRST).unwrap(), first_second);
    assert_eq!(first.record_json(SECOND).unwrap(), second_first);
    assert!(
        first
            .record_json("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
            .is_none()
    );
}

#[test]
fn replay_receipt_seal_and_bundle_tampering_fail_before_projection() {
    let (bundle, receipt, seal) = replay();
    let call = |bundle: &[u8], receipt: &[u8], seal: &str| {
        project_operational_observatory(
            bundle,
            receipt,
            seal,
            &actors(),
            &overlay(),
            OperationalProjectionLimits::default(),
        )
    };
    let wrong_seal = format!("sha256:{}", "00".repeat(32));
    assert_eq!(
        call(&bundle, &receipt, &wrong_seal).unwrap_err(),
        OperationalProjectionError::Replay
    );
    let mut wrong_receipt = receipt.clone();
    wrong_receipt[10] ^= 1;
    assert_eq!(
        call(&bundle, &wrong_receipt, &seal).unwrap_err(),
        OperationalProjectionError::Replay
    );
    let mut wrong_bundle = bundle.clone();
    wrong_bundle[10] ^= 1;
    assert_eq!(
        call(&wrong_bundle, &receipt, &seal).unwrap_err(),
        OperationalProjectionError::Replay
    );
}

#[test]
fn manifests_and_overlays_are_closed_bounded_unique_and_ordered() {
    let invalid = [
        mutate_manifest(|value| {
            value["schemaVersion"] = "operational-observatory-actors/2".into();
        }),
        mutate_manifest(|value| value["unknown"] = true.into()),
        mutate_manifest(|value| value["actors"].as_array_mut().unwrap().swap(0, 1)),
        mutate_manifest(|value| value["actors"][1]["actorId"] = "alpha".into()),
        mutate_manifest(|value| value["actors"][0]["producer"]["kind"] = "unknown".into()),
        mutate_manifest(|value| value["actors"][0]["displayName"] = "x".repeat(4097).into()),
    ];
    let (bundle, receipt, seal) = replay();
    for bytes in invalid {
        assert!(
            project_operational_observatory(
                &bundle,
                &receipt,
                &seal,
                &bytes,
                &overlay(),
                OperationalProjectionLimits::default(),
            )
            .is_err()
        );
    }

    let duplicate_key = String::from_utf8(actors())
        .unwrap()
        .replacen("{\"actors\":", "{\"actors\":[],\"actors\":", 1)
        .into_bytes();
    assert!(
        project_operational_observatory(
            &bundle,
            &receipt,
            &seal,
            &duplicate_key,
            &overlay(),
            OperationalProjectionLimits::default(),
        )
        .is_err()
    );

    let missing = format!(
        "{{\"entries\":[{{\"cue\":\"focus\",\"eventId\":\"sha256:{}\",\"narration\":\"Missing.\"}}],\"schemaVersion\":\"operational-observatory-editorial/1\"}}",
        "ee".repeat(32)
    );
    assert_eq!(
        project_operational_observatory(
            &bundle,
            &receipt,
            &seal,
            &actors(),
            missing.as_bytes(),
            OperationalProjectionLimits::default(),
        )
        .unwrap_err(),
        OperationalProjectionError::InvalidReference
    );
}

#[test]
fn restricted_events_are_explicit_and_cannot_receive_editorial_claims() {
    let restricted =
        mutate_manifest(|value| value["actors"][0]["visibility"] = "restricted".into());
    let (bundle, receipt, seal) = replay();
    assert_eq!(
        project_operational_observatory(
            &bundle,
            &receipt,
            &seal,
            &restricted,
            &overlay(),
            OperationalProjectionLimits::default(),
        )
        .unwrap_err(),
        OperationalProjectionError::InvalidReference
    );
    let projection = project(&restricted, &empty_overlay());
    let text = std::str::from_utf8(projection.record_json(FIRST).unwrap()).unwrap();
    assert!(text.contains("\"recordType\":\"restricted\""));
    assert!(!text.contains("interactionId"));
    verify_operational_projection(
        projection.package_jsonl(),
        projection.receipt_json(),
        &projection.receipt().input_digest,
    )
    .unwrap();
}

#[test]
fn package_verifier_rejects_unknown_kinds_fields_duplicates_order_and_bad_parent_reasons() {
    let projection = project(&actors(), &overlay());
    let lines: Vec<Vec<u8>> = projection.package_jsonl()[..projection.package_jsonl().len() - 1]
        .split(|byte| *byte == b'\n')
        .map(<[u8]>::to_vec)
        .collect();
    let verify_mutation =
        |mut lines: Vec<Vec<u8>>, index: usize, mutate: &dyn Fn(&mut serde_json::Value)| {
            let mut value: serde_json::Value = serde_json::from_slice(&lines[index]).unwrap();
            mutate(&mut value);
            lines[index] = serde_json::to_vec(&value).unwrap();
            let mut package = lines.join(&b'\n');
            package.push(b'\n');
            let receipt = rebound_receipt(&projection, &package);
            verify_operational_projection(&package, &receipt, &projection.receipt().input_digest)
        };
    let unknown = format!("sha256:{}", "f".repeat(64));
    assert!(
        verify_mutation(lines.clone(), 1, &|value| {
            value["parent"] = serde_json::json!({"eventId": unknown, "kind": "event"});
        })
        .is_err()
    );
    assert!(
        verify_mutation(lines.clone(), 1, &|value| {
            value["parent"] = serde_json::json!({"eventId": SECOND, "kind": "event"});
        })
        .is_err()
    );
    assert!(
        verify_mutation(lines.clone(), 2, &|value| {
            value["parent"] = serde_json::json!({"eventId": SECOND, "kind": "event"});
        })
        .is_err()
    );
    assert!(
        verify_mutation(lines.clone(), 2, &|value| {
            value["parent"] = serde_json::json!({
                "expectedEventId": unknown,
                "kind": "missing",
                "reason": "producerRestart"
            });
        })
        .is_err()
    );
    assert!(verify_mutation(lines.clone(), 1, &|value| value["unknown"] = true.into()).is_err());
    assert!(verify_mutation(lines.clone(), 1, &|value| value["kind"] = "invented".into()).is_err());
    assert!(
        verify_mutation(lines.clone(), 2, &|value| {
            value["parent"] = serde_json::json!({
                "eventId": FIRST,
                "kind": "missing",
                "reason": "invented"
            });
        })
        .is_err()
    );

    let mut reordered = lines.clone();
    reordered.swap(1, 2);
    let mut package = reordered.join(&b'\n');
    package.push(b'\n');
    assert!(
        verify_operational_projection(
            &package,
            &rebound_receipt(&projection, &package),
            &projection.receipt().input_digest,
        )
        .is_err()
    );

    let mut duplicate = lines;
    duplicate.push(duplicate[1].clone());
    let mut package = duplicate.join(&b'\n');
    package.push(b'\n');
    assert!(
        verify_operational_projection(
            &package,
            &rebound_receipt(&projection, &package),
            &projection.receipt().input_digest,
        )
        .is_err()
    );
}

#[test]
fn package_verifier_rejects_noncanonical_source_identifier_matrix() {
    let projection = project(&actors(), &overlay());
    let baseline: Vec<serde_json::Value> = std::str::from_utf8(projection.package_jsonl())
        .unwrap()
        .trim_end()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let invalid = [
        ("boolean", serde_json::json!(true)),
        ("object", serde_json::json!({"invented": "shape"})),
        ("number", serde_json::json!(7)),
        ("empty", serde_json::json!("")),
        ("oversized", serde_json::json!("x".repeat(257))),
        ("noncanonical", serde_json::json!("not canonical")),
    ];
    for field in ["interactionId", "peerId"] {
        for (case, replacement) in
            std::iter::once(("null", serde_json::Value::Null)).chain(invalid.iter().cloned())
        {
            let mut values = baseline.clone();
            values[1][field] = replacement;
            let mut package = values
                .iter()
                .map(|value| serde_json::to_vec(value).unwrap())
                .collect::<Vec<_>>()
                .join(&b'\n');
            package.push(b'\n');
            assert!(
                verify_operational_projection(
                    &package,
                    &rebound_receipt(&projection, &package),
                    &projection.receipt().input_digest,
                )
                .is_err(),
                "accepted required {field} sabotage: {case}"
            );
        }
    }
    for field in ["contextId", "taskId", "subjectId"] {
        for (case, replacement) in invalid.iter().cloned() {
            let mut values = baseline.clone();
            values[1][field] = replacement;
            let mut package = values
                .iter()
                .map(|value| serde_json::to_vec(value).unwrap())
                .collect::<Vec<_>>()
                .join(&b'\n');
            package.push(b'\n');
            assert!(
                verify_operational_projection(
                    &package,
                    &rebound_receipt(&projection, &package),
                    &projection.receipt().input_digest,
                )
                .is_err(),
                "accepted optional {field} sabotage: {case}"
            );
        }
    }
}

#[test]
fn package_verifier_rejects_gap_expected_id_that_is_present() {
    let projection = project(&actors(), &overlay());
    let mut values: Vec<serde_json::Value> = std::str::from_utf8(projection.package_jsonl())
        .unwrap()
        .trim_end()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    values[2]["parent"] = serde_json::json!({
        "expectedEventId": FIRST,
        "kind": "missing",
        "reason": "producerRestart"
    });
    values.insert(
        1,
        serde_json::json!({
            "children": [SECOND],
            "expectedEventId": FIRST,
            "reason": "unresolvedAtSeal",
            "recordId": format!("sha256:{}", "e".repeat(64)),
            "recordType": "gap"
        }),
    );
    let mut package = values
        .iter()
        .map(|value| serde_json::to_vec(value).unwrap())
        .collect::<Vec<_>>()
        .join(&b'\n');
    package.push(b'\n');

    assert_eq!(
        verify_operational_projection(
            &package,
            &rebound_receipt(&projection, &package),
            &projection.receipt().input_digest,
        )
        .unwrap_err(),
        OperationalProjectionError::InvalidReference
    );
}

#[test]
fn hard_limits_cannot_be_raised_and_output_bounds_are_enforced() {
    let (bundle, receipt, seal) = replay();
    let too_large = OperationalProjectionLimits {
        max_events: 100_001,
        ..OperationalProjectionLimits::default()
    };
    assert_eq!(
        project_operational_observatory(
            &bundle,
            &receipt,
            &seal,
            &actors(),
            &overlay(),
            too_large,
        )
        .unwrap_err(),
        OperationalProjectionError::CapacityExhausted
    );
    let tiny = OperationalProjectionLimits {
        max_output_bytes: 1,
        ..OperationalProjectionLimits::default()
    };
    assert_eq!(
        project_operational_observatory(&bundle, &receipt, &seal, &actors(), &overlay(), tiny,)
            .unwrap_err(),
        OperationalProjectionError::CapacityExhausted
    );
}

#[test]
fn recorded_missing_parent_reasons_and_unresolved_seal_gaps_are_explicit() {
    let missing = format!("sha256:{}", "dd".repeat(32));
    for (reason, wire) in [
        (CaptureGapReason::ExternalBoundary, "externalBoundary"),
        (CaptureGapReason::CaptureStartedLate, "captureStartedLate"),
        (CaptureGapReason::ProducerRestart, "producerRestart"),
    ] {
        let replay = replay_with_parent(CaptureParent::Missing {
            expected_event_id: missing.clone(),
            reason,
        });
        let projection = project_operational_observatory(
            replay.bundle_jsonl(),
            replay.receipt_json(),
            &replay.receipt().run_seal,
            &one_actor(),
            &empty_overlay(),
            OperationalProjectionLimits::default(),
        )
        .unwrap();
        assert!(
            std::str::from_utf8(projection.package_jsonl())
                .unwrap()
                .contains(&format!("\"reason\":\"{wire}\""))
        );
    }

    let replay = replay_with_parent(CaptureParent::Event(missing));
    let projection = project_operational_observatory(
        replay.bundle_jsonl(),
        replay.receipt_json(),
        &replay.receipt().run_seal,
        &one_actor(),
        &empty_overlay(),
        OperationalProjectionLimits::default(),
    )
    .unwrap();
    assert!(
        std::str::from_utf8(projection.package_jsonl())
            .unwrap()
            .contains("\"reason\":\"unresolvedAtSeal\"")
    );
}

#[test]
fn local_projector_executable_reproduces_checked_in_wave_two_fixture() {
    let fixture = "demo/fixtures/operational-observatory-v1";
    let root = std::env::temp_dir().join(format!(
        "smesh-operational-projector-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap();
    let package = root.join("package.jsonl");
    let receipt = root.join("receipt.json");
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_operational-observatory-project"))
        .args([
            format!("{ROOT}/expected.bundle.jsonl"),
            format!("{ROOT}/expected.receipt.json"),
            replay().2,
            format!("{fixture}/actors.json"),
            format!("{fixture}/editorial.json"),
            format!("{fixture}/source-facts.json"),
            package.display().to_string(),
            receipt.display().to_string(),
        ])
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(
        std::fs::read(&package).unwrap(),
        std::fs::read(format!("{fixture}/package.jsonl")).unwrap()
    );
    assert_eq!(
        std::fs::read(&receipt).unwrap(),
        std::fs::read(format!("{fixture}/receipt.json")).unwrap()
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn source_facts_are_digest_bound_closed_and_projected_as_authoritative_annotations() {
    let (bundle, receipt, seal) = replay();
    let first: serde_json::Value = serde_json::from_str(
        std::str::from_utf8(&bundle)
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    let event_id = first["causal"]["event"]["eventId"].as_str().unwrap();
    let content_digest = first["causal"]["event"]["content"]["digest"]
        .as_str()
        .unwrap();
    let facts = format!(
        "{{\"entries\":[{{\"eventId\":\"{event_id}\",\"failureKind\":\"primary-outage-observed\",\"fieldRestrictions\":[],\"outcome\":\"unavailable\",\"sourceContentDigest\":\"{content_digest}\",\"sourceSchemaVersion\":\"lifeline-failure-scenario/1\"}}],\"schemaVersion\":\"operational-observatory-source-facts/1\"}}"
    );
    let projection = project_operational_observatory_with_source_facts(
        &bundle,
        &receipt,
        &seal,
        &actors(),
        &overlay(),
        facts.as_bytes(),
        OperationalProjectionLimits::default(),
    )
    .unwrap();
    let record = std::str::from_utf8(projection.record_json(event_id).unwrap()).unwrap();
    assert!(record.contains("\"failureKind\":\"primary-outage-observed\""));
    assert!(record.contains("\"outcome\":\"unavailable\""));

    let wrong_digest = facts.replace(content_digest, &format!("sha256:{}", "f".repeat(64)));
    assert_eq!(
        project_operational_observatory_with_source_facts(
            &bundle,
            &receipt,
            &seal,
            &actors(),
            &overlay(),
            wrong_digest.as_bytes(),
            OperationalProjectionLimits::default(),
        )
        .unwrap_err(),
        OperationalProjectionError::InvalidReference
    );
}

#[test]
fn source_facts_cannot_target_actor_restricted_events() {
    let (bundle, receipt, seal) = replay();
    let first: serde_json::Value = serde_json::from_str(
        std::str::from_utf8(&bundle)
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    let event_id = first["causal"]["event"]["eventId"].as_str().unwrap();
    let content_digest = first["causal"]["event"]["content"]["digest"]
        .as_str()
        .unwrap();
    let facts = format!(
        "{{\"entries\":[{{\"eventId\":\"{event_id}\",\"failureKind\":\"primary-outage-observed\",\"fieldRestrictions\":[],\"outcome\":\"unavailable\",\"sourceContentDigest\":\"{content_digest}\",\"sourceSchemaVersion\":\"lifeline-failure-scenario/1\"}}],\"schemaVersion\":\"operational-observatory-source-facts/1\"}}"
    );
    let restricted =
        mutate_manifest(|value| value["actors"][0]["visibility"] = "restricted".into());

    assert_eq!(
        project_operational_observatory_with_source_facts(
            &bundle,
            &receipt,
            &seal,
            &restricted,
            &empty_overlay(),
            facts.as_bytes(),
            OperationalProjectionLimits::default(),
        )
        .unwrap_err(),
        OperationalProjectionError::InvalidReference
    );
}
