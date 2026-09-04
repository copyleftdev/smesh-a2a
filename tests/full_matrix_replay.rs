use sha2::{Digest, Sha256};
use smesh_a2a::{
    CaptureEvent, CaptureGapReason, CaptureKind, CaptureParent, CaptureProducer, CapturedContent,
    CausalMerger, CausalSourceEvent, HybridLogicalClock, MergeLimits, MissingParentPolicy,
    ProducerIdentity, ProducerKind, ReplaySealInput, capture_causal_source_jsonl,
    reconcile_published_replay_temporary, reconcile_unpublished_replay_temporary,
};

fn digest(byte: u8) -> String {
    format!("sha256:{}", format!("{byte:02x}").repeat(32))
}

fn event(id: u8, producer: &str, sequence: u64) -> CaptureEvent {
    CaptureEvent {
        event_id: digest(id),
        sequence,
        producer: CaptureProducer {
            identity: ProducerIdentity::new(ProducerKind::A2a, producer, "instance").unwrap(),
            sequence,
        },
        kind: CaptureKind::A2aSend,
        interaction_id: format!("interaction-{id}"),
        peer_id: "peer".into(),
        task_id: None,
        context_id: None,
        subject_id: None,
        parent: CaptureParent::Root,
        content: CapturedContent {
            digest: digest(200),
            byte_length: 1,
        },
    }
}

fn causal(
    mut event: CaptureEvent,
    physical: u64,
    logical: u64,
    lamport: u64,
    parent: CaptureParent,
) -> CausalSourceEvent {
    event.parent = parent;
    CausalSourceEvent::new(
        event,
        HybridLogicalClock {
            physical_ns: physical,
            logical,
        },
        lamport,
        None,
    )
    .unwrap()
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

fn causal_valid(
    run_id: &str,
    mut event: CaptureEvent,
    physical: u64,
    logical: u64,
    lamport: u64,
    parent: CaptureParent,
) -> CausalSourceEvent {
    event.parent = parent;
    CausalSourceEvent::new(
        bind_event_id(run_id, event),
        HybridLogicalClock {
            physical_ns: physical,
            logical,
        },
        lamport,
        None,
    )
    .unwrap()
}

fn protocol_hash_raw(label: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"SMESH-A2A\0");
    hasher.update(label.as_bytes());
    hasher.update(b"\0v1\0");
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn protocol_hash(label: &str, parts: &[&[u8]]) -> String {
    format!(
        "sha256:{:x}",
        Sha256::digest({
            let mut framed = Vec::new();
            framed.extend_from_slice(b"SMESH-A2A\0");
            framed.extend_from_slice(label.as_bytes());
            framed.extend_from_slice(b"\0v1\0");
            for part in parts {
                framed.extend_from_slice(&(part.len() as u64).to_be_bytes());
                framed.extend_from_slice(part);
            }
            framed
        })
    )
}

fn test_merkle_root(lines: &[Vec<u8>]) -> String {
    let mut level: Vec<[u8; 32]> = lines
        .iter()
        .map(|line| protocol_hash_raw("merkle-leaf", &[line]))
        .collect();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| {
                if pair.len() == 1 {
                    pair[0]
                } else {
                    protocol_hash_raw("merkle-node", &[&pair[0], &pair[1]])
                }
            })
            .collect();
    }
    let hex = level[0].iter().fold(String::new(), |mut output, byte| {
        use std::fmt::Write as _;
        write!(output, "{byte:02x}").unwrap();
        output
    });
    format!("sha256:{hex}")
}

fn reseal_terminal(bundle: &[u8], mutate: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
    let mut lines: Vec<Vec<u8>> = bundle[..bundle.len() - 1]
        .split(|byte| *byte == b'\n')
        .map(<[u8]>::to_vec)
        .collect();
    let mut terminal: serde_json::Value = serde_json::from_slice(lines.last().unwrap()).unwrap();
    mutate(&mut terminal);
    let claims = serde_json::to_vec(&terminal["claims"]).unwrap();
    terminal["sealDigest"] = protocol_hash("run-seal", &[&claims]).into();
    *lines.last_mut().unwrap() = serde_json::to_vec(&terminal).unwrap();
    let mut out = lines.join(&b'\n');
    out.push(b'\n');
    out
}

fn reseal_data_line(
    bundle: &[u8],
    index: usize,
    mutate: impl FnOnce(&mut serde_json::Value),
) -> Vec<u8> {
    let mut lines: Vec<Vec<u8>> = bundle[..bundle.len() - 1]
        .split(|byte| *byte == b'\n')
        .map(<[u8]>::to_vec)
        .collect();
    let terminal_index = lines.len() - 1;
    let mut value: serde_json::Value = serde_json::from_slice(&lines[index]).unwrap();
    mutate(&mut value);
    lines[index] = serde_json::to_vec(&value).unwrap();
    let mut merged = lines[..terminal_index].join(&b'\n');
    merged.push(b'\n');
    let mut terminal: serde_json::Value = serde_json::from_slice(&lines[terminal_index]).unwrap();
    terminal["claims"]["mergedJsonlDigest"] = protocol_hash("merged-jsonl", &[&merged]).into();
    terminal["claims"]["merkleRoot"] = test_merkle_root(&lines[..terminal_index]).into();
    let claims = serde_json::to_vec(&terminal["claims"]).unwrap();
    terminal["sealDigest"] = protocol_hash("run-seal", &[&claims]).into();
    lines[terminal_index] = serde_json::to_vec(&terminal).unwrap();
    let mut out = lines.join(&b'\n');
    out.push(b'\n');
    out
}

fn seal(merger: &CausalMerger) -> Vec<u8> {
    merger
        .finalize(ReplaySealInput::empty())
        .unwrap()
        .bundle_jsonl()
        .to_vec()
}

#[test]
fn clocked_source_record_preserves_hlc_lamport_and_source_identity() {
    let causal = CausalSourceEvent::new(
        bind_event_id("run", event(1, "producer", 0)),
        HybridLogicalClock {
            physical_ns: 123,
            logical: 7,
        },
        9,
        None,
    )
    .unwrap();
    let source = capture_causal_source_jsonl("run", &[causal]).unwrap();
    let mut merger =
        CausalMerger::new("run", MergeLimits::default(), MissingParentPolicy::Reject).unwrap();
    merger.ingest_source_jsonl(&source).unwrap();
    let replay = merger.finalize(ReplaySealInput::empty()).unwrap();
    let text = std::str::from_utf8(replay.bundle_jsonl()).unwrap();
    assert!(text.contains("\"physicalNs\":\"123\""));
    assert!(text.contains("\"logical\":\"7\""));
    assert!(text.contains("\"lamport\":\"9\""));
    assert!(text.contains("\"sourceSequence\":\"0\""));
}

#[test]
fn independent_equal_clock_events_are_byte_stable_across_ingestion_order() {
    let a = capture_causal_source_jsonl(
        "run",
        &[causal_valid(
            "run",
            event(1, "alpha", 0),
            100,
            0,
            0,
            CaptureParent::Root,
        )],
    )
    .unwrap();
    let b = capture_causal_source_jsonl(
        "run",
        &[causal_valid(
            "run",
            event(2, "beta", 0),
            100,
            0,
            0,
            CaptureParent::Root,
        )],
    )
    .unwrap();
    let mut left =
        CausalMerger::new("run", MergeLimits::default(), MissingParentPolicy::Reject).unwrap();
    left.ingest_source_jsonl(&a).unwrap();
    left.ingest_source_jsonl(&b).unwrap();
    let mut right =
        CausalMerger::new("run", MergeLimits::default(), MissingParentPolicy::Reject).unwrap();
    right.ingest_source_jsonl(&b).unwrap();
    right.ingest_source_jsonl(&a).unwrap();
    assert_eq!(seal(&left), seal(&right));
    let bytes = seal(&left);
    assert!(
        bytes
            .windows(b"\"id\":\"alpha\"".len())
            .position(|w| w == b"\"id\":\"alpha\"")
            .unwrap()
            < bytes
                .windows(b"\"id\":\"beta\"".len())
                .position(|w| w == b"\"id\":\"beta\"")
                .unwrap()
    );
}

#[test]
fn child_before_parent_is_pending_then_resolved() {
    let parent = causal_valid("run", event(10, "alpha", 0), 100, 0, 0, CaptureParent::Root);
    let child = causal_valid(
        "run",
        event(11, "beta", 0),
        101,
        0,
        1,
        CaptureParent::Event(parent.event.event_id.clone()),
    );
    let parent_source = capture_causal_source_jsonl("run", &[parent]).unwrap();
    let child_source = capture_causal_source_jsonl("run", &[child]).unwrap();
    let mut merger =
        CausalMerger::new("run", MergeLimits::default(), MissingParentPolicy::Reject).unwrap();
    merger.ingest_source_jsonl(&child_source).unwrap();
    assert_eq!(merger.pending_count(), 1);
    assert!(matches!(
        merger.finalize(ReplaySealInput::empty()),
        Err(smesh_a2a::ReplayError::MissingParents(_))
    ));
    merger.ingest_source_jsonl(&parent_source).unwrap();
    assert_eq!(merger.pending_count(), 0);
    let once = seal(&merger);
    assert_eq!(once, seal(&merger));
    assert!(smesh_a2a::verify_sealed_replay(&once).is_ok());
}

#[test]
#[allow(clippy::too_many_lines)] // The six explicit permutations are the evidence matrix.
fn all_three_source_permutations_and_duplicates_are_identical() {
    let root = causal_valid(
        "run-perm",
        event(20, "alpha", 0),
        10,
        0,
        0,
        CaptureParent::Root,
    );
    let child = causal_valid(
        "run-perm",
        event(21, "beta", 0),
        11,
        0,
        1,
        CaptureParent::Event(root.event.event_id.clone()),
    );
    let independent = causal_valid(
        "run-perm",
        event(22, "gamma", 0),
        10,
        0,
        0,
        CaptureParent::Root,
    );
    let more = [
        causal_valid(
            "run-perm",
            event(23, "delta", 0),
            10,
            0,
            0,
            CaptureParent::Root,
        ),
        causal_valid(
            "run-perm",
            event(24, "epsilon", 0),
            10,
            0,
            0,
            CaptureParent::Root,
        ),
        causal_valid(
            "run-perm",
            event(25, "zeta", 0),
            10,
            0,
            0,
            CaptureParent::Root,
        ),
        causal_valid(
            "run-perm",
            event(26, "eta", 0),
            10,
            0,
            0,
            CaptureParent::Root,
        ),
    ];
    let root_id = root.event.event_id.clone();
    let sources = [
        capture_causal_source_jsonl("run-perm", std::slice::from_ref(&root)).unwrap(),
        capture_causal_source_jsonl("run-perm", &[child, root]).unwrap(),
        capture_causal_source_jsonl(
            "run-perm",
            &[
                independent,
                more[0].clone(),
                more[1].clone(),
                more[2].clone(),
                more[3].clone(),
            ],
        )
        .unwrap(),
    ];
    let permutations = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    let mut expected = None;
    for order in permutations {
        let mut merger = CausalMerger::new(
            "run-perm",
            MergeLimits::default(),
            MissingParentPolicy::Reject,
        )
        .unwrap();
        for index in order {
            merger.ingest_source_jsonl(&sources[index]).unwrap();
        }
        let bytes = seal(&merger);
        if let Some(expected) = &expected {
            assert_eq!(expected, &bytes);
        } else {
            expected = Some(bytes);
        }
    }
    assert_eq!(permutations.len(), 6);
    let canonical = String::from_utf8(expected.unwrap()).unwrap();
    assert_eq!(canonical.matches("\"recordType\":\"event\"").count(), 7);
    assert!(
        sources[1]
            .windows(root_id.len())
            .any(|window| window == root_id.as_bytes())
    );
}

#[test]
fn missing_parent_policy_is_explicit_and_record_is_stable() {
    let missing = digest(99);
    let child = causal_valid(
        "run-missing",
        event(30, "alpha", 0),
        50,
        0,
        4,
        CaptureParent::Event(missing.clone()),
    );
    let source = capture_causal_source_jsonl("run-missing", &[child]).unwrap();
    let mut strict = CausalMerger::new(
        "run-missing",
        MergeLimits::default(),
        MissingParentPolicy::Reject,
    )
    .unwrap();
    strict.ingest_source_jsonl(&source).unwrap();
    assert_eq!(
        strict.finalize(ReplaySealInput::empty()).unwrap_err(),
        smesh_a2a::ReplayError::MissingParents(vec![missing.clone()])
    );
    let mut recording = CausalMerger::new(
        "run-missing",
        MergeLimits::default(),
        MissingParentPolicy::Record,
    )
    .unwrap();
    recording.ingest_source_jsonl(&source).unwrap();
    let bundle = seal(&recording);
    assert!(
        std::str::from_utf8(&bundle)
            .unwrap()
            .contains("\"recordType\":\"missingParent\"")
    );
    assert!(smesh_a2a::verify_sealed_replay(&bundle).is_ok());
}

#[test]
fn declared_missing_parent_conflicts_in_both_arrival_orders() {
    let parent = causal_valid(
        "run-claim",
        event(40, "parent", 0),
        1,
        0,
        0,
        CaptureParent::Root,
    );
    let missing_child = causal_valid(
        "run-claim",
        event(41, "child", 0),
        2,
        0,
        1,
        CaptureParent::Missing {
            expected_event_id: parent.event.event_id.clone(),
            reason: CaptureGapReason::ExternalBoundary,
        },
    );
    let p = capture_causal_source_jsonl("run-claim", &[parent]).unwrap();
    let c = capture_causal_source_jsonl("run-claim", &[missing_child]).unwrap();
    for order in [[&p, &c], [&c, &p]] {
        let mut merger = CausalMerger::new(
            "run-claim",
            MergeLimits::default(),
            MissingParentPolicy::Record,
        )
        .unwrap();
        merger.ingest_source_jsonl(order[0]).unwrap();
        assert_eq!(
            merger.ingest_source_jsonl(order[1]).unwrap_err(),
            smesh_a2a::ReplayError::MissingClaimConflict
        );
    }
}

#[test]
fn verifier_rejects_retained_event_declared_permanently_missing() {
    let run = "run-sealed-missing-conflict";
    let retained = causal_valid(run, event(42, "alpha", 0), 1, 0, 0, CaptureParent::Root);
    let declaring = causal_valid(
        run,
        event(43, "beta", 0),
        2,
        0,
        1,
        CaptureParent::Missing {
            expected_event_id: retained.event.event_id.clone(),
            reason: CaptureGapReason::ExternalBoundary,
        },
    );

    let independently_seal = |source_event: CausalSourceEvent| {
        let source = capture_causal_source_jsonl(run, &[source_event]).unwrap();
        let mut merger =
            CausalMerger::new(run, MergeLimits::default(), MissingParentPolicy::Record).unwrap();
        merger.ingest_source_jsonl(&source).unwrap();
        seal(&merger)
    };
    let retained_bundle = independently_seal(retained);
    let declaring_bundle = independently_seal(declaring);
    let record_and_claims = |bundle: &[u8]| {
        let lines: Vec<_> = bundle[..bundle.len() - 1]
            .split(|byte| *byte == b'\n')
            .collect();
        (
            serde_json::from_slice::<serde_json::Value>(lines[0]).unwrap(),
            serde_json::from_slice::<serde_json::Value>(lines[1]).unwrap()["claims"].clone(),
        )
    };
    let (mut retained_record, retained_claims) = record_and_claims(&retained_bundle);
    let (mut declaring_record, mut claims) = record_and_claims(&declaring_bundle);
    retained_record["mergeSequence"] = "0".into();
    declaring_record["mergeSequence"] = "1".into();
    let records = vec![
        serde_json::to_vec(&retained_record).unwrap(),
        serde_json::to_vec(&declaring_record).unwrap(),
    ];
    let mut merged = records.join(&b'\n');
    merged.push(b'\n');
    let mut producer_heads = retained_claims["producerHeads"].as_array().unwrap().clone();
    producer_heads.extend(claims["producerHeads"].as_array().unwrap().clone());
    producer_heads.sort_by(|left, right| {
        left["producerId"]
            .as_str()
            .cmp(&right["producerId"].as_str())
    });
    claims["eventCount"] = "2".into();
    claims["recordCount"] = "2".into();
    claims["mergedJsonlDigest"] = protocol_hash("merged-jsonl", &[&merged]).into();
    claims["merkleRoot"] = test_merkle_root(&records).into();
    claims["producerHeads"] = producer_heads.into();
    let seal_digest = protocol_hash("run-seal", &[&serde_json::to_vec(&claims).unwrap()]);
    let terminal = serde_json::json!({
        "claims": claims,
        "recordType": "seal",
        "sealDigest": seal_digest,
    });
    let mut malicious = merged;
    malicious.extend_from_slice(&serde_json::to_vec(&terminal).unwrap());
    malicious.push(b'\n');

    assert_eq!(
        smesh_a2a::verify_sealed_replay(&malicious).unwrap_err(),
        smesh_a2a::ReplayError::MissingClaimConflict
    );
}

#[test]
fn producer_chain_gap_and_clock_regression_fail_closed() {
    let first = causal_valid(
        "run-chain",
        event(50, "producer", 0),
        10,
        0,
        2,
        CaptureParent::Root,
    );
    let mut second_event = event(51, "producer", 1);
    second_event.sequence = 1;
    let second = CausalSourceEvent::new_chained(
        bind_event_id("run-chain", second_event),
        HybridLogicalClock {
            physical_ns: 9,
            logical: 0,
        },
        3,
        None,
        Some(first.producer_hash().into()),
    )
    .unwrap();
    let source = capture_causal_source_jsonl("run-chain", &[first, second]).unwrap();
    let mut merger = CausalMerger::new(
        "run-chain",
        MergeLimits::default(),
        MissingParentPolicy::Reject,
    )
    .unwrap();
    merger.ingest_source_jsonl(&source).unwrap();
    assert_eq!(
        merger.finalize(ReplaySealInput::empty()).unwrap_err(),
        smesh_a2a::ReplayError::ClockCausalityViolation
    );

    let gap_event = event(52, "gap", 2);
    let gap = CausalSourceEvent::new_chained(
        bind_event_id("run-gap", gap_event),
        HybridLogicalClock {
            physical_ns: 20,
            logical: 0,
        },
        3,
        None,
        Some(digest(1)),
    )
    .unwrap();
    let source = capture_causal_source_jsonl("run-gap", &[gap]).unwrap();
    let mut gap_merger = CausalMerger::new(
        "run-gap",
        MergeLimits::default(),
        MissingParentPolicy::Reject,
    )
    .unwrap();
    gap_merger.ingest_source_jsonl(&source).unwrap();
    assert_eq!(
        gap_merger.finalize(ReplaySealInput::empty()).unwrap_err(),
        smesh_a2a::ReplayError::SequenceGap
    );
}

#[test]
fn mixed_parent_and_producer_edges_form_a_detected_cycle() {
    let run = "run-cycle";
    let second_event = bind_event_id(run, event(61, "producer", 1));
    let mut first_event = event(60, "producer", 0);
    first_event.parent = CaptureParent::Event(second_event.event_id.clone());
    let first = CausalSourceEvent::new(
        bind_event_id(run, first_event),
        HybridLogicalClock {
            physical_ns: 1,
            logical: 0,
        },
        0,
        None,
    )
    .unwrap();
    let second = CausalSourceEvent::new_chained(
        second_event,
        HybridLogicalClock {
            physical_ns: 2,
            logical: 0,
        },
        1,
        None,
        Some(first.producer_hash().into()),
    )
    .unwrap();
    let mut cycle_ids = vec![first.event.event_id.clone(), second.event.event_id.clone()];
    cycle_ids.sort();
    let source = capture_causal_source_jsonl(run, &[first, second]).unwrap();
    let mut merger =
        CausalMerger::new(run, MergeLimits::default(), MissingParentPolicy::Reject).unwrap();
    merger.ingest_source_jsonl(&source).unwrap();
    assert_eq!(
        merger.finalize(ReplaySealInput::empty()).unwrap_err(),
        smesh_a2a::ReplayError::Cycle(cycle_ids)
    );
}

#[test]
fn coincident_explicit_and_producer_edge_consumes_one_edge() {
    let run = "run-coincident-edge";
    let first = causal_valid(run, event(62, "producer", 0), 1, 0, 0, CaptureParent::Root);
    let mut second_event = event(63, "producer", 1);
    second_event.parent = CaptureParent::Event(first.event.event_id.clone());
    let second = CausalSourceEvent::new_chained(
        bind_event_id(run, second_event),
        HybridLogicalClock {
            physical_ns: 2,
            logical: 0,
        },
        1,
        None,
        Some(first.producer_hash().into()),
    )
    .unwrap();
    let source = capture_causal_source_jsonl(run, &[first, second]).unwrap();
    let limits = MergeLimits {
        max_edges: 1,
        ..MergeLimits::default()
    };
    let mut merger = CausalMerger::new(run, limits, MissingParentPolicy::Reject).unwrap();
    merger.ingest_source_jsonl(&source).unwrap();
    merger.finalize(ReplaySealInput::empty()).unwrap();
}

#[test]
fn verify_rejects_resealed_unsupported_claim_constants() {
    let source = capture_causal_source_jsonl(
        "run-semantics",
        &[causal_valid(
            "run-semantics",
            event(106, "producer", 0),
            1,
            0,
            0,
            CaptureParent::Root,
        )],
    )
    .unwrap();
    let mut merger = CausalMerger::new(
        "run-semantics",
        MergeLimits::default(),
        MissingParentPolicy::Reject,
    )
    .unwrap();
    merger.ingest_source_jsonl(&source).unwrap();
    let changed = reseal_terminal(&seal(&merger), |terminal| {
        terminal["claims"]["schemaVersion"] = "full-matrix-replay/999".into();
    });
    assert_eq!(
        smesh_a2a::verify_sealed_replay(&changed).unwrap_err(),
        smesh_a2a::ReplayError::UnsupportedSchema
    );
}

#[test]
fn verify_recomputes_recorded_decision_set_instead_of_trusting_claim() {
    let run = "run-derived-claims";
    let event = causal_valid(run, event(107, "producer", 0), 1, 0, 0, CaptureParent::Root);
    let event = CausalSourceEvent::new(
        event.event,
        event.hlc,
        event.lamport,
        Some(serde_json::json!({"result":"allow"})),
    )
    .unwrap();
    let source = capture_causal_source_jsonl(run, &[event]).unwrap();
    let mut merger =
        CausalMerger::new(run, MergeLimits::default(), MissingParentPolicy::Reject).unwrap();
    merger.ingest_source_jsonl(&source).unwrap();
    let changed = reseal_data_line(&seal(&merger), 0, |record| {
        // Change a semantic field while retaining stale producer and decision claims.
        record["causal"]["recordedDecision"]["result"] = "deny".into();
    });
    assert!(smesh_a2a::verify_sealed_replay(&changed).is_err());
}

#[test]
fn verifier_rejects_resealed_child_before_parent_order() {
    let bundle =
        std::fs::read("demo/fixtures/full-matrix-replay-v1/expected.bundle.jsonl").unwrap();
    let mut lines: Vec<Vec<u8>> = bundle[..bundle.len() - 1]
        .split(|byte| *byte == b'\n')
        .map(<[u8]>::to_vec)
        .collect();
    let terminal_index = lines.len() - 1;
    lines.swap(0, 1);
    for (index, line) in lines[..terminal_index].iter_mut().enumerate() {
        let mut record: serde_json::Value = serde_json::from_slice(line).unwrap();
        record["mergeSequence"] = index.to_string().into();
        *line = serde_json::to_vec(&record).unwrap();
    }
    let mut merged = lines[..terminal_index].join(&b'\n');
    merged.push(b'\n');
    let mut terminal: serde_json::Value = serde_json::from_slice(&lines[terminal_index]).unwrap();
    terminal["claims"]["mergedJsonlDigest"] = protocol_hash("merged-jsonl", &[&merged]).into();
    terminal["claims"]["merkleRoot"] = test_merkle_root(&lines[..terminal_index]).into();
    terminal["sealDigest"] = protocol_hash(
        "run-seal",
        &[&serde_json::to_vec(&terminal["claims"]).unwrap()],
    )
    .into();
    lines[terminal_index] = serde_json::to_vec(&terminal).unwrap();
    let mut reordered = lines.join(&b'\n');
    reordered.push(b'\n');
    assert!(smesh_a2a::verify_sealed_replay(&reordered).is_err());
}

#[test]
fn verifier_rejects_closed_schema_sequence_and_derived_head_corruption() {
    let run = "run-corruption-matrix";
    let source = capture_causal_source_jsonl(
        run,
        &[causal_valid(
            run,
            event(112, "producer", 0),
            1,
            0,
            0,
            CaptureParent::Root,
        )],
    )
    .unwrap();
    let mut merger =
        CausalMerger::new(run, MergeLimits::default(), MissingParentPolicy::Reject).unwrap();
    merger.ingest_source_jsonl(&source).unwrap();
    let bundle = seal(&merger);
    let unknown = reseal_data_line(&bundle, 0, |record| {
        record["causal"]["event"]["unknown"] = "forbidden".into();
    });
    let sequence = reseal_data_line(&bundle, 0, |record| {
        record["mergeSequence"] = "1".into();
    });
    let head = reseal_terminal(&bundle, |terminal| {
        terminal["claims"]["producerHeads"][0]["headHash"] = digest(7).into();
    });
    for corrupted in [&unknown, &sequence, &head] {
        assert!(smesh_a2a::verify_sealed_replay(corrupted).is_err());
    }
}

#[test]
fn source_capture_rejects_capacity_before_a_later_malformed_event() {
    let run = "run-incremental-capacity";
    let payload = "x".repeat(60_000);
    let mut events: Vec<_> = (0..280)
        .map(|index| {
            let capture = bind_event_id(
                run,
                event(
                    u8::try_from(index % 250 + 1).unwrap(),
                    &format!("producer-{index}"),
                    0,
                ),
            );
            CausalSourceEvent::new(
                capture,
                HybridLogicalClock {
                    physical_ns: u64::try_from(index + 1).unwrap(),
                    logical: 0,
                },
                0,
                Some(serde_json::json!({"padding": payload})),
            )
            .unwrap()
        })
        .collect();
    events.last_mut().unwrap().recorded_decision = Some(serde_json::json!(1));

    assert_eq!(
        capture_causal_source_jsonl(run, &events).unwrap_err(),
        smesh_a2a::ReplayError::CapacityExhausted
    );
}

#[test]
fn in_memory_constructor_rejects_an_oversized_recorded_decision() {
    let result = CausalSourceEvent::new(
        event(71, "producer", 0),
        HybridLogicalClock {
            physical_ns: 1,
            logical: 0,
        },
        0,
        Some(serde_json::json!({"padding": "x".repeat(64 * 1024)})),
    );

    assert_eq!(
        result.unwrap_err(),
        smesh_a2a::ReplayError::CapacityExhausted
    );
}

#[test]
fn in_memory_constructor_rejects_excessive_recorded_decision_depth() {
    let mut decision = serde_json::Value::Null;
    for _ in 0..65 {
        decision = serde_json::Value::Array(vec![decision]);
    }
    let result = CausalSourceEvent::new(
        event(72, "producer", 0),
        HybridLogicalClock {
            physical_ns: 1,
            logical: 0,
        },
        0,
        Some(decision),
    );

    assert_eq!(result.unwrap_err(), smesh_a2a::ReplayError::Malformed);
}

#[test]
fn deeply_nested_rejected_decision_is_dropped_without_stack_overflow() {
    const CHILD: &str = "SMESH_REPLAY_DEEP_DROP_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let mut decision = serde_json::Value::Null;
        for _ in 0..100_000 {
            decision = serde_json::Value::Array(vec![decision]);
        }
        assert_eq!(
            CausalSourceEvent::new(
                event(74, "producer", 0),
                HybridLogicalClock {
                    physical_ns: 1,
                    logical: 0,
                },
                0,
                Some(decision),
            )
            .unwrap_err(),
            smesh_a2a::ReplayError::Malformed
        );
        return;
    }

    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("deeply_nested_rejected_decision_is_dropped_without_stack_overflow")
        .arg("--test-threads=1")
        .env(CHILD, "1")
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn source_capture_revalidates_mutated_recorded_decision_capacity() {
    let run = "run-mutated-decision";
    let mut source = CausalSourceEvent::new(
        bind_event_id(run, event(73, "producer", 0)),
        HybridLogicalClock {
            physical_ns: 1,
            logical: 0,
        },
        0,
        None,
    )
    .unwrap();
    source.recorded_decision = Some(serde_json::json!({"padding": "x".repeat(64 * 1024)}));

    assert_eq!(
        capture_causal_source_jsonl(run, &[source]).unwrap_err(),
        smesh_a2a::ReplayError::CapacityExhausted
    );
}

#[test]
fn verification_rejects_total_input_above_protocol_bound_before_parsing() {
    let oversized = vec![b' '; 16 * 1024 * 1024 + 1];
    assert_eq!(
        smesh_a2a::verify_sealed_replay(&oversized).unwrap_err(),
        smesh_a2a::ReplayError::CapacityExhausted
    );
}

#[test]
fn verification_rejects_excess_lines_before_a_later_malformed_line() {
    let mut hostile = Vec::new();
    for _ in 0..100_002 {
        hostile.extend_from_slice(b"{}\n");
    }
    hostile.push(b'\n');
    assert_eq!(
        smesh_a2a::verify_sealed_replay(&hostile).unwrap_err(),
        smesh_a2a::ReplayError::CapacityExhausted
    );
}

#[test]
fn source_ingestion_rejects_excess_lines_before_a_later_malformed_line() {
    let mut hostile = Vec::new();
    for _ in 0..100_002 {
        hostile.extend_from_slice(b"{}\n");
    }
    hostile.push(b'\n');
    let mut merger = CausalMerger::new(
        "run-line-cap",
        MergeLimits::default(),
        MissingParentPolicy::Reject,
    )
    .unwrap();
    assert_eq!(
        merger.ingest_source_jsonl(&hostile).unwrap_err(),
        smesh_a2a::ReplayError::CapacityExhausted
    );
}

#[test]
fn every_committed_byte_and_terminal_newline_are_verified() {
    let source = capture_causal_source_jsonl(
        "run-tamper",
        &[causal_valid(
            "run-tamper",
            event(70, "producer", 0),
            1,
            0,
            0,
            CaptureParent::Root,
        )],
    )
    .unwrap();
    let mut merger = CausalMerger::new(
        "run-tamper",
        MergeLimits::default(),
        MissingParentPolicy::Reject,
    )
    .unwrap();
    merger.ingest_source_jsonl(&source).unwrap();
    let bundle = seal(&merger);
    for index in [0, bundle.len() / 2, bundle.len() - 2] {
        let mut changed = bundle.clone();
        changed[index] ^= 1;
        assert!(smesh_a2a::verify_sealed_replay(&changed).is_err());
    }
    assert!(smesh_a2a::verify_sealed_replay(&bundle[..bundle.len() - 1]).is_err());
}

#[test]
fn persistence_rejects_bare_relative_path_before_publication() {
    let path = std::path::Path::new(".issue-24-relative-bundle.jsonl");
    let _ = std::fs::remove_file(path);
    let source = capture_causal_source_jsonl(
        "run-relative",
        &[causal_valid(
            "run-relative",
            event(109, "producer", 0),
            1,
            0,
            0,
            CaptureParent::Root,
        )],
    )
    .unwrap();
    let mut merger = CausalMerger::new(
        "run-relative",
        MergeLimits::default(),
        MissingParentPolicy::Reject,
    )
    .unwrap();
    merger.ingest_source_jsonl(&source).unwrap();
    let replay = merger.finalize(ReplaySealInput::empty()).unwrap();
    assert_eq!(
        replay.persist_new(path).unwrap_err(),
        smesh_a2a::ReplayError::Persistence
    );
    assert!(!path.exists());
}

#[test]
#[cfg(unix)]
fn persistence_rejects_group_or_world_accessible_parent() {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("smesh-replay-untrusted-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777)).unwrap();
    let source = capture_causal_source_jsonl(
        "run-untrusted-parent",
        &[causal_valid(
            "run-untrusted-parent",
            event(110, "producer", 0),
            1,
            0,
            0,
            CaptureParent::Root,
        )],
    )
    .unwrap();
    let mut merger = CausalMerger::new(
        "run-untrusted-parent",
        MergeLimits::default(),
        MissingParentPolicy::Reject,
    )
    .unwrap();
    merger.ingest_source_jsonl(&source).unwrap();
    let replay = merger.finalize(ReplaySealInput::empty()).unwrap();
    assert_eq!(
        replay.persist_new(&root.join("bundle.jsonl")).unwrap_err(),
        smesh_a2a::ReplayError::Persistence
    );
    assert!(!root.join("bundle.jsonl").exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg(unix)]
fn concurrent_create_new_has_one_winner_and_verified_bytes() {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Barrier};
    let run = "run-persist-race";
    let source = capture_causal_source_jsonl(
        run,
        &[causal_valid(
            run,
            event(113, "producer", 0),
            1,
            0,
            0,
            CaptureParent::Root,
        )],
    )
    .unwrap();
    let mut merger =
        CausalMerger::new(run, MergeLimits::default(), MissingParentPolicy::Reject).unwrap();
    merger.ingest_source_jsonl(&source).unwrap();
    let replay = merger.finalize(ReplaySealInput::empty()).unwrap();
    let root = std::env::temp_dir().join(format!("smesh-replay-race-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.join("bundle.jsonl");
    let barrier = Arc::new(Barrier::new(2));
    let results = std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            barrier.wait();
            replay.persist_new(&path)
        });
        let second = scope.spawn(|| {
            barrier.wait();
            replay.persist_new(&path)
        });
        [first.join().unwrap(), second.join().unwrap()]
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(smesh_a2a::ReplayError::AlreadyExists)))
            .count(),
        1
    );
    assert_eq!(std::fs::read(&path).unwrap(), replay.bundle_jsonl());
    assert!(smesh_a2a::verify_sealed_replay(&std::fs::read(&path).unwrap()).is_ok());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg(unix)]
fn published_temporary_hard_link_can_be_reconciled_by_token() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let token = "0123456789abcdef0123456789abcdef";
    let root = std::env::temp_dir().join(format!(
        "smesh-replay-published-cleanup-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.join("bundle.jsonl");
    let temporary = root.join(format!(".bundle.jsonl.{token}.tmp"));
    std::fs::write(&temporary, b"private replay bytes").unwrap();
    std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::hard_link(&temporary, &path).unwrap();

    reconcile_published_replay_temporary(&path, token).unwrap();

    assert!(!temporary.exists());
    assert_eq!(std::fs::read(&path).unwrap(), b"private replay bytes");
    assert_eq!(std::fs::metadata(&path).unwrap().nlink(), 1);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg(unix)]
fn unpublished_temporary_can_be_reconciled_after_another_writer_publishes() {
    use std::os::unix::fs::PermissionsExt;

    let token = "fedcba9876543210fedcba9876543210";
    let root = std::env::temp_dir().join(format!(
        "smesh-replay-unpublished-cleanup-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.join("bundle.jsonl");
    let temporary = root.join(format!(".bundle.jsonl.{token}.tmp"));
    std::fs::write(&temporary, b"stale private bytes").unwrap();
    std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&path, b"winner bytes").unwrap();

    reconcile_unpublished_replay_temporary(&path, token).unwrap();

    assert!(!temporary.exists());
    assert_eq!(std::fs::read(&path).unwrap(), b"winner bytes");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg(unix)]
fn published_reconciliation_preserves_a_lone_temp_when_destination_is_missing() {
    use std::os::unix::fs::PermissionsExt;

    let token = "11111111111111111111111111111111";
    let root = std::env::temp_dir().join(format!(
        "smesh-replay-published-lone-temp-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.join("bundle.jsonl");
    let temporary = root.join(format!(".bundle.jsonl.{token}.tmp"));
    std::fs::write(&temporary, b"only surviving replay bytes").unwrap();
    std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600)).unwrap();

    assert_eq!(
        reconcile_published_replay_temporary(&path, token),
        Err(smesh_a2a::ReplayError::Persistence)
    );
    assert_eq!(
        std::fs::read(&temporary).unwrap(),
        b"only surviving replay bytes"
    );
    assert!(!path.exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg(unix)]
fn published_reconciliation_requires_a_valid_surviving_destination_when_temp_is_missing() {
    use std::os::unix::fs::PermissionsExt;

    let token = "22222222222222222222222222222222";
    let root = std::env::temp_dir().join(format!(
        "smesh-replay-published-missing-temp-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.join("bundle.jsonl");

    assert_eq!(
        reconcile_published_replay_temporary(&path, token),
        Err(smesh_a2a::ReplayError::Persistence)
    );

    std::fs::write(&path, b"surviving replay bytes").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    reconcile_published_replay_temporary(&path, token).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"surviving replay bytes");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg(not(unix))]
fn persistence_fails_closed_on_unsupported_platforms() {
    let source = capture_causal_source_jsonl(
        "run-unsupported-persistence",
        &[causal_valid(
            "run-unsupported-persistence",
            event(114, "producer", 0),
            1,
            0,
            0,
            CaptureParent::Root,
        )],
    )
    .unwrap();
    let mut merger = CausalMerger::new(
        "run-unsupported-persistence",
        MergeLimits::default(),
        MissingParentPolicy::Reject,
    )
    .unwrap();
    merger.ingest_source_jsonl(&source).unwrap();
    let replay = merger.finalize(ReplaySealInput::empty()).unwrap();
    let path = std::env::temp_dir().join("smesh-replay-unsupported.jsonl");
    let _ = std::fs::remove_file(&path);

    assert_eq!(
        replay.persist_new(&path).unwrap_err(),
        smesh_a2a::ReplayError::Persistence
    );
    assert!(!path.exists());
}

#[test]
#[cfg(unix)]
fn create_new_persistence_is_private_and_non_overwriting() {
    let source = capture_causal_source_jsonl(
        "run-persist",
        &[causal_valid(
            "run-persist",
            event(80, "producer", 0),
            1,
            0,
            0,
            CaptureParent::Root,
        )],
    )
    .unwrap();
    let mut merger = CausalMerger::new(
        "run-persist",
        MergeLimits::default(),
        MissingParentPolicy::Reject,
    )
    .unwrap();
    merger.ingest_source_jsonl(&source).unwrap();
    let replay = merger.finalize(ReplaySealInput::empty()).unwrap();
    let root = std::env::temp_dir().join(format!("smesh-replay-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = root.join("bundle.jsonl");
    replay.persist_new(&path).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), replay.bundle_jsonl());
    assert_eq!(
        replay.persist_new(&path).unwrap_err(),
        smesh_a2a::ReplayError::AlreadyExists
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn rust_matches_checked_in_cross_language_bundle_and_receipt() {
    let root = std::path::Path::new("demo/fixtures/full-matrix-replay-v1");
    let source_a = std::fs::read(root.join("source-a.jsonl")).unwrap();
    let source_b = std::fs::read(root.join("source-b.jsonl")).unwrap();
    let mut merger = CausalMerger::new(
        "cross-language-vector",
        MergeLimits::default(),
        MissingParentPolicy::Reject,
    )
    .unwrap();
    merger.ingest_source_jsonl(&source_b).unwrap();
    assert_eq!(merger.pending_count(), 1);
    merger.ingest_source_jsonl(&source_a).unwrap();
    let replay = merger.finalize(ReplaySealInput::empty()).unwrap();
    assert_eq!(
        replay.bundle_jsonl(),
        std::fs::read(root.join("expected.bundle.jsonl")).unwrap()
    );
    assert_eq!(
        replay.receipt_json(),
        std::fs::read(root.join("expected.receipt.json")).unwrap()
    );
    assert_eq!(
        smesh_a2a::verify_sealed_replay(replay.bundle_jsonl()).unwrap(),
        *replay.receipt()
    );
    assert_eq!(
        smesh_a2a::verify_replay_receipt(
            replay.bundle_jsonl(),
            &std::fs::read(root.join("expected.receipt.json")).unwrap(),
            Some(&replay.receipt().run_seal),
        )
        .unwrap(),
        *replay.receipt()
    );
}

#[test]
fn supplied_receipt_is_verified_against_bundle_and_pinned_seal() {
    let run = "run-receipt";
    let source = capture_causal_source_jsonl(
        run,
        &[causal_valid(
            run,
            event(108, "producer", 0),
            1,
            0,
            0,
            CaptureParent::Root,
        )],
    )
    .unwrap();
    let mut merger =
        CausalMerger::new(run, MergeLimits::default(), MissingParentPolicy::Reject).unwrap();
    merger.ingest_source_jsonl(&source).unwrap();
    let replay = merger.finalize(ReplaySealInput::empty()).unwrap();
    assert_eq!(
        smesh_a2a::verify_replay_receipt(
            replay.bundle_jsonl(),
            replay.receipt_json(),
            Some(&replay.receipt().run_seal),
        )
        .unwrap(),
        *replay.receipt()
    );
    let mut receipt: serde_json::Value = serde_json::from_slice(replay.receipt_json()).unwrap();
    receipt["runId"] = "other-run".into();
    let tampered = serde_json::to_vec(&receipt).unwrap();
    assert!(
        smesh_a2a::verify_replay_receipt(
            replay.bundle_jsonl(),
            &tampered,
            Some(&replay.receipt().run_seal),
        )
        .is_err()
    );
    assert!(
        smesh_a2a::verify_replay_receipt(
            replay.bundle_jsonl(),
            replay.receipt_json(),
            Some(&digest(9)),
        )
        .is_err()
    );
}

#[test]
fn projection_count_is_rejected_before_sorting_or_serialization() {
    let run = "run-projection-bound";
    let source = capture_causal_source_jsonl(
        run,
        &[causal_valid(
            run,
            event(111, "producer", 0),
            1,
            0,
            0,
            CaptureParent::Root,
        )],
    )
    .unwrap();
    let mut merger =
        CausalMerger::new(run, MergeLimits::default(), MissingParentPolicy::Reject).unwrap();
    merger.ingest_source_jsonl(&source).unwrap();
    let baseline = merger.finalize(ReplaySealInput::empty()).unwrap();
    let mut input = ReplaySealInput::empty();
    input.projections = (0..129)
        .map(|index| smesh_a2a::ProjectionReceipt {
            projector_id: format!("projector-{index}"),
            projector_version: "1".into(),
            input_digest: baseline.receipt().input_jsonl_digest.clone(),
            output_digest: digest(1),
            output_byte_length: 0,
        })
        .collect();
    assert_eq!(
        merger.finalize(input).unwrap_err(),
        smesh_a2a::ReplayError::CapacityExhausted
    );
}

#[test]
fn output_capacity_precedes_later_projection_validation() {
    let run = "run-output-capacity-first";
    let source = capture_causal_source_jsonl(
        run,
        &[causal_valid(
            run,
            event(89, "producer", 0),
            1,
            0,
            0,
            CaptureParent::Root,
        )],
    )
    .unwrap();
    let limits = MergeLimits {
        max_output_bytes: 1,
        ..MergeLimits::default()
    };
    let mut merger = CausalMerger::new(run, limits, MissingParentPolicy::Reject).unwrap();
    merger.ingest_source_jsonl(&source).unwrap();
    let mut input = ReplaySealInput::empty();
    input.projections = vec![smesh_a2a::ProjectionReceipt {
        projector_id: "later-invalid-projection".into(),
        projector_version: "1".into(),
        input_digest: digest(99),
        output_digest: digest(2),
        output_byte_length: 1,
    }];
    assert_eq!(
        merger.finalize(input).unwrap_err(),
        smesh_a2a::ReplayError::CapacityExhausted
    );
}

#[test]
fn projection_receipts_are_sorted_and_sealed_without_callbacks() {
    let source = capture_causal_source_jsonl(
        "run-projection",
        &[causal_valid(
            "run-projection",
            event(90, "producer", 0),
            1,
            0,
            0,
            CaptureParent::Root,
        )],
    )
    .unwrap();
    let mut merger = CausalMerger::new(
        "run-projection",
        MergeLimits::default(),
        MissingParentPolicy::Reject,
    )
    .unwrap();
    merger.ingest_source_jsonl(&source).unwrap();
    let baseline = merger.finalize(ReplaySealInput::empty()).unwrap();
    let input_digest = baseline.receipt().input_jsonl_digest.clone();
    let mut wrong = ReplaySealInput::empty();
    wrong.projections = vec![smesh_a2a::ProjectionReceipt {
        projector_id: "wrong".into(),
        projector_version: "1".into(),
        input_digest: digest(99),
        output_digest: digest(2),
        output_byte_length: 1,
    }];
    assert_eq!(
        merger.finalize(wrong).unwrap_err(),
        smesh_a2a::ReplayError::ProjectionMismatch
    );
    let mut input = ReplaySealInput::empty();
    input.projections = vec![
        smesh_a2a::ProjectionReceipt {
            projector_id: "zeta".into(),
            projector_version: "1".into(),
            input_digest: input_digest.clone(),
            output_digest: digest(2),
            output_byte_length: 8,
        },
        smesh_a2a::ProjectionReceipt {
            projector_id: "alpha".into(),
            projector_version: "2".into(),
            input_digest,
            output_digest: digest(3),
            output_byte_length: 5,
        },
    ];
    let replay = merger.finalize(input).unwrap();
    assert_eq!(replay.receipt().projections[0].projector_id, "alpha");
    assert_eq!(
        smesh_a2a::verify_sealed_replay(replay.bundle_jsonl()).unwrap(),
        *replay.receipt()
    );
}

#[test]
fn merkle_odd_leaf_vectors_for_one_two_three_and_five_records_are_fixed() {
    let mut roots = Vec::new();
    for count in [1_u8, 2, 3, 5] {
        let mut merger = CausalMerger::new(
            format!("run-merkle-{count}"),
            MergeLimits::default(),
            MissingParentPolicy::Reject,
        )
        .unwrap();
        for id in 1..=count {
            let source = capture_causal_source_jsonl(
                &format!("run-merkle-{count}"),
                &[causal_valid(
                    &format!("run-merkle-{count}"),
                    event(id, &format!("producer-{id}"), 0),
                    u64::from(id),
                    0,
                    0,
                    CaptureParent::Root,
                )],
            )
            .unwrap();
            merger.ingest_source_jsonl(&source).unwrap();
        }
        let bundle = seal(&merger);
        let terminal: serde_json::Value = serde_json::from_slice(
            bundle
                .split(|b| *b == b'\n')
                .nth(usize::from(count))
                .unwrap(),
        )
        .unwrap();
        roots.push(
            terminal["claims"]["merkleRoot"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    assert_eq!(
        roots,
        vec![
            "sha256:5a7041b6e11db15adff66052264e7b2774c087ce53bdb29ef592fd0afb30d8dc",
            "sha256:54bccba29893e1baba93cc5d45e9d1e2ea509b1cccea651df833c70d76742ffe",
            "sha256:408264297a52b49ca7ce60b106f32e14284ec90c4a848e198b71112737fabd0c",
            "sha256:a0ba9823790911a661f25ca9e8eb38cd5fb909f19f44332ff6d85f9aae3f2785",
        ]
    );
}

#[test]
fn duplicate_is_idempotent_but_complete_envelope_conflict_is_fatal() {
    let original = causal_valid(
        "run-duplicate",
        event(100, "producer", 0),
        1,
        0,
        0,
        CaptureParent::Root,
    );
    let exact =
        capture_causal_source_jsonl("run-duplicate", std::slice::from_ref(&original)).unwrap();
    let changed = CausalSourceEvent::new(
        original.event.clone(),
        HybridLogicalClock {
            physical_ns: 2,
            logical: 0,
        },
        0,
        None,
    )
    .unwrap();
    let conflict = capture_causal_source_jsonl("run-duplicate", &[changed]).unwrap();
    let mut merger = CausalMerger::new(
        "run-duplicate",
        MergeLimits::default(),
        MissingParentPolicy::Reject,
    )
    .unwrap();
    merger.ingest_source_jsonl(&exact).unwrap();
    let before = seal(&merger);
    merger.ingest_source_jsonl(&exact).unwrap();
    assert_eq!(seal(&merger), before);
    assert_eq!(
        merger.ingest_source_jsonl(&conflict).unwrap_err(),
        smesh_a2a::ReplayError::DuplicateConflict
    );
    assert_eq!(seal(&merger), before);
}

#[test]
fn exact_duplicate_batches_do_not_consume_source_event_or_byte_capacity() {
    let source = capture_causal_source_jsonl(
        "run-resource-idempotent",
        &[causal_valid(
            "run-resource-idempotent",
            event(104, "producer", 0),
            1,
            0,
            0,
            CaptureParent::Root,
        )],
    )
    .unwrap();
    let limits = MergeLimits {
        max_sources: 1,
        max_events: 1,
        max_input_bytes: source.len(),
        ..MergeLimits::default()
    };
    let mut merger = CausalMerger::new(
        "run-resource-idempotent",
        limits,
        MissingParentPolicy::Reject,
    )
    .unwrap();
    assert_eq!(merger.ingest_source_jsonl(&source).unwrap(), 1);
    let before = seal(&merger);
    assert_eq!(merger.ingest_source_jsonl(&source).unwrap(), 1);
    assert_eq!(seal(&merger), before);
}

#[test]
fn source_rejects_non_derived_event_id_and_cross_run_replay() {
    let forged = causal(event(105, "producer", 0), 1, 0, 0, CaptureParent::Root);
    assert_eq!(
        capture_causal_source_jsonl("run-identity-a", &[forged]).unwrap_err(),
        smesh_a2a::ReplayError::InvalidIdentifier
    );

    let source_event = causal_valid(
        "run-identity-a",
        event(105, "producer", 0),
        1,
        0,
        0,
        CaptureParent::Root,
    );
    let source = capture_causal_source_jsonl("run-identity-a", &[source_event]).unwrap();
    let mut merger = CausalMerger::new(
        "run-identity-b",
        MergeLimits::default(),
        MissingParentPolicy::Reject,
    )
    .unwrap();
    assert_eq!(
        merger.ingest_source_jsonl(&source).unwrap_err(),
        smesh_a2a::ReplayError::InvalidIdentifier
    );
}

#[test]
fn malformed_admission_is_atomic_and_hard_limits_cannot_be_weakened() {
    let source = capture_causal_source_jsonl(
        "run-limits",
        &[causal_valid(
            "run-limits",
            event(101, "producer", 0),
            1,
            0,
            0,
            CaptureParent::Root,
        )],
    )
    .unwrap();
    let limits = MergeLimits {
        max_sources: 1,
        ..MergeLimits::default()
    };
    let mut merger = CausalMerger::new("run-limits", limits, MissingParentPolicy::Reject).unwrap();
    let mut malformed = source.clone();
    malformed.pop();
    assert_eq!(
        merger.ingest_source_jsonl(&malformed).unwrap_err(),
        smesh_a2a::ReplayError::Malformed
    );
    merger.ingest_source_jsonl(&source).unwrap();
    let before = seal(&merger);
    assert_eq!(merger.ingest_source_jsonl(&source).unwrap(), 1);
    assert_eq!(seal(&merger), before);
    let defaults = MergeLimits::default();
    let too_large = MergeLimits {
        max_events: defaults.max_events + 1,
        ..defaults
    };
    assert_eq!(
        CausalMerger::new("run", too_large, MissingParentPolicy::Reject).err(),
        Some(smesh_a2a::ReplayError::CapacityExhausted)
    );
}

#[test]
fn noncanonical_decimal_and_clock_overflow_are_rejected() {
    let source = capture_causal_source_jsonl(
        "run-decimal",
        &[causal_valid(
            "run-decimal",
            event(102, "producer", 0),
            1,
            0,
            0,
            CaptureParent::Root,
        )],
    )
    .unwrap();
    let text = String::from_utf8(source)
        .unwrap()
        .replace("\"physicalNs\":\"1\"", "\"physicalNs\":\"01\"");
    let mut merger = CausalMerger::new(
        "run-decimal",
        MergeLimits::default(),
        MissingParentPolicy::Reject,
    )
    .unwrap();
    assert_eq!(
        merger.ingest_source_jsonl(text.as_bytes()).unwrap_err(),
        smesh_a2a::ReplayError::Malformed
    );
    let overflow = text.replace("\"01\"", "\"18446744073709551616\"");
    assert_eq!(
        merger.ingest_source_jsonl(overflow.as_bytes()).unwrap_err(),
        smesh_a2a::ReplayError::Malformed
    );
    assert_eq!(merger.pending_count(), 0);
}

#[test]
fn changed_recorded_decision_changes_the_run_seal_without_recalculation() {
    let base = bind_event_id("run-decision", event(103, "producer", 0));
    let make = |decision: &str| {
        CausalSourceEvent::new(
            base.clone(),
            HybridLogicalClock {
                physical_ns: 1,
                logical: 0,
            },
            0,
            Some(serde_json::json!({"algorithm":"captured-v1","result":decision})),
        )
        .unwrap()
    };
    let source_a = capture_causal_source_jsonl("run-decision", &[make("allow")]).unwrap();
    let source_b = capture_causal_source_jsonl("run-decision", &[make("deny")]).unwrap();
    let build = |source: &[u8]| {
        let mut merger = CausalMerger::new(
            "run-decision",
            MergeLimits::default(),
            MissingParentPolicy::Reject,
        )
        .unwrap();
        merger.ingest_source_jsonl(source).unwrap();
        merger.finalize(ReplaySealInput::empty()).unwrap()
    };
    let allow = build(&source_a);
    let deny = build(&source_b);
    assert_ne!(allow.receipt().run_seal, deny.receipt().run_seal);
    assert!(
        std::str::from_utf8(allow.bundle_jsonl())
            .unwrap()
            .contains("\"result\":\"allow\"")
    );
    assert!(
        std::str::from_utf8(deny.bundle_jsonl())
            .unwrap()
            .contains("\"result\":\"deny\"")
    );
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(64))]
    #[test]
    fn bounded_causal_chain_partitions_permutations_and_retries_preserve_exact_bytes(
        count in 1usize..9,
        order_keys in proptest::collection::vec(proptest::num::u8::ANY, 8),
        partition_width in 1usize..4,
        duplicate in proptest::bool::ANY,
    ) {
        let run = "run-property";
        let mut events = Vec::new();
        let mut previous_id = None;
        let mut previous_hash = None;
        for index in 0..count {
            let mut capture = event(
                u8::try_from(index + 1).unwrap(),
                "chained-producer",
                u64::try_from(index).unwrap(),
            );
            capture.parent = previous_id.clone().map_or(CaptureParent::Root, CaptureParent::Event);
            capture = bind_event_id(run, capture);
            let causal = CausalSourceEvent::new_chained(
                capture,
                HybridLogicalClock {
                    physical_ns: u64::try_from(index + 1).unwrap(),
                    logical: 0,
                },
                u64::try_from(index).unwrap(),
                None,
                previous_hash,
            )
            .unwrap();
            previous_id = Some(causal.event.event_id.clone());
            previous_hash = Some(causal.producer_hash().to_owned());
            events.push(causal);
        }
        let sources: Vec<_> = events
            .chunks(partition_width)
            .map(|partition| capture_causal_source_jsonl(run, partition).unwrap())
            .collect();
        let mut baseline = CausalMerger::new(run, MergeLimits::default(), MissingParentPolicy::Reject).unwrap();
        for source in &sources { baseline.ingest_source_jsonl(source).unwrap(); }
        let expected = seal(&baseline);
        let mut indices: Vec<_> = (0..sources.len()).collect();
        indices.sort_by_key(|index| (order_keys[*index], *index));
        let mut permuted = CausalMerger::new(run, MergeLimits::default(), MissingParentPolicy::Reject).unwrap();
        for index in &indices { permuted.ingest_source_jsonl(&sources[*index]).unwrap(); }
        if duplicate { permuted.ingest_source_jsonl(&sources[indices[0]]).unwrap(); }
        proptest::prop_assert_eq!(seal(&permuted), expected);
    }
}
