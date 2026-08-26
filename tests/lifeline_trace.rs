use std::collections::HashSet;
use std::fs;

use smesh_a2a::{generate_lifeline_trace, verify_trace};

#[test]
fn lifeline_trace_is_deterministic_complete_and_hash_chained() {
    let first = generate_lifeline_trace().unwrap();
    let second = generate_lifeline_trace().unwrap();

    assert_eq!(first, second);
    assert!(first.len() >= 30);
    verify_trace(&first).unwrap();

    let layers: HashSet<_> = first.iter().map(|event| event.layer.as_str()).collect();
    assert_eq!(
        layers,
        HashSet::from(["a2a", "smesh", "tool", "artifact", "human", "system"])
    );
    assert!(
        first
            .iter()
            .any(|event| event.kind == "system.endpoint.failed")
    );
    assert!(first.iter().any(|event| event.kind == "a2a.task.canceled"));
    assert!(
        first
            .iter()
            .any(|event| event.kind == "a2a.agent.fallback-discovered")
    );
    assert!(
        first
            .iter()
            .any(|event| event.kind == "human.decision.ratified")
    );
}

#[test]
fn trace_verifier_rejects_corrupted_content_hash() {
    let mut events = generate_lifeline_trace().unwrap();
    events[1].message.content_hash = Some("0".repeat(64));
    let error = verify_trace(&events).unwrap_err().to_string();
    assert!(error.contains("content hash mismatch"));
}

#[test]
fn trace_verifier_rejects_sequence_time_identity_and_chain_corruption() {
    let original = generate_lifeline_trace().unwrap();

    let mut bad_sequence = original.clone();
    bad_sequence[2].sequence += 1;
    assert!(verify_trace(&bad_sequence).is_err());

    let mut bad_time = original.clone();
    bad_time[2].sim_time_ms = 0;
    assert!(verify_trace(&bad_time).is_err());

    let mut duplicate_id = original.clone();
    let existing_id = duplicate_id[1].event_id.clone();
    duplicate_id[2].event_id = existing_id;
    assert!(verify_trace(&duplicate_id).is_err());

    let mut bad_chain = original;
    bad_chain[2].integrity.prev_hash = Some("f".repeat(64));
    assert!(verify_trace(&bad_chain).is_err());
}

#[test]
fn checked_in_trace_is_byte_identical_to_the_generator() {
    let events = generate_lifeline_trace().unwrap();
    let generated = events
        .iter()
        .map(|event| serde_json::to_string(event).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let fixture = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/demo/lifeline.trace.jsonl"
    ))
    .unwrap();
    assert_eq!(generated, fixture);
}
