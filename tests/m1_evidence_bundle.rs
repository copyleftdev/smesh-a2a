use std::path::Path;

use serde_json::Value;
use sha2::{Digest, Sha256};
use smesh_a2a::{RuntimeEventCapture, RuntimeTraceKind};

#[test]
fn checked_in_m1_bundle_hashes_and_runtime_replay_verify() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest_bytes = std::fs::read(root.join("evidence/m1/manifest.json")).unwrap();
    let manifest: Value = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(manifest["schema"], "smesh-a2a/m1-evidence/v1");

    for artifact in manifest["artifacts"].as_array().unwrap() {
        let path = artifact["path"].as_str().unwrap();
        let expected = artifact["sha256"].as_str().unwrap();
        let bytes = std::fs::read(root.join(path)).unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&bytes)), expected);
    }

    let trace_bytes = std::fs::read(root.join("evidence/m1/runtime-trace.json")).unwrap();
    let trace = RuntimeEventCapture::replay(&trace_bytes).unwrap();
    assert!(trace.capture_valid);
    assert!(trace.events.iter().any(|event| {
        event.kind == RuntimeTraceKind::SignalEmitted
            && event.task_id.as_deref() == Some("trace-task")
            && event.context_id.as_deref() == Some("trace-context")
            && event.signal_hash.is_some()
    }));

    let gates = manifest["mergedGates"].as_array().unwrap();
    assert_eq!(gates.len(), 6);
    assert_eq!(
        gates
            .iter()
            .map(|gate| gate["issue"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![2, 3, 4, 5, 6, 7]
    );
    assert!(gates.iter().all(|gate| {
        gate["pullRequest"].as_u64().is_some()
            && gate["mergeCommit"].as_str().is_some_and(|commit| {
                commit.len() == 40 && commit.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
            && (gate["ciRun"].as_u64().is_some() || gate["exception"].as_str().is_some())
    }));
}
