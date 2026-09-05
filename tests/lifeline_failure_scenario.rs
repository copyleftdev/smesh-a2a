use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use smesh_a2a::{LIFELINE_FAILURE_TRACE_SCHEMA_VERSION, verify_lifeline_failure_trace};
use wait_timeout::ChildExt as _;

const MANIFEST: &str = "deploy/lifeline-teams.json";

#[test]
fn one_command_failure_scenario_is_causal_bounded_and_private() {
    let parent = TempDir::new("process");
    let output = parent.path().join("run");
    let status = bounded_status(
        Command::new(env!("CARGO_BIN_EXE_lifeline-failure-scenario"))
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join(MANIFEST))
            .arg(&output),
    );
    assert!(status.success());

    let trace_path = output.join("restricted-scenario.jsonl");
    let events = verify_lifeline_failure_trace(&trace_path).unwrap();
    assert_eq!(
        events[0].schema_version(),
        LIFELINE_FAILURE_TRACE_SCHEMA_VERSION
    );
    assert!(events.len() <= 64);
    assert_eq!(
        events
            .iter()
            .map(smesh_a2a::LifelineFailureEvent::sequence)
            .collect::<Vec<_>>(),
        (1..=events.len() as u64).collect::<Vec<_>>()
    );
    let kinds = events
        .iter()
        .map(smesh_a2a::LifelineFailureEvent::kind)
        .collect::<HashSet<_>>();
    for required in [
        "primary-outage-observed",
        "primary-stream-failed",
        "cancel-requested",
        "late-output-fenced",
        "internal-processor-stopped",
        "cancel-confirmed",
        "fallback-selected",
        "fallback-submitted",
        "fallback-completed",
        "sibling-submitted",
        "sibling-completed",
        "primary-final-reconciled",
        "scenario-completed",
    ] {
        assert!(kinds.contains(required), "missing {required}");
    }
    let position = |kind| {
        events
            .iter()
            .position(|event| event.kind() == kind)
            .unwrap()
    };
    assert!(position("cancel-requested") < position("internal-processor-stopped"));
    assert!(position("internal-processor-stopped") < position("cancel-confirmed"));
    assert!(position("cancel-confirmed") < position("fallback-selected"));
    assert!(position("fallback-completed") < position("primary-final-reconciled"));
    let stream_failure = events
        .iter()
        .find(|event| event.kind() == "primary-stream-failed")
        .unwrap();
    assert_eq!(stream_failure.outcome(), "error");

    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output.join("run.json")).unwrap()).unwrap();
    assert_eq!(run["schemaVersion"], "lifeline-failure-scenario-run/1");
    assert_eq!(run["primaryFinalState"], "canceled");
    assert_eq!(run["fallbackAttempts"], 1);
    assert_eq!(run["primaryAttempts"], 1);
    assert_eq!(run["siblingDispatches"], 3);
    assert_eq!(run["rootContextRestarts"], 0);
    assert_ne!(run["primaryTaskId"], run["fallbackTaskId"]);
    assert_eq!(run["rootContextId"], run["fallbackContextId"]);
    assert_eq!(run["fallbackReplacesTaskId"], run["primaryTaskId"]);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&trace_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(output.join("run.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)] // Keep the closed-protocol mutation matrix together.
fn trace_verification_rejects_tamper_order_parent_and_missing_failure_evidence() {
    let parent = TempDir::new("tamper");
    let output = parent.path().join("run");
    let status = bounded_status(
        Command::new(env!("CARGO_BIN_EXE_lifeline-failure-scenario"))
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join(MANIFEST))
            .arg(&output),
    );
    assert!(status.success());
    let source = std::fs::read_to_string(output.join("restricted-scenario.jsonl")).unwrap();
    let lines = source.lines().collect::<Vec<_>>();
    let primary_task_id = lines
        .iter()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|event| event["kind"] == "primary-submitted")
        .unwrap()["taskId"]
        .clone();

    let cases = [
        (
            "tamper",
            source.replacen("\"outcome\":\"canceled\"", "\"outcome\":\"completed\"", 1),
        ),
        ("blank-line", source.replacen('\n', "\n\n", 1)),
        (
            "closed-stream-is-not-a-failure-observation",
            mutate_event(
                &source,
                "primary-stream-failed",
                "outcome",
                &serde_json::Value::String("closed".to_owned()),
            ),
        ),
        (
            "sibling-gateway",
            source.replacen(
                "\"gatewayId\":\"meridian\"",
                "\"gatewayId\":\"atlas-fallback\"",
                1,
            ),
        ),
        (
            "primary-replacement",
            mutate_event(
                &source,
                "primary-submitted",
                "replacesTaskId",
                &serde_json::Value::String("forged-task".to_owned()),
            ),
        ),
        (
            "order",
            lines.iter().rev().copied().collect::<Vec<_>>().join("\n") + "\n",
        ),
        (
            "parent",
            source.replacen(
                "\"parentEventId\":\"event-1\"",
                "\"parentEventId\":\"event-999\"",
                1,
            ),
        ),
        (
            "omission",
            lines
                .iter()
                .copied()
                .filter(|line| !line.contains("internal-processor-stopped"))
                .collect::<Vec<_>>()
                .join("\n")
                + "\n",
        ),
        (
            "sibling-submission-omission",
            remove_kind_and_resequence(&source, "sibling-submitted"),
        ),
        (
            "sibling-completes-after-fallback",
            move_first_kind_after_and_resequence(&source, "sibling-completed", "fallback-selected"),
        ),
        (
            "no-fallback",
            lines
                .iter()
                .copied()
                .filter(|line| !line.contains("fallback-completed"))
                .collect::<Vec<_>>()
                .join("\n")
                + "\n",
        ),
        (
            "fallback-failed",
            source.replacen(
                "\"kind\":\"fallback-completed\"",
                "\"kind\":\"fallback-selected\"",
                1,
            ),
        ),
        (
            "fallback-reuses-primary-task",
            mutate_event(&source, "fallback-completed", "taskId", &primary_task_id),
        ),
        (
            "tertiary-attempt",
            source.replacen("\"attempt\":1", "\"attempt\":2", 1),
        ),
    ];
    for (label, bytes) in cases {
        let path = parent.path().join(format!("{label}.jsonl"));
        std::fs::write(&path, bytes).unwrap();
        assert!(
            verify_lifeline_failure_trace(&path).is_err(),
            "accepted {label}"
        );
    }
}

#[test]
fn one_command_verifier_replays_persisted_evidence() {
    let parent = TempDir::new("replay");
    let output = parent.path().join("run");
    let status = bounded_status(
        Command::new(env!("CARGO_BIN_EXE_lifeline-failure-scenario"))
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("deploy/lifeline-teams.json"))
            .arg(&output),
    );
    assert!(status.success());

    let verify = bounded_status(
        Command::new(env!("CARGO_BIN_EXE_lifeline-failure-scenario"))
            .arg("verify")
            .arg(output.join("run.json"))
            .arg(output.join("restricted-scenario.jsonl")),
    );
    assert!(verify.success());
}

#[test]
fn run_receipt_readback_rejects_downgrade_and_trace_mismatch() {
    let parent = TempDir::new("run-verification");
    let first_output = parent.path().join("first");
    let second_output = parent.path().join("second");
    for output in [&first_output, &second_output] {
        let status = bounded_status(
            Command::new(env!("CARGO_BIN_EXE_lifeline-failure-scenario"))
                .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join(MANIFEST))
                .arg(output),
        );
        assert!(status.success());
    }
    let first_events =
        verify_lifeline_failure_trace(&first_output.join("restricted-scenario.jsonl")).unwrap();
    let second_events =
        verify_lifeline_failure_trace(&second_output.join("restricted-scenario.jsonl")).unwrap();
    let run_bytes = std::fs::read(first_output.join("run.json")).unwrap();
    let run: smesh_a2a::LifelineFailureScenarioRun = serde_json::from_slice(&run_bytes).unwrap();
    assert!(run.verify(&first_events).is_ok());
    assert!(run.verify(&second_events).is_err());

    let mut changed_operation: serde_json::Value = serde_json::from_slice(&run_bytes).unwrap();
    let primary_receipt = changed_operation["directorRun"]["initialOperations"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|receipt| receipt["gatewayId"] == "atlas-primary")
        .unwrap();
    primary_receipt["operationId"] =
        serde_json::Value::String("forged-primary-operation".to_owned());
    let changed_operation: smesh_a2a::LifelineFailureScenarioRun =
        serde_json::from_value(changed_operation).unwrap();
    assert!(changed_operation.verify(&first_events).is_err());

    let mut changed_discovery: serde_json::Value = serde_json::from_slice(&run_bytes).unwrap();
    changed_discovery["directorRun"]["discoveredGateways"][0]["discoveryUrl"] =
        serde_json::Value::String("http://example.com".to_owned());
    let changed_discovery: smesh_a2a::LifelineFailureScenarioRun =
        serde_json::from_value(changed_discovery).unwrap();
    assert!(changed_discovery.verify(&first_events).is_err());

    let mut missing_review_references: serde_json::Value =
        serde_json::from_slice(&run_bytes).unwrap();
    missing_review_references["directorRun"]["review"]["referenceTaskIds"] =
        serde_json::Value::Array(Vec::new());
    let missing_review_references: smesh_a2a::LifelineFailureScenarioRun =
        serde_json::from_value(missing_review_references).unwrap();
    assert!(missing_review_references.verify(&first_events).is_err());

    let mut wrong_binding: serde_json::Value = serde_json::from_slice(&run_bytes).unwrap();
    let primary_receipt = wrong_binding["directorRun"]["initialOperations"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|receipt| receipt["gatewayId"] == "atlas-primary")
        .unwrap();
    primary_receipt["binding"] = serde_json::Value::String("HTTP+JSON".to_owned());
    let wrong_binding: smesh_a2a::LifelineFailureScenarioRun =
        serde_json::from_value(wrong_binding).unwrap();
    assert!(wrong_binding.verify(&first_events).is_err());

    let mut duplicate_sibling: serde_json::Value = serde_json::from_slice(&run_bytes).unwrap();
    let operations = duplicate_sibling["directorRun"]["initialOperations"]
        .as_array_mut()
        .unwrap();
    let sibling_indexes = operations
        .iter()
        .enumerate()
        .filter_map(|(index, receipt)| (receipt["gatewayId"] != "atlas-primary").then_some(index))
        .collect::<Vec<_>>();
    operations[sibling_indexes[1]] = operations[sibling_indexes[0]].clone();
    let mut references = operations
        .iter()
        .map(|receipt| receipt["taskId"].clone())
        .collect::<Vec<_>>();
    references.push(duplicate_sibling["directorRun"]["fallbackOperation"]["taskId"].clone());
    references.sort_by_key(serde_json::Value::to_string);
    references.dedup();
    duplicate_sibling["directorRun"]["review"]["referenceTaskIds"] =
        serde_json::Value::Array(references);
    let duplicate_sibling: smesh_a2a::LifelineFailureScenarioRun =
        serde_json::from_value(duplicate_sibling).unwrap();
    assert!(duplicate_sibling.verify(&first_events).is_err());

    let mut downgraded: serde_json::Value = serde_json::from_slice(&run_bytes).unwrap();
    downgraded["primaryFinalState"] = serde_json::Value::String("completed".to_owned());
    let downgraded: smesh_a2a::LifelineFailureScenarioRun =
        serde_json::from_value(downgraded).unwrap();
    assert!(downgraded.verify(&first_events).is_err());
}

#[test]
fn output_collision_fails_closed_without_replacing_existing_data() {
    let parent = TempDir::new("output-collision");
    let output = parent.path().join("occupied");
    std::fs::create_dir(&output).unwrap();
    std::fs::write(output.join("sentinel"), b"keep\n").unwrap();
    let status = bounded_status(
        Command::new(env!("CARGO_BIN_EXE_lifeline-failure-scenario"))
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join(MANIFEST))
            .arg(&output),
    );
    assert!(!status.success());
    assert_eq!(std::fs::read(output.join("sentinel")).unwrap(), b"keep\n");
    assert!(!output.join("restricted-scenario.jsonl").exists());
}

fn bounded_status(command: &mut Command) -> std::process::ExitStatus {
    let mut child = command.spawn().unwrap();
    child
        .wait_timeout(Duration::from_secs(20))
        .unwrap()
        .unwrap_or_else(|| {
            let _ = child.kill();
            let _ = child.wait();
            panic!("failure scenario watchdog expired")
        })
}

fn mutate_event(source: &str, kind: &str, field: &str, value: &serde_json::Value) -> String {
    source
        .lines()
        .map(|line| {
            let mut event = serde_json::from_str::<serde_json::Value>(line).unwrap();
            if event["kind"] == kind {
                event[field] = value.clone();
            }
            serde_json::to_string(&event).unwrap()
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn remove_kind_and_resequence(source: &str, kind: &str) -> String {
    let mut events = source
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|event| event["kind"] != kind)
        .collect::<Vec<_>>();
    for (index, event) in events.iter_mut().enumerate() {
        let sequence = u64::try_from(index + 1).unwrap();
        event["sequence"] = serde_json::Value::from(sequence);
        event["eventId"] = serde_json::Value::String(format!("event-{sequence}"));
        event["parentEventId"] = if index == 0 {
            serde_json::Value::Null
        } else {
            serde_json::Value::String(format!("event-{index}"))
        };
    }
    events
        .into_iter()
        .map(|event| serde_json::to_string(&event).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn move_first_kind_after_and_resequence(source: &str, moved: &str, after: &str) -> String {
    let mut events = source
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    let moved_index = events
        .iter()
        .position(|event| event["kind"] == moved)
        .unwrap();
    let moved_event = events.remove(moved_index);
    let after_index = events
        .iter()
        .position(|event| event["kind"] == after)
        .unwrap();
    events.insert(after_index + 1, moved_event);
    for (index, event) in events.iter_mut().enumerate() {
        let sequence = u64::try_from(index + 1).unwrap();
        event["sequence"] = serde_json::Value::from(sequence);
        event["eventId"] = serde_json::Value::String(format!("event-{sequence}"));
        event["parentEventId"] = if index == 0 {
            serde_json::Value::Null
        } else {
            serde_json::Value::String(format!("event-{index}"))
        };
    }
    events
        .into_iter()
        .map(|event| serde_json::to_string(&event).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

struct TempDir(PathBuf);
impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "smesh-lifeline-failure-{label}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(path)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
