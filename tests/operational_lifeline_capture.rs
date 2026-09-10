use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

#[allow(dead_code)]
#[path = "support/process.rs"]
mod process;

const OPERATIONAL_BIN: Option<&str> = option_env!("CARGO_BIN_EXE_operational-lifeline-capture");
const CONTEXT_FOR_TEST: &str = "lifeline-incident-0047";
const GENERATED_ARTIFACTS: [&str; 18] = [
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
    "restricted/source-facts.json",
    "restricted/review-packet.json",
    "restricted/review-receipt.json",
    "restricted/sealed-replay.jsonl",
];

#[cfg(target_os = "linux")]
#[test]
fn capture_command_lifecycle_reaps_planted_descendant_after_leader_exit() {
    let fixture = TempDir::new("capture-command-descendant");
    let marker = fixture.path().join("descendant-pid");
    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            "sleep 30 & printf '%s' \"$!\" > \"$1\"; exit 0",
            "capture-command-descendant",
        ])
        .arg(&marker);

    bounded(&mut command);

    let pid = std::fs::read_to_string(marker).unwrap();
    let proc_entry = Path::new("/proc").join(pid.trim());
    let survived = proc_entry.exists();
    if survived {
        let _ = Command::new("/bin/kill")
            .args(["-KILL", pid.trim()])
            .status();
    }
    assert!(!survived, "capture command descendant survived leader exit");
}

#[test]
#[allow(clippy::too_many_lines)] // End-to-end evidence assertions intentionally remain in one scenario.
fn six_gateway_operational_capture_is_real_private_and_deterministic() {
    let fixture = TempDir::new("e2e");
    let first = run_once(fixture.path(), "first");
    let second = run_once(fixture.path(), "second");
    let checked =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("demo/fixtures/operational-lifeline-v1");

    assert_eq!(generated_artifacts(&first), GENERATED_ARTIFACTS);
    assert_eq!(generated_artifacts(&second), GENERATED_ARTIFACTS);
    assert_eq!(generated_artifacts(&checked), GENERATED_ARTIFACTS);
    assert!(
        checked.join("README.md").is_file(),
        "the documentation-only file is explicit and not generated"
    );
    for name in GENERATED_ARTIFACTS {
        assert_eq!(
            std::fs::read(first.join(name)).unwrap(),
            std::fs::read(second.join(name)).unwrap(),
            "{name} differs across two regenerations"
        );
        assert_eq!(
            std::fs::read(first.join(name)).unwrap(),
            std::fs::read(checked.join(name)).unwrap(),
            "{name} differs from the checked production fixture"
        );
    }

    let actors: serde_json::Value = read_json(&first.join("actors.json"));
    assert_eq!(actors["sites"].as_array().unwrap().len(), 6);
    let site_ids = actors["sites"]
        .as_array()
        .unwrap()
        .iter()
        .map(|site| site["siteId"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        site_ids,
        BTreeSet::from([
            "atlas-fallback",
            "atlas-primary",
            "harbor",
            "helix",
            "meridian",
            "sentinel"
        ])
    );

    let package = std::fs::read_to_string(first.join("package.jsonl")).unwrap();
    assert!(!package.contains("lifeline.trace.jsonl"));
    assert!(!package.contains("authorization"));
    assert!(!package.contains("credential"));
    let records = package
        .lines()
        .skip(1)
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 46);
    let primary = records
        .iter()
        .find(|record| record["taskId"] == "lifeline-task-shipment-routing")
        .expect("authoritative primary task identity was discarded");
    assert_eq!(primary["interactionId"], "event-4");
    assert_eq!(primary["subjectId"], "lifeline-message-shipment-routing");
    assert_eq!(primary["contextId"], CONTEXT_FOR_TEST);
    let replacement = records
        .iter()
        .find(|record| record["subjectId"] == "lifeline-task-shipment-routing")
        .expect("authoritative replacement identity was discarded");
    assert_eq!(replacement["interactionId"], "event-14");
    assert!(!records.iter().any(|record| {
        record["interactionId"]
            .as_str()
            .is_some_and(|identity| identity.starts_with("official-a2a-"))
    }));
    let kinds = records
        .iter()
        .filter_map(|record| record["kind"].as_str())
        .collect::<HashSet<_>>();
    for required in [
        "a2aSend",
        "smeshSignalEmitted",
        "smeshTickCompleted",
        "toolCall",
        "toolResult",
        "artifactProduced",
        "humanPrompt",
        "humanDecision",
    ] {
        assert!(kinds.contains(required), "missing {required}");
    }
    let text = records
        .iter()
        .map(serde_json::Value::to_string)
        .collect::<String>();
    for required in [
        "event-5",
        "event-6",
        "event-7",
        "event-8",
        "event-10",
        "event-15",
        "event-16",
        "lifeline-task-shipment-routing",
        "lifeline-task-shipment-routing-fallback",
    ] {
        assert!(text.contains(required), "missing {required}");
    }
    assert!(!text.contains("restricted-source-signal-id-"));
    let restricted_sources = records
        .iter()
        .filter(|record| {
            record["sourceFacts"]["fieldRestrictions"]
                .as_array()
                .is_some_and(|items| !items.is_empty())
        })
        .collect::<Vec<_>>();
    assert_eq!(restricted_sources.len(), 5);
    assert!(restricted_sources.iter().all(|record| {
        record["subjectId"].is_null()
            && record["sourceFacts"]["fieldRestrictions"][0]["field"] == "subjectId"
            && record["sourceFacts"]["fieldRestrictions"][0]["reason"]
                == "sourceIdentifierUnavailable"
    }));
    let facts = read_json(&first.join("restricted/source-facts.json"));
    assert_eq!(facts["entries"].as_array().unwrap().len(), 24);
    let canonical_capture =
        std::fs::read_to_string(first.join("restricted/canonical-capture.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter_map(|record| record.get("event").cloned())
            .collect::<Vec<_>>();
    let mut observed_tool_results = 0;
    for team in ["atlas", "harbor", "helix", "meridian", "sentinel"] {
        let journal = std::fs::read_to_string(
            fixture
                .path()
                .join(format!("first-scenario/journals/{team}.jsonl")),
        )
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
        let call_record = journal
            .iter()
            .find(|record| record["kind"] == "tool_called")
            .unwrap();
        let call_sequence = call_record["sequence"].as_u64().unwrap();
        let completion_record = journal
            .iter()
            .find(|record| record["kind"] == "tool_completed")
            .unwrap();
        let completion_sequence = completion_record["sequence"].as_u64().unwrap();
        assert_eq!(completion_sequence, call_sequence + 1);
        let interaction_id = format!("journal-tool-{team}-{call_sequence}");
        let pair = canonical_capture
            .iter()
            .filter(|event| event["interactionId"] == interaction_id)
            .collect::<Vec<_>>();
        assert_eq!(pair.len(), 2);
        assert_eq!(pair[0]["kind"], "toolCall");
        assert_eq!(pair[1]["kind"], "toolResult");
        let call_marker = serde_json::to_vec(&serde_json::json!({"adapterVersion":"lifeline-team-journal-adapter/1","observedKind":"tool_called","schemaVersion":"lifeline-team-journal/1","sourceData":call_record["data"],"sourceSequence":call_sequence.to_string()})).unwrap();
        let result_marker = serde_json::to_vec(&serde_json::json!({"adapterVersion":"lifeline-team-journal-adapter/1","observedKind":"tool_completed","schemaVersion":"lifeline-team-journal/1","sourceData":completion_record["data"],"sourceSequence":completion_sequence.to_string()})).unwrap();
        assert_eq!(
            pair[0]["content"]["digest"],
            smesh_a2a::content_digest(&call_marker)
        );
        assert_eq!(
            pair[1]["content"]["digest"],
            smesh_a2a::content_digest(&result_marker)
        );
        assert_ne!(pair[0]["content"]["digest"], pair[1]["content"]["digest"]);
        observed_tool_results += 1;
    }
    assert_eq!(observed_tool_results, 5);
    let classified = records
        .iter()
        .filter_map(|record| {
            Some((
                record["interactionId"].as_str()?,
                record["sourceFacts"]["failureKind"].as_str()?,
            ))
        })
        .collect::<std::collections::HashMap<_, _>>();
    for (source_id, kind) in [
        ("event-5", "primary-outage-observed"),
        ("event-6", "primary-stream-failed"),
        ("event-7", "cancel-requested"),
        ("event-10", "cancel-confirmed"),
        ("event-8", "late-output-fenced"),
        ("event-11", "sibling-completed"),
        ("event-14", "fallback-selected"),
        ("event-15", "fallback-submitted"),
        ("event-16", "fallback-completed"),
        ("event-19", "scenario-completed"),
    ] {
        assert_eq!(
            classified.get(source_id),
            Some(&kind),
            "lost source fact {source_id}"
        );
    }
    let submitted = records
        .iter()
        .filter(|record| {
            record["interactionId"]
                .as_str()
                .is_some_and(|id| matches!(id, "event-1" | "event-2" | "event-3"))
        })
        .map(|record| {
            record["mergeIndex"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
        })
        .max()
        .unwrap();
    let completed = records
        .iter()
        .filter(|record| {
            record["interactionId"]
                .as_str()
                .is_some_and(|id| matches!(id, "event-11" | "event-12" | "event-13"))
        })
        .map(|record| {
            record["mergeIndex"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
        })
        .min()
        .unwrap();
    assert!(
        submitted < completed,
        "sibling dispatches were not observed before their deterministic completion barrier"
    );
    for name in [
        "package.jsonl",
        "receipt.json",
        "actors.json",
        "editorial.json",
        "browser-bootstrap.json",
        "public-manifest.json",
    ] {
        let public = std::fs::read_to_string(first.join(name))
            .unwrap()
            .to_ascii_lowercase();
        for forbidden in [
            "authorization:",
            "bearer ",
            "credential",
            "private until approval",
            "http://127.0.0.1",
        ] {
            assert!(
                !public.contains(forbidden),
                "{name} exposes forbidden public material: {forbidden}"
            );
        }
    }

    let criteria_evidence = read_json(&first.join("restricted/criteria-evidence.json"));
    assert_eq!(
        criteria_evidence["schemaVersion"],
        "operational-lifeline-criteria-evidence/1"
    );
    assert_eq!(criteria_evidence["seed"], "47");
    assert_eq!(criteria_evidence["scenario"]["rootContextRestarts"], "0");
    assert_eq!(
        criteria_evidence["scenario"]["primaryFinalState"],
        "canceled"
    );
    assert_eq!(
        criteria_evidence["scenario"]["identityReconciliation"]["matched"],
        true
    );
    assert!(criteria_evidence["scenario"]["identityReconciliation"]["unavailableIds"].is_null());
    assert_eq!(
        criteria_evidence["scenario"]["identityReconciliation"]["sourceIdentitySetDigest"],
        criteria_evidence["scenario"]["identityReconciliation"]["captureIdentitySetDigest"]
    );
    let source_bindings =
        criteria_evidence["scenario"]["identityReconciliation"]["sourceEventBindings"]
            .as_array()
            .unwrap();
    assert_eq!(source_bindings.len(), 19);
    assert!(source_bindings.iter().all(|binding| {
        binding
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == BTreeSet::from(["captureEventId", "sourceRecordDigest"])
            && binding["captureEventId"]
                .as_str()
                .is_some_and(|id| id.starts_with("sha256:") && id.len() == 71)
            && binding["sourceRecordDigest"]
                .as_str()
                .is_some_and(|digest| digest.starts_with("sha256:") && digest.len() == 71)
    }));
    let teams = criteria_evidence["teams"].as_array().unwrap();
    assert_eq!(teams.len(), 5);
    assert!(teams.iter().all(|team| {
        team["claim"]["observed"] == true
            && team["reinforcement"]["observed"] == true
            && team["reinforcement"]["distinctAttesters"] == true
            && team["backoff"]["winnerScoreGreater"] == true
            && team["backoff"]["losingRoleReinforced"] == true
            && team["contradictionDecay"]["hashReconciled"] == true
            && team["contradictionDecay"]["runtimeHashesEmitted"] == true
            && team["contradictionDecay"]["expiryTickObserved"] == true
            && team["contradictionDecay"]["removedFromActive"] == true
            && team["contradictionDecay"]["retainedInHistory"] == true
            && team["isolation"]["organizationBound"] == true
            && team["isolation"]["toolBound"] == true
            && team["isolation"]["candidateBound"] == true
            && team["sourceJournalDigest"]
                .as_str()
                .is_some_and(|digest| digest.starts_with("sha256:") && digest.len() == 71)
            && team["runtimeJournalDigest"]
                .as_str()
                .is_some_and(|digest| digest.starts_with("sha256:") && digest.len() == 71)
    }));

    let evidence: serde_json::Value = read_json(&first.join("restricted/evidence-manifest.json"));
    assert_eq!(evidence["schemaVersion"], "operational-lifeline-evidence/1");
    assert_eq!(evidence["gatewayCount"], "6");
    assert_eq!(evidence["agentCards"].as_array().unwrap().len(), 6);
    let card_gateways = evidence["agentCards"]
        .as_array()
        .unwrap()
        .iter()
        .map(|card| card["gatewayId"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(card_gateways, site_ids);
    assert!(
        evidence["agentCards"]
            .as_array()
            .unwrap()
            .iter()
            .all(
                |card| card["sourceSchema"] == "lifeline-failure-scenario-run/1"
                    && card["interfaceProtocols"]
                        .as_array()
                        .is_some_and(|protocols| protocols.len() == 2)
            )
    );
    assert_eq!(evidence["sourceSchemas"].as_array().unwrap().len(), 3);
    assert_eq!(evidence["humanRatification"]["authenticated"], false);
    assert_eq!(
        evidence["humanRatification"]["authenticationMethod"],
        "scripted-deterministic-test-human"
    );
    assert_eq!(
        evidence["humanRatification"]["authorityKind"],
        "scripted-deterministic-test-human-authority-fixture"
    );
    assert_eq!(
        evidence["humanRatification"]["candidatePublicBeforeDecision"],
        false
    );
    assert_eq!(evidence["humanRatification"]["decision"], "approve");
    assert_eq!(evidence["humanRatification"]["preDecisionEventCount"], "44");
    let packet = read_json(&first.join("restricted/review-packet.json"));
    let review = read_json(&first.join("restricted/review-receipt.json"));
    let decision = read_json(&first.join("restricted/decision-receipt.json"));
    let replay_receipt = read_json(&first.join("restricted/replay-receipt.json"));
    assert_eq!(
        packet["evidenceSnapshotHash"],
        evidence["humanRatification"]["preDecisionCaptureDigest"]
    );
    assert_eq!(
        packet["packetHash"],
        evidence["humanRatification"]["packetHash"]
    );
    assert_eq!(
        review["receiptHash"],
        evidence["humanRatification"]["reviewReceiptHash"]
    );
    assert_eq!(
        decision["receiptHash"],
        evidence["humanRatification"]["decisionReceiptHash"]
    );
    assert_eq!(
        review["packetHash"], packet["packetHash"],
        "review must bind the exact frozen candidate packet"
    );
    assert_eq!(
        decision["packetHash"], packet["packetHash"],
        "decision must reject a stale or different candidate packet"
    );
    assert_eq!(
        decision["previousReceiptHash"], review["receiptHash"],
        "decision must reject a stale or different review receipt"
    );
    assert_eq!(
        decision["evidenceSnapshotHash"], packet["evidenceSnapshotHash"],
        "decision must bind the exact pre-decision prefix"
    );
    assert_eq!(
        evidence["humanRatification"]["finalReplayRunSeal"], replay_receipt["runSeal"],
        "final replay seal must authenticate inclusion of the returned decision"
    );
    assert_eq!(
        evidence["humanRatification"]["decisionEventContentDigest"],
        smesh_a2a::content_digest(
            &std::fs::read(first.join("restricted/decision-receipt.json")).unwrap()
        )
    );
    assert_eq!(evidence["gapCount"], "0");
    assert_eq!(evidence["restrictionCount"], "5");
    assert_eq!(evidence["sourceClockRestrictionCount"], "46");
    assert_eq!(evidence["sourceIdentifierRestrictionCount"], "5");
    assert!(first.join("restricted/review-packet.json").is_file());
    assert!(first.join("restricted/review-receipt.json").is_file());
    assert!(first.join("restricted/decision-receipt.json").is_file());
    assert!(first.join("restricted/sealed-replay.jsonl").is_file());
    assert!(first.join("restricted/replay-receipt.json").is_file());
    assert!(!first.join("restricted/ratification.sqlite3").exists());

    let editorial: serde_json::Value = read_json(&first.join("editorial.json"));
    let event_ids = records
        .iter()
        .filter_map(|record| record["eventId"].as_str())
        .collect::<HashSet<_>>();
    assert!(
        editorial["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| event_ids.contains(entry["eventId"].as_str().unwrap()))
    );
}

#[test]
fn runtime_source_records_reject_unknown_fields() {
    let fixture = TempDir::new("runtime-source-unknown-field");
    let scenario = generate_scenario(fixture.path());

    let runtime_path = scenario.join("journals/atlas.runtime.jsonl");
    let runtime = std::fs::read_to_string(&runtime_path).unwrap();
    let mut lines = runtime.lines();
    let mut first: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
    first["unexpected"] = serde_json::json!(true);
    let malformed = std::iter::once(serde_json::to_string(&first).unwrap())
        .chain(lines.map(str::to_owned))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    std::fs::write(runtime_path, malformed).unwrap();

    let output = fixture.path().join("output");
    assert!(
        !operational_capture_succeeds(&scenario, &output),
        "unknown runtime fields must fail closed"
    );
}

#[test]
fn runtime_source_records_reject_noncanonical_bytes() {
    let fixture = TempDir::new("runtime-source-noncanonical");
    let scenario = generate_scenario(fixture.path());

    let runtime_path = scenario.join("journals/atlas.runtime.jsonl");
    let runtime = std::fs::read_to_string(&runtime_path).unwrap();
    std::fs::write(&runtime_path, format!(" {runtime}")).unwrap();

    let output = fixture.path().join("output");
    assert!(
        !operational_capture_succeeds(&scenario, &output),
        "noncanonical runtime bytes must fail closed"
    );
}

#[test]
fn runtime_source_sequences_must_be_contiguous() {
    let fixture = TempDir::new("runtime-source-sequences");
    let scenario = generate_scenario(fixture.path());

    let runtime_path = scenario.join("journals/atlas.runtime.jsonl");
    let original = std::fs::read_to_string(&runtime_path).unwrap();
    let records = original
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert!(records.len() >= 2, "runtime sequence fixture is too small");

    for case in ["start", "duplicate", "reversal", "gap"] {
        let mut malformed = records.clone();
        if case == "start" {
            for record in &mut malformed {
                let sequence = record["sequence"].as_u64().unwrap();
                record["sequence"] = serde_json::json!(sequence + 1);
            }
        } else {
            let mut trailing = malformed.last().unwrap().clone();
            let last_sequence = trailing["sequence"].as_u64().unwrap();
            trailing["sequence"] = serde_json::json!(match case {
                "duplicate" => last_sequence,
                "reversal" => last_sequence - 1,
                "gap" => last_sequence + 2,
                _ => unreachable!(),
            });
            malformed.push(trailing);
        }
        let bytes = malformed
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(&runtime_path, bytes).unwrap();

        let output = fixture.path().join(format!("output-{case}"));
        assert!(
            !operational_capture_succeeds(&scenario, &output),
            "{case} runtime sequence must fail closed"
        );
    }
}

#[test]
fn runtime_source_kinds_and_consumed_details_must_be_closed_and_typed() {
    let fixture = TempDir::new("runtime-source-details");
    let scenario = generate_scenario(fixture.path());

    let runtime_path = scenario.join("journals/atlas.runtime.jsonl");
    let original = std::fs::read_to_string(&runtime_path).unwrap();
    let records = original
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();

    for case in [
        "unknown-kind",
        "signal-detail-type",
        "signal-detail-field",
        "tick-detail-type",
        "tick-detail-field",
    ] {
        let mut malformed = records.clone();
        match case {
            "unknown-kind" => malformed.push(serde_json::json!({
                "data": {},
                "kind": "unreviewed_runtime_kind",
                "schemaVersion": "lifeline-runtime-trace/1",
                "sequence": malformed.last().unwrap()["sequence"].as_u64().unwrap() + 1,
            })),
            "signal-detail-type" => {
                let signal = malformed
                    .iter_mut()
                    .find(|record| record["kind"] == "signal_emitted")
                    .unwrap();
                signal["data"]["hash"] = serde_json::json!(false);
            }
            "signal-detail-field" => {
                let signal = malformed
                    .iter_mut()
                    .find(|record| record["kind"] == "signal_emitted")
                    .unwrap();
                signal["data"]["unexpected"] = serde_json::json!(true);
            }
            "tick-detail-type" => {
                let tick = malformed
                    .iter_mut()
                    .find(|record| record["kind"] == "tick_completed")
                    .unwrap();
                tick["data"]["tick"] = serde_json::json!("0");
            }
            "tick-detail-field" => {
                let tick = malformed
                    .iter_mut()
                    .find(|record| record["kind"] == "tick_completed")
                    .unwrap();
                tick["data"]["unexpected"] = serde_json::json!(true);
            }
            _ => unreachable!(),
        }
        let bytes = malformed
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(&runtime_path, bytes).unwrap();

        let output = fixture.path().join(format!("output-{case}"));
        assert!(
            !operational_capture_succeeds(&scenario, &output),
            "{case} runtime record must fail closed"
        );
    }
}

fn generate_scenario(root: &Path) -> PathBuf {
    let scenario = root.join("scenario");
    bounded(
        Command::new(env!("CARGO_BIN_EXE_lifeline-failure-scenario"))
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("deploy/lifeline-teams.json"))
            .arg(&scenario),
    );
    scenario
}

fn operational_capture_succeeds(scenario: &Path, output: &Path) -> bool {
    process::bounded_status(
        Command::new(OPERATIONAL_BIN.expect("operational capture binary is missing"))
            .arg(scenario)
            .arg(output),
        Duration::from_secs(30),
        "operational capture",
    )
    .unwrap_or_else(|error| panic!("operational capture lifecycle failed: {error}"))
    .success()
}

fn run_once(root: &Path, label: &str) -> PathBuf {
    let scenario = root.join(format!("{label}-scenario"));
    let output = root.join(format!("{label}-operational"));
    bounded(
        Command::new(env!("CARGO_BIN_EXE_lifeline-failure-scenario"))
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("deploy/lifeline-teams.json"))
            .arg(&scenario),
    );
    bounded(
        Command::new(OPERATIONAL_BIN.expect("operational capture binary is missing"))
            .arg(&scenario)
            .arg(&output),
    );
    output
}

fn bounded(command: &mut Command) {
    let status = process::bounded_status(command, Duration::from_secs(30), "operational command")
        .unwrap_or_else(|error| panic!("operational command lifecycle failed: {error}"));
    assert!(status.success());
}

fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn generated_artifacts(root: &Path) -> [&str; 18] {
    for name in GENERATED_ARTIFACTS {
        assert!(
            root.join(name).is_file(),
            "missing generated artifact {name}"
        );
    }
    let mut found = Vec::new();
    for directory in [root.to_path_buf(), root.join("restricted")] {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file()
                && path.file_name().and_then(|name| name.to_str()) != Some("README.md")
            {
                found.push(path);
            }
        }
    }
    assert_eq!(
        found.len(),
        GENERATED_ARTIFACTS.len(),
        "generated artifact allowlist changed"
    );
    GENERATED_ARTIFACTS
}

struct TempDir(PathBuf);
impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "smesh-operational-lifeline-{label}-{}-{}",
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
