use smesh_a2a::lifeline_acceptance::{
    AcceptancePlane, DenyEffectBroker, EffectClass, canonical_criteria, criteria_evidence_digest,
    evaluate_operational_lifeline, verify_acceptance_receipt, verify_acceptance_report,
};
use smesh_a2a::owned_temp::OwnedTempDir;
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

#[path = "support/process.rs"]
#[allow(dead_code)]
mod process;

const ACCEPTANCE_BIN: Option<&str> = option_env!("CARGO_BIN_EXE_operational-lifeline-acceptance");
const QUALIFICATION_BIN: Option<&str> =
    option_env!("CARGO_BIN_EXE_operational-lifeline-qualification");
const CLI_WATCHDOG: Duration = Duration::from_secs(30);
const QUALIFICATION_WATCHDOG: Duration = Duration::from_secs(60);

#[test]
fn registry_is_the_closed_milestone_20_through_29_contract() {
    let criteria = canonical_criteria().expect("canonical registry");
    assert_eq!(criteria.len(), 40);
    for (index, criterion) in criteria.iter().enumerate() {
        let issue = 20 + index / 4;
        let acceptance = 1 + index % 4;
        assert_eq!(criterion.id, format!("m3-{issue}-ac{acceptance}"));
        assert!(!criterion.statement.is_empty());
        assert!(!criterion.evaluator.is_empty());
        assert!(!criterion.required_evidence.is_empty());
    }
}

#[test]
fn deny_effect_broker_rejects_all_nine_classes_before_callback() {
    let broker = DenyEffectBroker;
    let mut invoked = 0_u8;
    for class in EffectClass::ALL {
        let result = broker.attempt(class, || invoked += 1);
        assert!(result.is_err(), "{class:?}");
    }
    assert_eq!(invoked, 0);
}

#[test]
fn missing_qualification_evidence_fails_with_an_exact_diagnostic() {
    let package =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("demo/fixtures/operational-lifeline-v1");
    let qualification = br#"{"probes":[],"runId":"lifeline-operational-0047","schemaVersion":"operational-lifeline-qualification-probes/1","seed":"47"}"#;
    let artifacts = evaluate_operational_lifeline(&package, qualification).unwrap();
    assert_eq!(artifacts.scorecard.results.len(), 40);
    assert_eq!(artifacts.scorecard.summary.total, "40");
    assert_eq!(artifacts.scorecard.summary.overall_status.as_str(), "fail");
    let result = artifacts
        .scorecard
        .results
        .iter()
        .find(|result| result.criterion_id == "m3-20-ac4")
        .unwrap();
    assert_eq!(result.status.as_str(), "fail");
    assert_eq!(result.missing_evidence.len(), 1);
    assert_eq!(
        result.missing_evidence[0].artifact,
        "qualification-probes.json"
    );
    assert_eq!(result.missing_evidence[0].selector, "/probes/m3-20-ac4");
    assert_eq!(result.diagnostics[0].code.as_str(), "missingEvidence");
}

#[test]
fn coherent_rehash_cannot_turn_a_contradictory_retained_fact_green() {
    let fixture = PackageCopy::new();
    let path = fixture.path().join("restricted/criteria-evidence.json");
    let mut evidence: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    evidence["scenario"]["rootContextRestarts"] = "1".into();
    std::fs::write(&path, serde_json::to_vec(&evidence).unwrap()).unwrap();

    let qualification = passing_qualification();
    let artifacts = evaluate_operational_lifeline(fixture.path(), &qualification).unwrap();
    let result = artifacts
        .scorecard
        .results
        .iter()
        .find(|result| result.criterion_id == "m3-26-ac4")
        .unwrap();
    assert_eq!(result.status.as_str(), "fail");
    assert_eq!(result.diagnostics[0].code.as_str(), "contradictoryEvidence");
    assert_eq!(result.diagnostics[0].fact_id, "rootContextRestarts");
    assert_eq!(result.diagnostics[0].observed, ["1"]);
}

#[test]
fn malformed_topology_evidence_is_not_an_artifact_presence_pass() {
    let fixture = PackageCopy::new();
    let path = fixture.path().join("restricted/evidence-manifest.json");
    let mut evidence: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    evidence["gatewayCount"] = "5".into();
    std::fs::write(&path, serde_json::to_vec(&evidence).unwrap()).unwrap();

    let artifacts =
        evaluate_operational_lifeline(fixture.path(), &passing_qualification()).unwrap();
    let result = artifacts
        .scorecard
        .results
        .iter()
        .find(|result| result.criterion_id == "m3-20-ac1")
        .unwrap();
    assert_eq!(result.status.as_str(), "fail");
    assert_eq!(result.diagnostics[0].code.as_str(), "contradictoryEvidence");
    assert_eq!(result.diagnostics[0].fact_id, "topologyEvidence");
}

#[test]
fn retained_identity_mismatch_is_not_a_source_capture_pass() {
    let fixture = PackageCopy::new();
    let path = fixture.path().join("restricted/criteria-evidence.json");
    let mut evidence: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    evidence["scenario"]["identityReconciliation"]["matched"] = false.into();
    std::fs::write(&path, serde_json::to_vec(&evidence).unwrap()).unwrap();

    let artifacts =
        evaluate_operational_lifeline(fixture.path(), &passing_qualification()).unwrap();
    let result = artifacts
        .scorecard
        .results
        .iter()
        .find(|result| result.criterion_id == "m3-21-ac4")
        .unwrap();
    assert_eq!(result.status.as_str(), "fail");
    assert_eq!(result.diagnostics[0].code.as_str(), "contradictoryEvidence");
    assert_eq!(
        result.diagnostics[0].fact_id,
        "sourceIdentityReconciliation"
    );
}

#[test]
fn retained_team_contradiction_is_not_a_claim_or_reinforcement_pass() {
    let fixture = PackageCopy::new();
    let path = fixture.path().join("restricted/criteria-evidence.json");
    let mut evidence: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    evidence["teams"][0]["reinforcement"]["observed"] = false.into();
    std::fs::write(&path, serde_json::to_vec(&evidence).unwrap()).unwrap();

    let artifacts =
        evaluate_operational_lifeline(fixture.path(), &passing_qualification()).unwrap();
    let result = artifacts
        .scorecard
        .results
        .iter()
        .find(|result| result.criterion_id == "m3-22-ac1")
        .unwrap();
    assert_eq!(result.status.as_str(), "fail");
    assert_eq!(result.diagnostics[0].code.as_str(), "contradictoryEvidence");
    assert_eq!(result.diagnostics[0].fact_id, "teamClaimReinforcement");
}

#[test]
fn canonical_receipt_binds_the_non_circular_scorecard() {
    let package =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("demo/fixtures/operational-lifeline-v1");
    let artifacts = evaluate_operational_lifeline(&package, &passing_qualification()).unwrap();
    assert_eq!(artifacts.scorecard.summary.overall_status.as_str(), "pass");
    assert_eq!(artifacts.scorecard.summary.passed, "40");
    assert!(
        serde_json::from_slice::<serde_json::Value>(&artifacts.scorecard_json).unwrap()
            ["scorecardDigest"]
            .is_null()
    );
    let verified =
        verify_acceptance_receipt(&artifacts.scorecard_json, &artifacts.receipt_json).unwrap();
    assert_eq!(verified, artifacts.receipt);
    assert!(
        serde_json::from_slice::<serde_json::Value>(&artifacts.receipt_json)
            .unwrap()["receiptDigest"]
            .as_str()
            .is_some_and(|digest| digest.starts_with("sha256:") && digest.len() == 71)
    );

    let mut tampered: serde_json::Value =
        serde_json::from_slice(&artifacts.scorecard_json).unwrap();
    tampered["seed"] = "48".into();
    let tampered = serde_json::to_vec(&tampered).unwrap();
    assert!(verify_acceptance_receipt(&tampered, &artifacts.receipt_json).is_err());

    let mut receipt: serde_json::Value = serde_json::from_slice(&artifacts.receipt_json).unwrap();
    receipt["unexpected"] = true.into();
    assert!(
        verify_acceptance_receipt(
            &artifacts.scorecard_json,
            &serde_json::to_vec(&receipt).unwrap()
        )
        .is_err()
    );
}

#[test]
fn coherent_rehash_cannot_change_the_closed_evaluator_assignment() {
    let package =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("demo/fixtures/operational-lifeline-v1");
    let artifacts = evaluate_operational_lifeline(&package, &passing_qualification()).unwrap();
    let mut scorecard: serde_json::Value =
        serde_json::from_slice(&artifacts.scorecard_json).unwrap();
    scorecard["results"][0]["evaluator"] = "qualification-probe-v1".into();
    let scorecard = serde_json::to_vec(&scorecard).unwrap();
    let mut receipt: serde_json::Value = serde_json::from_slice(&artifacts.receipt_json).unwrap();
    receipt["scorecardByteLength"] = scorecard.len().to_string().into();
    receipt["scorecardDigest"] = smesh_a2a::lifeline_acceptance::criteria_evidence_digest(
        "operational-lifeline-acceptance-scorecard",
        &scorecard,
    )
    .into();
    receipt.as_object_mut().unwrap().remove("receiptDigest");
    let receipt_without_digest = serde_json::to_vec(&receipt).unwrap();
    receipt["receiptDigest"] = smesh_a2a::lifeline_acceptance::criteria_evidence_digest(
        "operational-lifeline-acceptance-receipt",
        &receipt_without_digest,
    )
    .into();
    let receipt = serde_json::to_vec(&receipt).unwrap();

    assert!(verify_acceptance_receipt(&scorecard, &receipt).is_err());
}

#[test]
fn offline_report_rejects_coherently_rehashed_top_level_evaluator_identity() {
    let package =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("demo/fixtures/operational-lifeline-v1");
    let artifacts = evaluate_operational_lifeline(&package, &passing_qualification()).unwrap();

    for (field, substituted) in [
        ("evaluatorId", "attacker-selected-evaluator"),
        ("evaluatorVersion", "2"),
    ] {
        let root = TempRoot::new("verify-report-evaluator");
        let report = root.path().join("report");
        std::fs::create_dir(&report).unwrap();
        let mut scorecard: serde_json::Value =
            serde_json::from_slice(&artifacts.scorecard_json).unwrap();
        scorecard[field] = substituted.into();
        let scorecard = serde_json::to_vec(&scorecard).unwrap();
        let receipt = coherently_rebind_receipt(&artifacts.receipt_json, &scorecard);
        std::fs::write(report.join("acceptance-scorecard.json"), scorecard).unwrap();
        std::fs::write(report.join("acceptance-receipt.json"), receipt).unwrap();

        assert!(
            verify_acceptance_report(&report).is_err(),
            "accepted coherently rehashed {field} sabotage"
        );
    }
}

#[test]
fn offline_report_rejects_coherently_rebound_evidence_stripping_and_arbitrary_probe_digest() {
    let package =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("demo/fixtures/operational-lifeline-v1");
    let artifacts = evaluate_operational_lifeline(&package, &passing_qualification()).unwrap();

    for sabotage in ["strip", "arbitrary-digest"] {
        let mut scorecard: serde_json::Value =
            serde_json::from_slice(&artifacts.scorecard_json).unwrap();
        if sabotage == "strip" {
            for result in scorecard["results"].as_array_mut().unwrap() {
                result["evidence"] = serde_json::json!([]);
            }
        } else {
            let result = scorecard["results"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|result| result["criterionId"] == "m3-20-ac4")
                .unwrap();
            result["evidence"][0]["artifactDigest"] = format!("sha256:{}", "f".repeat(64)).into();
        }
        let scorecard = serde_json::to_vec(&scorecard).unwrap();
        let receipt = coherently_rebind_receipt(&artifacts.receipt_json, &scorecard);
        assert!(
            verify_acceptance_receipt(&scorecard, &receipt).is_err(),
            "accepted coherent {sabotage} sabotage"
        );
    }
}

#[test]
fn offline_report_reruns_all_fourteen_fact_validators_after_coherent_rebinding() {
    let package =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("demo/fixtures/operational-lifeline-v1");
    let artifacts = evaluate_operational_lifeline(&package, &passing_qualification()).unwrap();
    let baseline: serde_json::Value = serde_json::from_slice(&artifacts.scorecard_json).unwrap();
    let ids = baseline["qualificationFacts"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(ids.len(), 14);
    for id in ids {
        let mut scorecard = baseline.clone();
        scorecard["qualificationFacts"][&id] = serde_json::json!({"executed": true});
        let fact_bytes = serde_json::to_vec(&scorecard["qualificationFacts"][&id]).unwrap();
        let result = scorecard["results"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|result| result["criterionId"] == id)
            .unwrap();
        result["evidence"][0]["artifactDigest"] =
            smesh_a2a::lifeline_acceptance::criteria_evidence_digest(
                "operational-lifeline-qualification-evidence",
                &fact_bytes,
            )
            .into();
        let scorecard = serde_json::to_vec(&scorecard).unwrap();
        let receipt = coherently_rebind_receipt(&artifacts.receipt_json, &scorecard);
        assert!(
            verify_acceptance_receipt(&scorecard, &receipt).is_err(),
            "{id}"
        );
    }
}

fn coherently_rebind_receipt(original: &[u8], scorecard: &[u8]) -> Vec<u8> {
    let mut receipt: serde_json::Value = serde_json::from_slice(original).unwrap();
    receipt["scorecardByteLength"] = scorecard.len().to_string().into();
    receipt["scorecardDigest"] = smesh_a2a::lifeline_acceptance::criteria_evidence_digest(
        "operational-lifeline-acceptance-scorecard",
        scorecard,
    )
    .into();
    receipt.as_object_mut().unwrap().remove("receiptDigest");
    let bytes = serde_json::to_vec(&receipt).unwrap();
    receipt["receiptDigest"] = smesh_a2a::lifeline_acceptance::criteria_evidence_digest(
        "operational-lifeline-acceptance-receipt",
        &bytes,
    )
    .into();
    serde_json::to_vec(&receipt).unwrap()
}

#[test]
fn generic_self_attested_qualification_facts_fail_closed() {
    let package =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("demo/fixtures/operational-lifeline-v1");
    let mut value: serde_json::Value = serde_json::from_slice(&passing_qualification()).unwrap();
    let probe = &mut value["probes"][0];
    probe["facts"] = serde_json::json!({"executed": true});
    let bytes = serde_json::to_vec(&probe["facts"]).unwrap();
    probe["evidence"][0]["artifactDigest"] =
        smesh_a2a::lifeline_acceptance::criteria_evidence_digest(
            "operational-lifeline-qualification-evidence",
            &bytes,
        )
        .into();
    let evaluated = evaluate_operational_lifeline(&package, &serde_json::to_vec(&value).unwrap())
        .expect("well-formed contradictory qualification evidence");
    let result = evaluated
        .scorecard
        .results
        .iter()
        .find(|result| result.criterion_id == "m3-20-ac4")
        .unwrap();
    assert_eq!(result.status.as_str(), "fail");
    assert_eq!(result.diagnostics[0].code.as_str(), "contradictoryEvidence");
}

#[test]
fn every_qualification_criterion_rejects_coherently_rehashed_fabrication() {
    let package =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("demo/fixtures/operational-lifeline-v1");
    let baseline: serde_json::Value = serde_json::from_slice(&passing_qualification()).unwrap();
    for index in 0..baseline["probes"].as_array().unwrap().len() {
        let mut value = baseline.clone();
        let probe = &mut value["probes"][index];
        let criterion_id = probe["criterionId"].as_str().unwrap().to_owned();
        probe["facts"] = serde_json::json!({"executed": true});
        let bytes = serde_json::to_vec(&probe["facts"]).unwrap();
        probe["evidence"][0]["artifactDigest"] =
            smesh_a2a::lifeline_acceptance::criteria_evidence_digest(
                "operational-lifeline-qualification-evidence",
                &bytes,
            )
            .into();
        let evaluated =
            evaluate_operational_lifeline(&package, &serde_json::to_vec(&value).unwrap()).unwrap();
        let result = evaluated
            .scorecard
            .results
            .iter()
            .find(|result| result.criterion_id == criterion_id)
            .unwrap();
        assert_eq!(result.status.as_str(), "fail", "{criterion_id}");
        assert_eq!(
            result.diagnostics[0].code.as_str(),
            "contradictoryEvidence",
            "{criterion_id}"
        );
    }
}

#[test]
fn qualification_facts_bind_all_blocker_semantics() {
    let value: serde_json::Value = serde_json::from_slice(&passing_qualification()).unwrap();
    let facts = |id: &str| {
        value["probes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|probe| probe["criterionId"] == id)
            .unwrap()["facts"]
            .clone()
    };
    assert_eq!(facts("m3-23-ac3")["captureGapRecorded"], true);
    assert_eq!(facts("m3-23-ac3")["missingParentRecorded"], true);
    assert_eq!(facts("m3-24-ac3")["structurallyValidTamper"], true);
    assert_eq!(facts("m3-24-ac3")["derivedSealChanged"], true);
    assert_eq!(facts("m3-24-ac3")["originalReceiptRejected"], true);
    assert_eq!(facts("m3-24-ac3")["originalReceiptAndPinRejected"], true);
    assert_eq!(facts("m3-24-ac3")["attackerControlledChainRebound"], true);
    assert_eq!(facts("m3-25-ac2")["allPublicSurfacesScanned"], true);
    assert_eq!(facts("m3-25-ac2")["canariesAbsent"], true);
    assert_eq!(facts("m3-25-ac3")["equivalentInputsCompared"], true);
    assert_eq!(facts("m3-25-ac3")["changedInputChangedOutput"], true);
    assert_eq!(facts("m3-27-ac4")["authorizationToLedgerAttempt"], true);
    assert_eq!(facts("m3-28-ac3")["attackerDigestsRebound"], true);
    assert_eq!(facts("m3-28-ac3")["eventSemanticRejection"], true);
    assert_eq!(facts("m3-29-ac2")["allDiagnosticFieldsInspected"], true);
    assert_eq!(facts("m3-29-ac2")["rawValuesAbsent"], true);
    assert_eq!(facts("m3-29-ac4")["browserSyntheticRejected"], true);
    assert_eq!(facts("m3-29-ac4")["rustSyntheticRejected"], true);
    assert_eq!(facts("m3-20-ac4")["effectBoundaryDenyByDefault"], true);
    assert_eq!(facts("m3-20-ac4")["successfulRealActions"], "0");
    assert_eq!(
        facts("m3-20-ac4")["attemptKinds"],
        serde_json::json!(["liveEffect"])
    );
    assert_eq!(
        facts("m3-28-ac4")["attemptKinds"],
        serde_json::json!(["browserExternalFetch"])
    );
}

#[test]
fn topology_fact_rejects_an_unperformed_dns_attempt_kind() {
    let package =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("demo/fixtures/operational-lifeline-v1");
    let mut qualification: serde_json::Value =
        serde_json::from_slice(&passing_qualification()).unwrap();
    let probe = qualification["probes"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|probe| probe["criterionId"] == "m3-20-ac4")
        .unwrap();
    probe["facts"]["attemptKinds"] = serde_json::json!(["dnsNonLoopback", "liveEffect"]);
    let fact_bytes = serde_json::to_vec(&probe["facts"]).unwrap();
    probe["evidence"][0]["artifactDigest"] =
        criteria_evidence_digest("operational-lifeline-qualification-evidence", &fact_bytes).into();

    let evaluated =
        evaluate_operational_lifeline(&package, &serde_json::to_vec(&qualification).unwrap())
            .unwrap();
    let result = evaluated
        .scorecard
        .results
        .iter()
        .find(|result| result.criterion_id == "m3-20-ac4")
        .unwrap();
    assert_eq!(result.status.as_str(), "fail");
}

#[cfg(target_os = "linux")]
#[test]
fn qualification_browser_failure_does_not_emit_planted_stderr() {
    const CANARY: &str = "PRIVATE_BROWSER_STDERR_CANARY_/sensitive/path";
    let root = TempRoot::new("browser-stderr-privacy");
    let output = root.path().join("qualification.json");
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let package = repo.join("demo/fixtures/operational-lifeline-v1");
    let result = process::bounded_output(
        Command::new(QUALIFICATION_BIN.expect("qualification binary missing"))
            .arg(repo)
            .arg(&package)
            .arg(&package)
            .arg(&output)
            .env("SMESH_QUALIFICATION_PLANTED_STDERR", CANARY),
        QUALIFICATION_WATCHDOG,
        "qualification stderr privacy regression",
    )
    .unwrap();
    assert!(!result.status.success());
    let surfaces = [result.stdout, result.stderr];
    assert!(surfaces.iter().all(|surface| {
        !surface
            .windows(CANARY.len())
            .any(|window| window == CANARY.as_bytes())
    }));
    assert!(!output.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn acceptance_wrapper_cleans_normal_exit_descendant_and_redacts_qualification_stderr() {
    use std::os::unix::fs::PermissionsExt as _;

    const CANARY: &str = "PRIVATE_QUALIFICATION_STDERR_CANARY_/sensitive/path";
    let root = TempRoot::new("acceptance-wrapper-lifecycle-privacy");
    let acceptance = root.path().join("operational-lifeline-acceptance");
    std::fs::copy(
        ACCEPTANCE_BIN.expect("acceptance binary missing"),
        &acceptance,
    )
    .unwrap();
    let qualification_bin = root.path().join("operational-lifeline-qualification");
    let marker = root.path().join("descendant-pid");
    std::fs::write(
        &qualification_bin,
        format!(
            "#!/bin/sh\nsleep 30 & printf '%s' \"$!\" > '{}'\nprintf '%s\\n' '{}' >&2\nexit 1\n",
            marker.display(),
            CANARY
        ),
    )
    .unwrap();
    std::fs::set_permissions(&qualification_bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let supplied = root.path().join("supplied.json");
    std::fs::write(&supplied, b"{}").unwrap();
    let report = root.path().join("report");
    let package =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("demo/fixtures/operational-lifeline-v1");

    let started = Instant::now();
    let result = process::bounded_output(
        Command::new(acceptance)
            .arg(package)
            .arg(supplied)
            .arg(&report),
        Duration::from_secs(3),
        "acceptance wrapper normal-exit descendant regression",
    )
    .unwrap();

    assert!(!result.status.success());
    assert!(started.elapsed() < Duration::from_secs(2));
    let pid = std::fs::read_to_string(marker).unwrap();
    assert!(
        !Path::new("/proc").join(pid).exists(),
        "qualification descendant survived"
    );
    for surface in [&result.stdout, &result.stderr] {
        assert!(
            !surface
                .windows(CANARY.len())
                .any(|window| window == CANARY.as_bytes())
        );
    }
    assert!(!report.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn acceptance_wrapper_reaps_double_forked_escaped_pipe_holder_and_preserves_unrelated_process() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = TempRoot::new("acceptance-wrapper-escaped-pipe");
    let acceptance = root.path().join("operational-lifeline-acceptance");
    std::fs::copy(
        ACCEPTANCE_BIN.expect("acceptance binary missing"),
        &acceptance,
    )
    .unwrap();
    let escaped = root.path().join("escaped-descendant");
    let intermediate = root.path().join("escaped-intermediate");
    let qualification_bin = root.path().join("operational-lifeline-qualification");
    let supplied = root.path().join("supplied.json");
    std::fs::write(&supplied, b"{}").unwrap();
    let mut unrelated = Command::new("/bin/sleep").arg("30").spawn().unwrap();

    for iteration in 0..50 {
        let marker = root.path().join(format!("escaped-identity-{iteration}"));
        std::fs::write(
            &escaped,
            format!(
                "#!/bin/sh\nstart=$(/usr/bin/cut -d ' ' -f 22 /proc/$$/stat)\ntmp='{}.tmp.'$$\nprintf '%s %s\\n' \"$$\" \"$start\" > \"$tmp\"\n/bin/mv \"$tmp\" '{}'\nexec /bin/sleep 30\n",
                marker.display(),
                marker.display(),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&escaped, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(
            &intermediate,
            format!("#!/bin/sh\n'{}' &\nexit 0\n", escaped.display()),
        )
        .unwrap();
        std::fs::set_permissions(&intermediate, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(
            &qualification_bin,
            format!(
                "#!/bin/sh\n/usr/bin/setsid '{}' &\ni=0\nwhile [ ! -s '{}' ] && [ \"$i\" -lt 200 ]; do i=$((i + 1)); sleep 0.005; done\n[ -s '{}' ] || exit 2\nprintf diagnostic >&2\nexit 1\n",
                intermediate.display(),
                marker.display(),
                marker.display(),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&qualification_bin, std::fs::Permissions::from_mode(0o755))
            .unwrap();

        let started = Instant::now();
        let result = process::bounded_output(
            Command::new(&acceptance)
                .arg(
                    Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("demo/fixtures/operational-lifeline-v1"),
                )
                .arg(&supplied)
                .arg(root.path().join(format!("report-{iteration}"))),
            Duration::from_secs(3),
            "acceptance escaped pipe regression",
        )
        .unwrap();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(!result.status.success());
        let identity = std::fs::read_to_string(&marker).unwrap();
        let mut fields = identity.split_whitespace();
        let pid = fields.next().unwrap().parse::<u32>().unwrap();
        let start_time = fields.next().unwrap().parse::<u64>().unwrap();
        assert!(fields.next().is_none());
        assert!(
            !process_identity_is_live(pid, start_time),
            "escaped qualification descendant survived iteration {iteration}"
        );
        assert!(
            !String::from_utf8_lossy(&result.stderr).contains("cleanup failed"),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            unrelated.try_wait().unwrap().is_none(),
            "unrelated process was terminated at iteration {iteration}"
        );
    }

    unrelated.kill().unwrap();
    unrelated.wait().unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn acceptance_wrapper_recovers_from_kernel_emfile_at_pidfd_open() {
    use std::os::unix::fs::PermissionsExt as _;

    const CHILDREN: usize = 8;
    let root = TempRoot::new("acceptance-wrapper-low-nofile");
    let acceptance = root.path().join("operational-lifeline-acceptance");
    std::fs::copy(
        ACCEPTANCE_BIN.expect("acceptance binary missing"),
        &acceptance,
    )
    .unwrap();
    let holder = root.path().join("escaped-holder");
    std::fs::write(
        &holder,
        "#!/bin/sh\nmarker=$1\nstart=$(/usr/bin/cut -d ' ' -f 22 /proc/$$/stat)\ntmp=$marker.tmp.$$\nprintf '%s %s\\n' \"$$\" \"$start\" > \"$tmp\"\n/bin/mv \"$tmp\" \"$marker\"\nexec /bin/sleep 30\n",
    )
    .unwrap();
    std::fs::set_permissions(&holder, std::fs::Permissions::from_mode(0o755)).unwrap();
    let intermediate = root.path().join("escaped-intermediate");
    std::fs::write(
        &intermediate,
        format!("#!/bin/sh\n'{}' \"$1\" &\nexit 0\n", holder.display()),
    )
    .unwrap();
    std::fs::set_permissions(&intermediate, std::fs::Permissions::from_mode(0o755)).unwrap();

    let markers = (0..CHILDREN)
        .map(|index| root.path().join(format!("escaped-{index}")))
        .collect::<Vec<_>>();
    let mut launches = String::new();
    for marker in &markers {
        use std::fmt::Write as _;
        writeln!(
            launches,
            "/usr/bin/setsid '{}' '{}' &",
            intermediate.display(),
            marker.display()
        )
        .unwrap();
    }
    let readiness = markers
        .iter()
        .map(|marker| format!("[ -s '{}' ]", marker.display()))
        .collect::<Vec<_>>()
        .join(" && ");
    let qualification_bin = root.path().join("operational-lifeline-qualification");
    std::fs::write(
        &qualification_bin,
        format!(
            "#!/bin/sh\n{launches}i=0\nwhile ! {readiness}; do i=$((i + 1)); [ \"$i\" -lt 400 ] || exit 2; sleep 0.005; done\nexit 1\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&qualification_bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let supplied = root.path().join("supplied.json");
    std::fs::write(&supplied, b"{}").unwrap();
    let emergency_evidence = root.path().join("emergency-retry.json");
    let mut unrelated = Command::new("/bin/sleep").arg("30").spawn().unwrap();

    let started = Instant::now();
    let output = process::bounded_output(
        Command::new("/bin/sh")
            .args(["-c", "ulimit -n 24; exec \"$@\"", "low-nofile"])
            .arg(&acceptance)
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("demo/fixtures/operational-lifeline-v1"),
            )
            .arg(&supplied)
            .arg(root.path().join("report"))
            .env("SMESH_TEST_QUALIFICATION_EXHAUST_FDS_BEFORE_PIDFD", "1")
            .env(
                "SMESH_TEST_QUALIFICATION_EMERGENCY_EVIDENCE",
                &emergency_evidence,
            ),
        Duration::from_secs(6),
        "acceptance low-RLIMIT_NOFILE descendant regression",
    )
    .unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(!output.status.success());
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("cleanup failed"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let evidence: serde_json::Value =
        serde_json::from_slice(&std::fs::read(emergency_evidence).unwrap()).unwrap();
    assert_eq!(evidence["fixtureExhaustionEmfileCount"], 1);
    assert_eq!(evidence["pidfdOpenEmfileCount"], 1);
    assert_eq!(evidence["reserveReleaseCount"], 1);
    assert_eq!(evidence["pidfdRetrySuccessCount"], 1);
    for marker in markers {
        let identity = std::fs::read_to_string(marker).unwrap();
        let mut fields = identity.split_whitespace();
        let pid = fields.next().unwrap().parse::<u32>().unwrap();
        let start_time = fields.next().unwrap().parse::<u64>().unwrap();
        assert!(
            !process_identity_is_live(pid, start_time),
            "escaped pid {pid} survived"
        );
    }
    assert!(unrelated.try_wait().unwrap().is_none());
    unrelated.kill().unwrap();
    unrelated.wait().unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn acceptance_wrapper_reports_injected_term_failure_and_still_reaps_group() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = TempRoot::new("acceptance-wrapper-term-injection");
    let acceptance = root.path().join("operational-lifeline-acceptance");
    std::fs::copy(
        ACCEPTANCE_BIN.expect("acceptance binary missing"),
        &acceptance,
    )
    .unwrap();
    let qualification_bin = root.path().join("operational-lifeline-qualification");
    let marker = root.path().join("injected-term-pids");
    std::fs::write(
        &qualification_bin,
        format!(
            "#!/bin/sh\ntrap '' TERM\nsleep 30 & printf '%s %s' \"$$\" \"$!\" > '{}'\nwait\n",
            marker.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&qualification_bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let supplied = root.path().join("supplied.json");
    std::fs::write(&supplied, b"{}").unwrap();
    let result = process::bounded_output(
        Command::new(acceptance)
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("demo/fixtures/operational-lifeline-v1"),
            )
            .arg(&supplied)
            .arg(root.path().join("report"))
            .env("SMESH_TEST_QUALIFICATION_INITIAL_WAIT_FAILURE", "1")
            .env("SMESH_TEST_QUALIFICATION_SIGNAL_FAILURE", "TERM"),
        Duration::from_secs(5),
        "acceptance wrapper injected TERM regression",
    )
    .unwrap();
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr)
            .contains("repository qualification probe wait and cleanup failed"),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    for pid in std::fs::read_to_string(marker).unwrap().split_whitespace() {
        assert!(
            !Path::new("/proc").join(pid).exists(),
            "qualification pid {pid} survived"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn acceptance_report_surfaces_staging_cleanup_failure_without_touching_target() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = TempRoot::new("acceptance-report-cleanup-failure");
    let acceptance = root.path().join("operational-lifeline-acceptance");
    std::fs::copy(
        ACCEPTANCE_BIN.expect("acceptance binary missing"),
        &acceptance,
    )
    .unwrap();
    let qualification_bin = root.path().join("operational-lifeline-qualification");
    let supplied = root.path().join("supplied.json");
    std::fs::write(&supplied, passing_qualification()).unwrap();
    let report = root.path().join("report");
    std::fs::write(
        &qualification_bin,
        format!(
            "#!/bin/sh\ncp '{}' \"$4\"\nmkdir '{}'\nprintf preserve > '{}/sentinel'\nexit 0\n",
            supplied.display(),
            report.display(),
            report.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&qualification_bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let result = process::bounded_output(
        Command::new(acceptance)
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("demo/fixtures/operational-lifeline-v1"),
            )
            .arg(&supplied)
            .arg(&report)
            .env("SMESH_TEST_REPORT_STAGING_CLEANUP_FAILURE", "1"),
        CLI_WATCHDOG,
        "acceptance report cleanup failure regression",
    )
    .unwrap();
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr)
            .contains("report creation failed and staging cleanup failed")
    );
    assert_eq!(std::fs::read(report.join("sentinel")).unwrap(), b"preserve");
    let staging = std::fs::read_dir(root.path())
        .unwrap()
        .map(Result::unwrap)
        .find(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".report.staging-")
        })
        .expect("failed staging retained for operator cleanup")
        .path();
    std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::remove_dir_all(staging).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn acceptance_report_publication_preserves_late_collision_and_cleans_owned_staging() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = TempRoot::new("acceptance-report-publication");
    let acceptance = root.path().join("operational-lifeline-acceptance");
    std::fs::copy(
        ACCEPTANCE_BIN.expect("acceptance binary missing"),
        &acceptance,
    )
    .unwrap();
    let qualification_bin = root.path().join("operational-lifeline-qualification");
    let supplied = root.path().join("supplied.json");
    std::fs::write(&supplied, passing_qualification()).unwrap();
    let report = root.path().join("report");
    std::fs::write(
        &qualification_bin,
        format!(
            "#!/bin/sh\ncp '{}' \"$4\"\nmkdir '{}'\nprintf preserve > '{}/sentinel'\nexit 0\n",
            supplied.display(),
            report.display(),
            report.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&qualification_bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let package =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("demo/fixtures/operational-lifeline-v1");

    let result = process::bounded_output(
        Command::new(acceptance)
            .arg(package)
            .arg(&supplied)
            .arg(&report),
        CLI_WATCHDOG,
        "acceptance report publication collision regression",
    )
    .unwrap();

    assert!(!result.status.success());
    assert_eq!(std::fs::read(report.join("sentinel")).unwrap(), b"preserve");
    let staging_prefix = ".report.staging-";
    assert!(std::fs::read_dir(root.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(staging_prefix)
    }));
}

#[test]
fn qualification_evidence_order_does_not_change_canonical_outputs() {
    let package =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("demo/fixtures/operational-lifeline-v1");
    let mut left: serde_json::Value = serde_json::from_slice(&passing_qualification()).unwrap();
    let extra = serde_json::json!({
        "artifact": "probe-log.jsonl",
        "artifactDigest": format!("sha256:{}", "1".repeat(64)),
        "eventIds": ["probe-z", "probe-a"],
        "selector": "/records/1",
    });
    left["probes"][0]["evidence"]
        .as_array_mut()
        .unwrap()
        .push(extra);
    let mut right = left.clone();
    right["probes"][0]["evidence"]
        .as_array_mut()
        .unwrap()
        .reverse();

    let left =
        evaluate_operational_lifeline(&package, &serde_json::to_vec(&left).unwrap()).unwrap();
    let right =
        evaluate_operational_lifeline(&package, &serde_json::to_vec(&right).unwrap()).unwrap();
    assert_eq!(left.scorecard_json, right.scorecard_json);
    assert_eq!(left.receipt_json, right.receipt_json);
}

#[test]
fn acceptance_cli_requires_fresh_repository_owned_probe_execution() {
    let root = TempRoot::new("cli-probe-binding");
    let qualification = root.path().join("qualification.json");
    let output = root.path().join("report");
    let mut value: serde_json::Value = serde_json::from_slice(&passing_qualification()).unwrap();
    value["probes"][0]["status"] = "fail".into();
    std::fs::write(&qualification, serde_json::to_vec(&value).unwrap()).unwrap();
    let status = process::bounded_status(
        Command::new(ACCEPTANCE_BIN.expect("acceptance binary missing"))
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("demo/fixtures/operational-lifeline-v1"),
            )
            .arg(&qualification)
            .arg(&output),
        CLI_WATCHDOG,
        "acceptance CLI probe-binding rejection",
    )
    .unwrap();
    assert!(!status.success());
    assert!(!output.exists());
}

#[test]
fn operational_cli_writes_only_canonical_scorecard_and_receipt() {
    let root = TempRoot::new("cli");
    let qualification = root.path().join("qualification.json");
    let output = root.path().join("report");
    std::fs::write(&qualification, passing_qualification()).unwrap();
    let status = process::bounded_status(
        Command::new(ACCEPTANCE_BIN.expect("acceptance binary missing"))
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("demo/fixtures/operational-lifeline-v1"),
            )
            .arg(&qualification)
            .arg(&output),
        CLI_WATCHDOG,
        "acceptance CLI canonical report",
    )
    .unwrap();
    assert!(status.success());
    let mut names = std::fs::read_dir(&output)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(
        names,
        ["acceptance-receipt.json", "acceptance-scorecard.json"]
    );
    verify_acceptance_receipt(
        &std::fs::read(output.join("acceptance-scorecard.json")).unwrap(),
        &std::fs::read(output.join("acceptance-receipt.json")).unwrap(),
    )
    .unwrap();
}

#[test]
fn qualification_runner_executes_all_fourteen_closed_probes_deterministically() {
    let root = TempRoot::new("qualification-runner");
    let first = root.path().join("first.json");
    let second = root.path().join("second.json");
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let package = repo.join("demo/fixtures/operational-lifeline-v1");
    for output in [&first, &second] {
        let status = process::bounded_status(
            Command::new(QUALIFICATION_BIN.expect("qualification binary missing"))
                .arg(repo)
                .arg(&package)
                .arg(&package)
                .arg(output),
            QUALIFICATION_WATCHDOG,
            "deterministic qualification runner",
        )
        .unwrap();
        assert!(status.success());
    }
    let bytes = std::fs::read(&first).unwrap();
    assert_eq!(bytes, std::fs::read(&second).unwrap());
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(serde_json::to_vec(&value).unwrap(), bytes);
    let probes = value["probes"].as_array().unwrap();
    assert_eq!(probes.len(), 14);
    assert!(probes.iter().all(|probe| probe["status"] == "pass"));
    for probe in probes {
        let facts = serde_json::to_vec(&probe["facts"]).unwrap();
        assert_eq!(
            probe["evidence"][0]["artifactDigest"],
            smesh_a2a::lifeline_acceptance::criteria_evidence_digest(
                "operational-lifeline-qualification-evidence",
                &facts,
            )
        );
    }
    assert_eq!(
        probes
            .iter()
            .map(|probe| probe["criterionId"].as_str().unwrap())
            .collect::<Vec<_>>(),
        canonical_criteria()
            .unwrap()
            .iter()
            .filter(|criterion| criterion.plane == AcceptancePlane::Qualification)
            .map(|criterion| criterion.id.as_str())
            .collect::<Vec<_>>()
    );
    let evaluated = evaluate_operational_lifeline(&package, &bytes).unwrap();
    assert_eq!(evaluated.scorecard.summary.passed, "40");
}

#[cfg(unix)]
#[test]
fn qualification_preserves_predictable_collision_and_removes_only_owned_roots() {
    let root = TempRoot::new("qualification-temp-ownership");
    let temp_base = OwnedTempDir::create("sq-").unwrap();
    let output = root.path().join("qualification.json");
    let sentinel = root
        .path()
        .join("smesh-qualification-ratification-sentinel");
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let package = repo.join("demo/fixtures/operational-lifeline-v1");
    let script = format!(
        "old=\"$TMPDIR/smesh-qualification-ratification-$$\"; mkdir \"$old\"; : > \"$old/sentinel\"; ln -s \"$old/sentinel\" \"{}\"; exec \"$1\" \"$2\" \"$3\" \"$3\" \"$4\"",
        sentinel.display()
    );
    let _status = process::bounded_status(
        Command::new("/bin/sh")
            .args(["-c", &script, "qualification-temp-owner"])
            .arg(QUALIFICATION_BIN.expect("qualification binary missing"))
            .arg(repo)
            .arg(&package)
            .arg(&output)
            .env("TMPDIR", temp_base.path()),
        QUALIFICATION_WATCHDOG,
        "qualification temporary-root ownership regression",
    )
    .unwrap();
    assert!(
        sentinel.exists(),
        "pre-existing predictable path was deleted"
    );
    let leftovers = std::fs::read_dir(temp_base.path())
        .unwrap()
        .filter(|entry| {
            let entry = entry.as_ref().unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            name.starts_with("smesh-qualification-")
                && entry.file_type().unwrap().is_dir()
                && !entry.path().join("sentinel").exists()
        })
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert!(leftovers.is_empty(), "owned roots survived: {leftovers:?}");
}

#[cfg(target_os = "linux")]
#[test]
fn qualification_browser_socket_trace_has_no_dns_or_non_loopback_attempt() {
    assert!(
        Path::new("/usr/bin/strace").is_file(),
        "strace is required for Linux qualification"
    );
    assert!(
        Path::new("/usr/bin/bwrap").is_file(),
        "bubblewrap is required for Linux qualification"
    );
    let root = TempRoot::new("egress-strace");
    let trace = root.path().join("sockets.trace");
    let browser_profile = root.path().join("browser-profile");
    std::fs::create_dir(&browser_profile).unwrap();
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let status = process::bounded_status(
        Command::new("/usr/bin/strace")
            .args(["-f", "-qq", "-z", "-e", "trace=connect,sendto", "-o"])
            .arg(&trace)
            .args([
                "bwrap",
                "--unshare-net",
                "--die-with-parent",
                "--dev-bind",
                "/",
                "/",
                "--proc",
                "/proc",
                "--",
                "node",
            ])
            .arg(repo.join("demo/operational-qualification.mjs"))
            .env("SMESH_QUALIFICATION_BROWSER_PROFILE", &browser_profile)
            .current_dir(repo.join("demo")),
        QUALIFICATION_WATCHDOG,
        "qualification browser socket trace",
    )
    .unwrap();
    assert!(status.success());
    let sockets = std::fs::read_to_string(trace).unwrap();
    for line in sockets.lines().filter(|line| line.contains("AF_INET")) {
        assert!(
            line.contains("127.0.0.1")
                || line.contains("sin6_addr=inet_pton(AF_INET6, \"::1\"")
                || line.contains("EAFNOSUPPORT"),
            "external socket attempt: {line}"
        );
        assert!(!line.contains("sin_port=htons(53)"), "DNS attempt: {line}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn forced_browser_timeout_reaps_owned_node_chrome_and_listener() {
    let root = TempRoot::new("browser-timeout");
    let output = root.path().join("qualification.json");
    let marker = root.path().join("lifecycle.json");
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let package = repo.join("demo/fixtures/operational-lifeline-v1");
    let started = Instant::now();
    let status = process::bounded_status(
        Command::new(QUALIFICATION_BIN.expect("qualification binary missing"))
            .arg(repo)
            .arg(&package)
            .arg(&package)
            .arg(&output)
            .env("SMESH_QUALIFICATION_FORCE_BROWSER_HANG", "1")
            .env("SMESH_QUALIFICATION_BROWSER_TIMEOUT_MS", "500")
            .env("SMESH_QUALIFICATION_LIFECYCLE_MARKER", &marker),
        Duration::from_secs(5),
        "forced browser-timeout qualification runner",
    )
    .unwrap();
    assert!(!status.success());
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(!output.exists());
    let lifecycle: serde_json::Value =
        serde_json::from_slice(&std::fs::read(marker).unwrap()).unwrap();
    let node_pid = lifecycle["nodePid"].as_u64().unwrap();
    let browser_pid = lifecycle["browserPid"].as_u64().unwrap();
    let listener_socket = lifecycle["listenerSocket"]
        .as_str()
        .unwrap()
        .strip_prefix("socket:[")
        .and_then(|value| value.strip_suffix(']'))
        .unwrap();
    let profile_argument = lifecycle["profileArgument"].as_str().unwrap();
    let profile_path = profile_argument
        .strip_prefix("--user-data-dir=")
        .expect("Chrome profile argument");
    assert!(
        Path::new(profile_path)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("smesh-qualification-browser-profile-"),
        "profile was not created and owned by Rust: {profile_path}"
    );
    assert!(
        !Path::new(profile_path).exists(),
        "owned Chrome profile survived reap: {profile_path}"
    );
    for pid in [node_pid, browser_pid] {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Path::new(&format!("/proc/{pid}")).exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "orphan pid {pid}"
        );
    }
    for entry in std::fs::read_dir("/proc").unwrap() {
        let entry = entry.unwrap();
        if entry.file_name().to_string_lossy().parse::<u64>().is_err() {
            continue;
        }
        let cmdline = std::fs::read(entry.path().join("cmdline")).unwrap_or_default();
        assert!(
            !cmdline
                .windows(profile_argument.len())
                .any(|window| window == profile_argument.as_bytes()),
            "orphan Chrome descendant retained the owned profile"
        );
    }
    for sockets in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let table = std::fs::read_to_string(sockets).unwrap();
        assert!(
            !table
                .lines()
                .flat_map(|line| line.split_whitespace())
                .any(|field| field == listener_socket),
            "owned listener socket {listener_socket} survived timeout"
        );
    }
}

#[cfg(unix)]
#[test]
fn browser_watchdog_is_bounded_and_does_not_resolve_kill_from_path() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = TempRoot::new("browser-fake-kill");
    let fake_bin = root.path().join("bin");
    std::fs::create_dir(&fake_bin).unwrap();
    let invoked = root.path().join("fake-kill-invoked");
    let fake_kill = fake_bin.join("kill");
    std::fs::write(
        &fake_kill,
        format!(
            "#!/bin/sh\n: > '{}'\nsleep 2\nexec /bin/kill \"$@\"\n",
            invoked.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&fake_kill, std::fs::Permissions::from_mode(0o755)).unwrap();
    let output = root.path().join("qualification.json");
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let package = repo.join("demo/fixtures/operational-lifeline-v1");
    let mut path = fake_bin.into_os_string();
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap());
    let started = Instant::now();
    let status = process::bounded_status(
        Command::new(QUALIFICATION_BIN.expect("qualification binary missing"))
            .arg(repo)
            .arg(&package)
            .arg(&package)
            .arg(&output)
            .env("PATH", path)
            .env("SMESH_QUALIFICATION_FORCE_BROWSER_HANG", "1")
            .env("SMESH_QUALIFICATION_BROWSER_TIMEOUT_MS", "50"),
        Duration::from_secs(9),
        "PATH-independent browser watchdog regression",
    )
    .unwrap();
    assert!(!status.success());
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(!invoked.exists(), "PATH-resolved fake kill was invoked");
}

#[cfg(target_os = "linux")]
#[test]
fn tampered_lifecycle_marker_cannot_authorize_profile_cleanup() {
    let root = TempRoot::new("browser-marker-tamper");
    let unrelated = root.path().join("unrelated-profile");
    std::fs::create_dir(&unrelated).unwrap();
    let sentinel = unrelated.join("sentinel");
    std::fs::write(&sentinel, b"preserve").unwrap();
    let output = root.path().join("qualification.json");
    let marker = root.path().join("lifecycle.json");
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let package = repo.join("demo/fixtures/operational-lifeline-v1");
    let status = process::bounded_status(
        Command::new(QUALIFICATION_BIN.expect("qualification binary missing"))
            .arg(repo)
            .arg(&package)
            .arg(&package)
            .arg(&output)
            .env("SMESH_QUALIFICATION_FORCE_BROWSER_HANG", "1")
            .env("SMESH_QUALIFICATION_BROWSER_TIMEOUT_MS", "500")
            .env("SMESH_QUALIFICATION_LIFECYCLE_MARKER", &marker)
            .env("SMESH_QUALIFICATION_LIFECYCLE_REPORTED_PROFILE", &unrelated),
        Duration::from_secs(5),
        "tampered lifecycle-marker qualification runner",
    )
    .unwrap();
    assert!(!status.success());
    let lifecycle: serde_json::Value =
        serde_json::from_slice(&std::fs::read(marker).unwrap()).unwrap();
    assert_eq!(
        lifecycle["profileArgument"],
        format!("--user-data-dir={}", unrelated.display())
    );
    assert_eq!(std::fs::read(sentinel).unwrap(), b"preserve");
}

#[test]
fn verify_report_rejects_extras_and_noncanonical_bytes() {
    let package =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("demo/fixtures/operational-lifeline-v1");
    let artifacts = evaluate_operational_lifeline(&package, &passing_qualification()).unwrap();
    let root = TempRoot::new("verify-report");
    let report = root.path().join("report");
    std::fs::create_dir(&report).unwrap();
    std::fs::write(
        report.join("acceptance-scorecard.json"),
        &artifacts.scorecard_json,
    )
    .unwrap();
    std::fs::write(
        report.join("acceptance-receipt.json"),
        &artifacts.receipt_json,
    )
    .unwrap();
    assert!(verify_acceptance_report(&report).is_ok());

    std::fs::write(report.join("extra.json"), b"{}").unwrap();
    assert!(verify_acceptance_report(&report).is_err());
    std::fs::remove_file(report.join("extra.json")).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&artifacts.scorecard_json).unwrap();
    std::fs::write(
        report.join("acceptance-scorecard.json"),
        serde_json::to_vec_pretty(&value).unwrap(),
    )
    .unwrap();
    assert!(verify_acceptance_report(&report).is_err());

    std::fs::write(
        report.join("acceptance-scorecard.json"),
        &artifacts.scorecard_json,
    )
    .unwrap();
    std::fs::remove_file(report.join("acceptance-receipt.json")).unwrap();
    assert!(verify_acceptance_report(&report).is_err());
    std::fs::write(
        report.join("acceptance-receipt.json"),
        &artifacts.receipt_json,
    )
    .unwrap();
    std::fs::write(
        report.join("acceptance-scorecard.json"),
        vec![b'x'; 128 * 1024 + 1],
    )
    .unwrap();
    assert!(verify_acceptance_report(&report).is_err());

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        std::fs::write(
            report.join("acceptance-scorecard.json"),
            &artifacts.scorecard_json,
        )
        .unwrap();
        std::fs::remove_file(report.join("acceptance-receipt.json")).unwrap();
        symlink(
            report.join("acceptance-scorecard.json"),
            report.join("acceptance-receipt.json"),
        )
        .unwrap();
        assert!(verify_acceptance_report(&report).is_err());
    }
}

#[test]
fn verify_report_cli_accepts_only_the_exact_two_file_report() {
    let root = TempRoot::new("verify-report-cli");
    let qualification = root.path().join("qualification.json");
    let output = root.path().join("report");
    std::fs::write(&qualification, passing_qualification()).unwrap();
    let binary = ACCEPTANCE_BIN.expect("acceptance binary missing");
    assert!(
        process::bounded_status(
            Command::new(binary)
                .arg(
                    Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("demo/fixtures/operational-lifeline-v1"),
                )
                .arg(&qualification)
                .arg(&output),
            CLI_WATCHDOG,
            "acceptance report generation",
        )
        .unwrap()
        .success()
    );
    assert!(
        process::bounded_status(
            Command::new(binary).arg("verify-report").arg(&output),
            CLI_WATCHDOG,
            "valid acceptance report verification",
        )
        .unwrap()
        .success()
    );
    std::fs::write(output.join("unexpected"), b"x").unwrap();
    assert!(
        !process::bounded_status(
            Command::new(binary).arg("verify-report").arg(&output),
            CLI_WATCHDOG,
            "invalid acceptance report verification",
        )
        .unwrap()
        .success()
    );
}

fn passing_qualification() -> Vec<u8> {
    static BYTES: OnceLock<Vec<u8>> = OnceLock::new();
    BYTES
        .get_or_init(|| {
            let root = TempRoot::new("actual-qualification");
            let output = root.path().join("qualification.json");
            let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
            let package = repo.join("demo/fixtures/operational-lifeline-v1");
            let status = process::bounded_status(
                Command::new(QUALIFICATION_BIN.expect("qualification binary missing"))
                    .arg(repo)
                    .arg(&package)
                    .arg(&package)
                    .arg(&output),
                QUALIFICATION_WATCHDOG,
                "cached passing qualification",
            )
            .unwrap();
            assert!(status.success());
            std::fs::read(output).unwrap()
        })
        .clone()
}

#[cfg(target_os = "linux")]
fn process_identity_is_live(pid: u32, expected_start_time: u64) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    stat.rsplit_once(") ")
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .and_then(|start_time| start_time.parse::<u64>().ok())
        == Some(expected_start_time)
}

struct TempRoot(OwnedTempDir);

impl TempRoot {
    fn new(label: &str) -> Self {
        OwnedTempDir::create(&format!("smesh-lifeline-acceptance-{label}-"))
            .map(Self)
            .unwrap()
    }

    fn path(&self) -> &Path {
        self.0.path()
    }
}

struct PackageCopy(OwnedTempDir);

impl PackageCopy {
    fn new() -> Self {
        let owned = OwnedTempDir::create("smesh-lifeline-acceptance-package-").unwrap();
        let path = owned.path();
        let source =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("demo/fixtures/operational-lifeline-v1");
        std::fs::create_dir_all(path.join("restricted")).unwrap();
        for directory in [source.clone(), source.join("restricted")] {
            for entry in std::fs::read_dir(directory).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_file() {
                    let relative = entry.path().strip_prefix(&source).unwrap().to_owned();
                    std::fs::copy(entry.path(), path.join(relative)).unwrap();
                }
            }
        }
        Self(owned)
    }

    fn path(&self) -> &Path {
        self.0.path()
    }
}
