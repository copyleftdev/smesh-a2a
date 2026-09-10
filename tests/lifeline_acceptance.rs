use smesh_a2a::lifeline_acceptance::{
    AcceptancePlane, DenyEffectBroker, EffectClass, canonical_criteria, criteria_evidence_digest,
    evaluate_operational_lifeline, verify_acceptance_receipt, verify_acceptance_report,
};
use smesh_a2a::owned_temp::OwnedTempDir;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Barrier, Mutex, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

#[path = "support/process.rs"]
#[allow(dead_code)]
mod process;

const ACCEPTANCE_BIN: Option<&str> = option_env!("CARGO_BIN_EXE_operational-lifeline-acceptance");
const QUALIFICATION_BIN: Option<&str> =
    option_env!("CARGO_BIN_EXE_operational-lifeline-qualification");
const CLI_WATCHDOG: Duration = Duration::from_secs(30);
const QUALIFICATION_WATCHDOG: Duration = Duration::from_secs(60);

fn browser_process_lock() -> &'static Mutex<()> {
    static LOCK: Mutex<()> = Mutex::new(());
    &LOCK
}

fn with_browser_process_lock<T>(invoke: impl FnOnce() -> T) -> T {
    let _guard = browser_process_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    invoke()
}

fn bounded_browser_output(
    command: &mut Command,
    watchdog: Duration,
    label: &str,
) -> Result<(std::process::Output, Duration), String> {
    with_browser_process_lock(|| {
        let started = Instant::now();
        process::bounded_output(command, watchdog, label).map(|output| (output, started.elapsed()))
    })
}

fn bounded_browser_status(
    command: &mut Command,
    watchdog: Duration,
    label: &str,
) -> Result<(std::process::ExitStatus, Duration), String> {
    with_browser_process_lock(|| {
        let started = Instant::now();
        process::bounded_status(command, watchdog, label).map(|status| (status, started.elapsed()))
    })
}

#[test]
fn browser_process_lock_serializes_complete_invocations() {
    const WATCHDOG: Duration = Duration::from_secs(120);

    let rendezvous = Arc::new(Barrier::new(2));
    let (first_entered_tx, first_entered_rx) = mpsc::channel();
    let (release_first_tx, release_first_rx) = mpsc::channel();
    let (second_attempting_tx, second_attempting_rx) = mpsc::channel();
    let (second_entered_tx, second_entered_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();

    let first_done = done_tx.clone();
    let first = thread::spawn(move || {
        with_browser_process_lock(|| {
            first_entered_tx.send(()).unwrap();
            release_first_rx.recv_timeout(WATCHDOG).unwrap();
        });
        first_done.send(()).unwrap();
    });
    first_entered_rx.recv_timeout(WATCHDOG).unwrap();

    let second_rendezvous = Arc::clone(&rendezvous);
    let second_done = done_tx;
    let second = thread::spawn(move || {
        second_rendezvous.wait();
        assert!(browser_process_lock().try_lock().is_err());
        second_attempting_tx.send(()).unwrap();
        with_browser_process_lock(|| second_entered_tx.send(()).unwrap());
        second_done.send(()).unwrap();
    });
    rendezvous.wait();
    second_attempting_rx.recv_timeout(WATCHDOG).unwrap();
    assert!(
        matches!(
            second_entered_rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ),
        "second invocation entered while the first held the browser process lock"
    );

    release_first_tx.send(()).unwrap();
    second_entered_rx.recv_timeout(WATCHDOG).unwrap();
    done_rx.recv_timeout(WATCHDOG).unwrap();
    done_rx.recv_timeout(WATCHDOG).unwrap();
    first.join().unwrap();
    second.join().unwrap();
}

#[test]
fn bounded_browser_process_calls_are_centralized() {
    let source = include_str!("lifeline_acceptance.rs");
    let bounded_output = ["process::bounded_", "output("].concat();
    let bounded_status = ["process::bounded_", "status("].concat();
    assert_eq!(source.matches(&bounded_output).count(), 1);
    assert_eq!(source.matches(&bounded_status).count(), 1);
}

#[cfg(target_os = "linux")]
const OUTBOUND_SYSCALLS: [&str; 4] = ["connect", "sendto", "sendmsg", "sendmmsg"];

#[cfg(target_os = "linux")]
fn trace_pid_and_body(line: &str) -> Option<(String, &str)> {
    let line = line.trim_start();
    if let Some(rest) = line.strip_prefix("[pid ") {
        let (pid, body) = rest.split_once(']')?;
        return pid
            .chars()
            .all(|character| character.is_ascii_digit())
            .then(|| (pid.to_string(), body.trim_start()));
    }
    let split = line.find(char::is_whitespace);
    if let Some(index) = split {
        let candidate = &line[..index];
        if !candidate.is_empty()
            && candidate
                .chars()
                .all(|character| character.is_ascii_digit())
        {
            return Some((candidate.to_string(), line[index..].trim_start()));
        }
    }
    Some((String::new(), line))
}

#[cfg(target_os = "linux")]
fn split_top_level(value: &str) -> Option<Vec<&str>> {
    let mut fields = Vec::new();
    let mut stack = Vec::new();
    let mut quoted = false;
    let mut escaped = false;
    let mut start = 0;
    for (index, character) in value.char_indices() {
        if quoted {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                quoted = false;
            }
            continue;
        }
        match character {
            '"' => quoted = true,
            '(' | '{' | '[' => stack.push(character),
            ')' => {
                if stack.pop() != Some('(') {
                    return None;
                }
            }
            '}' => {
                if stack.pop() != Some('{') {
                    return None;
                }
            }
            ']' => {
                if stack.pop() != Some('[') {
                    return None;
                }
            }
            ',' if stack.is_empty() => {
                fields.push(value[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    if quoted || escaped || !stack.is_empty() {
        return None;
    }
    fields.push(value[start..].trim());
    Some(fields)
}

#[cfg(target_os = "linux")]
fn wrapped_fields(value: &str, open: char, close: char) -> Option<Vec<&str>> {
    let value = value.trim();
    let inner = value.strip_prefix(open)?.strip_suffix(close)?;
    split_top_level(inner)
}

#[cfg(target_os = "linux")]
fn quoted_after<'a>(value: &'a str, marker: &str) -> Option<&'a str> {
    let start = value.find(marker)? + marker.len();
    let suffix = &value[start..];
    let mut escaped = false;
    for (index, character) in suffix.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            return Some(&suffix[..index]);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn decoded_strace_string(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            if bytes.get(index + 1) != Some(&b'x') {
                return None;
            }
            let digits = std::str::from_utf8(bytes.get(index + 2..index + 4)?).ok()?;
            decoded.push(u8::from_str_radix(digits, 16).ok()?);
            index += 4;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

#[cfg(target_os = "linux")]
struct InetDestination {
    is_loopback: bool,
    is_dns: bool,
}

#[cfg(target_os = "linux")]
fn network_port(fields: &[&str], field_name: &str) -> Option<u16> {
    let mut ports = fields
        .iter()
        .filter_map(|field| field.strip_prefix(field_name));
    let port = ports.next()?;
    if ports.next().is_some() {
        return None;
    }
    port.strip_prefix("htons(")?.strip_suffix(')')?.parse().ok()
}

#[cfg(target_os = "linux")]
fn inet_destination(sockaddr: &str) -> Option<Vec<InetDestination>> {
    let sockaddr = sockaddr.trim();
    if sockaddr == "NULL" {
        return Some(Vec::new());
    }
    let fields = wrapped_fields(sockaddr, '{', '}')?;
    let family = fields
        .iter()
        .find_map(|field| field.strip_prefix("sa_family="))?;
    if family == "AF_INET6" {
        let port = network_port(&fields, "sin6_port=")?;
        let address = decoded_strace_string(quoted_after(sockaddr, "inet_pton(AF_INET6, \"")?)?;
        return address.parse::<std::net::Ipv6Addr>().ok().map(|address| {
            vec![InetDestination {
                is_loopback: address.is_loopback(),
                is_dns: port == 53,
            }]
        });
    }
    if family == "AF_INET" {
        let port = network_port(&fields, "sin_port=")?;
        let address = decoded_strace_string(quoted_after(sockaddr, "sin_addr=inet_addr(\"")?)?;
        return address.parse::<std::net::Ipv4Addr>().ok().map(|address| {
            vec![InetDestination {
                is_loopback: address.is_loopback(),
                is_dns: port == 53,
            }]
        });
    }
    Some(Vec::new())
}

#[cfg(target_os = "linux")]
fn message_destinations(header: &str) -> Option<Vec<InetDestination>> {
    let fields = wrapped_fields(header, '{', '}')?;
    let name = fields
        .iter()
        .find_map(|field| field.strip_prefix("msg_name="))?;
    inet_destination(name)
}

#[cfg(target_os = "linux")]
fn syscall_destinations(syscall: &str, arguments: &str) -> Option<Vec<InetDestination>> {
    let arguments = split_top_level(arguments)?;
    match syscall {
        "connect" => inet_destination(arguments.get(1)?),
        "sendto" => inet_destination(arguments.get(4)?),
        "sendmsg" => message_destinations(arguments.get(1)?),
        "sendmmsg" => {
            let messages = wrapped_fields(arguments.get(1)?, '[', ']')?;
            let mut destinations = Vec::new();
            for message in messages {
                let fields = wrapped_fields(message, '{', '}')?;
                let header = fields
                    .iter()
                    .find_map(|field| field.strip_prefix("msg_hdr="))?;
                destinations.extend(message_destinations(header)?);
            }
            Some(destinations)
        }
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn completed_call<'a>(body: &'a str, syscall: &str) -> Option<(&'a str, &'a str)> {
    let open = syscall.len();
    if body.as_bytes().get(open) != Some(&b'(') {
        return None;
    }
    let mut depth = 0_u32;
    let mut quoted = false;
    let mut escaped = false;
    for (offset, character) in body[open..].char_indices() {
        if quoted {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                quoted = false;
            }
            continue;
        }
        match character {
            '"' => quoted = true,
            '(' => depth += 1,
            ')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    let close = open + offset;
                    return Some((&body[open + 1..close], body[close + 1..].trim()));
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn explicitly_fail_closed(result: &str) -> bool {
    let Some(result) = result.strip_prefix("= -1 ") else {
        return false;
    };
    ["ENETUNREACH", "EACCES"].iter().any(|code| {
        result == *code
            || result
                .strip_prefix(&format!("{code} "))
                .is_some_and(|detail| detail.starts_with('(') && detail.ends_with(')'))
    })
}

#[cfg(target_os = "linux")]
fn completed_inet_effect(body: &str, syscall: &str) -> Option<bool> {
    let (arguments, result) = completed_call(body, syscall)?;
    let destinations = syscall_destinations(syscall, arguments)?;
    Some(
        destinations
            .iter()
            .all(|destination| destination.is_loopback && !destination.is_dns)
            || explicitly_fail_closed(result),
    )
}

#[cfg(target_os = "linux")]
fn forbidden_inet_effect(trace: &str) -> Option<String> {
    use std::collections::{HashMap, VecDeque};

    let mut unfinished: HashMap<(String, &'static str), VecDeque<(String, String)>> =
        HashMap::new();
    for line in trace.lines() {
        let Some((pid, body)) = trace_pid_and_body(line) else {
            if OUTBOUND_SYSCALLS
                .iter()
                .any(|syscall| line.contains(syscall))
            {
                return Some(line.to_string());
            }
            continue;
        };
        if let Some(resumed) = body.strip_prefix("<... ") {
            let Some((syscall, suffix)) = resumed.split_once(" resumed>") else {
                if OUTBOUND_SYSCALLS
                    .iter()
                    .any(|syscall| resumed.starts_with(syscall))
                {
                    return Some(line.to_string());
                }
                continue;
            };
            let Some(syscall) = OUTBOUND_SYSCALLS
                .iter()
                .copied()
                .find(|candidate| *candidate == syscall)
            else {
                continue;
            };
            let key = (pid, syscall);
            let Some((prefix, _original)) = unfinished.get_mut(&key).and_then(VecDeque::pop_front)
            else {
                return Some(line.to_string());
            };
            if completed_inet_effect(&format!("{prefix}{suffix}"), syscall) != Some(true) {
                return Some(line.to_string());
            }
            continue;
        }
        let Some(syscall) = OUTBOUND_SYSCALLS
            .iter()
            .copied()
            .find(|syscall| body.starts_with(&format!("{syscall}(")))
        else {
            if OUTBOUND_SYSCALLS.iter().any(|syscall| {
                body.strip_prefix(syscall).is_some_and(|suffix| {
                    !suffix.starts_with(|character: char| {
                        character.is_alphanumeric() || character == '_'
                    })
                })
            }) {
                return Some(line.to_string());
            }
            continue;
        };
        if let Some(prefix) = body.strip_suffix("<unfinished ...>") {
            unfinished
                .entry((pid, syscall))
                .or_default()
                .push_back((prefix.to_string(), line.to_string()));
        } else if completed_inet_effect(body, syscall) != Some(true) {
            return Some(line.to_string());
        }
    }
    unfinished
        .into_values()
        .flat_map(VecDeque::into_iter)
        .next()
        .map(|(_, original)| original)
}

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
fn browser_boundary_invariants_survive_coherent_rehash_and_offline_report_rebinding() {
    let package =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("demo/fixtures/operational-lifeline-v1");
    let baseline_qualification: serde_json::Value =
        serde_json::from_slice(&passing_qualification()).unwrap();
    let baseline_artifacts =
        evaluate_operational_lifeline(&package, &passing_qualification()).unwrap();
    for (label, fact_id, replacement) in [
        (
            "listener reached",
            "nodeListenerBrowserRequests",
            serde_json::json!("1"),
        ),
        (
            "unknown route continued",
            "unknownSameOriginAborted",
            serde_json::json!(false),
        ),
        (
            "request path altered",
            "requestPaths",
            serde_json::json!([
                "/fixtures/operational-lifeline-v1/actors.json",
                "/operational.html"
            ]),
        ),
        (
            "request path added",
            "requestPaths",
            serde_json::json!([
                "/fixtures/operational-lifeline-v1/actors.json",
                "/fixtures/operational-lifeline-v1/browser-bootstrap.json",
                "/fixtures/operational-lifeline-v1/editorial.json",
                "/fixtures/operational-lifeline-v1/package.jsonl",
                "/fixtures/operational-lifeline-v1/receipt.json",
                "/operational-app.mjs",
                "/operational-observatory.mjs",
                "/operational.css",
                "/operational.html",
                "/qualification-extra.mjs",
                "/vendor/three.module.min.js"
            ]),
        ),
    ] {
        let mut qualification = baseline_qualification.clone();
        let probe = qualification["probes"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|probe| probe["criterionId"] == "m3-28-ac4")
            .unwrap();
        probe["facts"][fact_id] = replacement.clone();
        let fact_bytes = serde_json::to_vec(&probe["facts"]).unwrap();
        probe["evidence"][0]["artifactDigest"] =
            criteria_evidence_digest("operational-lifeline-qualification-evidence", &fact_bytes)
                .into();
        let evaluated =
            evaluate_operational_lifeline(&package, &serde_json::to_vec(&qualification).unwrap())
                .unwrap();
        let result = evaluated
            .scorecard
            .results
            .iter()
            .find(|result| result.criterion_id == "m3-28-ac4")
            .unwrap();
        assert_eq!(result.status.as_str(), "fail", "{label}");
        assert_eq!(result.diagnostics[0].fact_id, fact_id, "{label}");
        assert_eq!(
            result.diagnostics[0].code.as_str(),
            "contradictoryEvidence",
            "{label}"
        );

        let mut scorecard: serde_json::Value =
            serde_json::from_slice(&baseline_artifacts.scorecard_json).unwrap();
        scorecard["qualificationFacts"]["m3-28-ac4"][fact_id] = replacement;
        let fact_bytes = serde_json::to_vec(&scorecard["qualificationFacts"]["m3-28-ac4"]).unwrap();
        let result = scorecard["results"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|result| result["criterionId"] == "m3-28-ac4")
            .unwrap();
        result["evidence"][0]["artifactDigest"] =
            criteria_evidence_digest("operational-lifeline-qualification-evidence", &fact_bytes)
                .into();
        let scorecard = serde_json::to_vec(&scorecard).unwrap();
        let receipt = coherently_rebind_receipt(&baseline_artifacts.receipt_json, &scorecard);
        let root = TempRoot::new("browser-invariant-report");
        let report = root.path().join("report");
        std::fs::create_dir(&report).unwrap();
        std::fs::write(report.join("acceptance-scorecard.json"), scorecard).unwrap();
        std::fs::write(report.join("acceptance-receipt.json"), receipt).unwrap();
        assert!(
            verify_acceptance_report(&report).is_err(),
            "offline verifier accepted {label}"
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
    assert_eq!(facts("m3-28-ac4")["nodeListenerBrowserRequests"], "0");
    assert_eq!(facts("m3-28-ac4")["unknownSameOriginAborted"], true);
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
    let (result, _) = bounded_browser_output(
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

    let (result, elapsed) = bounded_browser_output(
        Command::new(acceptance)
            .arg(package)
            .arg(supplied)
            .arg(&report),
        Duration::from_secs(3),
        "acceptance wrapper normal-exit descendant regression",
    )
    .unwrap();

    assert!(!result.status.success());
    assert!(elapsed < Duration::from_secs(2));
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

        let (result, elapsed) = bounded_browser_output(
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
        assert!(elapsed < Duration::from_secs(2));
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

    let (output, elapsed) = bounded_browser_output(
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
    assert!(elapsed < Duration::from_secs(5));
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
    let (result, _) = bounded_browser_output(
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
    let (result, _) = bounded_browser_output(
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

    let (result, _) = bounded_browser_output(
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
    let (status, _) = bounded_browser_status(
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
    let (status, _) = bounded_browser_status(
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
        let (status, _) = bounded_browser_status(
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
    let (_status, _) = bounded_browser_status(
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
fn socket_trace_parser_allows_loopback_effects_and_rejects_external_effects() {
    let allowed = concat!(
        "101 connect(7, {sa_family=AF_UNIX, sun_path=\"/tmp/browser.sock\"}, 110) = 0\n",
        "102 connect(8, {sa_family=AF_INET6, sin6_port=htons(443), inet_pton(AF_INET6, \"2001:4860:4860::8888\", &sin6_addr)}, 28) = -1 ENETUNREACH (Network is unreachable)\n",
        "103 sendto(9, \"dns\", 3, MSG_NOSIGNAL, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr(\"127.0.0.53\")}, 16) = -1 EACCES (Permission denied)\n",
        "107 connect(13, {sa_family=AF_INET6, sin6_port=htons(443), inet_pton(AF_INET6, \"2001:4860:4860::8888\", &sin6_addr)}, 28 <unfinished ...>\n",
        "107 <... connect resumed>) = -1 ENETUNREACH (Network is unreachable)\n",
        "108 connect(14, {sa_family=AF_INET, sin_port=htons(41721), sin_addr=inet_addr(\"127.42.0.1\")}, 16) = 0\n",
        "109 connect(15, {sa_family=AF_INET, sin_port=htons(41722), sin_addr=inet_addr(\"127.0.0.1\")}, 16) = -1 EINPROGRESS (Operation now in progress)\n",
        "110 connect(16, {sa_family=AF_INET6, sin6_port=htons(41723), inet_pton(AF_INET6, \"::1\", &sin6_addr)}, 28) = 0\n",
        "111 connect(17, {sa_family=AF_INET6, sin6_port=htons(41724), inet_pton(AF_INET6, \"::1\", &sin6_addr)}, 28) = -1 EINPROGRESS (Operation now in progress)\n",
        "112 sendto(18, \"local\", 5, MSG_NOSIGNAL, {sa_family=AF_INET6, sin6_port=htons(41725), inet_pton(AF_INET6, \"::1\", &sin6_addr)}, 28) = 5\n",
        "117 connect(23, {sa_family=AF_INET6, sin6_port=htons(443), inet_pton(AF_INET6, \"2001:db8::3\", &sin6_addr)}, 28 <unfinished ...>\n",
        "117 <... connect resumed>) = -1 ENETUNREACH (Network is unreachable)\n",
        "117 connect(24, {sa_family=AF_INET6, sin6_port=htons(443), inet_pton(AF_INET6, \"2001:db8::4\", &sin6_addr)}, 28 <unfinished ...>\n",
        "117 <... connect resumed>) = -1 EACCES (Permission denied)\n",
    );
    assert_eq!(forbidden_inet_effect(allowed), None);
    for effect in [
        "104 connect(10, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr(\"203.0.113.7\")}, 16) = 0",
        "105 connect(11, {sa_family=AF_INET6, sin6_port=htons(443), inet_pton(AF_INET6, \"2001:db8::1\", &sin6_addr)}, 28) = -1 EINPROGRESS (Operation now in progress)",
        "113 connect(19, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr(\"198.51.100.8\")}, 16 <unfinished ...>",
        "114 connect(20, {sa_family=AF_INET6, sin6_port=htons(443), inet_pton(AF_INET6, \"not-an-address\", &sin6_addr)}, 28) = 0",
        "115 connect(21, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr(\"203.0.113.8\")}, 16) = -1 EINPROGRESS (Operation now in progress)",
        "116 connect(22, {sa_family=AF_INET6, sin6_port=htons(443), inet_pton(AF_INET6, \"2001:db8::2\", &sin6_addr)}, 28) = 0",
    ] {
        assert_eq!(
            forbidden_inet_effect(&format!("{allowed}{effect}\n")),
            Some(effect.to_string())
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn socket_trace_parser_rejects_dns_unless_explicitly_fail_closed() {
    let explicitly_blocked = concat!(
        "401 connect(4, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr(\"127.0.0.53\")}, 16) = -1 EACCES (Permission denied)\n",
        "402 sendto(5, \"dns\", 3, MSG_NOSIGNAL, {sa_family=AF_INET6, sin6_port=htons(53), inet_pton(AF_INET6, \"::1\", &sin6_addr)}, 28) = -1 ENETUNREACH (Network is unreachable)\n",
        "403 sendmsg(6, {msg_name={sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr(\"127.0.0.53\")}, msg_namelen=16, msg_iov=[], msg_iovlen=0}, 0) = -1 EACCES (Permission denied)\n",
        "404 sendmmsg(7, [{msg_hdr={msg_name={sa_family=AF_INET6, sin6_port=htons(53), inet_pton(AF_INET6, \"::1\", &sin6_addr)}, msg_namelen=28, msg_iov=[], msg_iovlen=0}, msg_len=0}], 1, 0) = -1 ENETUNREACH (Network is unreachable)\n",
    );
    assert_eq!(forbidden_inet_effect(explicitly_blocked), None);

    for effect in [
        "405 connect(8, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr(\"127.0.0.53\")}, 16) = 0",
        "406 connect(9, {sa_family=AF_INET6, sin6_port=htons(53), inet_pton(AF_INET6, \"::1\", &sin6_addr)}, 28) = -1 EINPROGRESS (Operation now in progress)",
        "407 sendto(10, \"dns\", 3, MSG_NOSIGNAL, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr(\"127.0.0.53\")}, 16) = 3",
        "408 sendmsg(11, {msg_name={sa_family=AF_INET6, sin6_port=htons(53), inet_pton(AF_INET6, \"::1\", &sin6_addr)}, msg_namelen=28, msg_iov=[], msg_iovlen=0}, 0) = 1",
        "409 sendmmsg(12, [{msg_hdr={msg_name={sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr(\"127.0.0.53\")}, msg_namelen=16, msg_iov=[], msg_iovlen=0}, msg_len=0}], 1, 0) = 1",
        "410 sendto(13, \"dns\", 3, MSG_NOSIGNAL, {sa_family=AF_INET, sin_port=htons(unknown), sin_addr=inet_addr(\"127.0.0.1\")}, 16) = 3",
        "411 sendmsg(14, {msg_name={sa_family=AF_INET6, inet_pton(AF_INET6, \"::1\", &sin6_addr)}, msg_namelen=28, msg_iov=[], msg_iovlen=0}, 0) = 1",
        "412 connect(15, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr(\"127.0.0.53\")}, 16 <unfinished ...>",
        "413 sendto(16, \"dns\", 3, MSG_NOSIGNAL, {sa_family=AF_INET, sin_port=htons(8080), sin_port=htons(53), sin_addr=inet_addr(\"127.0.0.1\")}, 16) = 3",
    ] {
        assert_eq!(
            forbidden_inet_effect(&format!("{explicitly_blocked}{effect}\n")),
            Some(effect.to_string()),
            "{effect}",
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn socket_trace_parser_rejects_payload_address_and_result_spoofing() {
    let spoofed = "201 sendto(9, \"payload inet_addr(\\\"127.0.0.1\\\") and = -1 ENETUNREACH (\", 61, MSG_NOSIGNAL, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr(\"203.0.113.7\")}, 16) = 61\n";
    assert_eq!(
        forbidden_inet_effect(spoofed),
        Some(spoofed.trim().to_string())
    );
    let spoofed_dns_port = "202 sendto(10, \"payload sin_port=htons(53)\", 26, MSG_NOSIGNAL, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr(\"127.0.0.1\")}, 16) = 26\n";
    assert_eq!(forbidden_inet_effect(spoofed_dns_port), None);
}

#[cfg(target_os = "linux")]
#[test]
fn socket_trace_parser_structurally_covers_sendmsg_and_sendmmsg() {
    let allowed = concat!(
        "[pid 301] sendmsg(4, {msg_name={sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr(\"127.0.0.1\")}, msg_namelen=16, msg_iov=[{iov_base=\"local\", iov_len=5}], msg_iovlen=1}, 0) = 5\n",
        "302 sendmmsg(5, [{msg_hdr={msg_name={sa_family=AF_INET6, sin6_port=htons(80), inet_pton(AF_INET6, \"::1\", &sin6_addr)}, msg_namelen=28, msg_iov=[{iov_base=\"local\", iov_len=5}], msg_iovlen=1}, msg_len=5}], 1, MSG_NOSIGNAL) = 1\n",
        "303 sendmsg(6, {msg_name={sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr(\"203.0.113.30\")}, msg_namelen=16, msg_iov=[{iov_base=\"blocked\", iov_len=7}], msg_iovlen=1}, 0) = -1 EACCES (Permission denied)\n",
        "304 sendmmsg(7, [{msg_hdr={msg_name={sa_family=AF_INET6, sin6_port=htons(80), inet_pton(AF_INET6, \"2001:db8::30\", &sin6_addr)}, msg_namelen=28, msg_iov=[{iov_base=\"blocked\", iov_len=7}], msg_iovlen=1}, msg_len=0}], 1, 0) = -1 ENETUNREACH (Network is unreachable)\n",
        "305 sendmsg(8, {msg_name={sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr(\"203.0.113.31\")} <unfinished ...>\n",
        "306 sendmsg(9, {msg_name={sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr(\"203.0.113.32\")} <unfinished ...>\n",
        "306 <... sendmsg resumed>, msg_namelen=16, msg_iov=[], msg_iovlen=0}, 0) = -1 EACCES (Permission denied)\n",
        "305 <... sendmsg resumed>, msg_namelen=16, msg_iov=[], msg_iovlen=0}, 0) = -1 ENETUNREACH (Network is unreachable)\n",
    );
    assert_eq!(forbidden_inet_effect(allowed), None);

    for effect in [
        "307 sendmsg(10, {msg_name={sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr(\"203.0.113.33\")}, msg_namelen=16, msg_iov=[{iov_base=\"ok\", iov_len=2}], msg_iovlen=1}, 0) = 2",
        "308 sendmsg(11, {msg_name={sa_family=AF_INET6, sin6_port=htons(80), inet_pton(AF_INET6, \"2001:db8::33\", &sin6_addr)}, msg_namelen=28, msg_iov=[], msg_iovlen=0}, 0) = -1 EINPROGRESS (Operation now in progress)",
        "309 sendmmsg(12, [{msg_hdr={msg_name={sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr(\"203.0.113.34\")}, msg_namelen=16, msg_iov=[], msg_iovlen=0}, msg_len=0}], 1, 0) = 1",
        "310 sendmmsg(13, [{msg_hdr={msg_name={sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr(\"203.0.113.35\")}, msg_namelen=16, msg_iov=[], msg_iovlen=0}, msg_len=0}], 1, 0) = ?",
        "311 sendmsg(14, {msg_name={sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr(\"203.0.113.36\")}, msg_namelen=16, msg_iov=[{iov_base=\"inet_addr(\\\"127.0.0.1\\\") = -1 EACCES (\", iov_len=43}], msg_iovlen=1}, 0) = 43",
        "312 sendmsg malformed",
        "313 sendmsg(15, {msg_name={sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr(\"203.0.113.37\")}, msg_namelen=16, msg_iov=[], msg_iovlen=0}, 0) = -1 EACCES (Permission denied) trailing",
    ] {
        assert_eq!(
            forbidden_inet_effect(&format!("{allowed}{effect}\n")),
            Some(effect.to_string()),
            "{effect}",
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn qualification_browser_uses_anonymous_control_pipe_without_successful_dns_or_non_loopback_effects()
 {
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
    let (status, _) = bounded_browser_status(
        Command::new("/usr/bin/strace")
            .args([
                "-f",
                "-qq",
                "-v",
                "-xx",
                "-e",
                "trace=network,process",
                "-o",
            ])
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
    let trace_text = std::fs::read_to_string(trace).unwrap();
    let hex_argument = |argument: &str| {
        use std::fmt::Write;

        argument.bytes().fold(String::new(), |mut encoded, byte| {
            write!(encoded, "\\x{byte:02x}").unwrap();
            encoded
        })
    };
    assert!(
        trace_text.contains(&hex_argument("--remote-debugging-pipe")),
        "qualification browser must use anonymous CDP pipes"
    );
    assert!(
        !trace_text.contains(&hex_argument("--remote-debugging-port")),
        "qualification browser exposed a TCP CDP listener"
    );
    let page_network_syscall = forbidden_inet_effect(&trace_text);
    assert!(
        page_network_syscall.is_none(),
        "browser page asset network syscall: {}",
        page_network_syscall.unwrap_or_default()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn forced_browser_timeout_reaps_owned_node_chrome_and_listener() {
    let root = TempRoot::new("browser-timeout");
    let output = root.path().join("qualification.json");
    let marker = root.path().join("lifecycle.json");
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let package = repo.join("demo/fixtures/operational-lifeline-v1");
    let (status, elapsed) = bounded_browser_status(
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
    assert!(elapsed < Duration::from_secs(10));
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
    let (status, elapsed) = bounded_browser_status(
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
    assert!(elapsed < Duration::from_secs(2));
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
    let (status, _) = bounded_browser_status(
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
        bounded_browser_status(
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
        .0
        .success()
    );
    assert!(
        bounded_browser_status(
            Command::new(binary).arg("verify-report").arg(&output),
            CLI_WATCHDOG,
            "valid acceptance report verification",
        )
        .unwrap()
        .0
        .success()
    );
    std::fs::write(output.join("unexpected"), b"x").unwrap();
    assert!(
        !bounded_browser_status(
            Command::new(binary).arg("verify-report").arg(&output),
            CLI_WATCHDOG,
            "invalid acceptance report verification",
        )
        .unwrap()
        .0
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
            let (status, _) = bounded_browser_status(
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
