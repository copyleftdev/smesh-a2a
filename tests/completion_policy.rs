use smesh_a2a::{
    ArtifactManifest, CompletionEvidence, CompletionPolicySpec, CompletionSnapshot,
    PolicyBlockReason, PolicyDecision, PolicyError, RatificationReceipt, RatificationStatement,
    TrustedAuthority, VersionedCompletionPolicy, content_digest,
};
use smesh_core::NodeIdentity;

fn artifact() -> ArtifactManifest {
    ArtifactManifest {
        name: "result.json".to_owned(),
        media_type: "application/json".to_owned(),
        digest: content_digest(br#"{"ok":true}"#),
    }
}

fn subject() -> String {
    smesh_a2a::artifact_set_digest(&[artifact()]).unwrap()
}

fn review(id: &str, approved: bool, assurance_bps: u16) -> CompletionEvidence {
    let evidence = format!("review:{id}").into_bytes();
    CompletionEvidence::Review {
        id: id.to_owned(),
        issuer: "review-authority".to_owned(),
        subject_digest: subject(),
        evidence_digest: content_digest(&evidence),
        evidence,
        approved,
        assurance_bps,
    }
}

fn test_evidence(id: &str, passed: bool, assurance_bps: u16) -> CompletionEvidence {
    let evidence = format!("test:{id}").into_bytes();
    CompletionEvidence::Test {
        id: id.to_owned(),
        issuer: "test-authority".to_owned(),
        subject_digest: subject(),
        evidence_digest: content_digest(&evidence),
        evidence,
        passed,
        assurance_bps,
    }
}

fn contradiction(id: &str, blocking: bool) -> CompletionEvidence {
    let evidence = format!("contradiction:{id}").into_bytes();
    CompletionEvidence::Contradiction {
        id: id.to_owned(),
        issuer: "contradiction-monitor".to_owned(),
        subject_digest: subject(),
        evidence_digest: content_digest(&evidence),
        evidence,
        blocking,
    }
}

fn snapshot(mut evidence: Vec<CompletionEvidence>) -> CompletionSnapshot {
    if !evidence
        .iter()
        .any(|item| matches!(item, CompletionEvidence::Contradiction { .. }))
    {
        evidence.push(contradiction("clearance", false));
    }
    CompletionSnapshot {
        task_id: "task-1".to_owned(),
        context_id: "context-1".to_owned(),
        request_digest: content_digest(b"request-1"),
        artifacts: vec![artifact()],
        evidence,
    }
}

fn baseline_spec() -> CompletionPolicySpec {
    CompletionPolicySpec {
        policy_id: "test-policy".to_owned(),
        version: 1,
        required_reviews: 1,
        required_tests: 1,
        required_attestations: 0,
        required_contradiction_clearances: 1,
        min_assurance_bps: 7_500,
        require_human_ratification: false,
        review_issuers: vec!["review-authority".to_owned()],
        test_issuers: vec!["test-authority".to_owned()],
        contradiction_issuers: vec!["contradiction-monitor".to_owned()],
        attestation_authorities: Vec::new(),
        ratification_authorities: Vec::new(),
        max_evidence_records: 16,
        max_artifacts: 4,
    }
}

#[test]
fn completion_requires_positive_evidence_and_zero_blocking_contradictions() {
    let policy = VersionedCompletionPolicy::new(baseline_spec()).unwrap();

    let missing = policy.evaluate(&snapshot(Vec::new())).unwrap();
    assert!(matches!(
        missing,
        PolicyDecision::Blocked(ref block)
            if block.reasons.contains(&PolicyBlockReason::InsufficientReviews)
                && block.reasons.contains(&PolicyBlockReason::InsufficientTests)
    ));

    let contradicted = policy
        .evaluate(&snapshot(vec![
            review("r1", true, 9_000),
            test_evidence("t1", true, 9_000),
            contradiction("c1", true),
        ]))
        .unwrap();
    assert!(matches!(
        contradicted,
        PolicyDecision::Blocked(ref block)
            if block.reasons.contains(&PolicyBlockReason::BlockingContradiction)
    ));

    let negative_test = policy
        .evaluate(&snapshot(vec![
            review("r1", true, 9_000),
            test_evidence("t1", false, 9_000),
        ]))
        .unwrap();
    assert!(matches!(
        negative_test,
        PolicyDecision::Blocked(ref block)
            if block.reasons.contains(&PolicyBlockReason::FailedTest)
    ));

    let mut missing_clearance = snapshot(vec![
        review("r1", true, 9_000),
        test_evidence("t1", true, 9_000),
    ]);
    missing_clearance
        .evidence
        .retain(|item| !matches!(item, CompletionEvidence::Contradiction { .. }));
    assert!(matches!(
        policy.evaluate(&missing_clearance).unwrap(),
        PolicyDecision::Blocked(ref block)
            if block
                .reasons
                .contains(&PolicyBlockReason::InsufficientContradictionClearances)
    ));
}

#[test]
fn accepted_receipt_is_deterministic_and_records_policy_and_evidence_hashes() {
    let policy = VersionedCompletionPolicy::new(baseline_spec()).unwrap();
    let first = snapshot(vec![
        review("r2", true, 8_000),
        test_evidence("t1", true, 9_000),
        review("r1", true, 9_000),
        contradiction("advisory", false),
    ]);
    let reordered = snapshot(vec![
        contradiction("advisory", false),
        review("r1", true, 9_000),
        review("r2", true, 8_000),
        test_evidence("t1", true, 9_000),
    ]);

    let PolicyDecision::Accepted(receipt) = policy.evaluate(&first).unwrap() else {
        panic!("expected acceptance");
    };
    let PolicyDecision::Accepted(reordered_receipt) = policy.evaluate(&reordered).unwrap() else {
        panic!("expected acceptance after reordering");
    };

    assert_eq!(receipt, reordered_receipt);
    assert_eq!(receipt.policy_id, "test-policy");
    assert_eq!(receipt.policy_version, 1);
    assert!(receipt.policy_hash.starts_with("sha256:"));
    assert!(receipt.evidence_snapshot_hash.starts_with("sha256:"));
    assert_eq!(receipt.artifact_set_digest, subject());
    assert_eq!(receipt.assurance_bps, 9_000);
    assert_eq!(receipt.evidence_hashes.len(), 4);
    assert!(receipt.ratification_receipt_hash.is_none());
    assert!(policy.verify_receipt(&receipt));
    assert!(format!("{policy:?}").contains("[REDACTED]"));
    let mut forged = receipt.clone();
    forged.assurance_bps = forged.assurance_bps.saturating_sub(1);
    assert!(!policy.verify_receipt(&forged));
}

#[test]
fn human_required_policy_needs_an_allowlisted_signed_receipt() {
    let authority = NodeIdentity::generate_named("human-authority");
    let mut spec = baseline_spec();
    spec.require_human_ratification = true;
    spec.ratification_authorities = vec![TrustedAuthority {
        node_id: authority.node_id().to_owned(),
        public_key: authority.public_key_hex(),
    }];
    let policy = VersionedCompletionPolicy::new(spec).unwrap();
    let evidence = vec![review("r1", true, 9_000), test_evidence("t1", true, 9_000)];

    let PolicyDecision::AwaitingRatification(checkpoint) =
        policy.evaluate(&snapshot(evidence.clone())).unwrap()
    else {
        panic!("human-required policy must wait");
    };
    assert!(policy.verify_checkpoint(&checkpoint, "task-1", "context-1"));
    let mut forged_checkpoint = checkpoint.clone();
    forged_checkpoint.request_digest = content_digest(b"forged request");
    assert!(!policy.verify_checkpoint(&forged_checkpoint, "task-1", "context-1"));

    let statement = RatificationStatement {
        policy_hash: checkpoint.policy_hash,
        evidence_snapshot_hash: checkpoint.evidence_snapshot_hash,
        artifact_set_digest: checkpoint.artifact_set_digest,
        approved: true,
    };
    let receipt = RatificationReceipt {
        statement: statement.clone(),
        authority: authority.attest(&statement.digest().unwrap()).into(),
    };
    let mut ratified = evidence.clone();
    ratified.push(CompletionEvidence::Ratification(receipt));
    assert!(matches!(
        policy.evaluate(&snapshot(ratified.clone())).unwrap(),
        PolicyDecision::Accepted(_)
    ));
    let mut cross_context = snapshot(ratified);
    cross_context.context_id = "different-context".to_owned();
    assert!(matches!(
        policy.evaluate(&cross_context),
        Err(PolicyError::RatificationStatementMismatch)
    ));

    let attacker = NodeIdentity::generate_named("attacker");
    let forged = RatificationReceipt {
        statement: statement.clone(),
        authority: attacker.attest(&statement.digest().unwrap()).into(),
    };
    let mut forged_evidence = evidence.clone();
    forged_evidence.push(CompletionEvidence::Ratification(forged));
    assert!(matches!(
        policy.evaluate(&snapshot(forged_evidence)),
        Err(PolicyError::UntrustedRatificationAuthority)
    ));

    let rejected_statement = RatificationStatement {
        approved: false,
        ..statement
    };
    let rejected_receipt = RatificationReceipt {
        authority: authority
            .attest(&rejected_statement.digest().unwrap())
            .into(),
        statement: rejected_statement,
    };
    let mut rejected = evidence;
    rejected.push(CompletionEvidence::Ratification(rejected_receipt));
    assert!(matches!(
        policy.evaluate(&snapshot(rejected)).unwrap(),
        PolicyDecision::Blocked(ref block)
            if block.reasons.contains(&PolicyBlockReason::HumanRejected)
    ));
}

#[test]
fn malformed_or_ambiguous_policy_inputs_fail_closed() {
    let policy = VersionedCompletionPolicy::new(baseline_spec()).unwrap();

    let duplicate = snapshot(vec![
        review("same", true, 9_000),
        test_evidence("same", true, 9_000),
    ]);
    assert!(matches!(
        policy.evaluate(&duplicate),
        Err(PolicyError::DuplicateEvidenceId(id)) if id == "same"
    ));

    let first = review("r1", true, 9_000);
    let mut repeated_provenance = review("r2", true, 9_000);
    if let (
        CompletionEvidence::Review {
            evidence: first_evidence,
            evidence_digest: first_digest,
            ..
        },
        CompletionEvidence::Review {
            evidence: second_evidence,
            evidence_digest: second_digest,
            ..
        },
    ) = (&first, &mut repeated_provenance)
    {
        *second_evidence = first_evidence.clone();
        *second_digest = first_digest.clone();
    }
    assert!(matches!(
        policy.evaluate(&snapshot(vec![
            first,
            repeated_provenance,
            test_evidence("t1", true, 9_000),
        ])),
        Err(PolicyError::DuplicateEvidenceProvenance(_))
    ));

    let mut untrusted = review("untrusted", true, 9_000);
    if let CompletionEvidence::Review { issuer, .. } = &mut untrusted {
        *issuer = "worker-chosen-alias".to_owned();
    }
    assert!(matches!(
        policy.evaluate(&snapshot(
            vec![untrusted, test_evidence("t1", true, 9_000),]
        )),
        Err(PolicyError::UntrustedEvidenceIssuer { .. })
    ));

    let mut mismatched_payload = review("mismatch", true, 9_000);
    if let CompletionEvidence::Review { evidence, .. } = &mut mismatched_payload {
        evidence.push(0xff);
    }
    assert!(matches!(
        policy.evaluate(&snapshot(vec![
            mismatched_payload,
            test_evidence("t1", true, 9_000),
        ])),
        Err(PolicyError::EvidenceDigestMismatch)
    ));

    let mut wrong_subject = review("r1", true, 9_000);
    if let CompletionEvidence::Review { subject_digest, .. } = &mut wrong_subject {
        *subject_digest = content_digest(b"different artifact");
    }
    assert!(matches!(
        policy.evaluate(&snapshot(vec![
            wrong_subject,
            test_evidence("t1", true, 9_000)
        ])),
        Err(PolicyError::SubjectDigestMismatch { .. })
    ));

    assert!(matches!(
        VersionedCompletionPolicy::new(CompletionPolicySpec {
            min_assurance_bps: 10_001,
            ..baseline_spec()
        }),
        Err(PolicyError::InvalidPolicy(_))
    ));

    let too_much = (0..17)
        .map(|index| review(&format!("r{index}"), true, 9_000))
        .collect();
    assert!(matches!(
        policy.evaluate(&snapshot(too_much)),
        Err(PolicyError::EvidenceLimitExceeded { .. })
    ));
}

#[test]
fn required_attestation_must_be_valid_and_subject_bound() {
    let identity = NodeIdentity::generate_named("attester");
    let mut spec = baseline_spec();
    spec.required_attestations = 1;
    spec.attestation_authorities = vec![TrustedAuthority {
        node_id: identity.node_id().to_owned(),
        public_key: identity.public_key_hex(),
    }];
    let policy = VersionedCompletionPolicy::new(spec).unwrap();
    let attestation = CompletionEvidence::Attestation {
        id: "a1".to_owned(),
        subject_digest: subject(),
        attestation: identity.attest(&subject()).into(),
        assurance_bps: 9_000,
    };
    assert!(matches!(
        policy
            .evaluate(&snapshot(vec![
                review("r1", true, 9_000),
                test_evidence("t1", true, 9_000),
                attestation,
            ]))
            .unwrap(),
        PolicyDecision::Accepted(_)
    ));

    let invalid = CompletionEvidence::Attestation {
        id: "a1".to_owned(),
        subject_digest: subject(),
        attestation: identity
            .attest(&content_digest(b"different subject"))
            .into(),
        assurance_bps: 9_000,
    };
    assert!(matches!(
        policy.evaluate(&snapshot(vec![
            review("r1", true, 9_000),
            test_evidence("t1", true, 9_000),
            invalid,
        ])),
        Err(PolicyError::InvalidAttestation(_))
    ));

    let attacker = NodeIdentity::generate_named("self-selected-attester");
    let untrusted = CompletionEvidence::Attestation {
        id: "a1".to_owned(),
        subject_digest: subject(),
        attestation: attacker.attest(&subject()).into(),
        assurance_bps: 9_000,
    };
    assert!(matches!(
        policy.evaluate(&snapshot(vec![
            review("r1", true, 9_000),
            test_evidence("t1", true, 9_000),
            untrusted,
        ])),
        Err(PolicyError::UntrustedEvidenceIssuer { .. })
    ));
}

#[test]
fn repeated_logical_issuer_does_not_inflate_required_cardinality() {
    let mut spec = baseline_spec();
    spec.required_reviews = 2;
    spec.review_issuers = vec![
        "review-authority".to_owned(),
        "review-authority-2".to_owned(),
    ];
    let policy = VersionedCompletionPolicy::new(spec).unwrap();
    assert!(matches!(
        policy
            .evaluate(&snapshot(vec![
                review("r1", true, 9_000),
                review("r2", true, 9_000),
                test_evidence("t1", true, 9_000),
            ]))
            .unwrap(),
        PolicyDecision::Blocked(ref block)
            if block.reasons.contains(&PolicyBlockReason::InsufficientReviews)
    ));
}

#[test]
fn assurance_threshold_is_inclusive_and_low_assurance_blocks() {
    let policy = VersionedCompletionPolicy::new(baseline_spec()).unwrap();
    assert!(matches!(
        policy
            .evaluate(&snapshot(vec![
                review("r1", true, 7_500),
                test_evidence("t1", true, 7_500),
            ]))
            .unwrap(),
        PolicyDecision::Accepted(_)
    ));
    assert!(matches!(
        policy
            .evaluate(&snapshot(vec![
                review("r1", true, 7_499),
                test_evidence("t1", true, 9_000),
            ]))
            .unwrap(),
        PolicyDecision::Blocked(ref block)
            if block.reasons.contains(&PolicyBlockReason::InsufficientReviews)
                && block.reasons.contains(&PolicyBlockReason::InsufficientAssurance)
    ));
}

#[test]
fn content_and_artifact_hashes_are_golden_order_independent_and_byte_sensitive() {
    assert_eq!(
        content_digest(b"abc"),
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_ne!(content_digest(b"abc"), content_digest(b"abd"));

    let left = ArtifactManifest {
        name: "left".to_owned(),
        media_type: "text/plain".to_owned(),
        digest: content_digest(b"left"),
    };
    let right = ArtifactManifest {
        name: "right".to_owned(),
        media_type: "text/plain".to_owned(),
        digest: content_digest(b"right"),
    };
    assert_eq!(
        smesh_a2a::artifact_set_digest(&[left.clone(), right.clone()]).unwrap(),
        smesh_a2a::artifact_set_digest(&[right.clone(), left.clone()]).unwrap()
    );
    let renamed = ArtifactManifest {
        name: "renamed".to_owned(),
        ..right.clone()
    };
    assert_ne!(
        smesh_a2a::artifact_set_digest(&[left.clone(), renamed]).unwrap(),
        smesh_a2a::artifact_set_digest(&[left, right]).unwrap()
    );
}

#[test]
fn persisted_policy_inputs_reject_unknown_and_fractional_fields() {
    let mut policy_json = serde_json::to_value(baseline_spec()).unwrap();
    policy_json["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<CompletionPolicySpec>(policy_json).is_err());

    let mut fractional = serde_json::to_value(review("r1", true, 9_000)).unwrap();
    fractional["assuranceBps"] = serde_json::json!(7500.5);
    assert!(serde_json::from_value::<CompletionEvidence>(fractional).is_err());

    let identity = NodeIdentity::generate_named("nested-schema-test");
    let mut attestation = serde_json::to_value(CompletionEvidence::Attestation {
        id: "a1".to_owned(),
        subject_digest: subject(),
        attestation: identity.attest(&subject()).into(),
        assurance_bps: 9_000,
    })
    .unwrap();
    attestation["attestation"]["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<CompletionEvidence>(attestation).is_err());

    let statement = RatificationStatement {
        policy_hash: content_digest(b"policy"),
        evidence_snapshot_hash: content_digest(b"snapshot"),
        artifact_set_digest: subject(),
        approved: true,
    };
    let mut receipt = serde_json::to_value(RatificationReceipt {
        authority: identity.attest(&statement.digest().unwrap()).into(),
        statement,
    })
    .unwrap();
    receipt["authority"]["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<RatificationReceipt>(receipt).is_err());
}

#[test]
fn policy_version_and_configuration_are_bound_to_the_policy_hash() {
    let first = VersionedCompletionPolicy::new(baseline_spec()).unwrap();
    assert!(matches!(
        VersionedCompletionPolicy::new(CompletionPolicySpec {
            version: 2,
            ..baseline_spec()
        }),
        Err(PolicyError::InvalidPolicy(_))
    ));
    assert!(matches!(
        VersionedCompletionPolicy::new(CompletionPolicySpec {
            required_reviews: 0,
            ..baseline_spec()
        }),
        Err(PolicyError::InvalidPolicy(_))
    ));
    assert!(matches!(
        VersionedCompletionPolicy::new(CompletionPolicySpec {
            min_assurance_bps: 0,
            ..baseline_spec()
        }),
        Err(PolicyError::InvalidPolicy(_))
    ));
    let stricter = VersionedCompletionPolicy::new(CompletionPolicySpec {
        required_tests: 2,
        test_issuers: vec!["test-authority".to_owned(), "test-authority-2".to_owned()],
        ..baseline_spec()
    })
    .unwrap();

    assert_ne!(first.policy_hash(), stricter.policy_hash());
}
