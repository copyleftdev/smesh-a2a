use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey};
use smesh_a2a::{
    CandidateGenerationV1, IssuerDecisionV1, IssuerEnrollmentV1, IssuerEvidenceV1, IssuerRoleV1,
    SemanticEvidenceError, SignedIssuerEvidenceV1, TEXT_CONCORDANCE_COMPLETION_POLICY_REVISION_V1,
    TEXT_CONCORDANCE_COMPLETION_POLICY_V1, TextConcordanceCandidatePacketV1, TextConcordanceLimits,
    process_text_concordance, sign_text_concordance_evidence,
};

type EvidenceMutation = Box<dyn Fn(&mut IssuerEvidenceV1)>;

#[test]
fn completion_policy_identifier_matches_normative_profile() {
    assert_eq!(TEXT_CONCORDANCE_COMPLETION_POLICY_V1, "smesh-completion/v1");
    assert_eq!(TEXT_CONCORDANCE_COMPLETION_POLICY_REVISION_V1, 1);
}

fn candidate() -> CandidateGenerationV1 {
    CandidateGenerationV1 {
        tenant_scope: "tenant-a".to_owned(),
        task_id: "task-a".to_owned(),
        context_id: "context-a".to_owned(),
        request_digest: format!("sha256:{}", "11".repeat(32)),
        artifact_set_digest: format!("sha256:{}", "22".repeat(32)),
        dispatch_id: "dispatch-a".to_owned(),
        attempt: 7,
        fence: 9,
        completion_policy: "smesh-completion/v1".to_owned(),
        completion_policy_revision: 1,
    }
}

#[test]
fn candidate_generation_digest_matches_closed_vector() {
    let generation = candidate();
    assert_eq!(
        generation.id().unwrap(),
        "sha256:5a806330ce7abeb90bf2c83376f5ac16f8ece3681891e48cea7135c7bebb63ae"
    );
    assert_eq!(
        serde_json::to_string(&generation).unwrap(),
        r#"{"tenant_scope":"tenant-a","task_id":"task-a","context_id":"context-a","request_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","artifact_set_digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","dispatch_id":"dispatch-a","attempt":7,"fence":9,"completion_policy":"smesh-completion/v1","completion_policy_revision":1}"#
    );
}

#[test]
fn evidence_digest_matches_closed_vector_and_exact_role_decision_pair() {
    let generation = candidate();
    let evidence = IssuerEvidenceV1::for_candidate(
        &generation,
        IssuerRoleV1::Review,
        "review-key-1".to_owned(),
    )
    .unwrap();

    assert_eq!(evidence.decision, IssuerDecisionV1::Approve);
    assert_eq!(
        evidence.digest().unwrap(),
        "sha256:a463401ac4641b5306802fdb0c499f17006871e2332127de9b0a081029698603"
    );
    assert_eq!(evidence.candidate_generation_id, generation.id().unwrap());
    evidence.validate_candidate(&generation).unwrap();
}

#[test]
fn every_authority_binding_is_recomputed_against_candidate() {
    let generation = candidate();
    let baseline =
        IssuerEvidenceV1::for_candidate(&generation, IssuerRoleV1::Test, "test-key-1".to_owned())
            .unwrap();

    let mutations: Vec<EvidenceMutation> = vec![
        Box::new(|value| value.tenant_scope.push('x')),
        Box::new(|value| value.task_id.push('x')),
        Box::new(|value| value.context_id.push('x')),
        Box::new(|value| value.request_digest = format!("sha256:{}", "33".repeat(32))),
        Box::new(|value| value.artifact_set_digest = format!("sha256:{}", "44".repeat(32))),
        Box::new(|value| value.dispatch_id.push('x')),
        Box::new(|value| value.attempt += 1),
        Box::new(|value| value.fence += 1),
        Box::new(|value| value.completion_policy.push('x')),
        Box::new(|value| value.completion_policy_revision += 1),
        Box::new(|value| value.candidate_generation_id = format!("sha256:{}", "55".repeat(32))),
    ];

    for mutate in mutations {
        let mut changed = baseline.clone();
        mutate(&mut changed);
        assert_eq!(
            changed.validate_candidate(&generation),
            Err(SemanticEvidenceError::BindingMismatch)
        );
    }
}

#[test]
fn closed_role_decisions_cannot_be_crossed() {
    assert_eq!(IssuerRoleV1::Review.decision(), IssuerDecisionV1::Approve);
    assert_eq!(IssuerRoleV1::Test.decision(), IssuerDecisionV1::Approve);
    assert_eq!(
        IssuerRoleV1::Contradiction.decision(),
        IssuerDecisionV1::Clear
    );
}

#[test]
fn unknown_and_extra_evidence_fields_fail_deserialization() {
    let generation = candidate();
    let evidence = IssuerEvidenceV1::for_candidate(
        &generation,
        IssuerRoleV1::Contradiction,
        "contradiction-key-1".to_owned(),
    )
    .unwrap();
    let mut json = serde_json::to_value(evidence).unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("extra".to_owned(), serde_json::json!(true));
    assert!(serde_json::from_value::<IssuerEvidenceV1>(json).is_err());
}

fn signed_review() -> (
    CandidateGenerationV1,
    IssuerEnrollmentV1,
    SignedIssuerEvidenceV1,
) {
    let generation = candidate();
    let evidence = IssuerEvidenceV1::for_candidate(
        &generation,
        IssuerRoleV1::Review,
        "review-key-1".to_owned(),
    )
    .unwrap();
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let signature = signing_key.sign(evidence.digest().unwrap().as_bytes());
    let enrollment = IssuerEnrollmentV1 {
        tenant_scope: generation.tenant_scope.clone(),
        issuer_role: IssuerRoleV1::Review,
        issuer_identity: evidence.issuer_identity.clone(),
        public_key: URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
        valid_from: 100,
        expires_at: 200,
        revoked_at: None,
    };
    let signed = SignedIssuerEvidenceV1 {
        evidence,
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    };
    (generation, enrollment, signed)
}

#[test]
fn enrolled_ed25519_signature_authorizes_only_exact_bound_evidence() {
    let (generation, enrollment, signed) = signed_review();
    signed.verify(&generation, &enrollment, 150).unwrap();

    let mut changed = signed.clone();
    changed.evidence.task_id.push('x');
    assert_eq!(
        changed.verify(&generation, &enrollment, 150),
        Err(SemanticEvidenceError::BindingMismatch)
    );
}

#[test]
fn noncanonical_key_and_signature_encodings_fail_closed() {
    let (generation, enrollment, signed) = signed_review();

    let mut padded_key = enrollment.clone();
    padded_key.public_key.push('=');
    assert_eq!(
        signed.verify(&generation, &padded_key, 150),
        Err(SemanticEvidenceError::InvalidPublicKey)
    );

    let mut padded_signature = signed;
    padded_signature.signature.push('=');
    assert_eq!(
        padded_signature.verify(&generation, &enrollment, 150),
        Err(SemanticEvidenceError::InvalidSignatureEncoding)
    );
}

#[test]
fn wrong_scope_role_identity_and_validity_fail_closed() {
    let (generation, enrollment, signed) = signed_review();
    let mut cases = Vec::new();

    let mut wrong_tenant = enrollment.clone();
    wrong_tenant.tenant_scope.push('x');
    cases.push((wrong_tenant, 150));

    let mut wrong_role = enrollment.clone();
    wrong_role.issuer_role = IssuerRoleV1::Test;
    cases.push((wrong_role, 150));

    let mut wrong_identity = enrollment.clone();
    wrong_identity.issuer_identity.push('x');
    cases.push((wrong_identity, 150));

    let mut revoked = enrollment.clone();
    revoked.revoked_at = Some(140);
    cases.push((revoked, 150));
    cases.push((enrollment.clone(), 99));
    cases.push((enrollment, 200));

    for (invalid_enrollment, now) in cases {
        assert!(
            signed
                .verify(&generation, &invalid_enrollment, now)
                .is_err()
        );
    }
}

fn candidate_packet(input: &str) -> TextConcordanceCandidatePacketV1 {
    let output = process_text_concordance(input, TextConcordanceLimits::default()).unwrap();
    let candidate = CandidateGenerationV1 {
        tenant_scope: "tenant-a".to_owned(),
        task_id: "task-a".to_owned(),
        context_id: "context-a".to_owned(),
        request_digest: output.request_digest,
        artifact_set_digest: output.artifact_set_digest,
        dispatch_id: "dispatch-a".to_owned(),
        attempt: 7,
        fence: 9,
        completion_policy: TEXT_CONCORDANCE_COMPLETION_POLICY_V1.to_owned(),
        completion_policy_revision: TEXT_CONCORDANCE_COMPLETION_POLICY_REVISION_V1,
    };
    TextConcordanceCandidatePacketV1 {
        candidate,
        input: input.to_owned(),
        artifact: URL_SAFE_NO_PAD.encode(output.artifact_bytes),
        observed_conflict_digests: Vec::new(),
    }
}

#[test]
fn issuer_recomputes_candidate_artifact_before_signing() {
    let packet = candidate_packet("Useful input\n");
    let signed = sign_text_concordance_evidence(
        &packet,
        IssuerRoleV1::Review,
        "review-key-1".to_owned(),
        &[7; 32],
    )
    .unwrap();
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let enrollment = IssuerEnrollmentV1 {
        tenant_scope: "tenant-a".to_owned(),
        issuer_role: IssuerRoleV1::Review,
        issuer_identity: "review-key-1".to_owned(),
        public_key: URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
        valid_from: 100,
        expires_at: 200,
        revoked_at: None,
    };
    signed.verify(&packet.candidate, &enrollment, 150).unwrap();

    let mut changed = packet;
    changed.artifact = URL_SAFE_NO_PAD.encode(b"forged");
    assert_eq!(
        sign_text_concordance_evidence(
            &changed,
            IssuerRoleV1::Review,
            "review-key-1".to_owned(),
            &[7; 32],
        ),
        Err(SemanticEvidenceError::CandidateArtifactMismatch)
    );
}

#[test]
fn contradiction_issuer_never_clears_an_observed_conflict() {
    let mut packet = candidate_packet("Useful input\n");
    packet
        .observed_conflict_digests
        .push(format!("sha256:{}", "aa".repeat(32)));
    assert_eq!(
        sign_text_concordance_evidence(
            &packet,
            IssuerRoleV1::Contradiction,
            "contradiction-key-1".to_owned(),
            &[9; 32],
        ),
        Err(SemanticEvidenceError::ConflictObserved)
    );
}
