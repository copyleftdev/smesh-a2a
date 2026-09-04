use serde_json::Value;
use smesh_a2a::{
    ArtifactClassification, CausalMerger, DataClass, MergeLimits, MissingParentPolicy,
    PrivacyError, PrivacyPolicy, ProjectionReceipt, RedactionAction, RedactionRule,
    ReplaySealInput, RunHmacKey, TraceArtifactOrigin, sanitize_public_trace,
    sanitize_public_trace_with_receipts, scan_public_trace, verify_sanitized_trace,
};

fn rule(pointer: &str, class: DataClass, action: RedactionAction) -> RedactionRule {
    RedactionRule {
        pointer: pointer.to_owned(),
        class,
        action,
        stable_identifier: false,
        fictional_provenance: None,
    }
}

fn public_container(pointer: &str) -> RedactionRule {
    let mut rule = rule(pointer, DataClass::Public, RedactionAction::Keep);
    rule.fictional_provenance = Some("fixture:schema".into());
    rule
}

fn make_policy(policy_id: &str, rules: Vec<RedactionRule>) -> Result<PrivacyPolicy, PrivacyError> {
    PrivacyPolicy::new_versioned(policy_id, 1, "test-key-generation-1", rules)
}

#[test]
fn all_six_classes_are_enforced_before_public_output() {
    let source = br#"{"public":"invented","internal":"ops","confidential":"deal","pii":"person","phi":"diagnosis","secret":"pw"}"#;
    let mut public = rule("/public", DataClass::Public, RedactionAction::Keep);
    public.fictional_provenance = Some("fixture:lifeline".into());
    let policy = make_policy(
        "policy-1",
        vec![
            public,
            rule(
                "/internal",
                DataClass::Internal,
                RedactionAction::Placeholder,
            ),
            rule(
                "/confidential",
                DataClass::Confidential,
                RedactionAction::Placeholder,
            ),
            rule("/pii", DataClass::Pii, RedactionAction::Placeholder),
            rule("/phi", DataClass::Phi, RedactionAction::Placeholder),
            rule("/secret", DataClass::Secret, RedactionAction::Drop),
        ],
    )
    .unwrap();

    let output = sanitize_public_trace(source, "run-a", RunHmacKey::new([7; 32]), &policy).unwrap();
    let value: Value = serde_json::from_slice(&output.public_bytes).unwrap();
    assert_eq!(value["public"], "invented");
    let object = value.as_object().unwrap();
    for source_key in ["internal", "confidential", "pii", "phi", "secret"] {
        assert!(!object.contains_key(source_key));
    }
    for placeholder in [
        "[REDACTED:INTERNAL]",
        "[REDACTED:CONFIDENTIAL]",
        "[REDACTED:PII]",
        "[REDACTED:PHI]",
    ] {
        assert!(object.values().any(|value| value == placeholder));
    }
    assert_eq!(
        output.public_manifest.artifact.provenance.origin,
        TraceArtifactOrigin::Mixed
    );
    assert!(
        !String::from_utf8(output.public_bytes)
            .unwrap()
            .contains("pw")
    );
}

#[test]
fn stable_handles_are_run_scoped_and_key_is_debug_redacted() {
    let mut stable = rule("/subject", DataClass::Pii, RedactionAction::StableHandle);
    stable.stable_identifier = true;
    let policy = make_policy("policy-1", vec![stable]).unwrap();
    let one = sanitize_public_trace(
        br#"{"subject":"low-entropy-id"}"#,
        "run-a",
        RunHmacKey::new([9; 32]),
        &policy,
    )
    .unwrap();
    let repeat = sanitize_public_trace(
        br#"{"subject":"low-entropy-id"}"#,
        "run-a",
        RunHmacKey::new([9; 32]),
        &policy,
    )
    .unwrap();
    let other_run = sanitize_public_trace(
        br#"{"subject":"low-entropy-id"}"#,
        "run-b",
        RunHmacKey::new([9; 32]),
        &policy,
    )
    .unwrap();
    let mut stable_a = rule("/a", DataClass::Pii, RedactionAction::StableHandle);
    stable_a.stable_identifier = true;
    let mut stable_b = rule("/b", DataClass::Pii, RedactionAction::StableHandle);
    stable_b.stable_identifier = true;
    let same_values = sanitize_public_trace(
        br#"{"a":"low-entropy-id","b":"low-entropy-id"}"#,
        "run-a",
        RunHmacKey::new([9; 32]),
        &make_policy("policy-1", vec![stable_a, stable_b]).unwrap(),
    )
    .unwrap();
    let same_values: Value = serde_json::from_slice(&same_values.public_bytes).unwrap();
    let same_values = same_values.as_object().unwrap();
    assert_eq!(same_values.len(), 2);
    assert!(
        same_values
            .keys()
            .all(|key| key.starts_with("redacted-field-hmac-sha256:"))
    );
    let handles: Vec<_> = same_values.values().collect();
    assert_eq!(handles[0], handles[1]);
    assert!(
        handles[0]
            .as_str()
            .is_some_and(|value| value.starts_with("hmac-sha256:"))
    );
    assert_eq!(one.public_bytes, repeat.public_bytes);
    assert_ne!(one.public_bytes, other_run.public_bytes);
    let mut revision_stable = rule("/subject", DataClass::Pii, RedactionAction::StableHandle);
    revision_stable.stable_identifier = true;
    let revision_one = PrivacyPolicy::new_versioned(
        "policy-1",
        1,
        "test-key-generation-1",
        vec![revision_stable.clone()],
    )
    .unwrap();
    let revision_two = PrivacyPolicy::new_versioned(
        "policy-1",
        2,
        "test-key-generation-1",
        vec![revision_stable],
    )
    .unwrap();
    let revision_one = sanitize_public_trace(
        br#"{"subject":"low-entropy-id"}"#,
        "run-a",
        RunHmacKey::new([9; 32]),
        &revision_one,
    )
    .unwrap();
    let revision_two = sanitize_public_trace(
        br#"{"subject":"low-entropy-id"}"#,
        "run-a",
        RunHmacKey::new([9; 32]),
        &revision_two,
    )
    .unwrap();
    assert_ne!(revision_one.public_bytes, revision_two.public_bytes);
    assert!(
        !String::from_utf8(one.public_bytes)
            .unwrap()
            .contains("low-entropy-id")
    );
    assert_eq!(
        format!("{:?}", RunHmacKey::new([9; 32])),
        "RunHmacKey(<redacted>)"
    );
}

#[test]
fn action_log_is_sorted_uses_original_escaped_array_pointers_and_has_no_values() {
    let source = br#"{"a/b":[{"~id":"raw-one"}],"z":"raw-two"}"#;
    let policy = make_policy(
        "policy-1",
        vec![
            public_container("/a~1b"),
            rule("/z", DataClass::Confidential, RedactionAction::Placeholder),
            rule("/a~1b/0/~0id", DataClass::Pii, RedactionAction::Placeholder),
        ],
    )
    .unwrap();
    let output = sanitize_public_trace(source, "run-a", RunHmacKey::new([1; 32]), &policy).unwrap();
    assert_eq!(
        output
            .action_log
            .iter()
            .map(|entry| entry.pointer.as_str())
            .collect::<Vec<_>>(),
        vec!["/a~1b", "/a~1b/0/~0id", "/z"]
    );
    assert!(
        !String::from_utf8(output.action_log_bytes.clone())
            .unwrap()
            .contains("raw-")
    );

    let reversed = make_policy("policy-1", policy.rules().iter().cloned().rev().collect()).unwrap();
    let again =
        sanitize_public_trace(source, "run-a", RunHmacKey::new([1; 32]), &reversed).unwrap();
    assert_eq!(output.public_bytes, again.public_bytes);
    assert_eq!(output.action_log_bytes, again.action_log_bytes);
}

#[test]
fn restricted_audit_debug_redacts_json_pointers_and_bytes() {
    let mut public_parent = public_container("/patient");
    public_parent.fictional_provenance = Some("restricted-provenance-canary".into());
    let policy = make_policy(
        "restricted-policy-canary",
        vec![
            public_parent,
            rule(
                "/patient/name",
                DataClass::Pii,
                RedactionAction::Placeholder,
            ),
        ],
    )
    .unwrap();
    let output = sanitize_public_trace(
        br#"{"patient":{"name":"Alice"}}"#,
        "run-a",
        RunHmacKey::new([2; 32]),
        &policy,
    )
    .unwrap();
    let source_digest = output.restricted_manifest.source_digest.clone();

    for debug in [
        format!("{output:?}"),
        format!("{:?}", output.action_log[0]),
        format!("{:?}", policy.rules()[1]),
        format!("{policy:?}"),
        format!("{:?}", output.restricted_manifest),
    ] {
        for canary in [
            "/patient/name",
            "Alice",
            "restricted-policy-canary",
            "restricted-provenance-canary",
            &source_digest,
        ] {
            assert!(!debug.contains(canary), "restricted Debug leaked {canary}");
        }
    }
}

#[test]
fn array_pointer_indices_use_exact_rfc6901_tokens() {
    let mut first = rule("/items/0", DataClass::Public, RedactionAction::Keep);
    first.fictional_provenance = Some("fixture:array".into());
    let mut second = rule("/items/1", DataClass::Public, RedactionAction::Keep);
    second.fictional_provenance = Some("fixture:array".into());
    let policy = make_policy(
        "policy-1",
        vec![
            public_container("/items"),
            first,
            second,
            rule("/items/01", DataClass::Pii, RedactionAction::Placeholder),
        ],
    )
    .unwrap();
    assert_eq!(
        sanitize_public_trace(
            br#"{"items":["zero","one"]}"#,
            "run-a",
            RunHmacKey::new([1; 32]),
            &policy,
        )
        .unwrap_err(),
        PrivacyError::UnmatchedRule
    );
}

#[test]
fn semantic_scanner_decodes_nested_values_and_has_negative_controls() {
    let unsafe_documents = [
        br#"{"nested":{"password":"x"}}"#.as_slice(),
        br#"{"text":"Bearer abc.def-123"}"#,
        br#"{"text":"Bearer x"}"#,
        br#"{"text":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature"}"#,
        br#"{"text":"-----BEGIN PRIVATE KEY-----"}"#,
        br#"{"text":"alice\u0040example.com"}"#,
        br#"{"text":"123-45-6789"}"#,
        br#"{"text":"patient: Ada"}"#,
        br#"{"text":"MRN 00421"}"#,
        br#"{"text":"insurance policy: ZX-9"}"#,
    ];
    for document in unsafe_documents {
        assert_eq!(
            scan_public_trace(document),
            Err(PrivacyError::SensitiveContent)
        );
    }
    scan_public_trace(
        br#"{"note":"bearer of good news","id":"hmac-sha256:abc","mail":"at example dot com"}"#,
    )
    .unwrap();
}

#[test]
fn unicode_whitespace_bearer_separator_fails_closed() {
    let document =
        serde_json::to_vec(&serde_json::json!({"text": "Bearer\u{00a0}abc123"})).unwrap();
    assert_eq!(
        scan_public_trace(&document),
        Err(PrivacyError::SensitiveContent)
    );
}

#[test]
fn jwt_after_prefix_punctuation_fails_closed() {
    let jwt = format!("eyJ{}.{}.{}", "a".repeat(8), "b".repeat(8), "c".repeat(8));
    for text in [format!("jwt={jwt}"), format!("token:{jwt}")] {
        let document = serde_json::to_vec(&serde_json::json!({"text": text})).unwrap();
        assert_eq!(
            scan_public_trace(&document),
            Err(PrivacyError::SensitiveContent)
        );
    }
}

#[test]
fn bearer_and_modern_credential_forms_fail_closed() {
    for text in [
        "Bearer\tabc123",
        "Bearer: abc123",
        "Bearer=abc123",
        "Bearer abc123,",
        "Bearer abc123!",
        "Bearer abc123?",
        "Bearer abc123.",
        "Bearer abc123#",
        "Bearer abc123|",
        "Bearer abc123`",
        "bearer\nabc123",
    ] {
        let document = serde_json::to_vec(&serde_json::json!({"text": text})).unwrap();
        assert_eq!(
            scan_public_trace(&document),
            Err(PrivacyError::SensitiveContent),
            "scanner accepted {text:?}"
        );
    }

    let tokens = [
        format!("AKIA{}", "A".repeat(16)),
        format!("ASIA{}", "A".repeat(16)),
        format!("ghp_{}", "a".repeat(36)),
        format!("gho_{}", "a".repeat(36)),
        format!("ghu_{}", "a".repeat(36)),
        format!("ghs_{}", "a".repeat(36)),
        format!("ghr_{}", "a".repeat(36)),
        format!("github_pat_{}", "a".repeat(40)),
        format!("sk-proj-{}", "a".repeat(32)),
        format!("sk-svcacct-{}", "a".repeat(32)),
        format!("sk-{}", "a".repeat(32)),
    ];
    for token in &tokens {
        for document in [
            serde_json::to_vec(&serde_json::json!({"text": token})).unwrap(),
            serde_json::to_vec(&serde_json::json!({token: "fictional"})).unwrap(),
        ] {
            assert_eq!(
                scan_public_trace(&document),
                Err(PrivacyError::SensitiveContent),
                "scanner accepted credential family {}",
                token.split(['_', '-']).next().unwrap_or_default()
            );
        }
    }

    for near_miss in [
        format!("AKIA{}", "A".repeat(15)),
        format!("ASIA{}", "A".repeat(15)),
        format!("ghp_{}", "a".repeat(8)),
        format!("github_pat_{}", "a".repeat(8)),
        format!("sk-proj-{}", "a".repeat(8)),
    ] {
        let document = serde_json::to_vec(&serde_json::json!({"text": near_miss})).unwrap();
        scan_public_trace(&document).unwrap();
    }
}

#[test]
fn modern_credentials_are_rejected_at_every_public_metadata_ingress() {
    let canary = format!("sk-proj-{}", "a".repeat(32));
    let mut public = rule("/story", DataClass::Public, RedactionAction::Keep);
    public.fictional_provenance = Some("fixture:safe".into());

    assert_eq!(
        PrivacyPolicy::new_versioned(canary.clone(), 1, "safe-generation", vec![public.clone()]),
        Err(PrivacyError::MalformedPolicy)
    );
    assert_eq!(
        PrivacyPolicy::new_versioned("safe-policy", 1, canary.clone(), vec![public.clone()]),
        Err(PrivacyError::MalformedPolicy)
    );
    let mut unsafe_provenance = public.clone();
    unsafe_provenance.fictional_provenance = Some(canary.clone());
    assert_eq!(
        make_policy("safe-policy", vec![unsafe_provenance]),
        Err(PrivacyError::MalformedPolicy)
    );

    let policy = make_policy("safe-policy", vec![public]).unwrap();
    assert_eq!(
        sanitize_public_trace(
            br#"{"story":"fictional"}"#,
            &canary,
            RunHmacKey::new([1; 32]),
            &policy,
        ),
        Err(PrivacyError::MalformedInput)
    );
    let receipt = ProjectionReceipt {
        projector_id: canary.clone(),
        projector_version: "1".into(),
        input_digest: "sha256:00".into(),
        output_digest: "sha256:00".into(),
        output_byte_length: 0,
    };
    assert_eq!(
        sanitize_public_trace_with_receipts(
            br#"{"story":"fictional"}"#,
            "safe-run",
            RunHmacKey::new([1; 32]),
            &policy,
            vec![receipt],
        ),
        Err(PrivacyError::MalformedInput)
    );
}

#[test]
fn public_manifest_uses_keyed_commitments_for_restricted_metadata() {
    let mut public = rule("/Alice", DataClass::Public, RedactionAction::Keep);
    public.fictional_provenance = Some("synthetic-persona".into());
    let policy = make_policy("keyed-public-commitments", vec![public]).unwrap();

    let first = sanitize_public_trace(
        br#"{"Alice":"fictional"}"#,
        "run-keyed-commitments",
        RunHmacKey::new([1; 32]),
        &policy,
    )
    .unwrap();
    let second = sanitize_public_trace(
        br#"{"Alice":"fictional"}"#,
        "run-keyed-commitments",
        RunHmacKey::new([2; 32]),
        &policy,
    )
    .unwrap();
    let other_run = sanitize_public_trace(
        br#"{"Alice":"fictional"}"#,
        "run-other-commitment",
        RunHmacKey::new([1; 32]),
        &policy,
    )
    .unwrap();

    let mut other_public = rule("/Alice", DataClass::Public, RedactionAction::Keep);
    other_public.fictional_provenance = Some("synthetic-persona".into());
    let other_policy = PrivacyPolicy::new_versioned(
        "other-policy-context",
        2,
        "generation-2",
        vec![other_public],
    )
    .unwrap();
    let other_policy_output = sanitize_public_trace(
        br#"{"Alice":"fictional"}"#,
        "run-keyed-commitments",
        RunHmacKey::new([1; 32]),
        &other_policy,
    )
    .unwrap();

    assert_eq!(first.public_bytes, second.public_bytes);
    assert_eq!(
        first.public_manifest.output_digest,
        second.public_manifest.output_digest
    );
    assert_ne!(
        first.public_manifest.policy_commitment,
        second.public_manifest.policy_commitment
    );
    assert_ne!(
        first.public_manifest.action_log_commitment,
        second.public_manifest.action_log_commitment
    );
    assert_ne!(
        first.public_manifest.policy_commitment,
        other_run.public_manifest.policy_commitment
    );
    assert_ne!(
        first.public_manifest.action_log_commitment,
        other_run.public_manifest.action_log_commitment
    );
    assert_ne!(
        first.public_manifest.action_log_commitment,
        other_policy_output.public_manifest.action_log_commitment
    );
    assert!(
        first
            .public_manifest
            .policy_commitment
            .starts_with("hmac-sha256:")
    );
    assert!(
        first
            .public_manifest
            .action_log_commitment
            .starts_with("hmac-sha256:")
    );
    assert_eq!(
        first.restricted_manifest.policy_digest,
        second.restricted_manifest.policy_digest
    );
    assert_eq!(
        first.restricted_manifest.action_log_digest,
        second.restricted_manifest.action_log_digest
    );
    let public_manifest = serde_json::to_string(&first.public_manifest).unwrap();
    assert!(!public_manifest.contains("Alice"));
    assert!(!public_manifest.contains("policyDigest"));
    assert!(!public_manifest.contains("actionLogDigest"));
}

#[test]
fn manifests_separate_public_and_restricted_integrity_and_reject_downgrades() {
    let mut public = rule("/story", DataClass::Public, RedactionAction::Keep);
    public.fictional_provenance = Some("checked-in:lifeline-fiction".into());
    let policy = make_policy(
        "policy-1",
        vec![
            public,
            rule("/raw", DataClass::Secret, RedactionAction::Drop),
        ],
    )
    .unwrap();
    let source = br#"{"story":"fictional rescue","raw":"not-public"}"#;
    let output = sanitize_public_trace(source, "run-a", RunHmacKey::new([3; 32]), &policy).unwrap();

    assert_eq!(
        output.public_manifest.artifact.classification,
        ArtifactClassification::Public
    );
    assert_eq!(
        output.public_manifest.artifact.provenance.origin,
        TraceArtifactOrigin::Mixed
    );
    assert_eq!(
        output.restricted_manifest.artifact.classification,
        ArtifactClassification::Confidential
    );
    assert_eq!(
        output.restricted_manifest.source_artifact.classification,
        ArtifactClassification::Secret
    );
    assert_eq!(
        output
            .restricted_manifest
            .action_log_artifact
            .classification,
        ArtifactClassification::Confidential
    );
    assert!(
        output
            .restricted_manifest
            .action_log_digest
            .starts_with("sha256:")
    );
    assert!(
        output
            .public_manifest
            .action_log_commitment
            .starts_with("hmac-sha256:")
    );
    assert_ne!(
        output.restricted_manifest.action_log_digest,
        output.public_manifest.action_log_commitment
    );
    verify_sanitized_trace(
        &output,
        source,
        "run-a",
        RunHmacKey::new([3; 32]),
        &policy,
        Vec::new(),
    )
    .unwrap();

    let public_json = serde_json::to_string(&output.public_manifest).unwrap();
    assert!(!public_json.contains("sourceDigest"));
    assert!(!public_json.contains("not-public"));
    let mut downgraded = output.clone();
    downgraded
        .restricted_manifest
        .storage_policy
        .public_export_forbidden = false;
    assert_eq!(
        verify_sanitized_trace(
            &downgraded,
            source,
            "run-a",
            RunHmacKey::new([3; 32]),
            &policy,
            Vec::new(),
        ),
        Err(PrivacyError::VerificationFailed)
    );
    let mut tampered = output.clone();
    tampered.public_manifest.output_digest = "sha256:0000".into();
    assert_eq!(
        verify_sanitized_trace(
            &tampered,
            source,
            "run-a",
            RunHmacKey::new([3; 32]),
            &policy,
            Vec::new(),
        ),
        Err(PrivacyError::VerificationFailed)
    );
}

#[test]
fn restricted_policy_and_provenance_are_exact_and_downgrade_resistant() {
    let public_rule = |pointer: &str, provenance: &str| {
        let mut rule = rule(pointer, DataClass::Public, RedactionAction::Keep);
        rule.fictional_provenance = Some(provenance.into());
        rule
    };
    let policy = make_policy(
        "provenance-policy",
        vec![
            public_rule("/alpha", "fixture:z"),
            public_rule("/beta", "fixture:a"),
            public_rule("/gamma", "fixture:z"),
        ],
    )
    .unwrap();
    let source = br#"{"alpha":"a","beta":"b","gamma":"c"}"#;
    let output =
        sanitize_public_trace(source, "provenance-run", RunHmacKey::new([8; 32]), &policy).unwrap();

    let public = &output.public_manifest.artifact.provenance;
    assert_eq!(public.producer, "trace-privacy/redactor-v1");
    assert_eq!(public.policy_id, "provenance-policy");
    assert_eq!(public.origin, TraceArtifactOrigin::Fictional);
    assert_eq!(public.fictional_sources, ["fixture:a", "fixture:z"]);

    let restricted = &output.restricted_manifest;
    for (binding, classification, producer, origin) in [
        (
            &restricted.artifact,
            ArtifactClassification::Confidential,
            "trace-privacy/restricted-audit-v1",
            TraceArtifactOrigin::ConfidentialAudit,
        ),
        (
            &restricted.source_artifact,
            ArtifactClassification::Secret,
            "trace-privacy/restricted-source-v1",
            TraceArtifactOrigin::RestrictedSource,
        ),
        (
            &restricted.action_log_artifact,
            ArtifactClassification::Confidential,
            "trace-privacy/action-log-v1",
            TraceArtifactOrigin::ConfidentialAudit,
        ),
    ] {
        assert_eq!(binding.classification, classification);
        assert_eq!(binding.provenance.producer, producer);
        assert_eq!(binding.provenance.policy_id, "provenance-policy");
        assert_eq!(binding.provenance.origin, origin);
        assert!(binding.provenance.fictional_sources.is_empty());
    }

    for field in 0..4 {
        let mut downgraded = output.clone();
        let storage = &mut downgraded.restricted_manifest.storage_policy;
        match field {
            0 => storage.public_export_forbidden = false,
            1 => storage.authenticated_encryption_required = false,
            2 => storage.authorization_required = false,
            3 => storage.audit_required = false,
            _ => unreachable!(),
        }
        assert_eq!(
            verify_sanitized_trace(
                &downgraded,
                source,
                "provenance-run",
                RunHmacKey::new([8; 32]),
                &policy,
                Vec::new(),
            ),
            Err(PrivacyError::VerificationFailed)
        );
    }
}

#[test]
fn checked_in_lifeline_public_fixture_passes_semantic_scan() {
    let fixture = include_bytes!("../demo/lifeline.trace.jsonl");
    scan_public_trace(fixture).unwrap();
    assert!(fixture.ends_with(b"\n"));
    for line in fixture
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let value: Value = serde_json::from_slice(line).unwrap();
        assert_eq!(value["payload"]["fictional"], true);
    }
}

#[test]
fn issue_24_projection_receipts_are_restricted_and_publicly_committed() {
    let mut public = rule("/story", DataClass::Public, RedactionAction::Keep);
    public.fictional_provenance = Some("fixture:lifeline".into());
    let policy = make_policy("policy-1", vec![public]).unwrap();
    let mut merger = CausalMerger::new(
        "cross-language-vector",
        MergeLimits::default(),
        MissingParentPolicy::Reject,
    )
    .unwrap();
    merger
        .ingest_source_jsonl(include_bytes!(
            "../demo/fixtures/full-matrix-replay-v1/source-a.jsonl"
        ))
        .unwrap();
    let baseline = merger.finalize(ReplaySealInput::empty()).unwrap();
    let input_digest = baseline.receipt().input_jsonl_digest.clone();
    let output_digest = format!("sha256:{}", "2".repeat(64));
    let receipt = |id: &str| ProjectionReceipt {
        projector_id: id.into(),
        projector_version: "1".into(),
        input_digest: input_digest.clone(),
        output_digest: output_digest.clone(),
        output_byte_length: 123,
    };
    let sealed = merger
        .finalize(ReplaySealInput {
            artifact_manifest_digest: ReplaySealInput::empty().artifact_manifest_digest,
            projections: vec![receipt("z"), receipt("a")],
        })
        .unwrap();
    let genuine_receipts = sealed.receipt().projections.clone();
    assert_eq!(genuine_receipts[0].projector_id, "a");
    assert_eq!(genuine_receipts[1].projector_id, "z");

    let output = sanitize_public_trace_with_receipts(
        br#"{"story":"fictional"}"#,
        "run-a",
        RunHmacKey::new([4; 32]),
        &policy,
        genuine_receipts.clone(),
    )
    .unwrap();
    verify_sanitized_trace(
        &output,
        br#"{"story":"fictional"}"#,
        "run-a",
        RunHmacKey::new([4; 32]),
        &policy,
        genuine_receipts,
    )
    .unwrap();

    assert_eq!(
        output.public_manifest.projection_receipts[0].projector_id,
        "a"
    );
    assert_eq!(
        output.public_manifest.projection_receipts[1].projector_id,
        "z"
    );
    let public_manifest = serde_json::to_string(&output.public_manifest).unwrap();
    assert!(public_manifest.contains("receiptCommitment"));
    assert!(!public_manifest.contains("inputDigest"));
    assert!(!public_manifest.contains("outputDigest\":\"sha256:2222"));
    assert!(!public_manifest.contains(&input_digest));
    assert!(!public_manifest.contains(&output_digest));

    let restricted_manifest = serde_json::to_string(&output.restricted_manifest).unwrap();
    assert!(restricted_manifest.contains(&input_digest));
    assert!(restricted_manifest.contains(&output_digest));

    assert_eq!(
        sanitize_public_trace_with_receipts(
            br#"{"story":"fictional"}"#,
            "run-a",
            RunHmacKey::new([4; 32]),
            &policy,
            vec![receipt("patient:Alice")],
        ),
        Err(PrivacyError::MalformedInput)
    );
}

#[test]
fn unclassified_source_fields_fail_closed() {
    let policy = make_policy("policy-1", Vec::new()).unwrap();
    assert_eq!(
        sanitize_public_trace(
            br#"{"unclassified":"ordinary-looking-value"}"#,
            "run-a",
            RunHmacKey::new([0; 32]),
            &policy,
        )
        .unwrap_err(),
        PrivacyError::UnclassifiedValue
    );
}

#[test]
fn container_object_member_names_require_explicit_public_classification() {
    let source = br#"{"Alice":{"diagnosis":"condition"}}"#;
    let descendant_only = make_policy(
        "container-key-policy",
        vec![rule(
            "/Alice/diagnosis",
            DataClass::Phi,
            RedactionAction::Placeholder,
        )],
    )
    .unwrap();
    assert_eq!(
        sanitize_public_trace(
            source,
            "run-container-key",
            RunHmacKey::new([15; 32]),
            &descendant_only,
        ),
        Err(PrivacyError::UnclassifiedValue)
    );

    let mut public_container = rule("/Alice", DataClass::Public, RedactionAction::Keep);
    public_container.fictional_provenance = Some("synthetic-name".into());
    let classified = make_policy(
        "container-key-policy",
        vec![
            public_container,
            rule(
                "/Alice/diagnosis",
                DataClass::Phi,
                RedactionAction::Placeholder,
            ),
        ],
    )
    .unwrap();
    let output = sanitize_public_trace(
        source,
        "run-container-key",
        RunHmacKey::new([15; 32]),
        &classified,
    )
    .unwrap();
    let public: Value = serde_json::from_slice(&output.public_bytes).unwrap();
    let inner = public["Alice"].as_object().unwrap();
    assert!(!inner.contains_key("diagnosis"));
    assert_eq!(inner.values().next().unwrap(), "[REDACTED:PHI]");
}

#[test]
fn non_public_object_member_names_are_hmac_redacted() {
    let source = br#"{"Alice":"diagnosis"}"#;
    let policy = make_policy(
        "sensitive-key-policy",
        vec![rule("/Alice", DataClass::Pii, RedactionAction::Placeholder)],
    )
    .unwrap();

    let output = sanitize_public_trace(
        source,
        "run-sensitive-key",
        RunHmacKey::new([14; 32]),
        &policy,
    )
    .unwrap();
    let object = serde_json::from_slice::<Value>(&output.public_bytes)
        .unwrap()
        .as_object()
        .unwrap()
        .clone();
    assert!(!object.contains_key("Alice"));
    assert_eq!(object.len(), 1);
    let (key, value) = object.iter().next().unwrap();
    assert!(key.starts_with("redacted-field-hmac-sha256:"));
    assert_eq!(value, "[REDACTED:PII]");
}

#[test]
fn duplicate_json_object_keys_fail_closed_before_projection_or_scan() {
    let source = br#"{"safe":"fictional","safe":"patient:Alice"}"#;
    let mut public = rule("/safe", DataClass::Public, RedactionAction::Keep);
    public.fictional_provenance = Some("synthetic".into());
    let policy = make_policy("duplicate-json-policy", vec![public]).unwrap();

    assert_eq!(
        sanitize_public_trace(
            source,
            "run-duplicate-json",
            RunHmacKey::new([13; 32]),
            &policy,
        ),
        Err(PrivacyError::MalformedInput)
    );
    assert_eq!(scan_public_trace(source), Err(PrivacyError::MalformedInput));
}

#[test]
fn malformed_duplicate_unmatched_and_unsupported_policies_fail_closed() {
    let bypass: Result<PrivacyPolicy, _> = serde_json::from_slice(
        br#"{"policyId":"bypass","policyRevision":1,"keyGeneration":"key-1","rules":[{"pointer":"/secret","class":"secret","action":"keep","stableIdentifier":false,"fictionalProvenance":null}]}"#,
    );
    assert!(
        bypass.is_err(),
        "direct serde deserialization must enforce policy invariants"
    );
    assert_eq!(
        PrivacyPolicy::from_json(br#"{"policyId":"p","rules":[]}"#),
        Err(PrivacyError::MalformedPolicy)
    );
    assert_eq!(
        PrivacyPolicy::from_json(br#"{"policyId":"p","rules":[],"unknown":true}"#),
        Err(PrivacyError::MalformedPolicy)
    );
    assert_eq!(
        make_policy(
            "p",
            vec![
                rule("/x", DataClass::Pii, RedactionAction::Placeholder),
                rule("/x", DataClass::Pii, RedactionAction::Placeholder),
            ],
        ),
        Err(PrivacyError::DuplicateRule)
    );
    assert_eq!(
        make_policy(
            "p",
            vec![rule(
                "/bad~2pointer",
                DataClass::Pii,
                RedactionAction::Placeholder
            )],
        ),
        Err(PrivacyError::InvalidPointer)
    );
    for (class, action) in [
        (DataClass::Public, RedactionAction::Drop),
        (DataClass::Secret, RedactionAction::Placeholder),
        (DataClass::Pii, RedactionAction::Keep),
        (DataClass::Phi, RedactionAction::StableHandle),
    ] {
        assert_eq!(
            make_policy("p", vec![rule("/x", class, action)]),
            Err(PrivacyError::UnsupportedClassAction)
        );
    }
    let mut present = rule("/present", DataClass::Public, RedactionAction::Keep);
    present.fictional_provenance = Some("fixture:root".into());
    let policy = make_policy(
        "p",
        vec![
            present,
            rule("/missing", DataClass::Pii, RedactionAction::Placeholder),
        ],
    )
    .unwrap();
    assert_eq!(
        sanitize_public_trace(
            br#"{"present":"fictional"}"#,
            "run",
            RunHmacKey::new([0; 32]),
            &policy
        ),
        Err(PrivacyError::UnmatchedRule)
    );
}

#[test]
fn input_depth_line_total_and_record_limits_are_enforced() {
    let policy = make_policy(
        "p",
        vec![rule(
            "",
            DataClass::Confidential,
            RedactionAction::Placeholder,
        )],
    )
    .unwrap();
    let deep = format!("{}0{}", "{\"x\":".repeat(65), "}".repeat(65));
    assert_eq!(
        sanitize_public_trace(deep.as_bytes(), "run", RunHmacKey::new([0; 32]), &policy),
        Err(PrivacyError::LimitExceeded)
    );
    let long_line = format!(r#"{{"x":"{}"}}"#, "a".repeat(65 * 1024));
    assert_eq!(
        sanitize_public_trace(
            long_line.as_bytes(),
            "run",
            RunHmacKey::new([0; 32]),
            &policy
        ),
        Err(PrivacyError::LimitExceeded)
    );
    let many_records = format!(
        "{}\n",
        std::iter::repeat_n("{}", 100_001)
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert_eq!(
        sanitize_public_trace(
            many_records.as_bytes(),
            "run",
            RunHmacKey::new([0; 32]),
            &policy
        ),
        Err(PrivacyError::LimitExceeded)
    );
    let bounded_line = format!("{{\"x\":\"{}\"}}\n", "a".repeat(60 * 1024));
    let oversized_total = bounded_line.repeat(280);
    assert!(oversized_total.len() > 16 * 1024 * 1024);
    assert_eq!(
        sanitize_public_trace(
            oversized_total.as_bytes(),
            "run",
            RunHmacKey::new([0; 32]),
            &policy,
        ),
        Err(PrivacyError::LimitExceeded)
    );
}

#[test]
fn aggregate_classification_pointer_work_is_bounded() {
    let key = "k".repeat(16 * 1024);
    let source = serde_json::to_vec(&serde_json::json!({
        key.clone(): vec![Value::Null; 2_000]
    }))
    .unwrap();
    assert!(source.len() < 64 * 1024);

    let mut parent = rule(&format!("/{key}"), DataClass::Public, RedactionAction::Keep);
    parent.fictional_provenance = Some("bounded-pointer-work".into());
    let policy = make_policy("bounded-pointer-work", vec![parent]).unwrap();

    assert_eq!(
        sanitize_public_trace(
            &source,
            "run-bounded-pointer-work",
            RunHmacKey::new([1; 32]),
            &policy,
        ),
        Err(PrivacyError::LimitExceeded)
    );
}

#[test]
fn aggregate_classification_pointer_work_is_bounded_across_jsonl_records() {
    let field_name = "k".repeat(9_000);
    let record = serde_json::to_string(&serde_json::json!({
        field_name.clone(): vec![Value::Null; 1_000]
    }))
    .unwrap();
    let source = format!("{record}\n{record}\n");
    assert!(record.len() < 64 * 1024);
    let policy = make_policy(
        "pointer-work-jsonl",
        vec![rule(
            &format!("/{field_name}"),
            DataClass::Pii,
            RedactionAction::Placeholder,
        )],
    )
    .unwrap();

    assert!(matches!(
        sanitize_public_trace(
            source.as_bytes(),
            "run-pointer-work-jsonl",
            RunHmacKey::new([9; 32]),
            &policy
        ),
        Err(PrivacyError::LimitExceeded)
    ));
}

#[test]
fn public_output_expansion_is_bounded_after_member_name_redaction() {
    let mut object = serde_json::Map::new();
    let mut rules = Vec::new();
    for index in 0..1_000 {
        let key = format!("k{index}");
        object.insert(key.clone(), Value::String("x".into()));
        rules.push(rule(
            &format!("/{key}"),
            DataClass::Pii,
            RedactionAction::Placeholder,
        ));
    }
    let source = serde_json::to_string(&Value::Object(object)).unwrap();
    assert!(source.len() < 64 * 1024);
    let policy = make_policy("output-expansion", rules).unwrap();
    for encoded in [source.clone(), format!("{source}\n")] {
        assert_eq!(
            sanitize_public_trace(
                encoded.as_bytes(),
                "run-output-expansion",
                RunHmacKey::new([1; 32]),
                &policy,
            ),
            Err(PrivacyError::LimitExceeded)
        );
    }
}

#[test]
fn aggregate_action_log_projection_is_bounded() {
    let mut object = serde_json::Map::new();
    let mut rules = Vec::new();
    for index in 0..500 {
        let key = format!("field-{index}-{}", "x".repeat(80));
        object.insert(key.clone(), Value::String("v".into()));
        rules.push(rule(
            &format!("/{key}"),
            DataClass::Pii,
            RedactionAction::Placeholder,
        ));
    }
    let line = format!(
        "{}\n",
        serde_json::to_string(&Value::Object(object)).unwrap()
    );
    assert!(line.len() < 64 * 1024);
    let source = line.repeat(190);
    assert!(source.len() < 16 * 1024 * 1024);
    let policy = make_policy("action-log-bound", rules).unwrap();
    assert_eq!(
        sanitize_public_trace(
            source.as_bytes(),
            "run-action-log-bound",
            RunHmacKey::new([1; 32]),
            &policy,
        ),
        Err(PrivacyError::LimitExceeded)
    );
}

#[test]
fn projection_receipt_count_accepts_128_and_rejects_129() {
    let mut public = rule("/story", DataClass::Public, RedactionAction::Keep);
    public.fictional_provenance = Some("fixture:receipt-bound".into());
    let policy = make_policy("receipt-bound", vec![public]).unwrap();
    let source = br#"{"story":"fictional"}"#;
    let baseline = sanitize_public_trace(
        source,
        "run-receipt-bound",
        RunHmacKey::new([1; 32]),
        &policy,
    )
    .unwrap();
    let receipts = |count: usize| {
        (0..count)
            .map(|index| ProjectionReceipt {
                projector_id: format!("projector-{index:03}"),
                projector_version: "1".into(),
                input_digest: baseline.public_manifest.output_digest.clone(),
                output_digest: baseline.public_manifest.output_digest.clone(),
                output_byte_length: baseline.public_bytes.len() as u64,
            })
            .collect::<Vec<_>>()
    };

    assert!(
        sanitize_public_trace_with_receipts(
            source,
            "run-receipt-bound",
            RunHmacKey::new([1; 32]),
            &policy,
            receipts(128),
        )
        .is_ok()
    );
    assert_eq!(
        sanitize_public_trace_with_receipts(
            source,
            "run-receipt-bound",
            RunHmacKey::new([1; 32]),
            &policy,
            receipts(129),
        ),
        Err(PrivacyError::LimitExceeded)
    );
}

#[test]
fn secret_array_elements_are_nulled_without_shifting_original_pointers() {
    let policy = make_policy(
        "p",
        vec![
            public_container("/values"),
            rule("/values/0", DataClass::Secret, RedactionAction::Drop),
        ],
    )
    .unwrap();
    let output = sanitize_public_trace(
        br#"{"values":["tiny-secret"]}"#,
        "run",
        RunHmacKey::new([0; 32]),
        &policy,
    )
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&output.public_bytes).unwrap()["values"][0],
        Value::Null
    );
    assert!(
        output
            .action_log
            .iter()
            .any(|entry| entry.pointer == "/values/0")
    );
}

#[test]
fn jsonl_is_sanitized_record_by_record_with_terminal_lf_and_record_indices() {
    let policy = make_policy(
        "p",
        vec![
            rule("/id", DataClass::Pii, RedactionAction::Placeholder),
            rule("/secret", DataClass::Secret, RedactionAction::Drop),
        ],
    )
    .unwrap();
    let source = b"{\"id\":\"one\",\"secret\":\"x\"}\n{\"id\":\"two\",\"secret\":\"y\"}\n";
    let output = sanitize_public_trace(source, "run", RunHmacKey::new([5; 32]), &policy).unwrap();
    assert!(output.public_bytes.ends_with(b"\n"));
    let public_lines: Vec<_> = output
        .public_bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .collect();
    assert_eq!(public_lines.len(), 2);
    assert_eq!(
        output
            .action_log
            .iter()
            .map(|entry| entry.record_index)
            .collect::<Vec<_>>(),
        vec![0, 0, 1, 1]
    );
    assert!(
        output
            .action_log
            .iter()
            .all(|entry| entry.pointer == "/id" || entry.pointer == "/secret")
    );
    assert!(
        !String::from_utf8(output.public_bytes)
            .unwrap()
            .contains("\"secret\"")
    );
    assert_eq!(
        scan_public_trace(b"{}\n\n{}\n"),
        Err(PrivacyError::MalformedInput)
    );
    assert_eq!(
        scan_public_trace(b"{}\n{}"),
        Err(PrivacyError::MalformedInput)
    );
}

#[test]
fn aggregate_decoded_nodes_are_bounded_across_jsonl_records() {
    let values = std::iter::repeat_n("0", 30_000)
        .collect::<Vec<_>>()
        .join(",");
    let record = format!(r#"{{"values":[{values}]}}"#);
    let source = format!("{record}\n{record}\n{record}\n{record}\n");
    let policy = make_policy(
        "policy-1",
        vec![rule(
            "/values",
            DataClass::Confidential,
            RedactionAction::Placeholder,
        )],
    )
    .unwrap();

    assert!(matches!(
        sanitize_public_trace(
            source.as_bytes(),
            "run-a",
            RunHmacKey::new([1; 32]),
            &policy,
        ),
        Err(PrivacyError::LimitExceeded)
    ));
}

#[test]
fn policy_rule_count_is_bounded_before_processing() {
    let rules = (0..=100_000)
        .map(|index| {
            rule(
                &format!("/field-{index}"),
                DataClass::Pii,
                RedactionAction::Placeholder,
            )
        })
        .collect();
    assert!(matches!(
        make_policy("p", rules),
        Err(PrivacyError::LimitExceeded)
    ));
}

#[test]
fn policy_aggregate_bytes_are_bounded_before_pointer_indexing() {
    let rules = (0..280)
        .map(|index| {
            rule(
                &format!("/{}-{index}", "a".repeat(60 * 1024)),
                DataClass::Pii,
                RedactionAction::Placeholder,
            )
        })
        .collect();
    assert!(matches!(
        make_policy("p", rules),
        Err(PrivacyError::LimitExceeded)
    ));
}

#[test]
fn public_keep_requires_explicit_fictional_provenance() {
    let error = make_policy(
        "policy-1",
        vec![rule("/value", DataClass::Public, RedactionAction::Keep)],
    )
    .unwrap_err();
    assert_eq!(error, PrivacyError::UnsupportedClassAction);
}

#[test]
fn versioned_policy_metadata_and_key_generation_are_manifest_bound() {
    let mut public = rule("/story", DataClass::Public, RedactionAction::Keep);
    public.fictional_provenance = Some("fixture:versioned".into());
    let policy =
        PrivacyPolicy::new_versioned("policy-versioned", 7, "privacy-key-2026-09", vec![public])
            .unwrap();
    let output = sanitize_public_trace(
        br#"{"story":"fictional"}"#,
        "run-versioned",
        RunHmacKey::new([8; 32]),
        &policy,
    )
    .unwrap();

    assert_eq!(output.public_manifest.policy_id, "policy-versioned");
    assert_eq!(output.public_manifest.policy_revision, 7);
    assert_eq!(output.public_manifest.key_generation, "privacy-key-2026-09");
    assert_eq!(output.restricted_manifest.policy_revision, 7);
    assert_eq!(
        output.restricted_manifest.key_generation,
        "privacy-key-2026-09"
    );

    let mut tampered = output.clone();
    tampered.public_manifest.policy_revision += 1;
    assert_eq!(
        verify_sanitized_trace(
            &tampered,
            br#"{"story":"fictional"}"#,
            "run-versioned",
            RunHmacKey::new([8; 32]),
            &policy,
            Vec::new(),
        ),
        Err(PrivacyError::VerificationFailed)
    );
}

#[test]
fn policy_coverage_is_exact_and_overlapping_rules_are_rejected() {
    let mut root = rule("", DataClass::Public, RedactionAction::Keep);
    root.fictional_provenance = Some("fixture:root".into());
    let root_only = make_policy("p", vec![root.clone()]).unwrap();
    assert_eq!(
        sanitize_public_trace(
            br#"{"nested":{"value":"must-be-explicit"}}"#,
            "run",
            RunHmacKey::new([0; 32]),
            &root_only,
        ),
        Err(PrivacyError::UnclassifiedValue)
    );
    let descendant_without_container = make_policy(
        "p",
        vec![
            root,
            rule(
                "/nested/value",
                DataClass::Pii,
                RedactionAction::Placeholder,
            ),
        ],
    )
    .unwrap();
    assert_eq!(
        sanitize_public_trace(
            br#"{"nested":{"value":"must-be-explicit"}}"#,
            "run",
            RunHmacKey::new([0; 32]),
            &descendant_without_container,
        ),
        Err(PrivacyError::UnclassifiedValue)
    );
    assert_eq!(
        make_policy(
            "p",
            vec![
                rule("/a", DataClass::Pii, RedactionAction::Placeholder),
                rule("/a-b", DataClass::Pii, RedactionAction::Placeholder),
                rule("/a/b", DataClass::Pii, RedactionAction::Placeholder),
            ],
        ),
        Err(PrivacyError::OverlappingRule)
    );
}

#[test]
fn stable_handles_require_nonempty_string_identifiers() {
    let mut stable = rule("/id", DataClass::Pii, RedactionAction::StableHandle);
    stable.stable_identifier = true;
    let policy = make_policy("p", vec![stable]).unwrap();
    for source in [
        br#"{"id":17}"#.as_slice(),
        br#"{"id":{"nested":true}}"#,
        br#"{"id":""}"#,
    ] {
        assert_eq!(
            sanitize_public_trace(source, "run", RunHmacKey::new([0; 32]), &policy),
            Err(PrivacyError::InvalidStableIdentifier)
        );
    }
}

#[test]
fn generated_hmac_member_labels_cannot_self_trigger_secret_scanning() {
    let generated = format!(
        r#"{{"redacted-field-hmac-sha256:sk-{}":"[REDACTED:pii]"}}"#,
        "A".repeat(40)
    );
    assert_eq!(scan_public_trace(generated.as_bytes()), Ok(()));
}

#[test]
fn semantic_scanner_allows_only_sanitized_sensitive_keys() {
    for unsafe_document in [
        br#"{"patientId":"raw-id"}"#.as_slice(),
        br#"{"mrn":"7"}"#,
        br#"{"insuranceMemberId":"member-9"}"#,
        br#"{"clinicalNotes":"diagnosis HIV"}"#,
        br#"{"clientSecret":"value"}"#,
        br#"{"passwordHash":"value"}"#,
        br#"{"token":"opaque-value"}"#,
        br#"{"idToken":"opaque-value"}"#,
        br#"{"credential":"opaque-value"}"#,
        br#"{"passphrase":"opaque-value"}"#,
        br#"{"text":"bearer of bearer abc123"}"#,
        br#"{"owner@example.com":"fictional"}"#,
    ] {
        assert_eq!(
            scan_public_trace(unsafe_document),
            Err(PrivacyError::SensitiveContent)
        );
    }
    scan_public_trace(
        br#"{"patientId":"hmac-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","clinicalNotes":"[REDACTED:PHI]"}"#,
    )
    .unwrap();
}

#[test]
fn public_manifest_metadata_rejects_sensitive_or_unsafe_labels() {
    let mut public = rule("/story", DataClass::Public, RedactionAction::Keep);
    public.fictional_provenance = Some("fixture:safe".into());
    assert_eq!(
        make_policy("alice@example.com", vec![public.clone()]),
        Err(PrivacyError::MalformedPolicy)
    );
    assert_eq!(
        make_policy("patient:Alice", vec![public.clone()]),
        Err(PrivacyError::MalformedPolicy)
    );
    assert_eq!(
        PrivacyPolicy::new_versioned("safe-policy", 1, "key owner@example.com", vec![public]),
        Err(PrivacyError::MalformedPolicy)
    );

    let mut unsafe_provenance = rule("/story", DataClass::Public, RedactionAction::Keep);
    unsafe_provenance.fictional_provenance = Some("owner@example.com".into());
    assert_eq!(
        make_policy("safe-policy", vec![unsafe_provenance]),
        Err(PrivacyError::MalformedPolicy)
    );

    let mut public = rule("/story", DataClass::Public, RedactionAction::Keep);
    public.fictional_provenance = Some("fixture:safe".into());
    let policy = make_policy("safe-policy", vec![public]).unwrap();
    assert_eq!(
        sanitize_public_trace(
            br#"{"story":"fictional"}"#,
            "run owner@example.com",
            RunHmacKey::new([2; 32]),
            &policy,
        ),
        Err(PrivacyError::MalformedInput)
    );
    assert_eq!(
        sanitize_public_trace(
            br#"{"story":"fictional"}"#,
            "run:123-45-6789",
            RunHmacKey::new([2; 32]),
            &policy,
        ),
        Err(PrivacyError::MalformedInput)
    );
}

#[test]
fn full_verifier_replays_projection_and_rejects_coherent_forgery() {
    let policy = PrivacyPolicy::new_versioned(
        "policy-verified",
        3,
        "key-generation-3",
        vec![rule(
            "/subject",
            DataClass::Pii,
            RedactionAction::Placeholder,
        )],
    )
    .unwrap();
    let source = br#"{"subject":"original-private-id"}"#;
    let output =
        sanitize_public_trace(source, "run-verified", RunHmacKey::new([6; 32]), &policy).unwrap();
    verify_sanitized_trace(
        &output,
        source,
        "run-verified",
        RunHmacKey::new([6; 32]),
        &policy,
        Vec::new(),
    )
    .unwrap();

    let forged = sanitize_public_trace(
        br#"{"subject":"different-private-id"}"#,
        "run-verified",
        RunHmacKey::new([6; 32]),
        &policy,
    )
    .unwrap();
    assert_eq!(
        verify_sanitized_trace(
            &forged,
            source,
            "run-verified",
            RunHmacKey::new([6; 32]),
            &policy,
            Vec::new(),
        ),
        Err(PrivacyError::VerificationFailed)
    );
    assert_eq!(
        verify_sanitized_trace(
            &output,
            source,
            "other-run",
            RunHmacKey::new([6; 32]),
            &policy,
            Vec::new(),
        ),
        Err(PrivacyError::VerificationFailed)
    );
}
