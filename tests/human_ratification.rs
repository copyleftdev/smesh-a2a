#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::sync::Arc;

use a2a_server::TaskStore as _;
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine as _;
use hmac::{Hmac, Mac as _};
use http_body_util::BodyExt as _;
use sha2::Sha256;
use smesh_a2a::auth::{
    AuthState, AuthenticationError, BearerVerifier, PresentedBearer, Principal, PrincipalLimits,
};
use smesh_a2a::{
    AuthoritativeReviewCandidate, AuthorityIdentity as _, AuthorizationPolicy,
    DurableDispatchEnvelope, DurableLoopbackEndpoint, GatewayConfig, HumanDecision,
    HumanRatificationAction, HumanRatificationReceipt, InjectedClock, Operation,
    OutboxAuthority as _, RatificationCommand, RatificationError, RatificationLedger,
    ReceiverAdmission, ReviewAcknowledgement, ReviewArtifact, ReviewPacketInput, SqliteTaskStore,
    build_authorized_durable_loopback_gateway_with_ratification_and_telemetry,
};
use tower::ServiceExt as _;

struct Fixture(std::path::PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "smesh-human-ratification-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(root.join("ratification.sqlite3"))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.0.display()));
        }
        if let Some(parent) = self.0.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }
}

fn packet() -> ReviewPacketInput {
    let published_artifact = a2a::Artifact {
        artifact_id: "artifact-result".to_owned(),
        name: Some("result.json".to_owned()),
        description: None,
        parts: vec![a2a::Part::text("result").with_media_type("application/json")],
        metadata: None,
        extensions: None,
    };
    let canonical_json =
        serde_json::to_string(&serde_json::to_value(&published_artifact).unwrap()).unwrap();
    let artifacts = vec![ReviewArtifact {
        name: "result.json".to_owned(),
        media_type: "application/json".to_owned(),
        digest: smesh_a2a::content_digest(canonical_json.as_bytes()),
        canonical_json,
    }];
    let artifact_set_digest = smesh_a2a::content_digest(
        &serde_json::to_vec(&serde_json::to_value(vec![published_artifact]).unwrap()).unwrap(),
    );
    ReviewPacketInput {
        task_id: "task-27".to_owned(),
        tenant_id: "tenant-a".to_owned(),
        generation: 1,
        task_revision: 7,
        authorization_policy_id: "ratification-authz".to_owned(),
        authorization_policy_revision: 1,
        authorization_policy_digest: smesh_a2a::content_digest(b"ratification-authz-v1"),
        principal_scope: smesh_a2a::content_digest(b"ratifier-principal"),
        authentication_method: "bearer-jwt".to_owned(),
        context_id: "context-27".to_owned(),
        request_digest: smesh_a2a::content_digest(b"request-27"),
        idempotency_key_digest: smesh_a2a::content_digest(b"packet-27"),
        ratification_key_generation: smesh_a2a::content_digest(b"ratification-key-1"),
        checkpoint: "checkpoint".to_owned(),
        checkpoint_hash: smesh_a2a::content_digest(b"checkpoint"),
        completion_policy_id: "release-policy".to_owned(),
        completion_policy_version: 7,
        completion_policy_hash: smesh_a2a::content_digest(b"policy"),
        evidence_snapshot_hash: smesh_a2a::content_digest(b"evidence-snapshot"),
        artifact_set_digest,
        evidence: vec!["review-evidence".to_owned()],
        evidence_hashes: vec![smesh_a2a::content_digest(b"review-evidence")],
        artifacts,
        approved_task_digest: smesh_a2a::content_digest(b"approved-task"),
        approved_result_digest: smesh_a2a::content_digest(b"approved-result"),
        approved_transcript_digest: smesh_a2a::content_digest(b"approved-transcript"),
        uncertainty_summary:
            "One model-derived assertion remains uncertain. <script>alert(1)</script>".to_owned(),
        created_at_millis: 1_700_000_000_000,
    }
}

fn standalone_review(packet: &smesh_a2a::ReviewPacket, key: &str) -> ReviewAcknowledgement {
    ReviewAcknowledgement {
        tenant_id: packet.tenant_id.clone(),
        task_id: packet.task_id.clone(),
        generation: packet.generation,
        account_id: "ratifier".to_owned(),
        authorization_policy_id: packet.authorization_policy_id.clone(),
        authorization_policy_revision: packet.authorization_policy_revision,
        authorization_policy_digest: packet.authorization_policy_digest.clone(),
        principal_scope: smesh_a2a::content_digest(b"current-ratifier"),
        authentication_method: "mutual-tls".to_owned(),
        context_id: packet.context_id.clone(),
        request_digest: packet.request_digest.clone(),
        ratification_key_generation: packet.ratification_key_generation.clone(),
        expected_revision: 0,
        checkpoint_hash: packet.checkpoint_hash.clone(),
        packet_hash: packet.packet_hash.clone(),
        evidence_hashes: packet.evidence_hashes.clone(),
        artifact_hashes: packet
            .artifacts
            .iter()
            .map(|artifact| artifact.digest.clone())
            .collect(),
        artifact_manifest_digest: packet.artifact_set_digest.clone(),
        uncertainty_acknowledged: true,
        idempotency_key: key.to_owned(),
        reviewed_at_millis: 1_700_000_000_001,
    }
}

fn standalone_decision(packet: &smesh_a2a::ReviewPacket, key: &str) -> RatificationCommand {
    RatificationCommand {
        tenant_id: packet.tenant_id.clone(),
        task_id: packet.task_id.clone(),
        generation: packet.generation,
        account_id: "ratifier".to_owned(),
        authorization_policy_id: packet.authorization_policy_id.clone(),
        authorization_policy_revision: packet.authorization_policy_revision,
        authorization_policy_digest: packet.authorization_policy_digest.clone(),
        principal_scope: smesh_a2a::content_digest(b"current-ratifier"),
        authentication_method: "mutual-tls".to_owned(),
        context_id: packet.context_id.clone(),
        request_digest: packet.request_digest.clone(),
        ratification_key_generation: packet.ratification_key_generation.clone(),
        expected_revision: 1,
        checkpoint_hash: packet.checkpoint_hash.clone(),
        packet_hash: packet.packet_hash.clone(),
        artifact_manifest_digest: packet.artifact_set_digest.clone(),
        idempotency_key: key.to_owned(),
        decision: HumanDecision::Approve,
        rationale: "Exact candidate approved.".to_owned(),
        decided_at_millis: 1_700_000_000_002,
    }
}

fn principal(subject: &str) -> Principal {
    Principal::bearer_for_verifier(
        "test:ratification".to_owned(),
        subject.to_owned(),
        PrincipalLimits::default(),
    )
    .unwrap()
}

#[test]
fn only_a_human_ratifier_has_ratification_authority() {
    let policy = AuthorizationPolicy::from_json(
        br#"{
          "schemaVersion":"smesh-authz-policy/v1",
          "policyId":"ratification-authz",
          "revision":1,
          "tenants":[{"id":"tenant-a","enabled":true}],
          "accounts":[
            {"id":"ratifier","kind":"human","memberships":[{"tenantId":"tenant-a","roles":["humanRatifier"]}]},
            {"id":"viewer","kind":"human","memberships":[{"tenantId":"tenant-a","roles":["taskViewer"]}]},
            {"id":"agent","kind":"serviceAccount","memberships":[{"tenantId":"tenant-a","roles":["taskAgent"]}]}
          ],
          "principalBindings":[
            {"principal":{"issuer":"test:ratification","subject":"ratifier"},"accountId":"ratifier"},
            {"principal":{"issuer":"test:ratification","subject":"viewer"},"accountId":"viewer"},
            {"principal":{"issuer":"test:ratification","subject":"agent"},"accountId":"agent"}
          ]
        }"#,
    )
    .unwrap();

    let ratifier = policy.resolve(&principal("ratifier"), None).unwrap();
    assert!(ratifier.is_human());
    assert!(ratifier.authorize(Operation::ArtifactRead).is_err());
    assert!(ratifier.authorize(Operation::ArtifactResolve).is_err());
    for operation in [
        Operation::RatificationRead,
        Operation::RatificationReview,
        Operation::RatificationDecide,
    ] {
        assert!(ratifier.authorize(operation).is_ok());
        assert!(
            policy
                .resolve(&principal("viewer"), None)
                .unwrap()
                .authorize(operation)
                .is_err()
        );
        assert!(
            policy
                .resolve(&principal("agent"), None)
                .unwrap()
                .authorize(operation)
                .is_err()
        );
    }

    let service_policy = br#"{
      "schemaVersion":"smesh-authz-policy/v1","policyId":"invalid","revision":1,
      "tenants":[{"id":"tenant-a","enabled":true}],
      "accounts":[{"id":"service","kind":"serviceAccount","memberships":[{"tenantId":"tenant-a","roles":["humanRatifier"]}]}],
      "principalBindings":[{"principal":{"issuer":"test:ratification","subject":"service"},"accountId":"service"}]
    }"#;
    assert!(AuthorizationPolicy::from_json(service_policy).is_err());
}

#[test]
fn sqlite_ratification_capacity_uses_one_byte_accurate_combined_authority_query() {
    let source = include_str!("../src/sqlite_store.rs");
    let start = source
        .find("const RATIFICATION_ACCOUNTING_SELECT_SQL")
        .expect("ratification accounting query");
    let query_end = source[start..].find(";\n").unwrap() + start;
    let query = &source[start..query_end];
    assert!(query.contains("ratification_packets"));
    assert!(query.contains("ratification_events"));
    assert!(query.contains("length(CAST("));
    assert!(query.contains("COALESCE(length(CAST(reviewer_account_id AS BLOB)), 0)"));
    assert!(query.contains("COALESCE(length(CAST(head_receipt_hash AS BLOB)), 0)"));
    assert!(query.contains("COALESCE(length(CAST(previous_receipt_hash AS BLOB)), 0)"));
    assert_eq!(query.matches("SELECT COALESCE(SUM").count(), 2);
    assert!(source.contains("ensure_ratification_capacity(connection)"));
    assert!(source.contains("validate_ratification_capacity(&connection)?;"));
}

#[test]
fn artifact_manifest_digest_must_bind_the_exact_manifest() {
    let fixture = Fixture::new();
    let ledger = RatificationLedger::open(&fixture.0, [26; 32]).unwrap();
    let mut inconsistent = packet();
    inconsistent.artifact_set_digest = smesh_a2a::content_digest(b"different manifest");

    assert_eq!(
        ledger.freeze_packet(inconsistent).unwrap_err(),
        RatificationError::InvalidInput
    );
}

#[test]
fn frozen_packet_survives_restart_and_cannot_be_decided_before_exact_review() {
    let fixture = Fixture::new();
    let ledger = RatificationLedger::open(&fixture.0, [27; 32]).unwrap();
    let frozen = ledger.freeze_packet(packet()).unwrap();
    drop(ledger);

    let reopened = RatificationLedger::open(&fixture.0, [27; 32]).unwrap();
    assert_eq!(
        reopened.packet("tenant-a", "task-27").unwrap().unwrap(),
        frozen
    );
    let error = reopened
        .decide(RatificationCommand {
            tenant_id: "tenant-a".to_owned(),
            task_id: "task-27".to_owned(),
            account_id: "ratifier".to_owned(),
            generation: frozen.generation,
            authorization_policy_id: frozen.authorization_policy_id.clone(),
            authorization_policy_revision: frozen.authorization_policy_revision,
            authorization_policy_digest: frozen.authorization_policy_digest.clone(),
            principal_scope: frozen.principal_scope.clone(),
            authentication_method: frozen.authentication_method.clone(),
            context_id: frozen.context_id.clone(),
            request_digest: frozen.request_digest.clone(),
            ratification_key_generation: frozen.ratification_key_generation.clone(),
            expected_revision: 0,
            checkpoint_hash: frozen.checkpoint_hash.clone(),
            packet_hash: frozen.packet_hash.clone(),
            artifact_manifest_digest: frozen.artifact_set_digest.clone(),
            idempotency_key: "decision-1".to_owned(),
            decision: HumanDecision::Approve,
            rationale: "Evidence supports release.".to_owned(),
            decided_at_millis: 1_700_000_000_001,
        })
        .unwrap_err();
    assert_eq!(error, RatificationError::ReviewRequired);
}

#[test]
#[allow(clippy::too_many_lines)] // One binding matrix verifies both standalone mutation paths.
fn standalone_commands_reject_every_frozen_binding_mismatch_without_appending() {
    let fixture = Fixture::new();
    let ledger = RatificationLedger::open(&fixture.0, [71; 32]).unwrap();
    let frozen = ledger.freeze_packet(packet()).unwrap();
    let exact_review = standalone_review(&frozen, "binding-review");

    for field in [
        "tenant",
        "task",
        "generation",
        "policy-id",
        "policy-revision",
        "policy-digest",
        "context",
        "request",
        "key-generation",
        "checkpoint",
        "packet",
        "artifact-manifest",
    ] {
        let mut command = exact_review.clone();
        command.idempotency_key = format!("bad-review-{field}");
        match field {
            "tenant" => command.tenant_id = "other-tenant".to_owned(),
            "task" => command.task_id = "other-task".to_owned(),
            "generation" => command.generation += 1,
            "policy-id" => command.authorization_policy_id = "other-policy".to_owned(),
            "policy-revision" => command.authorization_policy_revision += 1,
            "policy-digest" => {
                command.authorization_policy_digest = smesh_a2a::content_digest(b"other-policy");
            }
            "context" => command.context_id = "other-context".to_owned(),
            "request" => command.request_digest = smesh_a2a::content_digest(b"other-request"),
            "key-generation" => {
                command.ratification_key_generation = smesh_a2a::content_digest(b"other-key");
            }
            "checkpoint" => {
                command.checkpoint_hash = smesh_a2a::content_digest(b"other-checkpoint");
            }
            "packet" => command.packet_hash = smesh_a2a::content_digest(b"other-packet"),
            "artifact-manifest" => {
                command.artifact_manifest_digest = smesh_a2a::content_digest(b"other-manifest");
            }
            _ => unreachable!(),
        }
        let expected = if matches!(field, "tenant" | "task") {
            RatificationError::NotFound
        } else if field == "artifact-manifest" {
            RatificationError::ExactReviewRequired
        } else {
            RatificationError::PreconditionFailed
        };
        assert_eq!(
            ledger.acknowledge_review(command).unwrap_err(),
            expected,
            "{field}"
        );
        assert!(
            ledger
                .history(&frozen.tenant_id, &frozen.task_id)
                .unwrap()
                .is_empty()
        );
    }

    let review = ledger.acknowledge_review(exact_review).unwrap();
    assert_eq!(
        review.principal_scope,
        smesh_a2a::content_digest(b"current-ratifier")
    );
    assert_eq!(review.authentication_method, "mutual-tls");
    assert_ne!(review.principal_scope, frozen.principal_scope);
    assert_ne!(review.authentication_method, frozen.authentication_method);

    let exact_decision = standalone_decision(&frozen, "binding-decision");
    for field in [
        "tenant",
        "task",
        "generation",
        "policy-id",
        "policy-revision",
        "policy-digest",
        "context",
        "request",
        "key-generation",
        "checkpoint",
        "packet",
        "artifact-manifest",
    ] {
        let mut command = exact_decision.clone();
        command.idempotency_key = format!("bad-decision-{field}");
        match field {
            "tenant" => command.tenant_id = "other-tenant".to_owned(),
            "task" => command.task_id = "other-task".to_owned(),
            "generation" => command.generation += 1,
            "policy-id" => command.authorization_policy_id = "other-policy".to_owned(),
            "policy-revision" => command.authorization_policy_revision += 1,
            "policy-digest" => {
                command.authorization_policy_digest = smesh_a2a::content_digest(b"other-policy");
            }
            "context" => command.context_id = "other-context".to_owned(),
            "request" => command.request_digest = smesh_a2a::content_digest(b"other-request"),
            "key-generation" => {
                command.ratification_key_generation = smesh_a2a::content_digest(b"other-key");
            }
            "checkpoint" => {
                command.checkpoint_hash = smesh_a2a::content_digest(b"other-checkpoint");
            }
            "packet" => command.packet_hash = smesh_a2a::content_digest(b"other-packet"),
            "artifact-manifest" => {
                command.artifact_manifest_digest = smesh_a2a::content_digest(b"other-manifest");
            }
            _ => unreachable!(),
        }
        let expected = if matches!(field, "tenant" | "task") {
            RatificationError::NotFound
        } else {
            RatificationError::PreconditionFailed
        };
        assert_eq!(ledger.decide(command).unwrap_err(), expected, "{field}");
        assert_eq!(
            ledger.history(&frozen.tenant_id, &frozen.task_id).unwrap(),
            vec![review.clone()]
        );
    }

    let decision = ledger.decide(exact_decision).unwrap();
    assert_eq!(
        decision.principal_scope,
        smesh_a2a::content_digest(b"current-ratifier")
    );
    assert_eq!(decision.authentication_method, "mutual-tls");
}

#[test]
fn standalone_commands_reject_invalid_ratifier_fields_without_appending() {
    let fixture = Fixture::new();
    let ledger = RatificationLedger::open(&fixture.0, [73; 32]).unwrap();
    let frozen = ledger.freeze_packet(packet()).unwrap();

    let invalid_fields = [
        ("empty-principal", "", "mutual-tls"),
        ("oversized-principal", &"p".repeat(257), "mutual-tls"),
        ("nul-principal", "ratifier\0principal", "mutual-tls"),
        ("non-ascii-principal", "ratifiér", "mutual-tls"),
        ("empty-authentication", "ratifier-principal", ""),
        (
            "oversized-authentication",
            "ratifier-principal",
            &"a".repeat(65),
        ),
        ("nul-authentication", "ratifier-principal", "mutual\0tls"),
        (
            "non-ascii-authentication",
            "ratifier-principal",
            "mutual-tlś",
        ),
    ];
    for (name, principal_scope, authentication_method) in &invalid_fields {
        let mut command = standalone_review(&frozen, &format!("invalid-review-{name}"));
        command.principal_scope = (*principal_scope).to_owned();
        command.authentication_method = (*authentication_method).to_owned();
        assert_eq!(
            ledger.acknowledge_review(command).unwrap_err(),
            RatificationError::InvalidInput,
            "{name}"
        );
        assert!(
            ledger
                .history(&frozen.tenant_id, &frozen.task_id)
                .unwrap()
                .is_empty(),
            "{name}"
        );
    }

    let review = ledger
        .acknowledge_review(standalone_review(&frozen, "valid-ratifier-review"))
        .unwrap();
    for (name, principal_scope, authentication_method) in invalid_fields {
        let mut command = standalone_decision(&frozen, &format!("invalid-decision-{name}"));
        command.principal_scope = principal_scope.to_owned();
        command.authentication_method = authentication_method.to_owned();
        assert_eq!(
            ledger.decide(command).unwrap_err(),
            RatificationError::InvalidInput,
            "{name}"
        );
        assert_eq!(
            ledger.history(&frozen.tenant_id, &frozen.task_id).unwrap(),
            vec![review.clone()],
            "{name}"
        );
    }
}

#[test]
fn standalone_semantic_errors_distinguish_preconditions_and_idempotency_conflicts() {
    let fixture = Fixture::new();
    let ledger = RatificationLedger::open(&fixture.0, [72; 32]).unwrap();
    let frozen = ledger.freeze_packet(packet()).unwrap();

    let mut stale = standalone_review(&frozen, "stale-review");
    stale.expected_revision = 1;
    assert_eq!(
        ledger.acknowledge_review(stale).unwrap_err(),
        RatificationError::PreconditionFailed
    );
    assert!(
        ledger
            .history(&frozen.tenant_id, &frozen.task_id)
            .unwrap()
            .is_empty()
    );

    let review_command = standalone_review(&frozen, "semantic-review");
    let review = ledger.acknowledge_review(review_command.clone()).unwrap();
    let mut changed_review = review_command;
    changed_review.authentication_method = "bearer-jwt".to_owned();
    assert_eq!(
        ledger.acknowledge_review(changed_review).unwrap_err(),
        RatificationError::IdempotencyConflict
    );
    assert_eq!(
        ledger.history(&frozen.tenant_id, &frozen.task_id).unwrap(),
        vec![review.clone()]
    );

    let decision_command = standalone_decision(&frozen, "semantic-decision");
    let decision = ledger.decide(decision_command.clone()).unwrap();
    let mut changed_decision = decision_command;
    changed_decision.rationale = "Changed semantic rationale.".to_owned();
    assert_eq!(
        ledger.decide(changed_decision).unwrap_err(),
        RatificationError::IdempotencyConflict
    );
    assert_eq!(
        ledger.history(&frozen.tenant_id, &frozen.task_id).unwrap(),
        vec![review, decision]
    );

    let mut after_terminal = standalone_review(&frozen, "after-terminal");
    after_terminal.expected_revision = 2;
    assert_eq!(
        ledger.acknowledge_review(after_terminal).unwrap_err(),
        RatificationError::PreconditionFailed
    );
}

#[test]
#[allow(clippy::too_many_lines)] // The receipt-chain scenario is intentionally end-to-end.
fn exact_review_then_amend_appends_a_chained_integrity_protected_receipt() {
    let fixture = Fixture::new();
    let ledger = RatificationLedger::open(&fixture.0, [28; 32]).unwrap();
    let frozen = ledger.freeze_packet(packet()).unwrap();
    let review = ReviewAcknowledgement {
        tenant_id: "tenant-a".to_owned(),
        task_id: "task-27".to_owned(),
        account_id: "ratifier".to_owned(),
        generation: frozen.generation,
        authorization_policy_id: frozen.authorization_policy_id.clone(),
        authorization_policy_revision: frozen.authorization_policy_revision,
        authorization_policy_digest: frozen.authorization_policy_digest.clone(),
        principal_scope: frozen.principal_scope.clone(),
        authentication_method: frozen.authentication_method.clone(),
        context_id: frozen.context_id.clone(),
        request_digest: frozen.request_digest.clone(),
        ratification_key_generation: frozen.ratification_key_generation.clone(),
        expected_revision: 0,
        checkpoint_hash: frozen.checkpoint_hash.clone(),
        packet_hash: frozen.packet_hash.clone(),
        evidence_hashes: frozen.evidence_hashes.clone(),
        artifact_hashes: frozen
            .artifacts
            .iter()
            .map(|item| item.digest.clone())
            .collect(),
        artifact_manifest_digest: frozen.artifact_set_digest.clone(),
        uncertainty_acknowledged: true,
        idempotency_key: "review-1".to_owned(),
        reviewed_at_millis: 1_700_000_000_001,
    };
    let reviewed = ledger.acknowledge_review(review.clone()).unwrap();
    assert_eq!(
        ledger
            .acknowledge_review(ReviewAcknowledgement {
                reviewed_at_millis: review.reviewed_at_millis + 999,
                ..review
            })
            .unwrap(),
        reviewed
    );
    assert!(ledger.verify_receipt(&reviewed));

    let amended = ledger
        .decide(RatificationCommand {
            tenant_id: "tenant-a".to_owned(),
            task_id: "task-27".to_owned(),
            account_id: "ratifier".to_owned(),
            generation: frozen.generation,
            authorization_policy_id: frozen.authorization_policy_id.clone(),
            authorization_policy_revision: frozen.authorization_policy_revision,
            authorization_policy_digest: frozen.authorization_policy_digest.clone(),
            principal_scope: frozen.principal_scope.clone(),
            authentication_method: frozen.authentication_method.clone(),
            context_id: frozen.context_id.clone(),
            request_digest: frozen.request_digest.clone(),
            ratification_key_generation: frozen.ratification_key_generation.clone(),
            expected_revision: 1,
            checkpoint_hash: frozen.checkpoint_hash.clone(),
            packet_hash: frozen.packet_hash.clone(),
            artifact_manifest_digest: frozen.artifact_set_digest.clone(),
            idempotency_key: "decision-amend-1".to_owned(),
            decision: HumanDecision::Amend,
            rationale: "Replace the uncertain model-derived assertion.".to_owned(),
            decided_at_millis: 1_700_000_000_002,
        })
        .unwrap();
    assert_eq!(amended.revision, 2);
    assert_eq!(
        amended.previous_receipt_hash.as_deref(),
        Some(reviewed.receipt_hash.as_str())
    );
    assert_eq!(amended.completion_policy_id, "release-policy");
    assert_eq!(
        amended.completion_policy_hash,
        frozen.completion_policy_hash
    );
    assert_eq!(
        amended.evidence_snapshot_hash,
        frozen.evidence_snapshot_hash
    );
    assert_eq!(amended.artifact_set_digest, frozen.artifact_set_digest);
    assert_eq!(
        amended.authorization_policy_id,
        frozen.authorization_policy_id
    );
    assert_eq!(
        amended.authorization_policy_revision,
        frozen.authorization_policy_revision
    );
    assert_eq!(
        amended.authorization_policy_digest,
        frozen.authorization_policy_digest
    );
    assert_eq!(amended.principal_scope, frozen.principal_scope);
    assert_eq!(amended.authentication_method, frozen.authentication_method);
    assert_eq!(amended.context_id, frozen.context_id);
    assert_eq!(amended.request_digest, frozen.request_digest);
    assert_eq!(
        amended.idempotency_key_digest,
        smesh_a2a::content_digest(b"decision-amend-1")
    );
    assert_eq!(
        amended.ratification_key_generation,
        frozen.ratification_key_generation
    );
    assert!(ledger.verify_receipt(&amended));
    assert_eq!(
        ledger.history("tenant-a", "task-27").unwrap(),
        vec![reviewed, amended.clone()]
    );

    let mut tampered: HumanRatificationReceipt = amended;
    tampered.rationale = "silently approve instead".to_owned();
    assert!(!ledger.verify_receipt(&tampered));
}

#[test]
fn exact_review_rejects_omissions_uncertainty_bypass_and_stale_replay() {
    let fixture = Fixture::new();
    let ledger = RatificationLedger::open(&fixture.0, [29; 32]).unwrap();
    let frozen = ledger.freeze_packet(packet()).unwrap();
    let acknowledgement = ReviewAcknowledgement {
        tenant_id: "tenant-a".to_owned(),
        task_id: "task-27".to_owned(),
        account_id: "ratifier".to_owned(),
        generation: frozen.generation,
        authorization_policy_id: frozen.authorization_policy_id.clone(),
        authorization_policy_revision: frozen.authorization_policy_revision,
        authorization_policy_digest: frozen.authorization_policy_digest.clone(),
        principal_scope: frozen.principal_scope.clone(),
        authentication_method: frozen.authentication_method.clone(),
        context_id: frozen.context_id.clone(),
        request_digest: frozen.request_digest.clone(),
        ratification_key_generation: frozen.ratification_key_generation.clone(),
        expected_revision: 0,
        checkpoint_hash: frozen.checkpoint_hash.clone(),
        packet_hash: frozen.packet_hash.clone(),
        evidence_hashes: Vec::new(),
        artifact_hashes: frozen
            .artifacts
            .iter()
            .map(|item| item.digest.clone())
            .collect(),
        artifact_manifest_digest: frozen.artifact_set_digest.clone(),
        uncertainty_acknowledged: true,
        idempotency_key: "review-bad".to_owned(),
        reviewed_at_millis: 1_700_000_000_001,
    };
    assert_eq!(
        ledger
            .acknowledge_review(acknowledgement.clone())
            .unwrap_err(),
        RatificationError::ExactReviewRequired
    );
    let wrong_manifest = ReviewAcknowledgement {
        evidence_hashes: frozen.evidence_hashes.clone(),
        artifact_manifest_digest: smesh_a2a::content_digest(b"different publication manifest"),
        idempotency_key: "review-wrong-manifest".to_owned(),
        ..acknowledgement.clone()
    };
    assert_eq!(
        ledger.acknowledge_review(wrong_manifest).unwrap_err(),
        RatificationError::ExactReviewRequired
    );
    let without_uncertainty = ReviewAcknowledgement {
        evidence_hashes: frozen.evidence_hashes.clone(),
        uncertainty_acknowledged: false,
        idempotency_key: "review-no-uncertainty".to_owned(),
        ..acknowledgement.clone()
    };
    assert_eq!(
        ledger.acknowledge_review(without_uncertainty).unwrap_err(),
        RatificationError::ExactReviewRequired
    );
    let accepted = ReviewAcknowledgement {
        evidence_hashes: frozen.evidence_hashes.clone(),
        idempotency_key: "review-good".to_owned(),
        ..acknowledgement
    };
    ledger.acknowledge_review(accepted.clone()).unwrap();
    assert_eq!(
        ledger
            .acknowledge_review(ReviewAcknowledgement {
                idempotency_key: "review-stale-replay".to_owned(),
                ..accepted
            })
            .unwrap_err(),
        RatificationError::PreconditionFailed
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Keep all terminal decision variants in one parity matrix.
fn all_decisions_are_durable_terminal_transitions_and_key_reuse_conflicts() {
    for (index, decision) in [
        HumanDecision::Approve,
        HumanDecision::Reject,
        HumanDecision::Amend,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new();
        let ledger =
            RatificationLedger::open(&fixture.0, [40 + u8::try_from(index).unwrap(); 32]).unwrap();
        let frozen = ledger.freeze_packet(packet()).unwrap();
        let review = ledger
            .acknowledge_review(ReviewAcknowledgement {
                tenant_id: frozen.tenant_id.clone(),
                task_id: frozen.task_id.clone(),
                account_id: "ratifier".to_owned(),
                generation: frozen.generation,
                authorization_policy_id: frozen.authorization_policy_id.clone(),
                authorization_policy_revision: frozen.authorization_policy_revision,
                authorization_policy_digest: frozen.authorization_policy_digest.clone(),
                principal_scope: frozen.principal_scope.clone(),
                authentication_method: frozen.authentication_method.clone(),
                context_id: frozen.context_id.clone(),
                request_digest: frozen.request_digest.clone(),
                ratification_key_generation: frozen.ratification_key_generation.clone(),
                expected_revision: 0,
                checkpoint_hash: frozen.checkpoint_hash.clone(),
                packet_hash: frozen.packet_hash.clone(),
                evidence_hashes: frozen.evidence_hashes.clone(),
                artifact_hashes: frozen
                    .artifacts
                    .iter()
                    .map(|artifact| artifact.digest.clone())
                    .collect(),
                artifact_manifest_digest: frozen.artifact_set_digest.clone(),
                uncertainty_acknowledged: true,
                idempotency_key: "transition-review".to_owned(),
                reviewed_at_millis: 1_700_000_000_010,
            })
            .unwrap();
        assert_eq!(
            ledger
                .decide(RatificationCommand {
                    tenant_id: frozen.tenant_id.clone(),
                    task_id: frozen.task_id.clone(),
                    account_id: "ratifier".to_owned(),
                    generation: frozen.generation,
                    authorization_policy_id: frozen.authorization_policy_id.clone(),
                    authorization_policy_revision: frozen.authorization_policy_revision,
                    authorization_policy_digest: frozen.authorization_policy_digest.clone(),
                    principal_scope: frozen.principal_scope.clone(),
                    authentication_method: frozen.authentication_method.clone(),
                    context_id: frozen.context_id.clone(),
                    request_digest: frozen.request_digest.clone(),
                    ratification_key_generation: frozen.ratification_key_generation.clone(),
                    expected_revision: 0,
                    checkpoint_hash: frozen.checkpoint_hash.clone(),
                    packet_hash: frozen.packet_hash.clone(),
                    artifact_manifest_digest: frozen.artifact_set_digest.clone(),
                    idempotency_key: "transition-review".to_owned(),
                    decision: decision.clone(),
                    rationale: "Conflicting reuse.".to_owned(),
                    decided_at_millis: 1_700_000_000_011,
                })
                .unwrap_err(),
            RatificationError::IdempotencyConflict
        );
        let receipt = ledger
            .decide(RatificationCommand {
                tenant_id: frozen.tenant_id.clone(),
                task_id: frozen.task_id.clone(),
                account_id: "ratifier".to_owned(),
                generation: frozen.generation,
                authorization_policy_id: frozen.authorization_policy_id.clone(),
                authorization_policy_revision: frozen.authorization_policy_revision,
                authorization_policy_digest: frozen.authorization_policy_digest.clone(),
                principal_scope: frozen.principal_scope.clone(),
                authentication_method: frozen.authentication_method.clone(),
                context_id: frozen.context_id.clone(),
                request_digest: frozen.request_digest.clone(),
                ratification_key_generation: frozen.ratification_key_generation.clone(),
                expected_revision: 1,
                checkpoint_hash: frozen.checkpoint_hash.clone(),
                packet_hash: frozen.packet_hash.clone(),
                artifact_manifest_digest: frozen.artifact_set_digest.clone(),
                idempotency_key: "transition-decision".to_owned(),
                decision: decision.clone(),
                rationale: "Terminal human decision.".to_owned(),
                decided_at_millis: 1_700_000_000_011,
            })
            .unwrap();
        assert_eq!(
            receipt.action,
            HumanRatificationAction::Decision(decision.clone())
        );
        drop(ledger);
        let reopened =
            RatificationLedger::open(&fixture.0, [40 + u8::try_from(index).unwrap(); 32]).unwrap();
        assert_eq!(
            reopened.history("tenant-a", "task-27").unwrap(),
            vec![review, receipt]
        );
        assert_eq!(
            reopened
                .decide(RatificationCommand {
                    tenant_id: "tenant-a".to_owned(),
                    task_id: "task-27".to_owned(),
                    account_id: "ratifier".to_owned(),
                    generation: frozen.generation,
                    authorization_policy_id: frozen.authorization_policy_id.clone(),
                    authorization_policy_revision: frozen.authorization_policy_revision,
                    authorization_policy_digest: frozen.authorization_policy_digest.clone(),
                    principal_scope: frozen.principal_scope.clone(),
                    authentication_method: frozen.authentication_method.clone(),
                    context_id: frozen.context_id.clone(),
                    request_digest: frozen.request_digest.clone(),
                    ratification_key_generation: frozen.ratification_key_generation.clone(),
                    expected_revision: 2,
                    checkpoint_hash: frozen.checkpoint_hash.clone(),
                    packet_hash: frozen.packet_hash.clone(),
                    artifact_manifest_digest: frozen.artifact_set_digest.clone(),
                    idempotency_key: "second-terminal-decision".to_owned(),
                    decision: HumanDecision::Approve,
                    rationale: "Must not overwrite terminal state.".to_owned(),
                    decided_at_millis: 1_700_000_000_012,
                })
                .unwrap_err(),
            RatificationError::PreconditionFailed
        );
    }
}

#[test]
fn terminal_decision_cannot_be_reopened_by_another_review() {
    let fixture = Fixture::new();
    let ledger = RatificationLedger::open(&fixture.0, [49; 32]).unwrap();
    let frozen = ledger.freeze_packet(packet()).unwrap();
    let acknowledgement = ReviewAcknowledgement {
        tenant_id: frozen.tenant_id.clone(),
        task_id: frozen.task_id.clone(),
        account_id: "ratifier".to_owned(),
        generation: frozen.generation,
        authorization_policy_id: frozen.authorization_policy_id.clone(),
        authorization_policy_revision: frozen.authorization_policy_revision,
        authorization_policy_digest: frozen.authorization_policy_digest.clone(),
        principal_scope: frozen.principal_scope.clone(),
        authentication_method: frozen.authentication_method.clone(),
        context_id: frozen.context_id.clone(),
        request_digest: frozen.request_digest.clone(),
        ratification_key_generation: frozen.ratification_key_generation.clone(),
        expected_revision: 0,
        checkpoint_hash: frozen.checkpoint_hash.clone(),
        packet_hash: frozen.packet_hash.clone(),
        evidence_hashes: frozen.evidence_hashes.clone(),
        artifact_hashes: frozen
            .artifacts
            .iter()
            .map(|artifact| artifact.digest.clone())
            .collect(),
        artifact_manifest_digest: frozen.artifact_set_digest.clone(),
        uncertainty_acknowledged: true,
        idempotency_key: "terminal-review".to_owned(),
        reviewed_at_millis: 1_700_000_000_012,
    };
    ledger.acknowledge_review(acknowledgement.clone()).unwrap();
    ledger
        .decide(RatificationCommand {
            tenant_id: frozen.tenant_id.clone(),
            task_id: frozen.task_id.clone(),
            account_id: "ratifier".to_owned(),
            generation: frozen.generation,
            authorization_policy_id: frozen.authorization_policy_id.clone(),
            authorization_policy_revision: frozen.authorization_policy_revision,
            authorization_policy_digest: frozen.authorization_policy_digest.clone(),
            principal_scope: frozen.principal_scope.clone(),
            authentication_method: frozen.authentication_method.clone(),
            context_id: frozen.context_id.clone(),
            request_digest: frozen.request_digest.clone(),
            ratification_key_generation: frozen.ratification_key_generation.clone(),
            expected_revision: 1,
            checkpoint_hash: frozen.checkpoint_hash.clone(),
            packet_hash: frozen.packet_hash.clone(),
            artifact_manifest_digest: frozen.artifact_set_digest.clone(),
            idempotency_key: "terminal-decision".to_owned(),
            decision: HumanDecision::Approve,
            rationale: "Terminal decision.".to_owned(),
            decided_at_millis: 1_700_000_000_013,
        })
        .unwrap();

    assert_eq!(
        ledger
            .acknowledge_review(ReviewAcknowledgement {
                expected_revision: 2,
                idempotency_key: "terminal-rereview".to_owned(),
                reviewed_at_millis: 1_700_000_000_014,
                ..acknowledgement
            })
            .unwrap_err(),
        RatificationError::PreconditionFailed
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Each persisted field is tampered independently in one matrix.
fn stored_packet_and_event_tampering_fail_closed() {
    let packet_fixture = Fixture::new();
    let ledger = RatificationLedger::open(&packet_fixture.0, [50; 32]).unwrap();
    ledger.freeze_packet(packet()).unwrap();
    let connection = rusqlite::Connection::open(&packet_fixture.0).unwrap();
    connection
        .execute_batch("DROP TRIGGER ratification_packets_no_update;")
        .unwrap();
    connection
        .execute(
            "UPDATE ratification_packets SET packet_json=?1 WHERE tenant_id='tenant-a' AND task_id='task-27'",
            [b"{}".as_slice()],
        )
        .unwrap();
    drop(connection);
    assert_eq!(
        ledger.packet("tenant-a", "task-27").unwrap_err(),
        RatificationError::Integrity
    );
    drop(ledger);
    let Err(error) = RatificationLedger::open(&packet_fixture.0, [50; 32]) else {
        panic!("standalone ledger reopened with a corrupt packet")
    };
    assert_eq!(error, RatificationError::Integrity);

    let event_fixture = Fixture::new();
    let ledger = RatificationLedger::open(&event_fixture.0, [51; 32]).unwrap();
    let frozen = ledger.freeze_packet(packet()).unwrap();
    ledger
        .acknowledge_review(ReviewAcknowledgement {
            tenant_id: frozen.tenant_id.clone(),
            task_id: frozen.task_id.clone(),
            account_id: "ratifier".to_owned(),
            generation: frozen.generation,
            authorization_policy_id: frozen.authorization_policy_id.clone(),
            authorization_policy_revision: frozen.authorization_policy_revision,
            authorization_policy_digest: frozen.authorization_policy_digest.clone(),
            principal_scope: frozen.principal_scope.clone(),
            authentication_method: frozen.authentication_method.clone(),
            context_id: frozen.context_id.clone(),
            request_digest: frozen.request_digest.clone(),
            ratification_key_generation: frozen.ratification_key_generation.clone(),
            expected_revision: 0,
            checkpoint_hash: frozen.checkpoint_hash.clone(),
            packet_hash: frozen.packet_hash.clone(),
            evidence_hashes: frozen.evidence_hashes.clone(),
            artifact_hashes: frozen
                .artifacts
                .iter()
                .map(|artifact| artifact.digest.clone())
                .collect(),
            artifact_manifest_digest: frozen.artifact_set_digest.clone(),
            uncertainty_acknowledged: true,
            idempotency_key: "tamper-review".to_owned(),
            reviewed_at_millis: 1_700_000_000_020,
        })
        .unwrap();
    let connection = rusqlite::Connection::open(&event_fixture.0).unwrap();
    connection
        .execute_batch("DROP TRIGGER ratification_events_no_update;")
        .unwrap();
    connection
        .execute(
            "UPDATE ratification_events SET event_json=?1 WHERE tenant_id='tenant-a' AND task_id='task-27'",
            [b"{}".as_slice()],
        )
        .unwrap();
    drop(connection);
    assert_eq!(
        ledger.history("tenant-a", "task-27").unwrap_err(),
        RatificationError::Integrity
    );
    drop(ledger);
    let Err(error) = RatificationLedger::open(&event_fixture.0, [51; 32]) else {
        panic!("standalone ledger reopened with a corrupt event")
    };
    assert_eq!(error, RatificationError::Integrity);

    let scope_fixture = Fixture::new();
    let ledger = RatificationLedger::open(&scope_fixture.0, [52; 32]).unwrap();
    let frozen = ledger.freeze_packet(packet()).unwrap();
    ledger
        .acknowledge_review(ReviewAcknowledgement {
            tenant_id: frozen.tenant_id.clone(),
            task_id: frozen.task_id.clone(),
            account_id: "ratifier".to_owned(),
            generation: frozen.generation,
            authorization_policy_id: frozen.authorization_policy_id.clone(),
            authorization_policy_revision: frozen.authorization_policy_revision,
            authorization_policy_digest: frozen.authorization_policy_digest.clone(),
            principal_scope: frozen.principal_scope.clone(),
            authentication_method: frozen.authentication_method.clone(),
            context_id: frozen.context_id.clone(),
            request_digest: frozen.request_digest.clone(),
            ratification_key_generation: frozen.ratification_key_generation.clone(),
            expected_revision: 0,
            checkpoint_hash: frozen.checkpoint_hash.clone(),
            packet_hash: frozen.packet_hash.clone(),
            evidence_hashes: frozen.evidence_hashes.clone(),
            artifact_hashes: frozen
                .artifacts
                .iter()
                .map(|artifact| artifact.digest.clone())
                .collect(),
            artifact_manifest_digest: frozen.artifact_set_digest.clone(),
            uncertainty_acknowledged: true,
            idempotency_key: "scope-review".to_owned(),
            reviewed_at_millis: 1_700_000_000_021,
        })
        .unwrap();
    let connection = rusqlite::Connection::open(&scope_fixture.0).unwrap();
    connection
        .execute_batch(
            "PRAGMA foreign_keys=OFF;
             DROP TRIGGER ratification_events_no_update;",
        )
        .unwrap();
    connection
        .execute(
            "UPDATE ratification_events SET task_id='other-task' WHERE tenant_id='tenant-a' AND task_id='task-27'",
            [],
        )
        .unwrap();
    drop(connection);
    assert_eq!(
        ledger.history("tenant-a", "other-task").unwrap_err(),
        RatificationError::Integrity
    );
    drop(ledger);
    let Err(error) = RatificationLedger::open(&scope_fixture.0, [52; 32]) else {
        panic!("standalone ledger reopened with a corrupt event scope")
    };
    assert_eq!(error, RatificationError::Integrity);
}

struct RouteVerifier;

#[async_trait]
impl BearerVerifier for RouteVerifier {
    async fn verify(&self, token: PresentedBearer<'_>) -> Result<Principal, AuthenticationError> {
        let subject = match token.as_str() {
            "ratifier-token" => "ratifier",
            "ratifier-two-token" => "ratifier-two",
            "ratifier-b-token" => "ratifier-b",
            "viewer-token" => "viewer",
            _ => return Err(AuthenticationError::InvalidToken),
        };
        Principal::bearer_for_verifier(
            "test:ratification".to_owned(),
            subject.to_owned(),
            PrincipalLimits::default(),
        )
        .map_err(|_| AuthenticationError::InvalidToken)
    }
}

#[tokio::test]
async fn ratification_bootstrap_is_public_static_and_data_free() {
    let fixture = Fixture::new();
    let store = SqliteTaskStore::open_with_ratification_key(
        &fixture.0,
        16,
        zeroize::Zeroizing::new([0x52; 32]),
        false,
    )
    .await
    .unwrap();
    let authorization = AuthorizationPolicy::from_json(
        br#"{
          "schemaVersion":"smesh-authz-policy/v1","policyId":"ratification-authz","revision":1,
          "tenants":[{"id":"tenant-a","enabled":true}],
          "accounts":[{"id":"ratifier","kind":"human","memberships":[{"tenantId":"tenant-a","roles":["humanRatifier"]}]}],
          "principalBindings":[{"principal":{"issuer":"test:ratification","subject":"ratifier"},"accountId":"ratifier"}]
        }"#,
    )
    .unwrap();
    let gateway = build_authorized_durable_loopback_gateway_with_ratification_and_telemetry(
        GatewayConfig::new("http://127.0.0.1:1", "ratification-test"),
        store,
        DurableLoopbackEndpoint::new(),
        InjectedClock::new(1_700_000_000_100),
        AuthState::new(Arc::new(RouteVerifier), [31; 32]),
        Arc::new(authorization),
        None,
    )
    .unwrap();
    let app = gateway.router();
    let expected_csp = "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; img-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

    for (uri, content_type) in [
        ("/ratification/console", "text/html; charset=utf-8"),
        ("/ratification/console.js", "text/javascript; charset=utf-8"),
    ] {
        let response = app
            .clone()
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        assert_eq!(response.headers()[header::CONTENT_TYPE], content_type);
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "private, no-store"
        );
        assert_eq!(
            response.headers()[header::CONTENT_SECURITY_POLICY],
            expected_csp
        );
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert_eq!(response.headers()["referrer-policy"], "no-referrer");
        assert_eq!(
            response.headers()["permissions-policy"],
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        );
        assert!(
            response
                .headers()
                .get("access-control-allow-origin")
                .is_none()
        );
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let text = std::str::from_utf8(&bytes).unwrap();
        for canary in [
            "task-27",
            "ratifier-token",
            "ratification-authz",
            "tenant-a",
            "sha256:60fe802f",
        ] {
            assert!(!text.contains(canary), "{uri} leaked {canary}");
        }
    }
    gateway.shutdown().await.unwrap();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn ratification_mutation_prebody_matrix_is_ordered_and_hardened() {
    let fixture = Fixture::new();
    let store = SqliteTaskStore::open_with_ratification_key(
        &fixture.0,
        16,
        zeroize::Zeroizing::new([0x52; 32]),
        false,
    )
    .await
    .unwrap();
    let authorization = AuthorizationPolicy::from_json(
        br#"{
          "schemaVersion":"smesh-authz-policy/v1","policyId":"ratification-authz","revision":1,
          "tenants":[{"id":"tenant-a","enabled":true}],
          "accounts":[
            {"id":"ratifier","kind":"human","memberships":[{"tenantId":"tenant-a","roles":["humanRatifier"]}]},
            {"id":"viewer","kind":"human","memberships":[{"tenantId":"tenant-a","roles":["taskViewer"]}]}
          ],
          "principalBindings":[
            {"principal":{"issuer":"test:ratification","subject":"ratifier"},"accountId":"ratifier"},
            {"principal":{"issuer":"test:ratification","subject":"viewer"},"accountId":"viewer"}
          ]
        }"#,
    )
    .unwrap();
    let gateway = build_authorized_durable_loopback_gateway_with_ratification_and_telemetry(
        GatewayConfig::new("http://127.0.0.1:1", "ratification-test"),
        store,
        DurableLoopbackEndpoint::new(),
        InjectedClock::new(1_700_000_000_100),
        AuthState::new(Arc::new(RouteVerifier), [31; 32]),
        Arc::new(authorization),
        None,
    )
    .unwrap();
    let app = gateway.router();
    let path = "/ratification/v1/tasks/missing/decision";
    let etag =
        "\"ratification-v1:0000000000000000000000000000000000000000000000000000000000000000\"";
    let body = Body::from(r#"{"decision":"approve","rationale":"reviewed"}"#);
    let base = || {
        Request::post(path)
            .header(header::AUTHORIZATION, "Bearer ratifier-token")
            .header(header::ORIGIN, "http://127.0.0.1:1")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::IF_MATCH, etag)
            .header("idempotency-key", "decision-1")
    };
    let mut cases = Vec::new();
    cases.push((
        "authentication-before-policy",
        Request::post(path)
            .header(header::ORIGIN, "https://attacker.example")
            .body(Body::from("{"))
            .unwrap(),
        StatusCode::UNAUTHORIZED,
    ));
    cases.push((
        "authorization-before-policy",
        Request::post(path)
            .header(header::AUTHORIZATION, "Bearer viewer-token")
            .header(header::ORIGIN, "https://attacker.example")
            .body(Body::from("{"))
            .unwrap(),
        StatusCode::FORBIDDEN,
    ));
    for (name, builder, expected) in [
        (
            "missing-origin",
            Request::post(path)
                .header(header::AUTHORIZATION, "Bearer ratifier-token")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, etag)
                .header("idempotency-key", "decision-1"),
            StatusCode::FORBIDDEN,
        ),
        (
            "null-origin",
            base().header(header::ORIGIN, "null"),
            StatusCode::FORBIDDEN,
        ),
        (
            "foreign-origin",
            base().header(header::ORIGIN, "https://attacker.example"),
            StatusCode::FORBIDDEN,
        ),
        (
            "comma-origin",
            Request::post(path)
                .header(header::AUTHORIZATION, "Bearer ratifier-token")
                .header(
                    header::ORIGIN,
                    "http://127.0.0.1:1,https://attacker.example",
                )
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, etag)
                .header("idempotency-key", "decision-1"),
            StatusCode::FORBIDDEN,
        ),
        (
            "duplicate-origin",
            base().header(header::ORIGIN, "http://127.0.0.1:1"),
            StatusCode::FORBIDDEN,
        ),
        (
            "missing-content-type",
            Request::post(path)
                .header(header::AUTHORIZATION, "Bearer ratifier-token")
                .header(header::ORIGIN, "http://127.0.0.1:1")
                .header(header::IF_MATCH, etag)
                .header("idempotency-key", "decision-1"),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            "parameterized-content-type",
            base().header(header::CONTENT_TYPE, "application/json; charset=utf-8"),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            "duplicate-content-type",
            base().header(header::CONTENT_TYPE, "application/json"),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            "missing-if-match",
            Request::post(path)
                .header(header::AUTHORIZATION, "Bearer ratifier-token")
                .header(header::ORIGIN, "http://127.0.0.1:1")
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "decision-1"),
            StatusCode::PRECONDITION_REQUIRED,
        ),
        (
            "weak-if-match",
            base().header(header::IF_MATCH, format!("W/{etag}")),
            StatusCode::BAD_REQUEST,
        ),
        (
            "wildcard-if-match",
            base().header(header::IF_MATCH, "*"),
            StatusCode::BAD_REQUEST,
        ),
        (
            "list-if-match",
            base().header(header::IF_MATCH, format!("{etag},{etag}")),
            StatusCode::BAD_REQUEST,
        ),
        (
            "duplicate-if-match",
            base().header(header::IF_MATCH, etag),
            StatusCode::BAD_REQUEST,
        ),
        (
            "overflow-if-match",
            base().header(
                header::IF_MATCH,
                format!("\"sha256:{}:0\"", "0".repeat(256)),
            ),
            StatusCode::BAD_REQUEST,
        ),
        (
            "revision-alias-if-match",
            base().header(
                header::IF_MATCH,
                "\"sha256:0000000000000000000000000000000000000000000000000000000000000000:00\"",
            ),
            StatusCode::BAD_REQUEST,
        ),
        (
            "missing-idempotency",
            Request::post(path)
                .header(header::AUTHORIZATION, "Bearer ratifier-token")
                .header(header::ORIGIN, "http://127.0.0.1:1")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, etag),
            StatusCode::BAD_REQUEST,
        ),
        (
            "comma-idempotency",
            base().header("idempotency-key", "one,two"),
            StatusCode::BAD_REQUEST,
        ),
        (
            "duplicate-idempotency",
            base().header("idempotency-key", "decision-1"),
            StatusCode::BAD_REQUEST,
        ),
        (
            "space-idempotency",
            base().header("idempotency-key", "one two"),
            StatusCode::BAD_REQUEST,
        ),
        (
            "overflow-idempotency",
            base().header("idempotency-key", "x".repeat(129)),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        cases.push((name, builder.body(Body::from("{")).unwrap(), expected));
    }
    cases.push((
        "body-after-policy",
        base().body(Body::from("{")).unwrap(),
        StatusCode::NOT_FOUND,
    ));
    cases.push((
        "valid-missing",
        base().body(body).unwrap(),
        StatusCode::NOT_FOUND,
    ));

    for (name, request, expected) in cases {
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), expected, "{name}");
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "private, no-store",
            "{name}"
        );
        assert_eq!(
            response.headers()["x-content-type-options"],
            "nosniff",
            "{name}"
        );
        assert_eq!(
            response.headers()["referrer-policy"],
            "no-referrer",
            "{name}"
        );
        assert!(
            response
                .headers()
                .get("access-control-allow-origin")
                .is_none(),
            "{name}"
        );
    }
    gateway.shutdown().await.unwrap();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn browser_dto_etag_review_decision_stale_and_replay_contract() {
    use smesh_a2a::{
        AuthorizationAuditInput, AuthorizationDecisionEffect, LegacyTenantBinding, OwnedTaskScope,
        RatificationAuthority as _, VisibilityScope,
    };

    let fixture = Fixture::new();
    let authorization = Arc::new(AuthorizationPolicy::from_json(
        br#"{
          "schemaVersion":"smesh-authz-policy/v1","policyId":"ratification-authz","revision":1,
          "tenants":[{"id":"tenant-a","enabled":true},{"id":"tenant-b","enabled":true}],
          "accounts":[
            {"id":"ratifier","kind":"human","memberships":[{"tenantId":"tenant-a","roles":["humanRatifier"]}]},
            {"id":"ratifier-two","kind":"human","memberships":[{"tenantId":"tenant-a","roles":["humanRatifier"]}]},
            {"id":"ratifier-b","kind":"human","memberships":[{"tenantId":"tenant-b","roles":["humanRatifier"]}]},
            {"id":"viewer","kind":"human","memberships":[{"tenantId":"tenant-a","roles":["taskViewer"]}]}
          ],
          "principalBindings":[
            {"principal":{"issuer":"test:ratification","subject":"ratifier"},"accountId":"ratifier"},
            {"principal":{"issuer":"test:ratification","subject":"ratifier-two"},"accountId":"ratifier-two"},
            {"principal":{"issuer":"test:ratification","subject":"ratifier-b"},"accountId":"ratifier-b"},
            {"principal":{"issuer":"test:ratification","subject":"viewer"},"accountId":"viewer"}
          ]
        }"#,
    ).unwrap());
    let context = authorization.resolve(&principal("ratifier"), None).unwrap();
    let store = SqliteTaskStore::open_with_ratification_key_and_legacy_binding(
        &fixture.0,
        16,
        LegacyTenantBinding::new(
            context.tenant_id(),
            context.account_id(),
            context.policy_id(),
            context.policy_revision(),
            context.policy_digest(),
        )
        .unwrap(),
        zeroize::Zeroizing::new([0x52; 32]),
        false,
    )
    .await
    .unwrap();
    let scope = OwnedTaskScope::new_with_principal_and_authentication(
        context.tenant_id(),
        context.account_id(),
        context.principal_scope(),
        VisibilityScope::Tenant,
        "bearer-jwt",
    )
    .unwrap();
    let mut admission = durable_admission();
    admission.task.id = "task-http-ratification".to_owned();
    admission.task.context_id = "context-http-ratification".to_owned();
    admission.task.history = Some(vec![admission.request.message.clone()]);
    admission.original_result = a2a::SendMessageResponse::Task(admission.task.clone());
    let audit = AuthorizationAuditInput::new(
        "http-setup-audit",
        context.tenant_id(),
        context.account_id(),
        context.policy_id(),
        context.policy_revision(),
        context.policy_digest(),
        "taskCreate",
        AuthorizationDecisionEffect::Allow,
        "authorized",
        "task",
        smesh_a2a::content_digest(b"task-http-ratification"),
        Some(admission.task.id.clone()),
        admission.now,
    )
    .unwrap();
    store
        .authorize_and_admit(&scope, admission, audit)
        .await
        .unwrap();
    let lease = store
        .claim_outbox("http-worker".to_owned(), 1_700_000_010_001, 60_000)
        .await
        .unwrap()
        .unwrap();
    let initial = store.get(&lease.task_id).await.unwrap().unwrap();
    let mut approved = initial.clone();
    approved.status.state = a2a::TaskState::Completed;
    approved.status.timestamp = chrono::DateTime::from_timestamp_millis(1_700_000_010_002);
    let exact_artifact = a2a::Artifact {
        artifact_id: "http-artifact".to_owned(),
        name: Some("release.txt".to_owned()),
        description: Some("publication description".to_owned()),
        parts: vec![
            a2a::Part::text("<script>private payload</script>")
                .with_media_type("text/html")
                .with_filename("private.html"),
        ],
        metadata: Some(std::collections::HashMap::from([(
            "publication-metadata".to_owned(),
            serde_json::json!({"nested":"<img src=x onerror=alert(1)>"}),
        )])),
        extensions: Some(vec!["https://example.test/private-extension".to_owned()]),
    };
    approved.artifacts = Some(vec![exact_artifact.clone()]);
    let transcript = vec![a2a::StreamResponse::Task(initial)];
    store
        .commit_delivery_for_ratification(
            &lease,
            approved.clone(),
            a2a::SendMessageResponse::Task(approved),
            &transcript,
            AuthoritativeReviewCandidate::new(
                "release-policy",
                7,
                smesh_a2a::content_digest(b"release-policy-v7"),
                b"sealed-http-checkpoint".to_vec(),
                vec![b"http evidence".to_vec()],
                "bounded uncertainty",
            )
            .unwrap(),
            1_700_000_010_002,
        )
        .await
        .unwrap();
    let packet = store
        .ratification_packet("tenant-a", &lease.task_id)
        .await
        .unwrap()
        .unwrap();
    let task_id = lease.task_id.clone();
    let store_probe = store.clone();
    let gateway = build_authorized_durable_loopback_gateway_with_ratification_and_telemetry(
        GatewayConfig::new("http://127.0.0.1:1", "ratification-test"),
        store,
        DurableLoopbackEndpoint::new(),
        InjectedClock::new(1_700_000_020_100),
        AuthState::new(Arc::new(RouteVerifier), [31; 32]),
        Arc::clone(&authorization),
        None,
    )
    .unwrap();
    let app = gateway.router();
    let get_request = || {
        Request::get(format!("/ratification/v1/tasks/{task_id}"))
            .header(header::AUTHORIZATION, "Bearer ratifier-token")
            .body(Body::empty())
            .unwrap()
    };
    let response = app.clone().oneshot(get_request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let etag0 = response.headers()[header::ETAG]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(etag0.starts_with("\"ratification-v1:"));
    assert_eq!(etag0.len(), 82);
    assert!(!etag0.contains(&packet.packet_hash));
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["etag"], etag0);
    assert_eq!(json["phase"], "awaitingReview");
    assert_eq!(json["reviewedByCurrentActor"], false);
    assert!(json["terminalDecision"].is_null());
    let historical = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/ratification/v1/tasks/{task_id}/generations/{}",
                packet.generation
            ))
            .header(header::AUTHORIZATION, "Bearer ratifier-token")
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(historical.status(), StatusCode::OK);
    let historical_json: serde_json::Value =
        serde_json::from_slice(&historical.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(historical_json["packet"]["generation"], packet.generation);
    for (name, path, token, expected) in [
        (
            "unauthenticated",
            format!("/ratification/v1/tasks/{task_id}/generations/1"),
            None,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "role-denied",
            format!("/ratification/v1/tasks/{task_id}/generations/1"),
            Some("viewer-token"),
            StatusCode::FORBIDDEN,
        ),
        (
            "missing-task",
            "/ratification/v1/tasks/missing/generations/1".to_owned(),
            Some("ratifier-token"),
            StatusCode::NOT_FOUND,
        ),
        (
            "cross-tenant",
            format!("/ratification/v1/tasks/{task_id}/generations/1"),
            Some("ratifier-b-token"),
            StatusCode::NOT_FOUND,
        ),
        (
            "missing-generation",
            format!("/ratification/v1/tasks/{task_id}/generations/2"),
            Some("ratifier-token"),
            StatusCode::NOT_FOUND,
        ),
        (
            "generation-zero",
            format!("/ratification/v1/tasks/{task_id}/generations/0"),
            Some("ratifier-token"),
            StatusCode::BAD_REQUEST,
        ),
        (
            "generation-overflow",
            format!("/ratification/v1/tasks/{task_id}/generations/18446744073709551616"),
            Some("ratifier-token"),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let mut request = Request::get(path);
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "{name}");
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "private, no-store",
            "{name}"
        );
        assert_eq!(
            response.headers()["x-content-type-options"],
            "nosniff",
            "{name}"
        );
        assert_eq!(
            response.headers()["referrer-policy"],
            "no-referrer",
            "{name}"
        );
    }
    let malformed_body = app
        .clone()
        .oneshot(
            Request::post(format!("/ratification/v1/tasks/{task_id}/review"))
                .header(header::AUTHORIZATION, "Bearer ratifier-token")
                .header(header::ORIGIN, "http://127.0.0.1:1")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, &etag0)
                .header("idempotency-key", "malformed-body")
                .body(Body::from("{"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(malformed_body.status(), StatusCode::BAD_REQUEST);
    let other_actor = app
        .clone()
        .oneshot(
            Request::get(format!("/ratification/v1/tasks/{task_id}"))
                .header(header::AUTHORIZATION, "Bearer ratifier-two-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(other_actor.status(), StatusCode::OK);
    let other_etag = other_actor.headers()[header::ETAG].to_str().unwrap();
    assert_ne!(other_etag, etag0);
    let actor_alias = app
        .clone()
        .oneshot(
            Request::post(format!("/ratification/v1/tasks/{task_id}/review"))
                .header(header::AUTHORIZATION, "Bearer ratifier-two-token")
                .header(header::ORIGIN, "http://127.0.0.1:1")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, &etag0)
                .header("idempotency-key", "other-actor-etag")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(actor_alias.status(), StatusCode::PRECONDITION_FAILED);
    let canonical_artifact =
        serde_json::to_string(&serde_json::to_value(&exact_artifact).unwrap()).unwrap();
    assert_eq!(
        json["packet"]["artifacts"][0]["canonicalJson"],
        canonical_artifact
    );
    assert_eq!(
        json["packet"]["artifacts"][0]["digest"],
        smesh_a2a::content_digest(canonical_artifact.as_bytes())
    );
    assert_eq!(
        json["packet"]["artifactSetDigest"],
        smesh_a2a::content_digest(
            &serde_json::to_vec(&serde_json::to_value(vec![exact_artifact]).unwrap()).unwrap()
        )
    );
    for forbidden in [
        "idempotencyKey",
        "principalScope",
        "authenticationMethod",
        "authorizationPolicyId",
        "requestDigest",
        "ratificationKeyGeneration",
        "\"seal\":",
    ] {
        assert!(
            !std::str::from_utf8(&bytes).unwrap().contains(forbidden),
            "leaked {forbidden}"
        );
    }
    let review_json = serde_json::json!({
        "evidenceHashes": packet.evidence_hashes,
        "artifactHashes": packet.artifacts.iter().map(|a| a.digest.clone()).collect::<Vec<_>>(),
        "artifactManifestDigest": packet.artifact_set_digest,
        "uncertaintyAcknowledged": true
    })
    .to_string();
    let review_request = |key: &str, etag: &str| {
        Request::post(format!("/ratification/v1/tasks/{task_id}/review"))
            .header(header::AUTHORIZATION, "Bearer ratifier-token")
            .header(header::ORIGIN, "http://127.0.0.1:1")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::IF_MATCH, etag)
            .header("idempotency-key", key)
            .body(Body::from(review_json.clone()))
            .unwrap()
    };
    let reviewed = app
        .clone()
        .oneshot(review_request("review-http-1", &etag0))
        .await
        .unwrap();
    assert_eq!(reviewed.status(), StatusCode::CREATED);
    let etag1 = reviewed.headers()[header::ETAG]
        .to_str()
        .unwrap()
        .to_owned();
    let reviewed_bytes = reviewed.into_body().collect().await.unwrap().to_bytes();
    let reviewed_json: serde_json::Value = serde_json::from_slice(&reviewed_bytes).unwrap();
    assert_eq!(reviewed_json["etag"], etag1);
    assert_ne!(etag1, etag0);
    assert!(
        !std::str::from_utf8(&reviewed_bytes)
            .unwrap()
            .contains("idempotency")
    );
    let audits_before_replay = store_probe.authorization_decision_count().await.unwrap();
    for (name, unauthorized_etag) in [
        (
            "arbitrary",
            "\"ratification-v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
        ),
        ("post-mutation", etag1.as_str()),
    ] {
        let rejected = app
            .clone()
            .oneshot(review_request("review-http-1", unauthorized_etag))
            .await
            .unwrap();
        assert_eq!(
            rejected.status(),
            StatusCode::PRECONDITION_FAILED,
            "{name} ETag must not authorize review replay"
        );
    }
    assert_eq!(
        store_probe.authorization_decision_count().await.unwrap(),
        audits_before_replay,
        "rejected review preconditions must not append authorization audits"
    );
    let replay = app
        .clone()
        .oneshot(review_request("review-http-1", &etag0))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::CREATED);
    assert_eq!(replay.headers()[header::ETAG], etag1);
    assert_eq!(
        replay.into_body().collect().await.unwrap().to_bytes(),
        reviewed_bytes
    );
    assert_eq!(
        store_probe.authorization_decision_count().await.unwrap(),
        audits_before_replay + 1,
        "an exact browser replay must atomically append a fresh authorization audit"
    );
    let stale = app
        .clone()
        .oneshot(review_request("review-http-stale", &etag0))
        .await
        .unwrap();
    assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);

    let decision_request = || {
        Request::post(format!("/ratification/v1/tasks/{task_id}/decision"))
            .header(header::AUTHORIZATION, "Bearer ratifier-token")
            .header(header::ORIGIN, "http://127.0.0.1:1")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::IF_MATCH, &etag1)
            .header("idempotency-key", "decision-http-1")
            .body(Body::from(
                r#"{"decision":"amend","rationale":"exact evidence reviewed"}"#,
            ))
            .unwrap()
    };
    let decision = app.clone().oneshot(decision_request()).await.unwrap();
    assert_eq!(decision.status(), StatusCode::CREATED);
    let etag2 = decision.headers()[header::ETAG]
        .to_str()
        .unwrap()
        .to_owned();
    let decision_bytes = decision.into_body().collect().await.unwrap().to_bytes();
    assert_ne!(etag2, etag1);
    let audits_before_decision_replay = store_probe.authorization_decision_count().await.unwrap();
    for (name, unauthorized_etag) in [
        (
            "arbitrary",
            "\"ratification-v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"",
        ),
        ("post-mutation", etag2.as_str()),
    ] {
        let rejected = app
            .clone()
            .oneshot(
                Request::post(format!("/ratification/v1/tasks/{task_id}/decision"))
                    .header(header::AUTHORIZATION, "Bearer ratifier-token")
                    .header(header::ORIGIN, "http://127.0.0.1:1")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::IF_MATCH, unauthorized_etag)
                    .header("idempotency-key", "decision-http-1")
                    .body(Body::from(
                        r#"{"decision":"amend","rationale":"exact evidence reviewed"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            rejected.status(),
            StatusCode::PRECONDITION_FAILED,
            "{name} ETag must not authorize decision replay"
        );
    }
    assert_eq!(
        store_probe.authorization_decision_count().await.unwrap(),
        audits_before_decision_replay,
        "rejected decision preconditions must not append authorization audits"
    );
    let decision_replay = app.clone().oneshot(decision_request()).await.unwrap();
    assert_eq!(decision_replay.status(), StatusCode::CREATED);
    assert_eq!(decision_replay.headers()[header::ETAG], etag2);
    assert_eq!(
        decision_replay
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
        decision_bytes
    );
    assert_eq!(
        store_probe.authorization_decision_count().await.unwrap(),
        audits_before_decision_replay + 1
    );
    let changed_payload = app
        .clone()
        .oneshot(
            Request::post(format!("/ratification/v1/tasks/{task_id}/decision"))
                .header(header::AUTHORIZATION, "Bearer ratifier-token")
                .header(header::ORIGIN, "http://127.0.0.1:1")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, &etag1)
                .header("idempotency-key", "decision-http-1")
                .body(Body::from(
                    r#"{"decision":"amend","rationale":"changed semantics"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(changed_payload.status(), StatusCode::PRECONDITION_FAILED);
    let changed_key = app
        .clone()
        .oneshot(
            Request::post(format!("/ratification/v1/tasks/{task_id}/decision"))
                .header(header::AUTHORIZATION, "Bearer ratifier-token")
                .header(header::ORIGIN, "http://127.0.0.1:1")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, &etag1)
                .header("idempotency-key", "decision-http-new-key")
                .body(Body::from(
                    r#"{"decision":"amend","rationale":"exact evidence reviewed"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(changed_key.status(), StatusCode::PRECONDITION_FAILED);
    let terminal = app.clone().oneshot(get_request()).await.unwrap();
    assert_eq!(terminal.headers()[header::ETAG], etag2);
    let terminal_json: serde_json::Value =
        serde_json::from_slice(&terminal.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(terminal_json["reviewedByCurrentActor"], true);
    assert_eq!(terminal_json["terminalDecision"], "amend");
    gateway.shutdown().await.unwrap();
    drop(store_probe);
    let store_probe = SqliteTaskStore::open_with_ratification_key_and_legacy_binding(
        &fixture.0,
        16,
        LegacyTenantBinding::new(
            context.tenant_id(),
            context.account_id(),
            context.policy_id(),
            context.policy_revision(),
            context.policy_digest(),
        )
        .unwrap(),
        zeroize::Zeroizing::new([0x52; 32]),
        false,
    )
    .await
    .unwrap();

    let amendment_lease = store_probe
        .claim_outbox(
            "http-generation-two-worker".to_owned(),
            1_700_000_200_101,
            60_000,
        )
        .await
        .unwrap()
        .unwrap();
    let payload = serde_json::to_vec(&amendment_lease.request).unwrap();
    let envelope = DurableDispatchEnvelope {
        tenant_scope: amendment_lease.tenant_scope.clone(),
        dispatch_id: amendment_lease.dispatch_id.clone(),
        payload_digest: smesh_a2a::content_digest(&payload),
        request: amendment_lease.request.clone(),
        execution_reservation: amendment_lease.execution_reservation.clone(),
    };
    match store_probe
        .begin_receive(
            envelope,
            "http-generation-two-receiver",
            1_700_000_200_101,
            60_000,
        )
        .await
        .unwrap()
    {
        ReceiverAdmission::Execute(receiver) => {
            store_probe
                .complete_loopback_receive(
                    &receiver,
                    &[smesh_a2a::MeshEvent::Completed {
                        summary: "HTTP generation two candidate".to_owned(),
                    }],
                    1_700_000_200_102,
                )
                .await
                .unwrap();
        }
        ReceiverAdmission::Replay(events) => assert!(
            events
                .iter()
                .any(|event| matches!(event, smesh_a2a::MeshEvent::Completed { .. }))
        ),
        ReceiverAdmission::ReplayOutcome(outcome) => assert!(
            outcome
                .events
                .iter()
                .any(|event| { matches!(event, smesh_a2a::MeshEvent::Completed { .. }) })
        ),
        ReceiverAdmission::Busy => panic!("stopped gateway retained an active receiver lease"),
    }
    let initial_two = store_probe
        .task_for_outbox(&amendment_lease)
        .await
        .unwrap()
        .unwrap();
    let mut candidate_two = initial_two.clone();
    candidate_two.status.state = a2a::TaskState::Completed;
    candidate_two.status.timestamp = chrono::DateTime::from_timestamp_millis(1_700_000_200_102);
    candidate_two.artifacts = Some(vec![a2a::Artifact {
        artifact_id: "http-generation-two-artifact".to_owned(),
        name: Some("generation-two.txt".to_owned()),
        description: None,
        parts: vec![a2a::Part::text("HTTP generation two candidate")],
        metadata: None,
        extensions: None,
    }]);
    store_probe
        .commit_delivery_for_ratification(
            &amendment_lease,
            candidate_two.clone(),
            a2a::SendMessageResponse::Task(candidate_two),
            &[a2a::StreamResponse::Task(initial_two)],
            AuthoritativeReviewCandidate::new(
                "release-policy",
                7,
                smesh_a2a::content_digest(b"release-policy-v7"),
                b"sealed-http-checkpoint-generation-two".to_vec(),
                vec![b"http generation two evidence".to_vec()],
                "bounded uncertainty",
            )
            .unwrap(),
            1_700_000_200_102,
        )
        .await
        .unwrap();
    let generation_two = store_probe
        .ratification_view(&scope, &task_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(generation_two.packet.generation, 2);

    // Produce enough real amendment continuations to prove that HTTP replay has
    // no generation-window expiry. Every generation traverses the same durable
    // review, decision, quota/outbox, receive, and ratification commit paths.
    for generation in 2_u64..=65 {
        let view = store_probe
            .ratification_view(&scope, &task_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(view.packet.generation, generation);
        let review_at = 1_700_000_300_000 + i64::try_from(generation).unwrap() * 10;
        let mut review_command = integrated_review(
            &view.packet,
            &scope,
            &task_id,
            &format!("historical-review-{generation}"),
        );
        review_command.reviewed_at_millis = review_at;
        store_probe
            .acknowledge_ratification_review(
                &scope,
                review_command,
                integrated_audit(
                    &view.packet,
                    &scope,
                    &task_id,
                    &format!("historical-review-audit-{generation}"),
                    "ratificationReview",
                    review_at,
                ),
            )
            .await
            .unwrap();
        let decision_at = review_at + 1;
        let mut decision_command = integrated_decision(
            &view.packet,
            &scope,
            &task_id,
            &format!("historical-decision-{generation}"),
            HumanDecision::Amend,
        );
        decision_command.decided_at_millis = decision_at;
        store_probe
            .decide_ratification(
                &scope,
                decision_command,
                integrated_audit(
                    &view.packet,
                    &scope,
                    &task_id,
                    &format!("historical-decision-audit-{generation}"),
                    "ratificationDecide",
                    decision_at,
                ),
            )
            .await
            .unwrap();
        let lease = store_probe
            .claim_outbox(
                format!("historical-worker-{generation}"),
                1_700_000_300_002 + i64::try_from(generation).unwrap() * 10,
                60_000,
            )
            .await
            .unwrap()
            .unwrap();
        let payload = serde_json::to_vec(&lease.request).unwrap();
        let envelope = DurableDispatchEnvelope {
            tenant_scope: lease.tenant_scope.clone(),
            dispatch_id: lease.dispatch_id.clone(),
            payload_digest: smesh_a2a::content_digest(&payload),
            request: lease.request.clone(),
            execution_reservation: lease.execution_reservation.clone(),
        };
        let ReceiverAdmission::Execute(receiver) = store_probe
            .begin_receive(
                envelope,
                &format!("historical-receiver-{generation}"),
                1_700_000_300_002 + i64::try_from(generation).unwrap() * 10,
                60_000,
            )
            .await
            .unwrap()
        else {
            panic!("historical continuation was not executable")
        };
        store_probe
            .complete_loopback_receive(
                &receiver,
                &[smesh_a2a::MeshEvent::Completed {
                    summary: format!("generation {} candidate", generation + 1),
                }],
                1_700_000_300_003 + i64::try_from(generation).unwrap() * 10,
            )
            .await
            .unwrap();
        let initial = store_probe.task_for_outbox(&lease).await.unwrap().unwrap();
        let mut candidate = initial.clone();
        candidate.status.state = a2a::TaskState::Completed;
        candidate.status.timestamp = chrono::DateTime::from_timestamp_millis(
            1_700_000_300_003 + i64::try_from(generation).unwrap() * 10,
        );
        candidate.artifacts = Some(vec![a2a::Artifact {
            artifact_id: format!("historical-artifact-{}", generation + 1),
            name: Some(format!("generation-{}.txt", generation + 1)),
            description: None,
            parts: vec![a2a::Part::text(format!(
                "generation {} candidate",
                generation + 1
            ))],
            metadata: None,
            extensions: None,
        }]);
        store_probe
            .commit_delivery_for_ratification(
                &lease,
                candidate.clone(),
                a2a::SendMessageResponse::Task(candidate),
                &[a2a::StreamResponse::Task(initial)],
                AuthoritativeReviewCandidate::new(
                    "release-policy",
                    7,
                    smesh_a2a::content_digest(b"release-policy-v7"),
                    format!("historical-checkpoint-{}", generation + 1).into_bytes(),
                    vec![format!("generation {} evidence", generation + 1).into_bytes()],
                    "bounded uncertainty",
                )
                .unwrap(),
                1_700_000_300_003 + i64::try_from(generation).unwrap() * 10,
            )
            .await
            .unwrap();
    }
    assert_eq!(
        store_probe
            .ratification_view(&scope, &task_id)
            .await
            .unwrap()
            .unwrap()
            .packet
            .generation,
        66
    );
    let mut other_admission = durable_admission();
    other_admission.request.message.message_id = "historical-other-message".to_owned();
    other_admission.task.id = "historical-other-task".to_owned();
    other_admission.task.context_id = "historical-other-context".to_owned();
    other_admission.task.history = Some(vec![other_admission.request.message.clone()]);
    other_admission.original_result = a2a::SendMessageResponse::Task(other_admission.task.clone());
    let other_task_id = other_admission.task.id.clone();
    store_probe
        .authorize_and_admit(
            &scope,
            other_admission,
            AuthorizationAuditInput::new(
                "historical-other-admission-audit",
                context.tenant_id(),
                context.account_id(),
                context.policy_id(),
                context.policy_revision(),
                context.policy_digest(),
                "taskCreate",
                AuthorizationDecisionEffect::Allow,
                "authorized",
                "task",
                smesh_a2a::content_digest(other_task_id.as_bytes()),
                Some(other_task_id.clone()),
                1_700_000_400_000,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let other_lease = store_probe
        .claim_outbox(
            "historical-other-worker".to_owned(),
            1_700_000_400_001,
            60_000,
        )
        .await
        .unwrap()
        .unwrap();
    let other_initial = store_probe
        .task_for_outbox(&other_lease)
        .await
        .unwrap()
        .unwrap();
    let mut other_candidate = other_initial.clone();
    other_candidate.status.state = a2a::TaskState::Completed;
    other_candidate.status.timestamp = chrono::DateTime::from_timestamp_millis(1_700_000_400_002);
    other_candidate.artifacts = Some(vec![a2a::Artifact {
        artifact_id: "historical-other-artifact".to_owned(),
        name: Some("historical-other.txt".to_owned()),
        description: None,
        parts: vec![a2a::Part::text("historical other candidate")],
        metadata: None,
        extensions: None,
    }]);
    store_probe
        .commit_delivery_for_ratification(
            &other_lease,
            other_candidate.clone(),
            a2a::SendMessageResponse::Task(other_candidate),
            &[a2a::StreamResponse::Task(other_initial)],
            AuthoritativeReviewCandidate::new(
                "release-policy",
                7,
                smesh_a2a::content_digest(b"release-policy-v7"),
                b"historical-other-checkpoint".to_vec(),
                vec![b"historical other evidence".to_vec()],
                "bounded uncertainty",
            )
            .unwrap(),
            1_700_000_400_002,
        )
        .await
        .unwrap();
    let gateway = build_authorized_durable_loopback_gateway_with_ratification_and_telemetry(
        GatewayConfig::new("http://127.0.0.1:1", "ratification-test"),
        store_probe.clone(),
        DurableLoopbackEndpoint::new(),
        InjectedClock::new(1_700_000_220_100),
        AuthState::new(Arc::new(RouteVerifier), [31; 32]),
        Arc::clone(&authorization),
        None,
    )
    .unwrap();
    let app = gateway.router();
    let generation_two_latest = app.clone().oneshot(get_request()).await.unwrap();
    assert_eq!(generation_two_latest.status(), StatusCode::OK);
    let generation_two_etag = generation_two_latest.headers()[header::ETAG]
        .to_str()
        .unwrap()
        .to_owned();
    let audits_before_historical_replay = store_probe.authorization_decision_count().await.unwrap();
    let durable_before_historical_replay = store_probe.atomic_record_counts().await.unwrap();
    let workflow_before_historical_replay = store_probe
        .ratification_view(&scope, &task_id)
        .await
        .unwrap()
        .unwrap();
    for (name, unauthorized_etag) in [
        (
            "arbitrary",
            "\"ratification-v1:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"",
        ),
        ("generation-one-post-mutation", etag2.as_str()),
        ("current-generation", generation_two_etag.as_str()),
    ] {
        let rejected = app
            .clone()
            .oneshot(
                Request::post(format!("/ratification/v1/tasks/{task_id}/decision"))
                    .header(header::AUTHORIZATION, "Bearer ratifier-token")
                    .header(header::ORIGIN, "http://127.0.0.1:1")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::IF_MATCH, unauthorized_etag)
                    .header("idempotency-key", "decision-http-1")
                    .body(Body::from(
                        r#"{"decision":"amend","rationale":"exact evidence reviewed"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            rejected.status(),
            StatusCode::PRECONDITION_FAILED,
            "{name} ETag must not authorize historical decision replay"
        );
    }
    assert_eq!(
        store_probe.authorization_decision_count().await.unwrap(),
        audits_before_historical_replay,
        "rejected historical preconditions must not append authorization audits"
    );
    let historical_generation_one = app
        .clone()
        .oneshot(
            Request::get(format!("/ratification/v1/tasks/{task_id}/generations/1"))
                .header(header::AUTHORIZATION, "Bearer ratifier-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(historical_generation_one.status(), StatusCode::OK);
    assert_eq!(historical_generation_one.headers()[header::ETAG], etag2);
    let historical_replay = app.clone().oneshot(decision_request()).await.unwrap();
    assert_eq!(historical_replay.status(), StatusCode::CREATED);
    assert_eq!(historical_replay.headers()[header::ETAG], etag2);
    assert_eq!(
        historical_replay
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
        decision_bytes
    );
    assert_eq!(
        store_probe.authorization_decision_count().await.unwrap(),
        audits_before_historical_replay + 1
    );
    let changed_historical_body = app
        .clone()
        .oneshot(
            Request::post(format!("/ratification/v1/tasks/{task_id}/decision"))
                .header(header::AUTHORIZATION, "Bearer ratifier-token")
                .header(header::ORIGIN, "http://127.0.0.1:1")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, &etag1)
                .header("idempotency-key", "decision-http-1")
                .body(Body::from(
                    r#"{"decision":"amend","rationale":"changed after generation two"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        changed_historical_body.status(),
        StatusCode::PRECONDITION_FAILED
    );
    let changed_historical_key = app
        .clone()
        .oneshot(
            Request::post(format!("/ratification/v1/tasks/{task_id}/decision"))
                .header(header::AUTHORIZATION, "Bearer ratifier-token")
                .header(header::ORIGIN, "http://127.0.0.1:1")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, &etag1)
                .header("idempotency-key", "decision-http-after-generation-two")
                .body(Body::from(
                    r#"{"decision":"amend","rationale":"exact evidence reviewed"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        changed_historical_key.status(),
        StatusCode::PRECONDITION_FAILED
    );
    let cross_actor_historical = app
        .clone()
        .oneshot(
            Request::post(format!("/ratification/v1/tasks/{task_id}/decision"))
                .header(header::AUTHORIZATION, "Bearer ratifier-two-token")
                .header(header::ORIGIN, "http://127.0.0.1:1")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, &etag1)
                .header("idempotency-key", "decision-http-1")
                .body(Body::from(
                    r#"{"decision":"amend","rationale":"exact evidence reviewed"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        cross_actor_historical.status(),
        StatusCode::PRECONDITION_FAILED
    );
    let changed_action = app
        .clone()
        .oneshot(
            Request::post(format!("/ratification/v1/tasks/{task_id}/decision"))
                .header(header::AUTHORIZATION, "Bearer ratifier-token")
                .header(header::ORIGIN, "http://127.0.0.1:1")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, &etag1)
                .header("idempotency-key", "decision-http-1")
                .body(Body::from(
                    r#"{"decision":"reject","rationale":"exact evidence reviewed"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(changed_action.status(), StatusCode::PRECONDITION_FAILED);
    let changed_task = app
        .clone()
        .oneshot(
            Request::post(format!("/ratification/v1/tasks/{other_task_id}/decision"))
                .header(header::AUTHORIZATION, "Bearer ratifier-token")
                .header(header::ORIGIN, "http://127.0.0.1:1")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, &etag1)
                .header("idempotency-key", "decision-http-1")
                .body(Body::from(
                    r#"{"decision":"amend","rationale":"exact evidence reviewed"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(changed_task.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(
        store_probe.authorization_decision_count().await.unwrap(),
        audits_before_historical_replay + 1,
        "failed historical replay variants must not append authorization audits"
    );
    assert_eq!(
        store_probe.atomic_record_counts().await.unwrap(),
        durable_before_historical_replay,
        "historical replay must not mutate task/event/idempotency/outbox cardinality"
    );
    assert_eq!(
        store_probe
            .ratification_view(&scope, &task_id)
            .await
            .unwrap()
            .unwrap(),
        workflow_before_historical_replay,
        "historical replay must not mutate the current workflow"
    );
    gateway.shutdown().await.unwrap();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn authorized_durable_builder_does_not_use_the_standalone_ratification_ledger() {
    let task_fixture = Fixture::new();
    let ratification_fixture = Fixture::new();
    let ledger = RatificationLedger::open(&ratification_fixture.0, [30; 32]).unwrap();
    let _standalone_frozen = ledger.freeze_packet(packet()).unwrap();
    let authorization = AuthorizationPolicy::from_json(
        br#"{
          "schemaVersion":"smesh-authz-policy/v1","policyId":"ratification-authz","revision":1,
          "tenants":[{"id":"tenant-a","enabled":true}],
          "accounts":[
            {"id":"ratifier","kind":"human","memberships":[{"tenantId":"tenant-a","roles":["humanRatifier"]}]},
            {"id":"viewer","kind":"human","memberships":[{"tenantId":"tenant-a","roles":["taskViewer"]}]}
          ],
          "principalBindings":[
            {"principal":{"issuer":"test:ratification","subject":"ratifier"},"accountId":"ratifier"},
            {"principal":{"issuer":"test:ratification","subject":"viewer"},"accountId":"viewer"}
          ]
        }"#,
    )
    .unwrap();
    let context = authorization.resolve(&principal("ratifier"), None).unwrap();
    let store = SqliteTaskStore::open_with_ratification_key_and_legacy_binding(
        &task_fixture.0,
        16,
        smesh_a2a::LegacyTenantBinding::new(
            context.tenant_id(),
            context.account_id(),
            context.policy_id(),
            context.policy_revision(),
            context.policy_digest(),
        )
        .unwrap(),
        zeroize::Zeroizing::new([0x52; 32]),
        false,
    )
    .await
    .unwrap();
    let scope = smesh_a2a::OwnedTaskScope::new_with_principal_and_authentication(
        context.tenant_id(),
        context.account_id(),
        context.principal_scope(),
        smesh_a2a::VisibilityScope::Tenant,
        "bearer-jwt",
    )
    .unwrap();
    let mut admission = durable_admission();
    admission.task.id = "task-27".to_owned();
    admission.task.context_id = "context-27".to_owned();
    admission.task.history = Some(vec![admission.request.message.clone()]);
    admission.original_result = a2a::SendMessageResponse::Task(admission.task.clone());
    let admission_audit = smesh_a2a::AuthorizationAuditInput::new(
        "production-route-admission-audit",
        context.tenant_id(),
        context.account_id(),
        context.policy_id(),
        context.policy_revision(),
        context.policy_digest(),
        "taskCreate",
        smesh_a2a::AuthorizationDecisionEffect::Allow,
        "authorized",
        "task",
        smesh_a2a::content_digest(b"task-27"),
        Some("task-27".to_owned()),
        admission.now,
    )
    .unwrap();
    smesh_a2a::TaskAdmission::authorize_and_admit(&store, &scope, admission, admission_audit)
        .await
        .unwrap();
    let lease = store
        .claim_outbox("production-route-worker", 1_700_000_010_001, 60_000)
        .await
        .unwrap()
        .unwrap();
    let initial = store.get(&lease.task_id).await.unwrap().unwrap();
    let mut approved = initial.clone();
    approved.status.state = a2a::TaskState::Completed;
    approved.status.timestamp = chrono::DateTime::from_timestamp_millis(1_700_000_010_002);
    approved.artifacts = Some(vec![a2a::Artifact {
        artifact_id: "production-route-artifact".to_owned(),
        name: Some("release.html".to_owned()),
        description: None,
        parts: vec![a2a::Part::text("<script>alert(1)</script>")],
        metadata: None,
        extensions: None,
    }]);
    store
        .commit_delivery_for_ratification(
            &lease,
            approved.clone(),
            a2a::SendMessageResponse::Task(approved),
            &[a2a::StreamResponse::Task(initial)],
            AuthoritativeReviewCandidate::new(
                "policy-7",
                7,
                smesh_a2a::content_digest(b"policy"),
                b"checkpoint bytes".to_vec(),
                vec![b"review-evidence".to_vec()],
                "Uncertainty remains",
            )
            .unwrap(),
            1_700_000_010_002,
        )
        .await
        .unwrap();
    let frozen = store
        .ratification_packet("tenant-a", "task-27")
        .await
        .unwrap()
        .unwrap();
    let gateway = build_authorized_durable_loopback_gateway_with_ratification_and_telemetry(
        GatewayConfig::new("http://127.0.0.1:1", "ratification-test"),
        store,
        DurableLoopbackEndpoint::new(),
        InjectedClock::new(1_700_000_020_100),
        AuthState::new(Arc::new(RouteVerifier), [31; 32]),
        Arc::new(authorization),
        None,
    )
    .unwrap();
    let app = gateway.router();

    let console = app
        .clone()
        .oneshot(
            Request::get("/ratification/console")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(console.status(), StatusCode::OK);
    assert_eq!(
        console.headers()[header::CONTENT_SECURITY_POLICY],
        "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; img-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    );
    let console_body = console.into_body().collect().await.unwrap().to_bytes();
    let console_body = std::str::from_utf8(&console_body).unwrap();
    assert!(console_body.contains("Human Ratification"));
    assert!(console_body.contains("id=\"review-submit\""));
    assert!(!console_body.contains(&frozen.checkpoint_hash));
    assert!(!console_body.contains("<script>alert(1)</script>"));

    let script = app
        .clone()
        .oneshot(
            Request::get("/ratification/console.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(script.status(), StatusCode::OK);
    let script_body = script.into_body().collect().await.unwrap().to_bytes();
    let script_body = std::str::from_utf8(&script_body).unwrap();
    assert!(script_body.contains("textContent"));
    assert!(!script_body.contains("innerHTML"));

    let unauthenticated = app
        .clone()
        .oneshot(
            Request::get("/ratification/v1/tasks/task-27")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    let unauthorized = app
        .clone()
        .oneshot(
            Request::get("/ratification/v1/tasks/task-27")
                .header(header::AUTHORIZATION, "Bearer viewer-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::FORBIDDEN);
    let review_page = app
        .clone()
        .oneshot(
            Request::get("/ratification/v1/tasks/task-27")
                .header(header::AUTHORIZATION, "Bearer ratifier-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(review_page.status(), StatusCode::OK);
    assert_eq!(
        review_page.headers()[header::CACHE_CONTROL],
        "private, no-store"
    );
    let etag0 = review_page.headers()[header::ETAG]
        .to_str()
        .unwrap()
        .to_owned();
    let review_json: serde_json::Value =
        serde_json::from_slice(&review_page.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(
        review_json["packet"]["uncertaintySummary"],
        frozen.uncertainty_summary
    );
    assert_eq!(
        review_json["packet"]["checkpointHash"],
        frozen.checkpoint_hash
    );
    assert_eq!(
        review_json["packet"]["evidenceHashes"][0],
        frozen.evidence_hashes[0]
    );

    let review_body = serde_json::json!({
        "evidenceHashes": frozen.evidence_hashes,
        "artifactHashes": frozen.artifacts.iter().map(|item| item.digest.clone()).collect::<Vec<_>>(),
        "artifactManifestDigest": frozen.artifact_set_digest,
        "uncertaintyAcknowledged": true
    });
    let cross_origin = app
        .clone()
        .oneshot(
            Request::post("/ratification/v1/tasks/task-27/review")
                .header(header::AUTHORIZATION, "Bearer ratifier-token")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "https://attacker.example")
                .header(header::IF_MATCH, &etag0)
                .header("idempotency-key", "wire-review-cross-origin")
                .body(Body::from(review_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cross_origin.status(), StatusCode::FORBIDDEN);
    let fresh_review_page = app
        .clone()
        .oneshot(
            Request::get("/ratification/v1/tasks/task-27")
                .header(header::AUTHORIZATION, "Bearer ratifier-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(fresh_review_page.status(), StatusCode::OK);
    let etag0 = fresh_review_page.headers()[header::ETAG]
        .to_str()
        .unwrap()
        .to_owned();
    let reviewed = app
        .clone()
        .oneshot(
            Request::post("/ratification/v1/tasks/task-27/review")
                .header(header::AUTHORIZATION, "Bearer ratifier-token")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "http://127.0.0.1:1")
                .header(header::IF_MATCH, &etag0)
                .header("idempotency-key", "wire-review-1")
                .body(Body::from(review_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reviewed.status(), StatusCode::CREATED);
    let etag1 = reviewed.headers()[header::ETAG]
        .to_str()
        .unwrap()
        .to_owned();
    let first_review = reviewed.into_body().collect().await.unwrap().to_bytes();
    let review_replay = app
        .clone()
        .oneshot(
            Request::post("/ratification/v1/tasks/task-27/review")
                .header(header::AUTHORIZATION, "Bearer ratifier-token")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "http://127.0.0.1:1")
                .header(header::IF_MATCH, &etag0)
                .header("idempotency-key", "wire-review-1")
                .body(Body::from(review_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(review_replay.status(), StatusCode::CREATED);
    assert_eq!(review_replay.headers()[header::ETAG], etag1);
    assert_eq!(
        review_replay
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
        first_review
    );
    let stale = app
        .clone()
        .oneshot(
            Request::post("/ratification/v1/tasks/task-27/review")
                .header(header::AUTHORIZATION, "Bearer ratifier-token")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "http://127.0.0.1:1")
                .header(header::IF_MATCH, &etag0)
                .header("idempotency-key", "wire-review-stale")
                .body(Body::from(review_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);
    let decision = app
        .oneshot(
            Request::post("/ratification/v1/tasks/task-27/decision")
                .header(header::AUTHORIZATION, "Bearer ratifier-token")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "http://127.0.0.1:1")
                .header(header::IF_MATCH, &etag1)
                .header("idempotency-key", "wire-decision-1")
                .body(Body::from(
                    serde_json::json!({
                        "decision":"approve",
                        "rationale":"Reviewed exact evidence and artifacts."
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(decision.status(), StatusCode::CREATED);
    let etag2 = decision.headers()[header::ETAG]
        .to_str()
        .unwrap()
        .to_owned();
    let receipt: serde_json::Value =
        serde_json::from_slice(&decision.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(receipt["revision"], 2);
    assert_eq!(receipt["etag"], etag2);
    assert_eq!(receipt["action"]["decision"], "approve");
    gateway.shutdown().await.unwrap();
}

#[test]
fn decision_requires_the_same_actor_and_exact_replay_is_byte_identical() {
    let fixture = Fixture::new();
    let ledger = RatificationLedger::open(&fixture.0, [61; 32]).unwrap();
    let frozen = ledger.freeze_packet(packet()).unwrap();
    ledger
        .acknowledge_review(ReviewAcknowledgement {
            tenant_id: frozen.tenant_id.clone(),
            task_id: frozen.task_id.clone(),
            account_id: "ratifier".to_owned(),
            generation: frozen.generation,
            authorization_policy_id: frozen.authorization_policy_id.clone(),
            authorization_policy_revision: frozen.authorization_policy_revision,
            authorization_policy_digest: frozen.authorization_policy_digest.clone(),
            principal_scope: frozen.principal_scope.clone(),
            authentication_method: frozen.authentication_method.clone(),
            context_id: frozen.context_id.clone(),
            request_digest: frozen.request_digest.clone(),
            ratification_key_generation: frozen.ratification_key_generation.clone(),
            expected_revision: 0,
            checkpoint_hash: frozen.checkpoint_hash.clone(),
            packet_hash: frozen.packet_hash.clone(),
            evidence_hashes: frozen.evidence_hashes.clone(),
            artifact_hashes: frozen.artifacts.iter().map(|a| a.digest.clone()).collect(),
            artifact_manifest_digest: frozen.artifact_set_digest.clone(),
            uncertainty_acknowledged: true,
            idempotency_key: "same-actor-review".to_owned(),
            reviewed_at_millis: 1_700_000_000_100,
        })
        .unwrap();
    let command = RatificationCommand {
        tenant_id: frozen.tenant_id.clone(),
        task_id: frozen.task_id.clone(),
        account_id: "ratifier".to_owned(),
        generation: frozen.generation,
        authorization_policy_id: frozen.authorization_policy_id.clone(),
        authorization_policy_revision: frozen.authorization_policy_revision,
        authorization_policy_digest: frozen.authorization_policy_digest.clone(),
        principal_scope: frozen.principal_scope.clone(),
        authentication_method: frozen.authentication_method.clone(),
        context_id: frozen.context_id.clone(),
        request_digest: frozen.request_digest.clone(),
        ratification_key_generation: frozen.ratification_key_generation.clone(),
        expected_revision: 1,
        checkpoint_hash: frozen.checkpoint_hash.clone(),
        packet_hash: frozen.packet_hash.clone(),
        artifact_manifest_digest: frozen.artifact_set_digest.clone(),
        idempotency_key: "same-actor-decision".to_owned(),
        decision: HumanDecision::Approve,
        rationale: "Exact candidate approved.".to_owned(),
        decided_at_millis: 1_700_000_000_101,
    };
    assert_eq!(
        ledger
            .decide(RatificationCommand {
                account_id: "other-ratifier".to_owned(),
                idempotency_key: "other-actor-decision".to_owned(),
                ..command.clone()
            })
            .unwrap_err(),
        RatificationError::ReviewRequired
    );
    let first = ledger.decide(command.clone()).unwrap();
    let replay = ledger
        .decide(RatificationCommand {
            decided_at_millis: command.decided_at_millis + 9_999,
            ..command
        })
        .unwrap();
    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&replay).unwrap()
    );
}

#[test]
fn standalone_open_binds_key_and_rejects_malformed_schema() {
    let fixture = Fixture::new();
    drop(RatificationLedger::open(&fixture.0, [80; 32]).unwrap());
    let Err(error) = RatificationLedger::open(&fixture.0, [81; 32]) else {
        panic!("standalone ledger accepted the wrong key")
    };
    assert_eq!(error, RatificationError::Integrity);

    let malformed = Fixture::new();
    let connection = rusqlite::Connection::open(&malformed.0).unwrap();
    connection
        .execute_batch("CREATE TABLE ratification_packets(tenant_id TEXT);")
        .unwrap();
    drop(connection);
    let Err(error) = RatificationLedger::open(&malformed.0, [82; 32]) else {
        panic!("standalone ledger accepted a malformed schema")
    };
    assert_eq!(error, RatificationError::Integrity);
}

#[test]
fn standalone_total_schema_deletion_with_ledger_markers_fails_integrity() {
    let fixture = Fixture::new();
    drop(RatificationLedger::open(&fixture.0, [0x83; 32]).unwrap());
    let connection = rusqlite::Connection::open(&fixture.0).unwrap();
    let application_id: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .unwrap();
    let user_version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    let objects = {
        let mut statement = connection
            .prepare(
                "SELECT type,name FROM sqlite_master
                 WHERE name NOT LIKE 'sqlite_%'
                 ORDER BY CASE type WHEN 'trigger' THEN 0 WHEN 'index' THEN 1
                                    WHEN 'view' THEN 2 ELSE 3 END",
            )
            .unwrap();
        statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    for (kind, name) in objects {
        connection
            .execute_batch(&format!(
                "DROP {} IF EXISTS \"{}\";",
                kind.to_ascii_uppercase(),
                name.replace('"', "\"\"")
            ))
            .unwrap();
    }
    assert_eq!(
        connection
            .pragma_query_value(None, "application_id", |row| row.get::<_, i64>(0))
            .unwrap(),
        application_id
    );
    assert_eq!(
        connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        user_version
    );
    drop(connection);

    let Err(error) = RatificationLedger::open(&fixture.0, [0x83; 32]) else {
        panic!("standalone ledger recreated a previously initialized deleted schema")
    };
    assert_eq!(error, RatificationError::Integrity);
}

#[test]
fn standalone_generations_require_authenticated_contiguous_amendments_and_survive_restart() {
    let fixture = Fixture::new();
    let ledger = RatificationLedger::open(&fixture.0, [85; 32]).unwrap();
    let first = ledger.freeze_packet(packet()).unwrap();

    let mut premature = packet();
    premature.generation = 2;
    premature.task_revision += 1;
    premature.checkpoint = "generation two".to_owned();
    premature.checkpoint_hash = smesh_a2a::content_digest(premature.checkpoint.as_bytes());
    assert_eq!(
        ledger.freeze_packet(premature.clone()).unwrap_err(),
        RatificationError::Conflict
    );
    let mut gap = premature.clone();
    gap.generation = 3;
    assert_eq!(
        ledger.freeze_packet(gap).unwrap_err(),
        RatificationError::Conflict
    );

    ledger
        .acknowledge_review(standalone_review(&first, "generation-one-review"))
        .unwrap();
    let mut amend = standalone_decision(&first, "generation-one-amend");
    amend.decision = HumanDecision::Amend;
    ledger.decide(amend).unwrap();
    let second = ledger.freeze_packet(premature).unwrap();
    ledger
        .acknowledge_review(standalone_review(&second, "generation-two-review"))
        .unwrap();
    assert_eq!(
        ledger.packet("tenant-a", "task-27").unwrap(),
        Some(second.clone())
    );
    assert_eq!(
        ledger
            .packet_at_generation("tenant-a", "task-27", 1)
            .unwrap(),
        Some(first.clone())
    );
    assert_eq!(
        ledger
            .history_at_generation("tenant-a", "task-27", 1)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(ledger.history("tenant-a", "task-27").unwrap().len(), 1);
    drop(ledger);

    let reopened = RatificationLedger::open(&fixture.0, [85; 32]).unwrap();
    assert_eq!(
        reopened.packet("tenant-a", "task-27").unwrap(),
        Some(second)
    );
    assert_eq!(reopened.history("tenant-a", "task-27").unwrap().len(), 1);
}

#[test]
fn standalone_global_anchor_rejects_whole_reset_and_deleted_generation() {
    for delete_sql in [
        "DELETE FROM ratification_heads; DELETE FROM ratification_events; DELETE FROM ratification_roots; DELETE FROM ratification_packets;",
        "DELETE FROM ratification_heads WHERE generation=1; DELETE FROM ratification_events WHERE generation=1; DELETE FROM ratification_roots WHERE generation=1; DELETE FROM ratification_packets WHERE generation=1;",
        "DELETE FROM ratification_heads; DELETE FROM ratification_events; DELETE FROM ratification_roots; DELETE FROM ratification_packets; DELETE FROM ratification_metadata;",
    ] {
        let fixture = Fixture::new();
        let ledger = RatificationLedger::open(&fixture.0, [86; 32]).unwrap();
        let first = ledger.freeze_packet(packet()).unwrap();
        ledger
            .acknowledge_review(standalone_review(&first, "anchor-review"))
            .unwrap();
        let mut amend = standalone_decision(&first, "anchor-amend");
        amend.decision = HumanDecision::Amend;
        ledger.decide(amend).unwrap();
        let mut next = packet();
        next.generation = 2;
        next.task_revision += 1;
        next.checkpoint = "next generation".to_owned();
        next.checkpoint_hash = smesh_a2a::content_digest(next.checkpoint.as_bytes());
        ledger.freeze_packet(next).unwrap();
        let connection = rusqlite::Connection::open(&fixture.0).unwrap();
        connection.execute_batch("PRAGMA foreign_keys=OFF; DROP TRIGGER ratification_metadata_no_delete; DROP TRIGGER ratification_heads_no_delete; DROP TRIGGER ratification_events_no_delete; DROP TRIGGER ratification_roots_no_delete; DROP TRIGGER ratification_packets_no_delete;").unwrap();
        connection.execute_batch(delete_sql).unwrap();
        drop(connection);
        assert_eq!(
            ledger.packet("tenant-a", "task-27").unwrap_err(),
            RatificationError::Integrity
        );
        drop(ledger);
        let Err(error) = RatificationLedger::open(&fixture.0, [86; 32]) else {
            panic!("standalone ledger reopened after authenticated rows were deleted")
        };
        assert_eq!(error, RatificationError::Integrity);
    }
}

#[test]
fn standalone_foreign_key_and_accounting_tampering_fail_closed() {
    for sql in [
        "PRAGMA foreign_keys=OFF; DROP TRIGGER ratification_events_no_update; UPDATE ratification_events SET task_id='orphan';",
        "DROP TRIGGER ratification_metadata_identity; UPDATE ratification_metadata SET retained_bytes=retained_bytes+1;",
    ] {
        let fixture = Fixture::new();
        let ledger = RatificationLedger::open(&fixture.0, [88; 32]).unwrap();
        let frozen = ledger.freeze_packet(packet()).unwrap();
        ledger
            .acknowledge_review(standalone_review(&frozen, "integrity-review"))
            .unwrap();
        let connection = rusqlite::Connection::open(&fixture.0).unwrap();
        connection.execute_batch(sql).unwrap();
        drop(connection);
        assert_eq!(
            ledger.history("tenant-a", "task-27").unwrap_err(),
            RatificationError::Integrity
        );
    }
}

#[test]
fn standalone_corrupt_idempotency_owner_chain_rejects_without_mutation() {
    let fixture = Fixture::new();
    let ledger = RatificationLedger::open(&fixture.0, [89; 32]).unwrap();
    let owner = ledger.freeze_packet(packet()).unwrap();
    ledger
        .acknowledge_review(standalone_review(&owner, "shared-owner-key"))
        .unwrap();
    let mut other_input = packet();
    other_input.task_id = "task-other".to_owned();
    other_input.context_id = "context-other".to_owned();
    let other = ledger.freeze_packet(other_input).unwrap();
    let connection = rusqlite::Connection::open(&fixture.0).unwrap();
    connection.execute_batch("PRAGMA foreign_keys=OFF; DROP TRIGGER ratification_events_no_update; UPDATE ratification_events SET event_hash='sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' WHERE task_id='task-27';").unwrap();
    let before: i64 = connection
        .query_row("SELECT count(*) FROM ratification_events", [], |row| {
            row.get(0)
        })
        .unwrap();
    drop(connection);
    assert_eq!(
        ledger
            .acknowledge_review(standalone_review(&other, "shared-owner-key"))
            .unwrap_err(),
        RatificationError::Integrity
    );
    let connection = rusqlite::Connection::open(&fixture.0).unwrap();
    let after: i64 = connection
        .query_row("SELECT count(*) FROM ratification_events", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(after, before);
}

#[test]
fn standalone_locator_tampering_is_integrity_and_mutation_free() {
    let fixture = Fixture::new();
    let ledger = RatificationLedger::open(&fixture.0, [87; 32]).unwrap();
    let frozen = ledger.freeze_packet(packet()).unwrap();
    let review = standalone_review(&frozen, "locator-review");
    ledger.acknowledge_review(review.clone()).unwrap();
    let connection = rusqlite::Connection::open(&fixture.0).unwrap();
    connection.execute_batch("PRAGMA foreign_keys=OFF; DROP TRIGGER ratification_events_no_update; UPDATE ratification_events SET account_id='other-account';").unwrap();
    let before: i64 = connection
        .query_row("SELECT count(*) FROM ratification_events", [], |row| {
            row.get(0)
        })
        .unwrap();
    drop(connection);
    assert_eq!(
        ledger.acknowledge_review(review).unwrap_err(),
        RatificationError::Integrity
    );
    let connection = rusqlite::Connection::open(&fixture.0).unwrap();
    let after: i64 = connection
        .query_row("SELECT count(*) FROM ratification_events", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(after, before);
}

#[test]
fn standalone_schema_prevents_packet_event_head_and_root_rewrite() {
    let fixture = Fixture::new();
    let ledger = RatificationLedger::open(&fixture.0, [83; 32]).unwrap();
    let frozen = ledger.freeze_packet(packet()).unwrap();
    ledger
        .acknowledge_review(standalone_review(&frozen, "append-only-review"))
        .unwrap();
    drop(ledger);
    let connection = rusqlite::Connection::open(&fixture.0).unwrap();
    for statement in [
        "UPDATE ratification_packets SET packet_hash='x'",
        "DELETE FROM ratification_packets",
        "UPDATE ratification_events SET event_kind='decision'",
        "DELETE FROM ratification_events",
        "UPDATE ratification_heads SET revision=99",
        "DELETE FROM ratification_heads",
        "DELETE FROM ratification_roots",
        "DELETE FROM ratification_metadata",
    ] {
        assert!(connection.execute(statement, []).is_err(), "{statement}");
    }
}

#[test]
fn standalone_replay_authenticates_packet_chain_and_head_in_transaction() {
    let fixture = Fixture::new();
    let ledger = RatificationLedger::open(&fixture.0, [84; 32]).unwrap();
    let frozen = ledger.freeze_packet(packet()).unwrap();
    let review = standalone_review(&frozen, "authenticated-replay");
    ledger.acknowledge_review(review.clone()).unwrap();
    let connection = rusqlite::Connection::open(&fixture.0).unwrap();
    connection
        .execute_batch(
            "DROP TRIGGER ratification_heads_no_delete;
             DELETE FROM ratification_heads;",
        )
        .unwrap();
    drop(connection);
    assert_eq!(
        ledger.acknowledge_review(review.clone()).unwrap_err(),
        RatificationError::Integrity
    );
    let mut conflict = review;
    conflict.reviewed_at_millis += 1;
    assert_eq!(
        ledger.acknowledge_review(conflict).unwrap_err(),
        RatificationError::Integrity
    );
    drop(ledger);
    let Err(error) = RatificationLedger::open(&fixture.0, [84; 32]) else {
        panic!("standalone ledger reopened without an authenticated head")
    };
    assert_eq!(error, RatificationError::Integrity);
}

#[test]
#[allow(clippy::too_many_lines)] // The paired live-read and restart tamper matrix stays explicit.
fn packet_revision_tampering_and_receipt_tail_deletion_fail_closed() {
    let packet_fixture = Fixture::new();
    let ledger = RatificationLedger::open(&packet_fixture.0, [62; 32]).unwrap();
    ledger.freeze_packet(packet()).unwrap();
    let connection = rusqlite::Connection::open(&packet_fixture.0).unwrap();
    let bytes: Vec<u8> = connection
        .query_row("SELECT packet_json FROM ratification_packets", [], |row| {
            row.get(0)
        })
        .unwrap();
    let mut json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    json["revision"] = serde_json::json!(99);
    connection
        .execute_batch("DROP TRIGGER ratification_packets_no_update;")
        .unwrap();
    connection
        .execute(
            "UPDATE ratification_packets SET packet_json=?1",
            [serde_json::to_vec(&json).unwrap()],
        )
        .unwrap();
    drop(connection);
    assert_eq!(
        ledger.packet("tenant-a", "task-27").unwrap_err(),
        RatificationError::Integrity
    );
    drop(ledger);
    let Err(error) = RatificationLedger::open(&packet_fixture.0, [62; 32]) else {
        panic!("standalone ledger reopened with a corrupt packet revision")
    };
    assert_eq!(error, RatificationError::Integrity);

    let tail_fixture = Fixture::new();
    let ledger = RatificationLedger::open(&tail_fixture.0, [63; 32]).unwrap();
    let frozen = ledger.freeze_packet(packet()).unwrap();
    ledger
        .acknowledge_review(ReviewAcknowledgement {
            tenant_id: frozen.tenant_id.clone(),
            task_id: frozen.task_id.clone(),
            account_id: "ratifier".to_owned(),
            generation: frozen.generation,
            authorization_policy_id: frozen.authorization_policy_id.clone(),
            authorization_policy_revision: frozen.authorization_policy_revision,
            authorization_policy_digest: frozen.authorization_policy_digest.clone(),
            principal_scope: frozen.principal_scope.clone(),
            authentication_method: frozen.authentication_method.clone(),
            context_id: frozen.context_id.clone(),
            request_digest: frozen.request_digest.clone(),
            ratification_key_generation: frozen.ratification_key_generation.clone(),
            expected_revision: 0,
            checkpoint_hash: frozen.checkpoint_hash.clone(),
            packet_hash: frozen.packet_hash.clone(),
            evidence_hashes: frozen.evidence_hashes.clone(),
            artifact_hashes: frozen.artifacts.iter().map(|a| a.digest.clone()).collect(),
            artifact_manifest_digest: frozen.artifact_set_digest.clone(),
            uncertainty_acknowledged: true,
            idempotency_key: "tail-review".to_owned(),
            reviewed_at_millis: 1_700_000_000_200,
        })
        .unwrap();
    ledger
        .decide(RatificationCommand {
            tenant_id: frozen.tenant_id.clone(),
            task_id: frozen.task_id.clone(),
            account_id: "ratifier".to_owned(),
            generation: frozen.generation,
            authorization_policy_id: frozen.authorization_policy_id.clone(),
            authorization_policy_revision: frozen.authorization_policy_revision,
            authorization_policy_digest: frozen.authorization_policy_digest.clone(),
            principal_scope: frozen.principal_scope.clone(),
            authentication_method: frozen.authentication_method.clone(),
            context_id: frozen.context_id.clone(),
            request_digest: frozen.request_digest.clone(),
            ratification_key_generation: frozen.ratification_key_generation.clone(),
            expected_revision: 1,
            checkpoint_hash: frozen.checkpoint_hash.clone(),
            packet_hash: frozen.packet_hash.clone(),
            artifact_manifest_digest: frozen.artifact_set_digest.clone(),
            idempotency_key: "tail-decision".to_owned(),
            decision: HumanDecision::Reject,
            rationale: "Rejected.".to_owned(),
            decided_at_millis: 1_700_000_000_201,
        })
        .unwrap();
    let connection = rusqlite::Connection::open(&tail_fixture.0).unwrap();
    connection
        .execute_batch(
            "PRAGMA foreign_keys=OFF;
             DROP TRIGGER ratification_events_no_delete;",
        )
        .unwrap();
    connection
        .execute("DELETE FROM ratification_events WHERE revision=2", [])
        .unwrap();
    drop(connection);
    assert_eq!(
        ledger.history("tenant-a", "task-27").unwrap_err(),
        RatificationError::Integrity
    );
    drop(ledger);
    let Err(error) = RatificationLedger::open(&tail_fixture.0, [63; 32]) else {
        panic!("standalone ledger reopened without its receipt tail")
    };
    assert_eq!(error, RatificationError::Integrity);
}

fn durable_admission() -> smesh_a2a::SendMessageAdmission {
    let mut message = a2a::Message::new(a2a::Role::User, vec![a2a::Part::text("build release")]);
    "ratification-message".clone_into(&mut message.message_id);
    let request = a2a::SendMessageRequest {
        message: message.clone(),
        configuration: None,
        metadata: None,
        tenant: None,
    };
    let task = a2a::Task {
        id: "task-authoritative-ratification".to_owned(),
        context_id: "context-authoritative-ratification".to_owned(),
        status: a2a::TaskStatus {
            state: a2a::TaskState::Submitted,
            message: None,
            timestamp: chrono::DateTime::from_timestamp_millis(1_700_000_010_000),
        },
        artifacts: None,
        history: Some(vec![message]),
        metadata: None,
    };
    smesh_a2a::SendMessageAdmission {
        request,
        streaming: false,
        task: task.clone(),
        original_result: a2a::SendMessageResponse::Task(task),
        input_limits: smesh_a2a::InputLimits::default(),
        now: 1_700_000_010_000,
        max_attempts: 8,
    }
}

#[tokio::test]
async fn unkeyed_sqlite_store_does_not_expose_ratification_authority() {
    let fixture = Fixture::new();
    let store = SqliteTaskStore::open(&fixture.0, 16).await.unwrap();
    assert!(store.ratification_authority().is_none());
    let admission = durable_admission();
    let task_id = admission.task.id.clone();
    store.admit_send_message(admission).await.unwrap();
    let lease = store
        .claim_outbox(
            "unkeyed-ratification-worker".to_owned(),
            1_700_000_010_001,
            60_000,
        )
        .await
        .unwrap()
        .unwrap();
    let mut task = store.get(&task_id).await.unwrap().unwrap();
    task.status.state = a2a::TaskState::Completed;
    let result = a2a::SendMessageResponse::Task(task.clone());
    let candidate = AuthoritativeReviewCandidate::new(
        "release-policy",
        7,
        smesh_a2a::content_digest(b"release-policy-v7"),
        b"sealed-checkpoint-v7".to_vec(),
        vec![b"review evidence: tests passed".to_vec()],
        "bounded uncertainty",
    )
    .unwrap();
    let error = store
        .commit_delivery_for_ratification(&lease, task, result, &[], candidate, 1_700_000_010_002)
        .await
        .unwrap_err();
    assert_eq!(error.message, "ratification is not enabled");

    let authorization = AuthorizationPolicy::from_json(
        br#"{
          "schemaVersion":"smesh-authz-policy/v1","policyId":"ratification-authz","revision":1,
          "tenants":[{"id":"tenant-a","enabled":true}],
          "accounts":[{"id":"ratifier","kind":"human","memberships":[{"tenantId":"tenant-a","roles":["humanRatifier"]}]}],
          "principalBindings":[{"principal":{"issuer":"test:ratification","subject":"ratifier"},"accountId":"ratifier"}]
        }"#,
    )
    .unwrap();
    assert!(
        build_authorized_durable_loopback_gateway_with_ratification_and_telemetry(
            GatewayConfig::new("http://127.0.0.1:1", "ratification-test"),
            store,
            DurableLoopbackEndpoint::new(),
            InjectedClock::new(1_700_000_010_003),
            AuthState::new(Arc::new(RouteVerifier), [31; 32]),
            Arc::new(authorization),
            None,
        )
        .is_err()
    );
}

#[tokio::test]
async fn external_ratification_key_binds_even_an_empty_authority() {
    let fixture = Fixture::new();
    let store = SqliteTaskStore::open_with_ratification_key(
        &fixture.0,
        16,
        zeroize::Zeroizing::new([0x41; 32]),
        false,
    )
    .await
    .unwrap();
    assert!(store.ratification_authority().is_some());
    drop(store);

    assert!(
        SqliteTaskStore::open_with_ratification_key(
            &fixture.0,
            16,
            zeroize::Zeroizing::new([0x42; 32]),
            false,
        )
        .await
        .is_err()
    );
    SqliteTaskStore::open_with_ratification_key(
        &fixture.0,
        16,
        zeroize::Zeroizing::new([0x41; 32]),
        false,
    )
    .await
    .unwrap();
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Full private/public handoff is asserted in one scenario.
async fn sqlite_authority_atomically_freezes_delivery_and_suppresses_candidate_artifacts() {
    let fixture = Fixture::new();
    let store = SqliteTaskStore::open_with_ratification_key(
        &fixture.0,
        16,
        zeroize::Zeroizing::new([0x52; 32]),
        false,
    )
    .await
    .unwrap();
    let admission = durable_admission();
    let task_id = admission.task.id.clone();
    store.admit_send_message(admission).await.unwrap();
    let lease = store
        .claim_outbox("ratification-worker".to_owned(), 1_700_000_010_001, 60_000)
        .await
        .unwrap()
        .unwrap();
    let initial = store.get(&task_id).await.unwrap().unwrap();
    let mut candidate_task = initial.clone();
    candidate_task.status = a2a::TaskStatus {
        state: a2a::TaskState::Completed,
        message: Some(a2a::Message::new(
            a2a::Role::Agent,
            vec![a2a::Part::text("ready")],
        )),
        timestamp: chrono::DateTime::from_timestamp_millis(1_700_000_010_002),
    };
    candidate_task.artifacts = Some(vec![a2a::Artifact {
        artifact_id: "artifact-ratified".to_owned(),
        name: Some("release.txt".to_owned()),
        description: None,
        parts: vec![a2a::Part::text("<script>untrusted candidate</script>")],
        metadata: None,
        extensions: None,
    }]);
    let transcript = vec![
        a2a::StreamResponse::Task(initial),
        a2a::StreamResponse::StatusUpdate(a2a::TaskStatusUpdateEvent {
            task_id: candidate_task.id.clone(),
            context_id: candidate_task.context_id.clone(),
            status: candidate_task.status.clone(),
            metadata: None,
        }),
    ];
    let candidate = AuthoritativeReviewCandidate::new(
        "release-policy",
        7,
        smesh_a2a::content_digest(b"release-policy-v7"),
        b"sealed-checkpoint-v7".to_vec(),
        vec![b"review evidence: tests passed".to_vec()],
        "model confidence remains bounded",
    )
    .unwrap();
    assert_eq!(
        store
            .commit_delivery_for_ratification(
                &lease,
                candidate_task.clone(),
                a2a::SendMessageResponse::Task(candidate_task),
                &transcript,
                candidate,
                1_700_000_010_002,
            )
            .await
            .unwrap(),
        smesh_a2a::TransitionOutcome::Applied
    );
    let awaiting = store.get(&task_id).await.unwrap().unwrap();
    assert_eq!(awaiting.status.state, a2a::TaskState::InputRequired);
    assert!(awaiting.artifacts.is_none());
    let packet = store
        .ratification_packet(smesh_a2a::TRUSTED_SINGLE_TENANT_SCOPE, &task_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(packet.task_revision, 2);
    assert_eq!(packet.generation, 1);
    assert_eq!(packet.authorization_policy_id, "smesh-dev-only-policy");
    assert_eq!(packet.authorization_policy_revision, 1);
    assert_eq!(
        packet.authorization_policy_digest,
        smesh_a2a::content_digest(b"smesh-dev-only-policy/v1")
    );
    assert_eq!(packet.principal_scope, "smesh-dev-only-account");
    assert_eq!(packet.authentication_method, "trusted-local");
    assert_eq!(packet.context_id, "context-authoritative-ratification");
    assert_eq!(
        packet.request_digest,
        smesh_a2a::canonical_send_message_digest(&durable_admission().request, false).unwrap()
    );
    assert_eq!(packet.ratification_key_generation.len(), 71);
    assert_eq!(packet.evidence, ["review evidence: tests passed"]);
    assert!(
        serde_json::to_string(&packet)
            .unwrap()
            .contains("untrusted candidate")
    );
    assert!(
        !serde_json::to_string(&awaiting)
            .unwrap()
            .contains("untrusted candidate")
    );
}

#[allow(clippy::too_many_lines)]
async fn integrated_ratification_fixture(
    suffix: u64,
) -> (
    Fixture,
    SqliteTaskStore,
    String,
    a2a::Task,
    smesh_a2a::OwnedTaskScope,
    smesh_a2a::ReviewPacket,
) {
    use smesh_a2a::{OwnedTaskScope, RatificationAuthority as _, VisibilityScope};
    let fixture = Fixture::new();
    let store = SqliteTaskStore::open_with_ratification_key(
        &fixture.0,
        16,
        zeroize::Zeroizing::new([0x52; 32]),
        false,
    )
    .await
    .unwrap();
    let mut admission = durable_admission();
    admission.request.message.message_id = format!("ratification-message-{suffix}");
    admission.task.id = format!("task-authoritative-ratification-{suffix}");
    admission.task.context_id = format!("context-authoritative-ratification-{suffix}");
    admission.task.history = Some(vec![admission.request.message.clone()]);
    admission.original_result = a2a::SendMessageResponse::Task(admission.task.clone());
    let task_id = admission.task.id.clone();
    let scope = OwnedTaskScope::new_with_principal_and_authentication(
        smesh_a2a::TRUSTED_SINGLE_TENANT_SCOPE,
        "smesh-dev-only-account",
        "smesh-dev-only-account",
        VisibilityScope::Tenant,
        "trusted-local",
    )
    .unwrap();
    let admission_audit = smesh_a2a::AuthorizationAuditInput::new(
        format!("ratification-admission-audit-{suffix}"),
        scope.tenant_scope(),
        scope.owner_account_id(),
        "smesh-dev-only-policy",
        1,
        smesh_a2a::content_digest(b"smesh-dev-only-policy/v1"),
        "taskCreate",
        smesh_a2a::AuthorizationDecisionEffect::Allow,
        "authorized",
        "task",
        smesh_a2a::content_digest(task_id.as_bytes()),
        Some(task_id.clone()),
        admission.now,
    )
    .unwrap();
    smesh_a2a::TaskAdmission::authorize_and_admit(&store, &scope, admission, admission_audit)
        .await
        .unwrap();
    let lease = store
        .claim_outbox(
            format!("ratification-worker-{suffix}"),
            1_700_000_020_001,
            60_000,
        )
        .await
        .unwrap()
        .unwrap();
    let initial = store.get(&task_id).await.unwrap().unwrap();
    let mut approved = initial.clone();
    approved.status = a2a::TaskStatus {
        state: a2a::TaskState::Completed,
        message: Some(a2a::Message::new(
            a2a::Role::Agent,
            vec![a2a::Part::text("approved")],
        )),
        timestamp: chrono::DateTime::from_timestamp_millis(1_700_000_020_002),
    };
    approved.artifacts = Some(vec![a2a::Artifact {
        artifact_id: format!("artifact-ratified-{suffix}"),
        name: Some("release.txt".to_owned()),
        description: None,
        parts: vec![a2a::Part::text("sealed candidate")],
        metadata: None,
        extensions: None,
    }]);
    let transcript = vec![
        a2a::StreamResponse::Task(initial),
        a2a::StreamResponse::StatusUpdate(a2a::TaskStatusUpdateEvent {
            task_id: approved.id.clone(),
            context_id: approved.context_id.clone(),
            status: approved.status.clone(),
            metadata: None,
        }),
    ];
    store
        .commit_delivery_for_ratification(
            &lease,
            approved.clone(),
            a2a::SendMessageResponse::Task(approved.clone()),
            &transcript,
            AuthoritativeReviewCandidate::new(
                "release-policy",
                7,
                smesh_a2a::content_digest(b"release-policy-v7"),
                format!("sealed-checkpoint-{suffix}").into_bytes(),
                vec![b"review evidence: tests passed".to_vec()],
                "bounded uncertainty",
            )
            .unwrap(),
            1_700_000_020_002,
        )
        .await
        .unwrap();
    let packet = store
        .ratification_view(&scope, &task_id)
        .await
        .unwrap()
        .unwrap()
        .packet;
    (fixture, store, task_id, approved, scope, packet)
}

fn integrated_audit(
    packet: &smesh_a2a::ReviewPacket,
    scope: &smesh_a2a::OwnedTaskScope,
    task_id: &str,
    id: &str,
    operation: &str,
    at: i64,
) -> smesh_a2a::AuthorizationAuditInput {
    smesh_a2a::AuthorizationAuditInput::new(
        id,
        scope.tenant_scope(),
        scope.owner_account_id(),
        packet.authorization_policy_id.clone(),
        packet.authorization_policy_revision,
        packet.authorization_policy_digest.clone(),
        operation,
        smesh_a2a::AuthorizationDecisionEffect::Allow,
        "authorized",
        "ratification",
        packet.packet_hash.clone(),
        Some(task_id.to_owned()),
        at,
    )
    .unwrap()
}

fn integrated_review(
    packet: &smesh_a2a::ReviewPacket,
    scope: &smesh_a2a::OwnedTaskScope,
    task_id: &str,
    key: &str,
) -> ReviewAcknowledgement {
    ReviewAcknowledgement {
        tenant_id: scope.tenant_scope().to_owned(),
        task_id: task_id.to_owned(),
        generation: packet.generation,
        account_id: scope.owner_account_id().to_owned(),
        authorization_policy_id: packet.authorization_policy_id.clone(),
        authorization_policy_revision: packet.authorization_policy_revision,
        authorization_policy_digest: packet.authorization_policy_digest.clone(),
        principal_scope: scope.principal_scope().to_owned(),
        authentication_method: scope.authentication_method().to_owned(),
        context_id: packet.context_id.clone(),
        request_digest: packet.request_digest.clone(),
        ratification_key_generation: packet.ratification_key_generation.clone(),
        expected_revision: 0,
        checkpoint_hash: packet.checkpoint_hash.clone(),
        packet_hash: packet.packet_hash.clone(),
        evidence_hashes: packet.evidence_hashes.clone(),
        artifact_hashes: packet.artifacts.iter().map(|a| a.digest.clone()).collect(),
        artifact_manifest_digest: packet.artifact_set_digest.clone(),
        uncertainty_acknowledged: true,
        idempotency_key: key.to_owned(),
        reviewed_at_millis: 1_700_000_020_003,
    }
}

fn integrated_decision(
    packet: &smesh_a2a::ReviewPacket,
    scope: &smesh_a2a::OwnedTaskScope,
    task_id: &str,
    key: &str,
    decision: HumanDecision,
) -> RatificationCommand {
    RatificationCommand {
        tenant_id: scope.tenant_scope().to_owned(),
        task_id: task_id.to_owned(),
        generation: packet.generation,
        account_id: scope.owner_account_id().to_owned(),
        authorization_policy_id: packet.authorization_policy_id.clone(),
        authorization_policy_revision: packet.authorization_policy_revision,
        authorization_policy_digest: packet.authorization_policy_digest.clone(),
        principal_scope: scope.principal_scope().to_owned(),
        authentication_method: scope.authentication_method().to_owned(),
        context_id: packet.context_id.clone(),
        request_digest: packet.request_digest.clone(),
        ratification_key_generation: packet.ratification_key_generation.clone(),
        expected_revision: 1,
        checkpoint_hash: packet.checkpoint_hash.clone(),
        packet_hash: packet.packet_hash.clone(),
        artifact_manifest_digest: packet.artifact_set_digest.clone(),
        idempotency_key: key.to_owned(),
        decision,
        rationale: "exact decision rationale".to_owned(),
        decided_at_millis: 1_700_000_020_004,
    }
}

#[tokio::test]
async fn sqlite_startup_rejects_impossible_ratification_state_revision_pairs() {
    use smesh_a2a::RatificationAuthority as _;

    let invalid_pairs = [
        ("awaiting_review", 1_u64),
        ("reviewed", 0),
        ("approved", 1),
        ("rejected", 1),
        ("amended", 1),
        ("canceled", 2),
        ("superseded", 2),
        ("rejected", 2),
        ("amended", 2),
    ];
    for (index, (state, revision)) in invalid_pairs.into_iter().enumerate() {
        let suffix = 100 + u64::try_from(index).unwrap();
        let (fixture, store, task_id, _approved, scope, packet) =
            integrated_ratification_fixture(suffix).await;
        if revision >= 1 {
            store
                .acknowledge_ratification_review(
                    &scope,
                    integrated_review(
                        &packet,
                        &scope,
                        &task_id,
                        &format!("state-revision-review-{index}"),
                    ),
                    integrated_audit(
                        &packet,
                        &scope,
                        &task_id,
                        &format!("state-revision-review-audit-{index}"),
                        "ratificationReview",
                        1_700_000_020_003,
                    ),
                )
                .await
                .unwrap();
        }
        if revision == 2 {
            store
                .decide_ratification(
                    &scope,
                    integrated_decision(
                        &packet,
                        &scope,
                        &task_id,
                        &format!("state-revision-decision-{index}"),
                        HumanDecision::Approve,
                    ),
                    integrated_audit(
                        &packet,
                        &scope,
                        &task_id,
                        &format!("state-revision-decision-audit-{index}"),
                        "ratificationDecide",
                        1_700_000_020_004,
                    ),
                )
                .await
                .unwrap();
        }
        drop(store);

        let connection = rusqlite::Connection::open(&fixture.0).unwrap();
        connection
            .execute(
                "UPDATE ratification_packets SET state=?1 WHERE task_id=?2",
                rusqlite::params![state, task_id],
            )
            .unwrap();
        let (stored_revision, receipt_count, head): (i64, i64, Option<String>) = connection
            .query_row(
                "SELECT p.revision,
                        (SELECT COUNT(*) FROM ratification_events e
                         WHERE e.tenant_scope=p.tenant_scope AND e.task_id=p.task_id
                           AND e.generation=p.generation),
                        p.head_receipt_hash
                 FROM ratification_packets p WHERE p.task_id=?1",
                [&task_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(stored_revision, i64::try_from(revision).unwrap());
        assert_eq!(receipt_count, stored_revision);
        assert_eq!(head.is_some(), revision > 0);
        drop(connection);

        assert!(
            SqliteTaskStore::open_with_ratification_key(
                &fixture.0,
                16,
                zeroize::Zeroizing::new([0x52; 32]),
                false,
            )
            .await
            .is_err(),
            "state={state}, revision={revision}"
        );
    }
}

fn disable_integrated_ratification_immutability(connection: &rusqlite::Connection) {
    connection
        .execute_batch(
            "PRAGMA foreign_keys=OFF;
             DROP TRIGGER tasks_ownership_immutable;
             DROP TRIGGER idempotency_identity_update;
             DROP TRIGGER outbox_identity_update;
             DROP TRIGGER outbox_message_immutable;
             DROP TRIGGER ratification_packets_identity_immutable;
             DROP TRIGGER ratification_packets_no_delete;
             DROP TRIGGER ratification_events_no_update;
             DROP TRIGGER ratification_events_no_delete;",
        )
        .unwrap();
}

fn integrated_ratification_state(
    connection: &rusqlite::Connection,
) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
    [
        "tasks",
        "ratification_packets",
        "ratification_events",
        "idempotency_records",
        "stream_transcripts",
        "stream_frames",
        "task_events",
        "outbox",
        "callback_configs",
        "callback_events",
        "callback_deliveries",
        "authorization_decisions",
    ]
    .into_iter()
    .map(|table| {
        let mut statement = connection
            .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
            .unwrap();
        let column_count = statement.column_count();
        let rows = statement
            .query_map([], |row| {
                (0..column_count)
                    .map(|column| row.get(column))
                    .collect::<rusqlite::Result<Vec<rusqlite::types::Value>>>()
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        (table.to_owned(), rows)
    })
    .collect()
}

#[tokio::test]
async fn sqlite_replay_rejects_duplicate_delivered_causative_identity_without_mutation() {
    use smesh_a2a::RatificationAuthority as _;

    let (fixture, store, task_id, _approved, scope, packet) =
        integrated_ratification_fixture(98).await;
    let review = integrated_review(&packet, &scope, &task_id, "duplicate-cause-review");
    store
        .acknowledge_ratification_review(
            &scope,
            review.clone(),
            integrated_audit(
                &packet,
                &scope,
                &task_id,
                "duplicate-cause-initial-audit",
                "ratificationReview",
                1_700_000_020_003,
            ),
        )
        .await
        .unwrap();
    let connection = rusqlite::Connection::open(&fixture.0).unwrap();
    connection
        .execute(
            "INSERT INTO idempotency_records(
                 tenant_scope,message_id,request_digest,task_id,state,admission_result_json,
                 final_result_json,created_at,updated_at,digest_version,actor_account_id,
                 causative_request_json,invocation_kind)
             SELECT tenant_scope,'duplicate-cause-message',request_digest,task_id,state,
                    admission_result_json,final_result_json,created_at,updated_at,digest_version,
                    actor_account_id,causative_request_json,invocation_kind
             FROM idempotency_records WHERE tenant_scope=?1 AND task_id=?2 LIMIT 1",
            rusqlite::params![scope.tenant_scope(), task_id],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO outbox(
                 dispatch_id,tenant_scope,task_id,message_id,causative_revision,
                 payload_json,payload_digest,state,attempt_count,max_attempts,
                 available_at,created_at,updated_at,dispatch_identity_version)
             SELECT 'duplicate-causative-dispatch',tenant_scope,task_id,
                    'duplicate-cause-message',causative_revision,payload_json,payload_digest,
                    'delivered',attempt_count,max_attempts,available_at,created_at,updated_at,
                    dispatch_identity_version
             FROM outbox WHERE tenant_scope=?1 AND task_id=?2 AND state='delivered'",
            rusqlite::params![scope.tenant_scope(), task_id],
        )
        .unwrap();
    let before = integrated_ratification_state(&connection);
    drop(connection);

    let error = store
        .acknowledge_ratification_review(
            &scope,
            review,
            integrated_audit(
                &packet,
                &scope,
                &task_id,
                "duplicate-cause-replay-audit",
                "ratificationReview",
                1_700_000_020_004,
            ),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, a2a::error_code::INTERNAL_ERROR);
    let connection = rusqlite::Connection::open(&fixture.0).unwrap();
    assert_eq!(integrated_ratification_state(&connection), before);
}

#[tokio::test]
async fn sqlite_revision_zero_packet_rejects_orphan_receipt_without_mutation() {
    use smesh_a2a::RatificationAuthority as _;

    let (fixture, store, task_id, _approved, scope, packet) =
        integrated_ratification_fixture(99).await;
    store
        .acknowledge_ratification_review(
            &scope,
            integrated_review(&packet, &scope, &task_id, "orphan-review"),
            integrated_audit(
                &packet,
                &scope,
                &task_id,
                "orphan-review-audit",
                "ratificationReview",
                1_700_000_020_003,
            ),
        )
        .await
        .unwrap();
    let connection = rusqlite::Connection::open(&fixture.0).unwrap();
    disable_integrated_ratification_immutability(&connection);
    connection
        .execute_batch(
            "UPDATE ratification_events SET revision=2;
             UPDATE ratification_packets SET state='awaiting_review',revision=0,
                 reviewer_account_id=NULL,head_receipt_hash=NULL;",
        )
        .unwrap();
    let before = integrated_ratification_state(&connection);
    drop(connection);

    let error = store
        .acknowledge_ratification_review(
            &scope,
            integrated_review(&packet, &scope, &task_id, "replacement-review"),
            integrated_audit(
                &packet,
                &scope,
                &task_id,
                "replacement-review-audit",
                "ratificationReview",
                1_700_000_020_004,
            ),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, a2a::error_code::INTERNAL_ERROR);
    let connection = rusqlite::Connection::open(&fixture.0).unwrap();
    assert_eq!(integrated_ratification_state(&connection), before);
}

#[tokio::test]
async fn sqlite_review_replay_fails_closed_over_every_authenticated_input() {
    use smesh_a2a::RatificationAuthority as _;

    let corruptions = [
        "UPDATE tasks SET revision=revision+1",
        "UPDATE tasks SET task_json='{}'",
        "UPDATE tasks SET owner_account_id='forged-owner'",
        "UPDATE tasks SET context_id='forged-context'",
        "UPDATE tasks SET status_timestamp='2099-01-01T00:00:00+00:00'",
        "UPDATE tasks SET principal_scope='forged-principal'",
        "UPDATE tasks SET authentication_method='forged-authentication'",
        "UPDATE outbox SET causative_revision=causative_revision+1",
        "UPDATE outbox SET state='dead'",
        "UPDATE outbox SET message_id='forged-cause-message'",
        "UPDATE idempotency_records SET actor_account_id='forged-cause-actor'",
        "UPDATE idempotency_records SET actor_account_id=NULL",
        "UPDATE idempotency_records SET request_digest='sha256:0000000000000000000000000000000000000000000000000000000000000000'",
        "UPDATE idempotency_records SET message_id='forged-cause-identity'",
        "UPDATE ratification_packets SET packet_json='{}'",
        "UPDATE ratification_packets SET packet_seal='forged'",
        "UPDATE ratification_packets SET packet_hash='sha256:0000000000000000000000000000000000000000000000000000000000000000'",
        "UPDATE ratification_packets SET checkpoint_hash='sha256:0000000000000000000000000000000000000000000000000000000000000000'",
        "UPDATE ratification_packets SET task_revision=task_revision+1",
        "UPDATE ratification_packets SET approved_task_json='{}'",
        "UPDATE ratification_packets SET approved_result_json='{}'",
        "UPDATE ratification_packets SET approved_transcript_json='[]'",
        "UPDATE ratification_packets SET reviewer_account_id='forged-reviewer'",
        "UPDATE ratification_events SET receipt_json='{}'",
        "UPDATE ratification_events SET task_id='forged-task'",
        "UPDATE ratification_events SET generation=99",
        "UPDATE ratification_events SET revision=2",
        "UPDATE ratification_events SET account_id='forged-account'",
        "UPDATE ratification_events SET action='approve'",
        "UPDATE ratification_events SET command_digest='sha256:0000000000000000000000000000000000000000000000000000000000000000'",
        "UPDATE ratification_events SET idempotency_key='forged-key'",
        "UPDATE ratification_events SET occurred_at=occurred_at+1",
        "UPDATE ratification_events SET receipt_hash='sha256:0000000000000000000000000000000000000000000000000000000000000000'",
        "UPDATE ratification_events SET receipt_seal='forged'",
        "UPDATE ratification_events SET previous_receipt_hash='sha256:0000000000000000000000000000000000000000000000000000000000000000'",
        "UPDATE ratification_packets SET head_receipt_hash='sha256:0000000000000000000000000000000000000000000000000000000000000000'",
        "DELETE FROM ratification_events",
    ];
    for (index, corruption) in corruptions.into_iter().enumerate() {
        let suffix = 100 + u64::try_from(index).unwrap();
        let (fixture, store, task_id, _approved, scope, packet) =
            integrated_ratification_fixture(suffix).await;
        let review = integrated_review(&packet, &scope, &task_id, "replay-review");
        store
            .acknowledge_ratification_review(
                &scope,
                review.clone(),
                integrated_audit(
                    &packet,
                    &scope,
                    &task_id,
                    "initial-review-audit",
                    "ratificationReview",
                    1_700_000_020_003,
                ),
            )
            .await
            .unwrap();
        let connection = rusqlite::Connection::open(&fixture.0).unwrap();
        disable_integrated_ratification_immutability(&connection);
        connection.execute_batch(corruption).unwrap();
        let before = integrated_ratification_state(&connection);
        drop(connection);

        let mut replay = review;
        replay.reviewed_at_millis += 99;
        let error = store
            .acknowledge_ratification_review(
                &scope,
                replay,
                integrated_audit(
                    &packet,
                    &scope,
                    &task_id,
                    "corrupt-review-replay-audit",
                    "ratificationReview",
                    1_700_000_020_102,
                ),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, a2a::error_code::INTERNAL_ERROR, "{corruption}");
        let connection = rusqlite::Connection::open(&fixture.0).unwrap();
        assert_eq!(
            integrated_ratification_state(&connection),
            before,
            "failed review replay mutated durable state: {corruption}"
        );
    }
}

#[tokio::test]
async fn sqlite_decision_replay_fails_closed_over_full_receipt_chain() {
    use smesh_a2a::RatificationAuthority as _;

    let corruptions = [
        "UPDATE tasks SET revision=revision+1",
        "UPDATE tasks SET task_json='{}'",
        "UPDATE tasks SET owner_account_id='forged-owner'",
        "UPDATE tasks SET status_timestamp='2099-01-01T00:00:00+00:00'",
        "UPDATE tasks SET principal_scope='forged-principal'",
        "UPDATE outbox SET causative_revision=causative_revision+1",
        "UPDATE outbox SET state='dead'",
        "UPDATE outbox SET message_id='forged-cause-message'",
        "UPDATE idempotency_records SET actor_account_id='forged-cause-actor'",
        "UPDATE idempotency_records SET actor_account_id=NULL",
        "UPDATE idempotency_records SET request_digest='sha256:0000000000000000000000000000000000000000000000000000000000000000'",
        "UPDATE idempotency_records SET message_id='forged-cause-identity'",
        "UPDATE ratification_packets SET packet_seal='forged'",
        "UPDATE ratification_packets SET approved_task_json='{}'",
        "UPDATE ratification_packets SET approved_result_json='{}'",
        "UPDATE ratification_packets SET approved_transcript_json='[]'",
        "UPDATE ratification_events SET receipt_json='{}' WHERE revision=1",
        "UPDATE ratification_events SET receipt_hash='sha256:0000000000000000000000000000000000000000000000000000000000000000' WHERE revision=1",
        "UPDATE ratification_events SET receipt_json='{}' WHERE revision=2",
        "UPDATE ratification_events SET action='review' WHERE revision=2",
        "UPDATE ratification_events SET command_digest='sha256:0000000000000000000000000000000000000000000000000000000000000000' WHERE revision=2",
        "UPDATE ratification_events SET occurred_at=occurred_at+1 WHERE revision=2",
        "UPDATE ratification_events SET previous_receipt_hash=NULL WHERE revision=2",
        "UPDATE ratification_packets SET head_receipt_hash=(SELECT receipt_hash FROM ratification_events WHERE revision=1)",
        "DELETE FROM ratification_events WHERE revision=1",
        "DELETE FROM ratification_events WHERE revision=2",
    ];
    for (index, corruption) in corruptions.into_iter().enumerate() {
        let suffix = 200 + u64::try_from(index).unwrap();
        let (fixture, store, task_id, _approved, scope, packet) =
            integrated_ratification_fixture(suffix).await;
        store
            .acknowledge_ratification_review(
                &scope,
                integrated_review(&packet, &scope, &task_id, "chain-review"),
                integrated_audit(
                    &packet,
                    &scope,
                    &task_id,
                    "chain-review-audit",
                    "ratificationReview",
                    1_700_000_020_003,
                ),
            )
            .await
            .unwrap();
        let decision = integrated_decision(
            &packet,
            &scope,
            &task_id,
            "chain-decision",
            HumanDecision::Approve,
        );
        store
            .decide_ratification(
                &scope,
                decision.clone(),
                integrated_audit(
                    &packet,
                    &scope,
                    &task_id,
                    "chain-decision-audit",
                    "ratificationDecide",
                    1_700_000_020_004,
                ),
            )
            .await
            .unwrap();
        let connection = rusqlite::Connection::open(&fixture.0).unwrap();
        disable_integrated_ratification_immutability(&connection);
        connection.execute_batch(corruption).unwrap();
        let before = integrated_ratification_state(&connection);
        drop(connection);

        let mut replay = decision;
        replay.decided_at_millis += 99;
        let error = store
            .decide_ratification(
                &scope,
                replay,
                integrated_audit(
                    &packet,
                    &scope,
                    &task_id,
                    "corrupt-decision-replay-audit",
                    "ratificationDecide",
                    1_700_000_020_103,
                ),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, a2a::error_code::INTERNAL_ERROR, "{corruption}");
        let connection = rusqlite::Connection::open(&fixture.0).unwrap();
        assert_eq!(
            integrated_ratification_state(&connection),
            before,
            "failed decision replay mutated durable state: {corruption}"
        );
    }
}

#[tokio::test]
async fn sqlite_terminal_state_swap_fails_every_view_and_restart_without_mutation() {
    use smesh_a2a::{RatificationAuthority as _, RatificationState};
    let (fixture, store, task_id, _approved, scope, packet) =
        integrated_ratification_fixture(391).await;
    store
        .acknowledge_ratification_review(
            &scope,
            integrated_review(&packet, &scope, &task_id, "swap-review"),
            integrated_audit(
                &packet,
                &scope,
                &task_id,
                "swap-review-audit",
                "ratificationReview",
                1_700_000_020_003,
            ),
        )
        .await
        .unwrap();
    store
        .decide_ratification(
            &scope,
            integrated_decision(
                &packet,
                &scope,
                &task_id,
                "swap-decision",
                HumanDecision::Approve,
            ),
            integrated_audit(
                &packet,
                &scope,
                &task_id,
                "swap-decision-audit",
                "ratificationDecide",
                1_700_000_020_004,
            ),
        )
        .await
        .unwrap();
    let connection = rusqlite::Connection::open(&fixture.0).unwrap();
    connection
        .execute(
            "UPDATE ratification_packets SET state='rejected' WHERE task_id=?1",
            [&task_id],
        )
        .unwrap();
    let before = integrated_ratification_state(&connection);
    drop(connection);
    assert!(store.ratification_view(&scope, &task_id).await.is_err());
    let connection = rusqlite::Connection::open(&fixture.0).unwrap();
    assert_eq!(integrated_ratification_state(&connection), before);
    drop(connection);
    drop(store);
    assert!(
        SqliteTaskStore::open_with_ratification_key(
            &fixture.0,
            16,
            zeroize::Zeroizing::new([0x52; 32]),
            false
        )
        .await
        .is_err()
    );
    let _ = RatificationState::Approved;
}

#[tokio::test]
async fn sqlite_ratification_distinguishes_idempotency_reuse_from_stale_preconditions() {
    use smesh_a2a::RatificationAuthority as _;

    let (_fixture, store, task_id, _approved, scope, packet) =
        integrated_ratification_fixture(300).await;
    let review = integrated_review(&packet, &scope, &task_id, "semantic-review");
    store
        .acknowledge_ratification_review(
            &scope,
            review.clone(),
            integrated_audit(
                &packet,
                &scope,
                &task_id,
                "semantic-review-audit",
                "ratificationReview",
                1_700_000_020_003,
            ),
        )
        .await
        .unwrap();
    let conflicting_reuse = ReviewAcknowledgement {
        uncertainty_acknowledged: false,
        ..review
    };
    let reuse_error = store
        .acknowledge_ratification_review(
            &scope,
            conflicting_reuse,
            integrated_audit(
                &packet,
                &scope,
                &task_id,
                "semantic-reuse-audit",
                "ratificationReview",
                1_700_000_020_004,
            ),
        )
        .await
        .unwrap_err();
    assert_eq!(reuse_error.code, -32_621);

    let stale = integrated_review(&packet, &scope, &task_id, "stale-review");
    let stale_error = store
        .acknowledge_ratification_review(
            &scope,
            stale,
            integrated_audit(
                &packet,
                &scope,
                &task_id,
                "stale-review-audit",
                "ratificationReview",
                1_700_000_020_005,
            ),
        )
        .await
        .unwrap_err();
    assert_eq!(stale_error.code, -32_620);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn sqlite_cross_task_ratification_idempotency_conflict_is_authenticated_and_atomic() {
    use smesh_a2a::{OwnedTaskScope, RatificationAuthority as _, VisibilityScope};

    let (fixture, store, first_task, _approved, scope, first_packet) =
        integrated_ratification_fixture(301).await;
    store
        .acknowledge_ratification_review(
            &scope,
            integrated_review(&first_packet, &scope, &first_task, "global-review-key"),
            integrated_audit(
                &first_packet,
                &scope,
                &first_task,
                "global-first-review-audit",
                "ratificationReview",
                1_700_000_020_003,
            ),
        )
        .await
        .unwrap();

    let mut admission = durable_admission();
    admission.request.message.message_id = "ratification-message-302".to_owned();
    admission.task.id = "task-authoritative-ratification-302".to_owned();
    admission.task.context_id = "context-authoritative-ratification-302".to_owned();
    admission.task.history = Some(vec![admission.request.message.clone()]);
    admission.original_result = a2a::SendMessageResponse::Task(admission.task.clone());
    let second_task = admission.task.id.clone();
    let admission_now = admission.now;
    smesh_a2a::TaskAdmission::authorize_and_admit(
        &store,
        &scope,
        admission,
        smesh_a2a::AuthorizationAuditInput::new(
            "ratification-second-admission-audit",
            scope.tenant_scope(),
            scope.owner_account_id(),
            "smesh-dev-only-policy",
            1,
            smesh_a2a::content_digest(b"smesh-dev-only-policy/v1"),
            "taskCreate",
            smesh_a2a::AuthorizationDecisionEffect::Allow,
            "authorized",
            "task",
            smesh_a2a::content_digest(second_task.as_bytes()),
            Some(second_task.clone()),
            admission_now,
        )
        .unwrap(),
    )
    .await
    .unwrap();
    let lease = store
        .claim_outbox(
            "ratification-worker-302".to_owned(),
            1_700_000_020_010,
            60_000,
        )
        .await
        .unwrap()
        .unwrap();
    let initial = store.get(&second_task).await.unwrap().unwrap();
    let mut approved = initial.clone();
    approved.status.state = a2a::TaskState::Completed;
    approved.status.timestamp = chrono::DateTime::from_timestamp_millis(1_700_000_020_011);
    approved.artifacts = Some(vec![a2a::Artifact {
        artifact_id: "artifact-ratified-302".to_owned(),
        name: Some("release.txt".to_owned()),
        description: None,
        parts: vec![a2a::Part::text("sealed candidate")],
        metadata: None,
        extensions: None,
    }]);
    let transcript = vec![a2a::StreamResponse::Task(initial)];
    store
        .commit_delivery_for_ratification(
            &lease,
            approved.clone(),
            a2a::SendMessageResponse::Task(approved),
            &transcript,
            AuthoritativeReviewCandidate::new(
                "release-policy",
                7,
                smesh_a2a::content_digest(b"release-policy-v7"),
                b"sealed-checkpoint-302".to_vec(),
                vec![b"review evidence: tests passed".to_vec()],
                "bounded uncertainty",
            )
            .unwrap(),
            1_700_000_020_011,
        )
        .await
        .unwrap();
    let scope = OwnedTaskScope::new_with_principal_and_authentication(
        smesh_a2a::TRUSTED_SINGLE_TENANT_SCOPE,
        "smesh-dev-only-account",
        "smesh-dev-only-account",
        VisibilityScope::Tenant,
        "trusted-local",
    )
    .unwrap();
    let second_packet = store
        .ratification_view(&scope, &second_task)
        .await
        .unwrap()
        .unwrap()
        .packet;
    let connection = rusqlite::Connection::open(&fixture.0).unwrap();
    let before = integrated_ratification_state(&connection);
    drop(connection);

    let error = store
        .acknowledge_ratification_review(
            &scope,
            integrated_review(&second_packet, &scope, &second_task, "global-review-key"),
            integrated_audit(
                &second_packet,
                &scope,
                &second_task,
                "global-second-review-audit",
                "ratificationReview",
                1_700_000_020_012,
            ),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, -32_621);
    let connection = rusqlite::Connection::open(&fixture.0).unwrap();
    assert_eq!(integrated_ratification_state(&connection), before);
    disable_integrated_ratification_immutability(&connection);
    assert_eq!(
        connection
            .execute(
                "UPDATE idempotency_records SET actor_account_id='forged-conflict-owner' WHERE task_id=?1",
                [&first_task],
            )
            .unwrap(),
        1
    );
    let owner_tampered_before = integrated_ratification_state(&connection);
    drop(connection);
    let error = store
        .acknowledge_ratification_review(
            &scope,
            integrated_review(&second_packet, &scope, &second_task, "global-review-key"),
            integrated_audit(
                &second_packet,
                &scope,
                &second_task,
                "global-tampered-owner-audit",
                "ratificationReview",
                1_700_000_020_013,
            ),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, a2a::error_code::INTERNAL_ERROR);
    let connection = rusqlite::Connection::open(&fixture.0).unwrap();
    assert_eq!(
        integrated_ratification_state(&connection),
        owner_tampered_before
    );
    assert_eq!(
        connection
            .execute(
                "UPDATE idempotency_records SET actor_account_id=NULL WHERE task_id=?1",
                [&first_task],
            )
            .unwrap(),
        1
    );
    let null_owner_before = integrated_ratification_state(&connection);
    drop(connection);
    let error = store
        .acknowledge_ratification_review(
            &scope,
            integrated_review(&second_packet, &scope, &second_task, "global-review-key"),
            integrated_audit(
                &second_packet,
                &scope,
                &second_task,
                "global-null-owner-audit",
                "ratificationReview",
                1_700_000_020_013,
            ),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, a2a::error_code::INTERNAL_ERROR);
    let connection = rusqlite::Connection::open(&fixture.0).unwrap();
    assert_eq!(
        integrated_ratification_state(&connection),
        null_owner_before
    );
    assert_eq!(
        connection
            .execute(
                "UPDATE idempotency_records SET actor_account_id='smesh-dev-only-account' WHERE task_id=?1",
                [&first_task],
            )
            .unwrap(),
        1
    );
    connection
        .execute(
            "UPDATE ratification_events SET receipt_json='{}' WHERE task_id=?1",
            [&first_task],
        )
        .unwrap();
    let tampered_before = integrated_ratification_state(&connection);
    drop(connection);
    let error = store
        .acknowledge_ratification_review(
            &scope,
            integrated_review(&second_packet, &scope, &second_task, "global-review-key"),
            integrated_audit(
                &second_packet,
                &scope,
                &second_task,
                "global-tampered-chain-audit",
                "ratificationReview",
                1_700_000_020_013,
            ),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, a2a::error_code::INTERNAL_ERROR);
    let connection = rusqlite::Connection::open(&fixture.0).unwrap();
    assert_eq!(integrated_ratification_state(&connection), tampered_before);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn sqlite_cross_generation_ratification_idempotency_conflict_is_authenticated_and_atomic() {
    use smesh_a2a::RatificationAuthority as _;

    let (fixture, store, task_id, _approved, scope, first_packet) =
        integrated_ratification_fixture(303).await;
    store
        .acknowledge_ratification_review(
            &scope,
            integrated_review(&first_packet, &scope, &task_id, "generation-global-key"),
            integrated_audit(
                &first_packet,
                &scope,
                &task_id,
                "generation-one-review-audit",
                "ratificationReview",
                1_700_000_020_003,
            ),
        )
        .await
        .unwrap();
    let generation_one_amend = integrated_decision(
        &first_packet,
        &scope,
        &task_id,
        "generation-one-amend",
        HumanDecision::Amend,
    );
    let first_amend_receipt = store
        .decide_ratification(
            &scope,
            generation_one_amend.clone(),
            integrated_audit(
                &first_packet,
                &scope,
                &task_id,
                "generation-one-amend-audit",
                "ratificationDecide",
                1_700_000_020_004,
            ),
        )
        .await
        .unwrap();
    let lease = store
        .claim_outbox(
            "generation-two-worker".to_owned(),
            1_700_000_020_005,
            60_000,
        )
        .await
        .unwrap()
        .unwrap();
    let payload = serde_json::to_vec(&lease.request).unwrap();
    let envelope = DurableDispatchEnvelope {
        tenant_scope: lease.tenant_scope.clone(),
        dispatch_id: lease.dispatch_id.clone(),
        payload_digest: smesh_a2a::content_digest(&payload),
        request: lease.request.clone(),
        execution_reservation: lease.execution_reservation.clone(),
    };
    let ReceiverAdmission::Execute(receiver) = store
        .begin_receive(
            envelope,
            "generation-two-receiver",
            1_700_000_020_005,
            60_000,
        )
        .await
        .unwrap()
    else {
        panic!("generation two receiver lease was not executable")
    };
    store
        .complete_loopback_receive(
            &receiver,
            &[smesh_a2a::MeshEvent::Completed {
                summary: "generation two candidate".to_owned(),
            }],
            1_700_000_020_006,
        )
        .await
        .unwrap();
    let initial = store.task_for_outbox(&lease).await.unwrap().unwrap();
    let mut approved = initial.clone();
    approved.status = a2a::TaskStatus {
        state: a2a::TaskState::Completed,
        message: Some(a2a::Message::new(
            a2a::Role::Agent,
            vec![a2a::Part::text("generation two candidate")],
        )),
        timestamp: chrono::DateTime::from_timestamp_millis(1_700_000_020_006),
    };
    approved.artifacts = Some(vec![a2a::Artifact {
        artifact_id: "artifact-ratified-generation-two".to_owned(),
        name: Some("release.txt".to_owned()),
        description: None,
        parts: vec![a2a::Part::text("generation two sealed candidate")],
        metadata: None,
        extensions: None,
    }]);
    let transcript = vec![
        a2a::StreamResponse::Task(initial),
        a2a::StreamResponse::ArtifactUpdate(a2a::TaskArtifactUpdateEvent {
            task_id: approved.id.clone(),
            context_id: approved.context_id.clone(),
            artifact: approved.artifacts.as_ref().unwrap()[0].clone(),
            append: None,
            last_chunk: Some(true),
            metadata: None,
        }),
        a2a::StreamResponse::StatusUpdate(a2a::TaskStatusUpdateEvent {
            task_id: approved.id.clone(),
            context_id: approved.context_id.clone(),
            status: approved.status.clone(),
            metadata: None,
        }),
    ];
    store
        .commit_delivery_for_ratification(
            &lease,
            approved.clone(),
            a2a::SendMessageResponse::Task(approved),
            &transcript,
            AuthoritativeReviewCandidate::new(
                "release-policy",
                7,
                smesh_a2a::content_digest(b"release-policy-v7"),
                b"sealed-checkpoint-generation-two".to_vec(),
                vec![b"generation two evidence".to_vec()],
                "bounded uncertainty",
            )
            .unwrap(),
            1_700_000_020_006,
        )
        .await
        .unwrap();
    let second_packet = store
        .ratification_view(&scope, &task_id)
        .await
        .unwrap()
        .unwrap()
        .packet;
    assert_eq!(second_packet.generation, 2);
    let first_view = store
        .ratification_view_at_generation(&scope, &task_id, 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first_view.packet, first_packet);
    assert_eq!(first_view.state, smesh_a2a::RatificationState::Amended);
    assert_eq!(first_view.history.len(), 2);
    let audits_before_exact_replay = store.authorization_decision_count().await.unwrap();
    let replayed_amend_receipt = store
        .decide_ratification(
            &scope,
            generation_one_amend,
            integrated_audit(
                &first_packet,
                &scope,
                &task_id,
                "generation-one-amend-replay-audit",
                "ratificationDecide",
                1_700_000_020_007,
            ),
        )
        .await
        .unwrap();
    assert_eq!(replayed_amend_receipt, first_amend_receipt);
    assert_eq!(
        store.authorization_decision_count().await.unwrap(),
        audits_before_exact_replay + 1
    );
    let connection = rusqlite::Connection::open(&fixture.0).unwrap();
    let before = integrated_ratification_state(&connection);
    drop(connection);

    let error = store
        .acknowledge_ratification_review(
            &scope,
            integrated_review(&second_packet, &scope, &task_id, "generation-global-key"),
            integrated_audit(
                &second_packet,
                &scope,
                &task_id,
                "generation-two-conflict-audit",
                "ratificationReview",
                1_700_000_020_007,
            ),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, -32_621);
    let connection = rusqlite::Connection::open(&fixture.0).unwrap();
    assert_eq!(integrated_ratification_state(&connection), before);
    connection
        .execute_batch(
            "PRAGMA foreign_keys=OFF;
         DROP TRIGGER ratification_events_no_delete;
         DROP TRIGGER ratification_packets_no_delete;
         DELETE FROM ratification_events WHERE generation=1;
         DELETE FROM ratification_packets WHERE generation=1;
         CREATE TRIGGER ratification_packets_no_delete BEFORE DELETE ON ratification_packets
          BEGIN SELECT RAISE(ABORT,'ratification packet is durable'); END;
         CREATE TRIGGER ratification_events_no_delete BEFORE DELETE ON ratification_events
          BEGIN SELECT RAISE(ABORT,'ratification event is immutable'); END;",
        )
        .unwrap();
    drop(connection);
    drop(store);
    assert!(
        SqliteTaskStore::open_with_ratification_key(
            &fixture.0,
            16,
            zeroize::Zeroizing::new([0x52; 32]),
            false,
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn sqlite_missing_whole_ledger_anchor_after_ratification_fails_reopen() {
    let (fixture, store, _task_id, _approved, _scope, _packet) =
        integrated_ratification_fixture(304).await;
    drop(store);
    let connection = rusqlite::Connection::open(&fixture.0).unwrap();
    connection.execute_batch(
        "PRAGMA foreign_keys=OFF;
         DROP TRIGGER ratification_key_check_no_delete;
         DROP TRIGGER ratification_ledger_anchor_no_delete;
         DROP TRIGGER ratification_events_no_delete;
         DROP TRIGGER ratification_packets_no_delete;
         DELETE FROM ratification_events;
         DELETE FROM ratification_packets;
         DELETE FROM ratification_key_check;
         DELETE FROM ratification_ledger_anchor;
         CREATE TRIGGER ratification_key_check_no_delete BEFORE DELETE ON ratification_key_check
          BEGIN SELECT RAISE(ABORT,'ratification key check is immutable'); END;
         CREATE TRIGGER ratification_ledger_anchor_no_delete BEFORE DELETE ON ratification_ledger_anchor
          BEGIN SELECT RAISE(ABORT,'ratification ledger anchor is durable'); END;
         CREATE TRIGGER ratification_packets_no_delete BEFORE DELETE ON ratification_packets
          BEGIN SELECT RAISE(ABORT,'ratification packet is durable'); END;
         CREATE TRIGGER ratification_events_no_delete BEFORE DELETE ON ratification_events
          BEGIN SELECT RAISE(ABORT,'ratification event is immutable'); END;"
    ).unwrap();
    drop(connection);
    assert!(
        SqliteTaskStore::open_with_ratification_key(
            &fixture.0,
            16,
            zeroize::Zeroizing::new([0x52; 32]),
            false,
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn sqlite_live_reads_and_review_reject_privileged_whole_ledger_deletion_without_mutation() {
    use smesh_a2a::RatificationAuthority as _;

    let (fixture, store, task_id, _approved, scope, packet) =
        integrated_ratification_fixture(305).await;
    let connection = rusqlite::Connection::open(&fixture.0).unwrap();
    connection
        .execute_batch(
            "PRAGMA foreign_keys=OFF;
             DROP TRIGGER ratification_events_no_delete;
             DROP TRIGGER ratification_packets_no_delete;
             DELETE FROM ratification_events;
             DELETE FROM ratification_packets;
             CREATE TRIGGER ratification_packets_no_delete BEFORE DELETE ON ratification_packets
              BEGIN SELECT RAISE(ABORT,'ratification packet is durable'); END;
             CREATE TRIGGER ratification_events_no_delete BEFORE DELETE ON ratification_events
              BEGIN SELECT RAISE(ABORT,'ratification event is immutable'); END;",
        )
        .unwrap();
    let before = integrated_ratification_state(&connection);
    drop(connection);

    assert!(store.ratification_view(&scope, &task_id).await.is_err());
    assert!(
        store
            .ratification_view_at_generation(&scope, &task_id, 1)
            .await
            .is_err()
    );
    assert!(
        store
            .acknowledge_ratification_review(
                &scope,
                integrated_review(&packet, &scope, &task_id, "deleted-ledger-review"),
                integrated_audit(
                    &packet,
                    &scope,
                    &task_id,
                    "deleted-ledger-review-audit",
                    "ratificationReview",
                    1_700_000_020_003,
                ),
            )
            .await
            .is_err()
    );

    let connection = rusqlite::Connection::open(&fixture.0).unwrap();
    assert_eq!(integrated_ratification_state(&connection), before);
}

#[tokio::test]
async fn sqlite_cancellation_and_continuation_close_active_ratification_packets() {
    use smesh_a2a::{RatificationAuthority as _, RatificationState};
    let (_fixture, store, task_id, _approved, scope, _packet) =
        integrated_ratification_fixture(5).await;
    store
        .request_cancellation(&task_id, 1_700_000_020_010)
        .await
        .unwrap();
    assert_eq!(
        store
            .ratification_view(&scope, &task_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        RatificationState::Canceled
    );

    let (_fixture, store, task_id, _approved, scope, _packet) =
        integrated_ratification_fixture(6).await;
    let task = store.get(&task_id).await.unwrap().unwrap();
    let mut message = a2a::Message::new(
        a2a::Role::User,
        vec![a2a::Part::text("continue with new evidence")],
    );
    message.message_id = "continuation-after-ratification".to_owned();
    message.task_id = Some(task.id.clone());
    message.context_id = Some(task.context_id.clone());
    let request = a2a::SendMessageRequest {
        message,
        configuration: None,
        metadata: None,
        tenant: None,
    };
    store
        .admit_continuation(smesh_a2a::SendMessageAdmission {
            request,
            streaming: false,
            task: task.clone(),
            original_result: a2a::SendMessageResponse::Task(task),
            input_limits: smesh_a2a::InputLimits::default(),
            now: 1_700_000_020_011,
            max_attempts: 8,
        })
        .await
        .unwrap();
    assert_eq!(
        store
            .ratification_view(&scope, &task_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        RatificationState::Superseded
    );
}

#[tokio::test]
async fn sqlite_corruption_before_amendment_claim_returns_no_lease_or_receiver_effect() {
    use smesh_a2a::RatificationAuthority as _;

    let (fixture, store, task_id, _approved, scope, packet) =
        integrated_ratification_fixture(27).await;
    store
        .acknowledge_ratification_review(
            &scope,
            integrated_review(&packet, &scope, &task_id, "claim-corruption-review"),
            integrated_audit(
                &packet,
                &scope,
                &task_id,
                "claim-corruption-review-audit",
                "ratificationReview",
                1_700_000_020_003,
            ),
        )
        .await
        .unwrap();
    store
        .decide_ratification(
            &scope,
            integrated_decision(
                &packet,
                &scope,
                &task_id,
                "claim-corruption-amend",
                HumanDecision::Amend,
            ),
            integrated_audit(
                &packet,
                &scope,
                &task_id,
                "claim-corruption-amend-audit",
                "ratificationDecide",
                1_700_000_020_004,
            ),
        )
        .await
        .unwrap();

    let connection = rusqlite::Connection::open(&fixture.0).unwrap();
    connection
        .execute(
            "UPDATE ratification_ledger_anchor SET packet_count=packet_count+1 WHERE singleton=1",
            [],
        )
        .unwrap();
    let before: (String, i64, i64) = connection
        .query_row(
            "SELECT state,attempt_count,(SELECT count(*) FROM receiver_inbox)
             FROM outbox WHERE task_id=?1 AND ratification_required=1",
            [&task_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert!(
        store
            .claim_outbox("corrupt-amend-worker".to_owned(), 1_700_000_020_005, 60_000)
            .await
            .is_err()
    );
    let after: (String, i64, i64) = connection
        .query_row(
            "SELECT state,attempt_count,(SELECT count(*) FROM receiver_inbox)
             FROM outbox WHERE task_id=?1 AND ratification_required=1",
            [&task_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        after, before,
        "claim failure must leave no lease or receiver effect"
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One transaction/race/restart matrix shares a single fixture flow.
async fn sqlite_ratification_reject_amend_race_restart_and_atomic_rollback() {
    use smesh_a2a::{RatificationAuthority as _, RatificationState};
    for (suffix, decision, expected_state, expected_task_state) in [
        (
            1,
            HumanDecision::Reject,
            RatificationState::Rejected,
            a2a::TaskState::Rejected,
        ),
        (
            2,
            HumanDecision::Amend,
            RatificationState::Amended,
            a2a::TaskState::InputRequired,
        ),
    ] {
        let (fixture, store, task_id, _approved, scope, packet) =
            integrated_ratification_fixture(suffix).await;
        store
            .acknowledge_ratification_review(
                &scope,
                integrated_review(&packet, &scope, &task_id, &format!("review-{suffix}")),
                integrated_audit(
                    &packet,
                    &scope,
                    &task_id,
                    &format!("audit-review-{suffix}"),
                    "ratificationReview",
                    1_700_000_020_003,
                ),
            )
            .await
            .unwrap();
        store
            .decide_ratification(
                &scope,
                integrated_decision(
                    &packet,
                    &scope,
                    &task_id,
                    &format!("decision-{suffix}"),
                    decision,
                ),
                integrated_audit(
                    &packet,
                    &scope,
                    &task_id,
                    &format!("audit-decision-{suffix}"),
                    "ratificationDecide",
                    1_700_000_020_004,
                ),
            )
            .await
            .unwrap();
        assert_eq!(
            store.get(&task_id).await.unwrap().unwrap().status.state,
            expected_task_state
        );
        assert_eq!(
            store
                .ratification_view(&scope, &task_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            expected_state
        );
        if expected_state == RatificationState::Amended {
            let lease = store
                .claim_outbox("amend-worker".to_owned(), 1_700_000_020_005, 60_000)
                .await
                .unwrap()
                .unwrap();
            assert!(lease.ratification_required);
            let before = store.atomic_record_counts().await.unwrap();
            let still_private = store.get(&task_id).await.unwrap().unwrap();
            let mut downgraded = lease.clone();
            downgraded.ratification_required = false;
            let mut forged_terminal = still_private.clone();
            forged_terminal.status = a2a::TaskStatus {
                state: a2a::TaskState::Completed,
                message: Some(a2a::Message::new(
                    a2a::Role::Agent,
                    vec![a2a::Part::text("unratified amendment result")],
                )),
                timestamp: chrono::DateTime::from_timestamp_millis(1_700_000_020_006),
            };
            let forged_transcript = [
                a2a::StreamResponse::Task(still_private.clone()),
                a2a::StreamResponse::StatusUpdate(a2a::TaskStatusUpdateEvent {
                    task_id: forged_terminal.id.clone(),
                    context_id: forged_terminal.context_id.clone(),
                    status: forged_terminal.status.clone(),
                    metadata: None,
                }),
            ];
            assert!(
                store
                    .commit_delivery(
                        &downgraded,
                        forged_terminal.clone(),
                        a2a::SendMessageResponse::Task(forged_terminal),
                        &forged_transcript,
                        1_700_000_020_006,
                    )
                    .await
                    .is_err(),
                "cloning and downgrading a durable amendment lease must not enable generic commit"
            );
            assert!(
                store
                    .commit_delivery(
                        &lease,
                        still_private.clone(),
                        a2a::SendMessageResponse::Task(still_private),
                        &[],
                        1_700_000_020_006,
                    )
                    .await
                    .is_err()
            );
            assert_eq!(store.atomic_record_counts().await.unwrap(), before);
        }
        drop(store);
        let reopened = SqliteTaskStore::open_with_ratification_key(
            &fixture.0,
            16,
            zeroize::Zeroizing::new([0x52; 32]),
            false,
        )
        .await
        .unwrap();
        assert_eq!(
            reopened
                .ratification_view(&scope, &task_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            expected_state
        );
        if expected_state == RatificationState::Amended {
            let reclaimed = reopened
                .claim_outbox("amend-worker-restart".to_owned(), 1_700_000_080_006, 60_000)
                .await
                .unwrap()
                .unwrap();
            assert!(reclaimed.ratification_required);
            let mut downgraded = reclaimed.clone();
            downgraded.ratification_required = false;
            let connection = rusqlite::Connection::open(&fixture.0).unwrap();
            connection
                .execute(
                    "UPDATE ratification_ledger_anchor SET packet_count=packet_count+1 WHERE singleton=1",
                    [],
                )
                .unwrap();
            assert!(
                reopened
                    .finish_outbox_attempt(
                        &downgraded,
                        smesh_a2a::AttemptDisposition::Permanent {
                            error: "sabotaged amendment failure".to_owned(),
                        },
                        1_700_000_080_007,
                    )
                    .await
                    .is_err(),
                "downgrading the cloned lease must not bypass amendment anchor authentication"
            );
        }
    }

    let (_fixture, store, task_id, _approved, scope, packet) =
        integrated_ratification_fixture(3).await;
    store
        .acknowledge_ratification_review(
            &scope,
            integrated_review(&packet, &scope, &task_id, "race-review"),
            integrated_audit(
                &packet,
                &scope,
                &task_id,
                "race-review-audit",
                "ratificationReview",
                1_700_000_020_003,
            ),
        )
        .await
        .unwrap();
    let (approve, reject) = tokio::join!(
        store.decide_ratification(
            &scope,
            integrated_decision(
                &packet,
                &scope,
                &task_id,
                "race-approve",
                HumanDecision::Approve
            ),
            integrated_audit(
                &packet,
                &scope,
                &task_id,
                "race-approve-audit",
                "ratificationDecide",
                1_700_000_020_004
            )
        ),
        store.decide_ratification(
            &scope,
            integrated_decision(
                &packet,
                &scope,
                &task_id,
                "race-reject",
                HumanDecision::Reject
            ),
            integrated_audit(
                &packet,
                &scope,
                &task_id,
                "race-reject-audit",
                "ratificationDecide",
                1_700_000_020_004
            )
        ),
    );
    assert_eq!(
        usize::from(approve.is_ok()) + usize::from(reject.is_ok()),
        1
    );

    let (fixture, store, task_id, _approved, scope, packet) =
        integrated_ratification_fixture(4).await;
    let review_audit = integrated_audit(
        &packet,
        &scope,
        &task_id,
        "rollback-audit",
        "ratificationReview",
        1_700_000_020_003,
    );
    store
        .acknowledge_ratification_review(
            &scope,
            integrated_review(&packet, &scope, &task_id, "rollback-review"),
            review_audit,
        )
        .await
        .unwrap();
    let duplicate_audit = integrated_audit(
        &packet,
        &scope,
        &task_id,
        "rollback-audit",
        "ratificationDecide",
        1_700_000_020_004,
    );
    assert!(
        store
            .decide_ratification(
                &scope,
                integrated_decision(
                    &packet,
                    &scope,
                    &task_id,
                    "rollback-decision",
                    HumanDecision::Approve
                ),
                duplicate_audit
            )
            .await
            .is_err()
    );
    assert_eq!(
        store
            .ratification_view(&scope, &task_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        RatificationState::Reviewed
    );
    assert_eq!(
        store.get(&task_id).await.unwrap().unwrap().status.state,
        a2a::TaskState::InputRequired
    );
    drop(store);
    let connection = rusqlite::Connection::open(&fixture.0).unwrap();
    assert!(
        connection
            .execute("UPDATE ratification_events SET receipt_json='{}'", [])
            .is_err()
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // This is one vertical approval transaction and replay proof.
async fn sqlite_ratification_review_and_approval_publish_the_sealed_candidate() {
    use smesh_a2a::{
        AuthorizationAuditInput, AuthorizationDecisionEffect, OwnedTaskScope,
        RatificationAuthority as _, RatificationState, VisibilityScope,
    };

    let fixture = Fixture::new();
    let store = SqliteTaskStore::open_with_ratification_key(
        &fixture.0,
        16,
        zeroize::Zeroizing::new([0x52; 32]),
        false,
    )
    .await
    .unwrap();
    let scope = OwnedTaskScope::new_with_principal_and_authentication(
        smesh_a2a::TRUSTED_SINGLE_TENANT_SCOPE,
        "smesh-dev-only-account",
        "smesh-dev-only-account",
        VisibilityScope::Tenant,
        "trusted-local",
    )
    .unwrap();
    let mut admission = durable_admission();
    admission.streaming = true;
    let task_id = admission.task.id.clone();
    let admission_audit = AuthorizationAuditInput::new(
        "review-approval-admission-audit",
        scope.tenant_scope(),
        scope.owner_account_id(),
        "smesh-dev-only-policy",
        1,
        smesh_a2a::content_digest(b"smesh-dev-only-policy/v1"),
        "taskCreate",
        AuthorizationDecisionEffect::Allow,
        "authorized",
        "task",
        smesh_a2a::content_digest(task_id.as_bytes()),
        Some(task_id.clone()),
        admission.now,
    )
    .unwrap();
    smesh_a2a::TaskAdmission::authorize_and_admit(&store, &scope, admission, admission_audit)
        .await
        .unwrap();
    let lease = store
        .claim_outbox("ratification-worker".to_owned(), 1_700_000_010_001, 60_000)
        .await
        .unwrap()
        .unwrap();
    let initial = store.get(&task_id).await.unwrap().unwrap();
    let mut approved = initial.clone();
    approved.status.state = a2a::TaskState::Completed;
    approved.status.message = Some(a2a::Message::new(
        a2a::Role::Agent,
        vec![a2a::Part::text("approved")],
    ));
    approved.status.timestamp = chrono::DateTime::from_timestamp_millis(1_700_000_010_002);
    approved.artifacts = Some(vec![a2a::Artifact {
        artifact_id: "artifact-ratified".to_owned(),
        name: Some("release.txt".to_owned()),
        description: None,
        parts: vec![a2a::Part::text("sealed candidate")],
        metadata: None,
        extensions: None,
    }]);
    let transcript = vec![
        a2a::StreamResponse::Task(initial),
        a2a::StreamResponse::StatusUpdate(a2a::TaskStatusUpdateEvent {
            task_id: approved.id.clone(),
            context_id: approved.context_id.clone(),
            status: approved.status.clone(),
            metadata: None,
        }),
    ];
    store
        .commit_delivery_for_ratification(
            &lease,
            approved.clone(),
            a2a::SendMessageResponse::Task(approved.clone()),
            &transcript,
            AuthoritativeReviewCandidate::new(
                "release-policy",
                7,
                smesh_a2a::content_digest(b"release-policy-v7"),
                b"sealed-checkpoint-v7".to_vec(),
                vec![b"review evidence: tests passed".to_vec()],
                "bounded uncertainty",
            )
            .unwrap(),
            1_700_000_010_002,
        )
        .await
        .unwrap();

    let view = store
        .ratification_view(&scope, &task_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(view.state, RatificationState::AwaitingReview);
    let packet = view.packet;
    let make_audit = |id: &str, operation: &str, at| {
        AuthorizationAuditInput::new(
            id,
            scope.tenant_scope(),
            scope.owner_account_id(),
            packet.authorization_policy_id.clone(),
            packet.authorization_policy_revision,
            packet.authorization_policy_digest.clone(),
            operation,
            AuthorizationDecisionEffect::Allow,
            "authorized",
            "ratification",
            packet.packet_hash.clone(),
            Some(task_id.clone()),
            at,
        )
        .unwrap()
    };
    let review = ReviewAcknowledgement {
        tenant_id: scope.tenant_scope().to_owned(),
        task_id: task_id.clone(),
        generation: packet.generation,
        account_id: scope.owner_account_id().to_owned(),
        authorization_policy_id: packet.authorization_policy_id.clone(),
        authorization_policy_revision: packet.authorization_policy_revision,
        authorization_policy_digest: packet.authorization_policy_digest.clone(),
        principal_scope: scope.principal_scope().to_owned(),
        authentication_method: scope.authentication_method().to_owned(),
        context_id: packet.context_id.clone(),
        request_digest: packet.request_digest.clone(),
        ratification_key_generation: packet.ratification_key_generation.clone(),
        expected_revision: 0,
        checkpoint_hash: packet.checkpoint_hash.clone(),
        packet_hash: packet.packet_hash.clone(),
        evidence_hashes: packet.evidence_hashes.clone(),
        artifact_hashes: packet.artifacts.iter().map(|a| a.digest.clone()).collect(),
        artifact_manifest_digest: packet.artifact_set_digest.clone(),
        uncertainty_acknowledged: true,
        idempotency_key: "review-approve".to_owned(),
        reviewed_at_millis: 1_700_000_010_003,
    };
    let review_replay = ReviewAcknowledgement {
        reviewed_at_millis: review.reviewed_at_millis + 99,
        ..review.clone()
    };
    let reviewed = store
        .acknowledge_ratification_review(
            &scope,
            review,
            make_audit("review-authorized", "ratificationReview", 1_700_000_010_003),
        )
        .await
        .unwrap();
    let replayed = store
        .acknowledge_ratification_review(
            &scope,
            review_replay.clone(),
            make_audit("review-replay", "ratificationReview", 1_700_000_010_102),
        )
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_vec(&reviewed).unwrap(),
        serde_json::to_vec(&replayed).unwrap()
    );
    assert!(
        store
            .acknowledge_ratification_review(
                &scope,
                review_replay,
                make_audit("review-replay", "ratificationReview", 1_700_000_010_103),
            )
            .await
            .is_err()
    );
    assert_eq!(
        store
            .ratification_view(&scope, &task_id)
            .await
            .unwrap()
            .unwrap()
            .history
            .len(),
        1
    );
    let command = RatificationCommand {
        tenant_id: scope.tenant_scope().to_owned(),
        task_id: task_id.clone(),
        generation: packet.generation,
        account_id: scope.owner_account_id().to_owned(),
        authorization_policy_id: packet.authorization_policy_id.clone(),
        authorization_policy_revision: packet.authorization_policy_revision,
        authorization_policy_digest: packet.authorization_policy_digest.clone(),
        principal_scope: scope.principal_scope().to_owned(),
        authentication_method: scope.authentication_method().to_owned(),
        context_id: packet.context_id.clone(),
        request_digest: packet.request_digest.clone(),
        ratification_key_generation: packet.ratification_key_generation.clone(),
        expected_revision: 1,
        checkpoint_hash: packet.checkpoint_hash.clone(),
        packet_hash: packet.packet_hash.clone(),
        artifact_manifest_digest: packet.artifact_set_digest.clone(),
        idempotency_key: "decision-approve".to_owned(),
        decision: HumanDecision::Approve,
        rationale: "approved exact sealed candidate".to_owned(),
        decided_at_millis: 1_700_000_010_004,
    };
    let cross_context = RatificationCommand {
        context_id: "cross-context".to_owned(),
        idempotency_key: "decision-cross-context".to_owned(),
        ..command.clone()
    };
    assert!(
        store
            .decide_ratification(
                &scope,
                cross_context,
                make_audit(
                    "decision-cross-context",
                    "ratificationDecide",
                    1_700_000_010_004
                ),
            )
            .await
            .is_err()
    );
    let stale_policy = RatificationCommand {
        authorization_policy_revision: command.authorization_policy_revision + 1,
        idempotency_key: "decision-stale-policy".to_owned(),
        ..command.clone()
    };
    assert!(
        store
            .decide_ratification(
                &scope,
                stale_policy,
                make_audit(
                    "decision-stale-policy",
                    "ratificationDecide",
                    1_700_000_010_004
                ),
            )
            .await
            .is_err()
    );
    let decision_replay = RatificationCommand {
        decided_at_millis: command.decided_at_millis + 99,
        ..command.clone()
    };
    let decision = store
        .decide_ratification(
            &scope,
            command,
            make_audit(
                "decision-authorized",
                "ratificationDecide",
                1_700_000_010_004,
            ),
        )
        .await
        .unwrap();
    let replayed_decision = store
        .decide_ratification(
            &scope,
            decision_replay.clone(),
            make_audit("decision-replay", "ratificationDecide", 1_700_000_010_103),
        )
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_vec(&decision).unwrap(),
        serde_json::to_vec(&replayed_decision).unwrap()
    );
    assert!(
        store
            .decide_ratification(
                &scope,
                decision_replay,
                make_audit("decision-replay", "ratificationDecide", 1_700_000_010_104),
            )
            .await
            .is_err()
    );
    assert_eq!(
        store
            .ratification_view(&scope, &task_id)
            .await
            .unwrap()
            .unwrap()
            .history
            .len(),
        2
    );

    assert_eq!(store.get(&task_id).await.unwrap().unwrap(), approved);
    let decided = store
        .ratification_view(&scope, &task_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(decided.state, RatificationState::Approved);
    assert_eq!(decided.revision, 2);
    drop(store);
    let connection = rusqlite::Connection::open(&fixture.0).unwrap();
    let persisted_result: String = connection
        .query_row(
            "SELECT final_result_json FROM idempotency_records WHERE task_id=?1",
            [&task_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        persisted_result,
        serde_json::to_string(&a2a::SendMessageResponse::Task(approved.clone())).unwrap()
    );
    let persisted_frames = connection
        .prepare("SELECT frame_json FROM stream_frames WHERE message_id=(SELECT message_id FROM stream_transcripts WHERE task_id=?1) ORDER BY frame_seq")
        .unwrap()
        .query_map([&task_id], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        persisted_frames,
        transcript
            .iter()
            .map(|frame| serde_json::to_string(frame).unwrap())
            .collect::<Vec<_>>()
    );
}

const RATIFICATION_BYTES_SQL: &str = "SELECT
 (SELECT COALESCE(SUM(length(CAST(tenant_scope AS BLOB))+length(CAST(task_id AS BLOB))+length(CAST(checkpoint_hash AS BLOB))+length(CAST(packet_hash AS BLOB))+length(CAST(packet_seal AS BLOB))+length(CAST(packet_json AS BLOB))+length(CAST(approved_task_json AS BLOB))+length(CAST(approved_result_json AS BLOB))+length(CAST(approved_transcript_json AS BLOB))+length(CAST(state AS BLOB))+COALESCE(length(CAST(reviewer_account_id AS BLOB)),0)+COALESCE(length(CAST(head_receipt_hash AS BLOB)),0)+40),0) FROM ratification_packets)+
 (SELECT COALESCE(SUM(length(CAST(tenant_scope AS BLOB))+length(CAST(task_id AS BLOB))+length(CAST(account_id AS BLOB))+length(CAST(action AS BLOB))+length(CAST(command_digest AS BLOB))+length(CAST(idempotency_key AS BLOB))+length(CAST(receipt_json AS BLOB))+length(CAST(receipt_hash AS BLOB))+length(CAST(receipt_seal AS BLOB))+COALESCE(length(CAST(previous_receipt_hash AS BLOB)),0)+24),0) FROM ratification_events)";

fn ratification_test_mac(domain: &[u8], payload: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(&[0x52; 32]).unwrap();
    mac.update(domain);
    mac.update(payload);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct RatificationPacketStatement<'a> {
    input: &'a ReviewPacketInput,
    revision: u64,
}

fn reseal_ratification_test_packet(packet: &mut smesh_a2a::ReviewPacket) {
    let statement = RatificationPacketStatement {
        input: &packet.input,
        revision: packet.revision,
    };
    packet.packet_hash = smesh_a2a::content_digest(&serde_json::to_vec(&statement).unwrap());
    packet.seal = ratification_test_mac(
        b"smesh-human-ratification-packet/v1\0",
        packet.packet_hash.as_bytes(),
    );
}

fn reseal_integrated_ratification_anchor(db: &rusqlite::Connection) {
    let retained_bytes: i64 = db
        .query_row(RATIFICATION_BYTES_SQL, [], |row| row.get(0))
        .unwrap();
    let mut canonical = Vec::new();
    let mut packet_count = 0_i64;
    for query in [
        "SELECT json_array(tenant_scope,task_id,generation,task_revision,checkpoint_hash,packet_hash,packet_seal,packet_json,approved_task_json,approved_result_json,approved_transcript_json,state,revision,reviewer_account_id,head_receipt_hash,created_at,updated_at) FROM ratification_packets ORDER BY tenant_scope,task_id,generation",
        "SELECT json_array(tenant_scope,task_id,generation,revision,account_id,action,command_digest,idempotency_key,receipt_json,receipt_hash,receipt_seal,previous_receipt_hash,occurred_at) FROM ratification_events ORDER BY tenant_scope,task_id,generation,revision",
    ] {
        let mut statement = db.prepare(query).unwrap();
        for row in statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
        {
            let encoded = row.unwrap();
            canonical.extend_from_slice(&u64::try_from(encoded.len()).unwrap().to_be_bytes());
            canonical.extend_from_slice(encoded.as_bytes());
            if query.contains("ratification_packets") {
                packet_count += 1;
            }
        }
    }
    let event_count: i64 = db
        .query_row("SELECT count(*) FROM ratification_events", [], |row| {
            row.get(0)
        })
        .unwrap();
    canonical.extend_from_slice(&packet_count.to_be_bytes());
    canonical.extend_from_slice(&event_count.to_be_bytes());
    canonical.extend_from_slice(&retained_bytes.to_be_bytes());
    let state_hash = smesh_a2a::content_digest(&canonical);
    let key_generation = smesh_a2a::content_digest(&[0x52; 32]);
    let payload =
        format!("{key_generation}:{packet_count}:{event_count}:{retained_bytes}:{state_hash}");
    let state_seal = ratification_test_mac(
        b"smesh-integrated-ratification-ledger-anchor/v1\0",
        payload.as_bytes(),
    );
    db.execute(
        "UPDATE ratification_ledger_anchor SET packet_count=?1,event_count=?2,retained_bytes=?3,state_hash=?4,state_seal=?5 WHERE singleton=1",
        rusqlite::params![packet_count,event_count,retained_bytes,state_hash,state_seal],
    )
    .unwrap();
}

fn pad_integrated_ratification_to_limit(path: &std::path::Path, limit: i64) {
    let mut db = rusqlite::Connection::open(path).unwrap();
    db.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
    let (source_packet_json, source_approved_task_json): (String, String) = db
        .query_row(
            "SELECT packet_json,approved_task_json FROM ratification_packets WHERE generation=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let source_packet: smesh_a2a::ReviewPacket = serde_json::from_str(&source_packet_json).unwrap();
    let source_task: serde_json::Value = serde_json::from_str(&source_approved_task_json).unwrap();
    let mut clone_index = 0_u64;
    loop {
        let current: i64 = db
            .query_row(RATIFICATION_BYTES_SQL, [], |row| row.get(0))
            .unwrap();
        if limit - current <= 900_000 {
            break;
        }
        clone_index += 1;
        let clone_task_id = format!("capacity-padding-{clone_index}");
        let mut approved_task = source_task.clone();
        approved_task["id"] = serde_json::Value::String(clone_task_id.clone());
        approved_task["metadata"] = serde_json::json!({"capacityPadding": "x".repeat(800_000)});
        let approved_task_json = serde_json::to_string(&approved_task).unwrap();
        assert!(approved_task_json.len() <= 1024 * 1024);
        let mut packet = source_packet.clone();
        packet.input.task_id.clone_from(&clone_task_id);
        packet.input.approved_task_digest =
            smesh_a2a::content_digest(approved_task_json.as_bytes());
        reseal_ratification_test_packet(&mut packet);
        db.execute(
            "INSERT INTO tasks(task_id,context_id,state,status_timestamp,revision,task_json,tenant_scope,owner_account_id,principal_scope,authentication_method)
             SELECT ?1,context_id,state,status_timestamp,revision,task_json,tenant_scope,owner_account_id,principal_scope,authentication_method
             FROM tasks ORDER BY created_order LIMIT 1",
            [&clone_task_id],
        )
        .unwrap();
        db.execute(
            "INSERT INTO ratification_packets(tenant_scope,task_id,generation,task_revision,checkpoint_hash,packet_hash,packet_seal,packet_json,approved_task_json,approved_result_json,approved_transcript_json,state,revision,reviewer_account_id,head_receipt_hash,created_at,updated_at)
             SELECT tenant_scope,?1,1,task_revision,checkpoint_hash,?2,?3,?4,?5,approved_result_json,approved_transcript_json,state,revision,reviewer_account_id,head_receipt_hash,created_at,updated_at
             FROM ratification_packets WHERE generation=1 ORDER BY task_id LIMIT 1",
            rusqlite::params![
                clone_task_id,
                packet.packet_hash,
                packet.seal,
                serde_json::to_string(&packet).unwrap(),
                approved_task_json
            ],
        )
        .unwrap();
    }
    let current: i64 = db
        .query_row(RATIFICATION_BYTES_SQL, [], |row| row.get(0))
        .unwrap();
    let padding = usize::try_from(limit - current).unwrap();
    assert!(padding > 0);
    let (packet_json, mut approved_result_json): (String, String) = db
        .query_row(
            "SELECT packet_json,approved_result_json FROM ratification_packets WHERE task_id='capacity-padding-1'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    approved_result_json.push_str(&" ".repeat(padding));

    let mut packet: smesh_a2a::ReviewPacket = serde_json::from_str(&packet_json).unwrap();
    packet.input.approved_result_digest =
        smesh_a2a::content_digest(approved_result_json.as_bytes());
    reseal_ratification_test_packet(&mut packet);
    let tx = db.transaction().unwrap();
    tx.execute_batch("DROP TRIGGER ratification_packets_identity_immutable;")
        .unwrap();
    tx.execute(
        "UPDATE ratification_packets SET packet_hash=?1,packet_seal=?2,packet_json=?3,approved_result_json=?4 WHERE task_id=?5 AND generation=1",
        rusqlite::params![
            packet.packet_hash,
            packet.seal,
            serde_json::to_string(&packet).unwrap(),
            approved_result_json,
            "capacity-padding-1"
        ],
    )
    .unwrap();
    tx.execute_batch(
        "CREATE TRIGGER ratification_packets_identity_immutable BEFORE UPDATE OF tenant_scope,task_id,generation,task_revision,checkpoint_hash,packet_hash,packet_seal,packet_json,approved_task_json,approved_result_json,approved_transcript_json,created_at ON ratification_packets
         BEGIN SELECT RAISE(ABORT,'ratification packet identity is immutable'); END;",
    )
    .unwrap();
    tx.commit().unwrap();
    reseal_integrated_ratification_anchor(&db);
    assert_eq!(
        db.query_row::<i64, _, _>(RATIFICATION_BYTES_SQL, [], |row| row.get(0))
            .unwrap(),
        limit
    );
}

#[tokio::test]
async fn sqlite_review_capacity_denial_rolls_back_event_packet_and_audit() {
    use smesh_a2a::RatificationAuthority as _;
    let (fixture, store, task_id, _approved, scope, packet) =
        integrated_ratification_fixture(80).await;
    pad_integrated_ratification_to_limit(&fixture.0, 64_i64 * 1024 * 1024);
    let result = store
        .acknowledge_ratification_review(
            &scope,
            integrated_review(&packet, &scope, &task_id, "capacity-review"),
            integrated_audit(
                &packet,
                &scope,
                &task_id,
                "capacity-review-audit",
                "ratificationReview",
                1_700_000_020_003,
            ),
        )
        .await;
    let error = result.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("ratification durable byte capacity reached"),
        "{error}"
    );
    let db = rusqlite::Connection::open(&fixture.0).unwrap();
    let state: (String, i64, i64, i64) = db
        .query_row(
            "SELECT p.state,p.revision,(SELECT count(*) FROM ratification_events),(SELECT count(*) FROM authorization_decisions WHERE decision_id='capacity-review-audit') FROM ratification_packets p",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(state, ("awaiting_review".into(), 0, 0, 0));
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn sqlite_decision_capacity_denial_rolls_back_every_effect() {
    use smesh_a2a::RatificationAuthority as _;
    let (probe_fixture, probe_store, probe_task_id, _approved, probe_scope, probe_packet) =
        integrated_ratification_fixture(83).await;
    let before_review: i64 = rusqlite::Connection::open(&probe_fixture.0)
        .unwrap()
        .query_row(RATIFICATION_BYTES_SQL, [], |row| row.get(0))
        .unwrap();
    probe_store
        .acknowledge_ratification_review(
            &probe_scope,
            integrated_review(
                &probe_packet,
                &probe_scope,
                &probe_task_id,
                "capacity-decision-review",
            ),
            integrated_audit(
                &probe_packet,
                &probe_scope,
                &probe_task_id,
                "capacity-decision-review-audit",
                "ratificationReview",
                1_700_000_020_003,
            ),
        )
        .await
        .unwrap();
    let after_review: i64 = rusqlite::Connection::open(&probe_fixture.0)
        .unwrap()
        .query_row(RATIFICATION_BYTES_SQL, [], |row| row.get(0))
        .unwrap();
    let review_bytes = after_review - before_review;
    drop(probe_store);
    drop(probe_fixture);

    let (fixture, store, task_id, _approved, scope, packet) =
        integrated_ratification_fixture(81).await;
    pad_integrated_ratification_to_limit(&fixture.0, 64_i64 * 1024 * 1024 - review_bytes);
    store
        .acknowledge_ratification_review(
            &scope,
            integrated_review(&packet, &scope, &task_id, "capacity-decision-review"),
            integrated_audit(
                &packet,
                &scope,
                &task_id,
                "capacity-decision-review-audit",
                "ratificationReview",
                1_700_000_020_003,
            ),
        )
        .await
        .unwrap();
    assert_eq!(
        rusqlite::Connection::open(&fixture.0)
            .unwrap()
            .query_row::<i64, _, _>(RATIFICATION_BYTES_SQL, [], |row| row.get(0))
            .unwrap(),
        64_i64 * 1024 * 1024
    );
    let before = store.atomic_record_counts().await.unwrap();
    let result = store
        .decide_ratification(
            &scope,
            integrated_decision(
                &packet,
                &scope,
                &task_id,
                "capacity-decision",
                HumanDecision::Amend,
            ),
            integrated_audit(
                &packet,
                &scope,
                &task_id,
                "capacity-decision-audit",
                "ratificationDecide",
                1_700_000_020_004,
            ),
        )
        .await;
    let error = result.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("ratification durable byte capacity reached"),
        "{error}"
    );
    assert_eq!(store.atomic_record_counts().await.unwrap(), before);
    assert_eq!(
        store.get(&task_id).await.unwrap().unwrap().status.state,
        a2a::TaskState::InputRequired
    );
    let db = rusqlite::Connection::open(&fixture.0).unwrap();
    let state: (String, i64, i64, i64) = db
        .query_row(
            "SELECT p.state,p.revision,(SELECT count(*) FROM ratification_events),(SELECT count(*) FROM authorization_decisions WHERE decision_id='capacity-decision-audit') FROM ratification_packets p",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(state, ("reviewed".into(), 1, 1, 0));
}

#[tokio::test]
async fn sqlite_oversized_ratification_is_capacity_before_json_decode() {
    let (fixture, store, task_id, _approved, scope, _packet) =
        integrated_ratification_fixture(82).await;
    drop(store);
    let db = rusqlite::Connection::open(&fixture.0).unwrap();
    let oversized = serde_json::to_string(&"雪".repeat((64 * 1024 * 1024 / 3) + 1)).unwrap();
    db.execute(
        "INSERT INTO ratification_packets(tenant_scope,task_id,generation,task_revision,checkpoint_hash,packet_hash,packet_seal,packet_json,approved_task_json,approved_result_json,approved_transcript_json,state,revision,created_at,updated_at)
         VALUES(?1,?2,2,1,?3,?4,'seal',?5,'{}','{}','[]','canceled',0,1,1)",
        rusqlite::params![
            scope.tenant_scope(),
            task_id,
            format!("sha256:{}", "3".repeat(64)),
            format!("sha256:{}", "4".repeat(64)),
            oversized
        ],
    )
    .unwrap();
    drop(db);
    let reopened = SqliteTaskStore::open_with_ratification_key(
        &fixture.0,
        16,
        zeroize::Zeroizing::new([0x52; 32]),
        false,
    )
    .await;
    assert!(matches!(
        reopened,
        Err(smesh_a2a::SqliteStoreError::Capacity)
    ));
}
