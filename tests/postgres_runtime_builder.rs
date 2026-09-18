#![cfg(debug_assertions)]

use std::env;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::Request;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt as _;
use smesh_a2a::auth::{
    AuthState, AuthenticationError, BearerVerifier, PresentedBearer, Principal, PrincipalLimits,
};
use smesh_a2a::{
    AuthorizationPolicy, CandidateGenerationV1, DispatchError, DurableWorkEnvelope, GatewayConfig,
    InjectedClock, IssuerEnrollmentV1, IssuerRoleV1, PostgresStoreConfig, PostgresTaskStore,
    QuotaPolicy, RuntimeEventSink, RuntimeTask, RuntimeTaskProcessor, RuntimeWorker,
    SemanticEvidenceIngestOutcome, TEXT_CONCORDANCE_COMPLETION_POLICY_REVISION_V1,
    TEXT_CONCORDANCE_COMPLETION_POLICY_V1, TextConcordanceCandidatePacketV1,
    TextConcordanceIssuerProcess, TextConcordanceIssuerSet, TextConcordanceLimits, VisibilityScope,
    build_authorized_postgres_runtime_gateway,
    build_authorized_postgres_text_concordance_runtime_gateway, process_text_concordance,
    sign_text_concordance_evidence,
};
use smesh_core::{Network, Node};
use smesh_runtime::{RuntimeConfig, SmeshRuntime};
use tokio::sync::oneshot;
use tokio_postgres::NoTls;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt as _;

const WATCHDOG: Duration = Duration::from_secs(30);

struct IssuerFixture(PathBuf);

impl IssuerFixture {
    fn new() -> Self {
        let path = env::temp_dir().join(format!(
            "smesh-runtime-builder-issuers-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn issuer_set(&self) -> TextConcordanceIssuerSet {
        let program = PathBuf::from(env!("CARGO_BIN_EXE_smesh-text-concordance-issuer"));
        let issuers = [
            (IssuerRoleV1::Review, "builder-review", 1_u8),
            (IssuerRoleV1::Test, "builder-test", 2_u8),
            (IssuerRoleV1::Contradiction, "builder-contradiction", 3_u8),
        ]
        .map(|(role, identity, seed)| {
            let key_file = self.0.join(identity);
            std::fs::write(&key_file, [seed; 32]).unwrap();
            std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
            TextConcordanceIssuerProcess {
                role,
                identity: identity.to_owned(),
                program: program.clone(),
                key_file,
            }
        });
        TextConcordanceIssuerSet::new(issuers).unwrap()
    }
}

impl Drop for IssuerFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn required_url(name: &str) -> Option<String> {
    match env::var(name) {
        Ok(value) => Some(value),
        Err(env::VarError::NotPresent | env::VarError::NotUnicode(_))
            if env::var("SMESH_POSTGRES_TEST_REQUIRED").as_deref() == Ok("1") =>
        {
            panic!("{name} is required")
        }
        Err(_) => {
            eprintln!("skipping PostgreSQL runtime builder test: {name} is absent");
            None
        }
    }
}

struct BuilderVerifier;

#[async_trait]
impl BearerVerifier for BuilderVerifier {
    async fn verify(&self, token: PresentedBearer<'_>) -> Result<Principal, AuthenticationError> {
        if token.as_str() != "builder-agent" {
            return Err(AuthenticationError::InvalidToken);
        }
        Principal::bearer_for_verifier(
            "test:postgres-builder".into(),
            "builder-agent".into(),
            PrincipalLimits::default(),
        )
        .map_err(|_| AuthenticationError::InvalidToken)
    }
}

fn authorization_policy() -> AuthorizationPolicy {
    AuthorizationPolicy::from_json(
        br#"{
          "schemaVersion":"smesh-authz-policy/v1",
          "policyId":"postgres-runtime-builder",
          "revision":7,
          "tenants":[{"id":"tenant-builder","enabled":true}],
          "accounts":[{"id":"builder-agent","kind":"serviceAccount","memberships":[{"tenantId":"tenant-builder","roles":["taskAgent"]}]}],
          "principalBindings":[{"principal":{"issuer":"test:postgres-builder","subject":"builder-agent"},"accountId":"builder-agent"}]
        }"#,
    )
    .unwrap()
}

fn quota_policy() -> Arc<QuotaPolicy> {
    Arc::new(
        QuotaPolicy::from_json(
            br#"{
              "schemaVersion":"smesh-quota-policy/v1","policyId":"builder-quota","revision":1,
              "requestWindowMillis":60000,"reconnectWindowMillis":60000,
              "limits":{
                "requestCount":{"tenant":10,"account":10,"principal":10},
                "concurrentActiveWork":{"tenant":2,"account":2,"principal":2},
                "inputBytes":{"tenant":1048576,"account":1048576,"principal":1048576},
                "outputBytes":{"tenant":1048576,"account":1048576,"principal":1048576},
                "eventCount":{"tenant":64,"account":64,"principal":64},
                "concurrentStreams":{"tenant":2,"account":2,"principal":2},
                "concurrentSubscriptions":{"tenant":2,"account":2,"principal":2},
                "reconnectCount":{"tenant":4,"account":4,"principal":4},
                "retainedAuthorityBytes":{"tenant":16777216,"account":16777216,"principal":16777216}
              },"overrides":[]
            }"#,
        )
        .unwrap(),
    )
}

fn semantic_enrollments_at(now: u64) -> [IssuerEnrollmentV1; 3] {
    [
        (IssuerRoleV1::Review, "builder-review", 1_u8),
        (IssuerRoleV1::Test, "builder-test", 2_u8),
        (IssuerRoleV1::Contradiction, "builder-contradiction", 3_u8),
    ]
    .map(|(issuer_role, issuer_identity, seed)| {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        IssuerEnrollmentV1 {
            tenant_scope: "tenant-builder".to_owned(),
            issuer_role,
            issuer_identity: issuer_identity.to_owned(),
            public_key: URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
            valid_from: now.saturating_sub(60_000),
            expires_at: now.saturating_add(4_000),
            revoked_at: None,
        }
    })
}

fn semantic_enrollments() -> [IssuerEnrollmentV1; 3] {
    [
        (IssuerRoleV1::Review, "builder-review", 1_u8),
        (IssuerRoleV1::Test, "builder-test", 2_u8),
        (IssuerRoleV1::Contradiction, "builder-contradiction", 3_u8),
    ]
    .map(|(issuer_role, issuer_identity, seed)| {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        IssuerEnrollmentV1 {
            tenant_scope: "tenant-builder".to_owned(),
            issuer_role,
            issuer_identity: issuer_identity.to_owned(),
            public_key: URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
            valid_from: 1_600_000_000_000,
            expires_at: 1_800_000_000_000,
            revoked_at: None,
        }
    })
}

struct RecordingProcessor {
    observed: Mutex<Option<oneshot::Sender<DurableWorkEnvelope>>>,
}

struct CompletingProcessor;

#[async_trait]
impl RuntimeTaskProcessor for CompletingProcessor {
    async fn process(
        &self,
        task: RuntimeTask,
        _cancellation: CancellationToken,
        events: RuntimeEventSink,
    ) -> Result<(), DispatchError> {
        let output = process_text_concordance(&task.request.text, TextConcordanceLimits::default())
            .map_err(|_| DispatchError::message("text-concordance processor rejected input"))?;
        events
            .artifact_bytes(
                smesh_a2a::TEXT_CONCORDANCE_ARTIFACT_NAME_V1,
                smesh_a2a::TEXT_CONCORDANCE_MEDIA_TYPE,
                &output.artifact_bytes,
            )
            .await?;
        events
            .propose_completion("text-concordance/v1 candidate proposed")
            .await
    }
}

#[async_trait]
impl RuntimeTaskProcessor for RecordingProcessor {
    async fn process(
        &self,
        task: RuntimeTask,
        _cancellation: CancellationToken,
        events: RuntimeEventSink,
    ) -> Result<(), DispatchError> {
        let envelope = task
            .durable_envelope()
            .expect("production builder must submit authority-owned durable work")
            .clone();
        let output =
            process_text_concordance(&envelope.request().text, TextConcordanceLimits::default())
                .map_err(|_| DispatchError::message("text-concordance processor rejected input"))?;
        events
            .artifact_bytes(
                "text-concordance.json",
                "application/vnd.smesh.text-concordance+json;version=1",
                &output.artifact_bytes,
            )
            .await?;
        events
            .propose_completion("text-concordance/v1 candidate proposed")
            .await?;
        if let Some(sender) = self.observed.lock().unwrap().take() {
            sender.send(envelope).expect("builder observation receiver");
        }
        std::future::pending::<Result<(), DispatchError>>().await
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Keep real-worker observation and durable non-publication witnesses together.
async fn postgres_runtime_builder_uses_real_worker_and_authoritative_envelope() {
    tokio::time::timeout(WATCHDOG, async {
        let Some(admin) = required_url("SMESH_TEST_POSTGRES_ADMIN_URL") else {
            return;
        };
        let Some(runtime_url) = required_url("SMESH_TEST_POSTGRES_RUNTIME_URL") else {
            return;
        };
        let schema = format!("smesh_runtime_builder_{:016x}", rand::random::<u64>());
        let config = PostgresStoreConfig::new(&admin, &runtime_url, &schema)
            .unwrap()
            .with_test_only_insecure_loopback(true)
            .with_test_only_parent_managed_cleanup()
            .with_quota_policy(quota_policy());
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        store
            .initialize_text_concordance_authority(
                "tenant-builder",
                "builder-agent",
                &smesh_a2a::content_digest(
                    b"quota-principal-v1\0test:postgres-builder\0builder-agent",
                ),
                &semantic_enrollments(),
                1_700_000_000_000,
            )
            .await
            .unwrap();
        let semantic_authority = store.clone();

        let mut network = Network::new();
        network.add_node(Node::named("builder-runtime"));
        let runtime = Arc::new(SmeshRuntime::with_network(
            network,
            RuntimeConfig::default(),
        ));
        let (observed_tx, observed_rx) = oneshot::channel();
        let (dispatcher, worker) = RuntimeWorker::spawn(
            runtime,
            "builder-runtime",
            RecordingProcessor {
                observed: Mutex::new(Some(observed_tx)),
            },
            2,
        )
        .await
        .unwrap();
        let policy = Arc::new(authorization_policy());
        let gateway = build_authorized_postgres_runtime_gateway(
            GatewayConfig::new("http://127.0.0.1:1", "postgres-runtime-builder"),
            store,
            Arc::new(dispatcher),
            InjectedClock::new(1_700_000_000_000),
            AuthState::new(Arc::new(BuilderVerifier), [0x94; 32]),
            Arc::clone(&policy),
        )
        .unwrap();

        let mut message = a2a::Message::new(a2a::Role::User, vec![a2a::Part::text("builder work")]);
        message.message_id = "postgres-runtime-builder-message".to_owned();
        message.context_id = Some("postgres-runtime-builder-context".to_owned());
        let params = serde_json::to_value(a2a::SendMessageRequest {
            message,
            configuration: None,
            metadata: None,
            tenant: None,
        })
        .unwrap();
        let admitted_digest = smesh_a2a::canonical_send_message_digest_v2(
            "tenant-builder", "builder-agent",
            &serde_json::from_value(params.clone()).unwrap(), false,
        ).unwrap();
        let router = gateway.router();
        let response = tokio::spawn(async move {
            router
                .oneshot(
                    Request::post("/jsonrpc")
                    .header("authorization", "Bearer builder-agent")
                    .header("x-smesh-tenant", "tenant-builder")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "jsonrpc":"2.0",
                            "id":"builder-request",
                            "method":a2a::jsonrpc::methods::SEND_MESSAGE,
                            "params":params
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
                )
                .await
                .unwrap()
        });
        let envelope = observed_rx.await.expect("runtime processor observation");
        let output = process_text_concordance(
            &envelope.request().text,
            TextConcordanceLimits::default(),
        )
        .unwrap();
        let packet = TextConcordanceCandidatePacketV1 {
            candidate: CandidateGenerationV1 {
                tenant_scope: envelope.scope().tenant_scope().to_owned(),
                task_id: envelope.request().task_id.clone(),
                context_id: envelope.request().context_id.clone(),
                request_digest: output.request_digest,
                artifact_set_digest: output.artifact_set_digest,
                dispatch_id: envelope.correlation().dispatch_id().to_owned(),
                attempt: u64::from(envelope.correlation().attempt()),
                fence: envelope.correlation().fence(),
                completion_policy: TEXT_CONCORDANCE_COMPLETION_POLICY_V1.to_owned(),
                completion_policy_revision: TEXT_CONCORDANCE_COMPLETION_POLICY_REVISION_V1,
            },
            input: envelope.request().text.clone(),
            artifact: URL_SAFE_NO_PAD.encode(output.artifact_bytes),
            observed_conflict_digests: Vec::new(),
        };
        let frozen_id = semantic_authority
            .freeze_text_concordance_candidate(
                &packet,
                r#"{"termination":"success"}"#,
                envelope.scope().account_id(),
                envelope.scope().principal_scope(),
                1_700_000_000_000,
            )
            .await
            .unwrap();
        assert_eq!(frozen_id, packet.candidate.id().unwrap());
        let (mut attack_client, attack_connection) =
            tokio_postgres::connect(&runtime_url, NoTls).await.unwrap();
        let attack_join = tokio::spawn(attack_connection);
        let attack = attack_client.transaction().await.unwrap();
        attack
            .batch_execute(&format!(
                "SET LOCAL ROLE {schema}_runtime; SET LOCAL smesh.tenant_scope='tenant-builder'; SET LOCAL smesh.account_id='builder-agent'"
            ))
            .await
            .unwrap();
        let append = format!(
            "INSERT INTO {schema}.candidate_artifacts(tenant_scope,candidate_generation_id,ordinal,task_id,name,media_type,artifact_digest,artifact_bytes,owner_account_id,principal_scope,created_at)
             SELECT tenant_scope,candidate_generation_id,1,task_id,name,media_type,artifact_digest,artifact_bytes,owner_account_id,principal_scope,created_at
               FROM {schema}.candidate_artifacts
              WHERE tenant_scope='tenant-builder' AND candidate_generation_id=$1 AND ordinal=0"
        );
        assert!(
            attack.execute(&append, &[&frozen_id]).await.is_err(),
            "frozen candidate artifact set remained appendable"
        );
        attack.rollback().await.unwrap();
        drop(attack_client);
        attack_join.await.unwrap().unwrap();
        assert_eq!(
            semantic_authority
                .load_text_concordance_candidate(&packet.candidate.tenant_scope, &frozen_id)
                .await
                .unwrap(),
            packet
        );
        let review = sign_text_concordance_evidence(
            &packet,
            IssuerRoleV1::Review,
            "builder-review".to_owned(),
            &[1_u8; 32],
        )
        .unwrap();
        assert_eq!(
            semantic_authority
                .submit_text_concordance_evidence(&review, 1_700_000_000_000)
                .await
                .unwrap(),
            SemanticEvidenceIngestOutcome::Accepted
        );
        assert_eq!(
            semantic_authority
                .submit_text_concordance_evidence(&review, 1_700_000_000_000)
                .await
                .unwrap(),
            SemanticEvidenceIngestOutcome::Duplicate
        );
        assert!(
            semantic_authority
                .approve_text_concordance_candidate(
                    &packet.candidate.tenant_scope,
                    &frozen_id,
                    1_700_000_000_000,
                )
                .await
                .is_err(),
            "missing role evidence approved the candidate"
        );
        for (role, identity, seed) in [
            (IssuerRoleV1::Test, "builder-test", 2_u8),
            (
                IssuerRoleV1::Contradiction,
                "builder-contradiction",
                3_u8,
            ),
        ] {
            let signed = sign_text_concordance_evidence(
                &packet,
                role,
                identity.to_owned(),
                &[seed; 32],
            )
            .unwrap();
            assert_eq!(
                semantic_authority
                    .submit_text_concordance_evidence(&signed, 1_700_000_000_000)
                    .await
                    .unwrap(),
                SemanticEvidenceIngestOutcome::Accepted
            );
        }
        let approval_receipt = semantic_authority
            .approve_text_concordance_candidate(
                &packet.candidate.tenant_scope,
                &frozen_id,
                1_700_000_000_000,
            )
            .await
            .unwrap();
        assert!(approval_receipt.starts_with("sha256:"));
        let conflicting_output =
            process_text_concordance("builder work!", TextConcordanceLimits::default()).unwrap();
        let mut conflicting = packet.clone();
        conflicting.input = "builder work!".to_owned();
        conflicting.candidate.request_digest = conflicting_output.request_digest;
        conflicting.candidate.artifact_set_digest = conflicting_output.artifact_set_digest;
        conflicting.artifact = URL_SAFE_NO_PAD.encode(conflicting_output.artifact_bytes);
        assert!(
            semantic_authority
                .freeze_text_concordance_candidate(
                    &conflicting,
                    r#"{"termination":"success"}"#,
                    envelope.scope().account_id(),
                    envelope.scope().principal_scope(),
                    1_700_000_000_000,
                )
                .await
                .is_err(),
            "conflicting generation replaced immutable authority"
        );
        let (conflict_client, conflict_connection) =
            tokio_postgres::connect(&runtime_url, NoTls).await.unwrap();
        let conflict_join = tokio::spawn(conflict_connection);
        conflict_client
            .batch_execute(&format!(
                "SET ROLE {schema}_runtime; SET smesh.tenant_scope='tenant-builder'; SET smesh.account_id='builder-agent'"
            ))
            .await
            .unwrap();
        let conflict_witness = conflict_client
            .query_one(
                &format!(
                    "SELECT state,(SELECT count(*)::bigint FROM {schema}.evidence_conflicts WHERE tenant_scope='tenant-builder' AND candidate_generation_id=$1) FROM {schema}.candidate_generations WHERE tenant_scope='tenant-builder' AND candidate_generation_id=$1"
                ),
                &[&frozen_id],
            )
            .await
            .unwrap();
        assert_eq!(conflict_witness.get::<_, String>(0), "conflicted");
        assert_eq!(conflict_witness.get::<_, i64>(1), 1);
        drop(conflict_client);
        conflict_join.await.unwrap().unwrap();
        let shutdown = gateway.shutdown().await;
        assert!(shutdown.is_err(), "post-receive runtime shutdown resolved safely");
        let response = response.await.unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("error").is_some(), "runtime proposal resolved publicly: {json}");
        assert_eq!(envelope.request().protocol, "a2a-v1");
        assert_eq!(envelope.request().text, "builder work");
        assert_eq!(envelope.request().context_id, "postgres-runtime-builder-context");
        assert!(!envelope.request().task_id.is_empty());
        assert_eq!(envelope.scope().tenant_scope(), "tenant-builder");
        assert_eq!(envelope.scope().account_id(), "builder-agent");
        assert_eq!(
            envelope.scope().principal_scope(),
            smesh_a2a::content_digest(
                b"quota-principal-v1\0test:postgres-builder\0builder-agent"
            )
        );
        assert_eq!(envelope.scope().authentication_method(), "bearer-jwt");
        assert_eq!(envelope.scope().visibility(), VisibilityScope::Own);
        assert_eq!(
            envelope.scope().authorization_policy_id(),
            "postgres-runtime-builder"
        );
        assert_eq!(envelope.scope().authorization_policy_revision(), 7);
        assert_eq!(envelope.scope().authorization_policy_digest(), policy.digest());
        assert_eq!(envelope.correlation().tenant_scope(), "tenant-builder");
        assert_eq!(envelope.correlation().dispatch_id().len(), 71);
        assert_ne!(
            envelope.transport_payload_digest(),
            envelope.authorized_request_digest()
        );
        assert_eq!(
            envelope.transport_payload_digest(),
            smesh_a2a::content_digest(&serde_json::to_vec(envelope.request()).unwrap())
        );
        assert_eq!(envelope.authorized_request_digest(), admitted_digest,
            "runtime digest is not the exact canonical admitted A2A digest");
        assert_eq!(envelope.correlation().attempt(), 1);
        assert_eq!(envelope.correlation().fence(), 1);
        let reservation = envelope.execution_reservation().expect("production reservation");
        assert!(!reservation.reservation_id.is_empty());
        assert_eq!(reservation.reservation_version, 1);
        assert_eq!(reservation.policy_id, "builder-quota");
        assert_eq!(reservation.policy_revision, 1);
        assert_eq!(reservation.policy_digest, quota_policy().digest());
        assert_eq!(reservation.budget, envelope.budget());
        assert!(reservation.binding_digest.starts_with("sha256:"));
        assert!(envelope.budget().max_output_bytes() > 0);
        assert!(envelope.budget().max_event_count() > 0);

        let (mut client, connection) = tokio_postgres::connect(&admin, NoTls).await.unwrap();
        let connection = tokio::spawn(async move { connection.await.unwrap() });
        let transaction = client.transaction().await.unwrap();
        transaction
            .query_one(
                "SELECT set_config('smesh.tenant_scope',$1,true)",
                &[&"tenant-builder"],
            )
            .await
            .unwrap();
        let row = transaction
            .query_one(
                &format!(
                    "SELECT o.state,o.attempt_count,o.quota_binding_digest,o.quota_reservation_id,
                       o.quota_reservation_version,o.reserved_output_bytes,o.reserved_event_count,
                       (SELECT t.state FROM {schema}.tasks t WHERE t.tenant_scope=o.tenant_scope AND t.task_id=o.task_id),
                       (SELECT t.task_json FROM {schema}.tasks t WHERE t.tenant_scope=o.tenant_scope AND t.task_id=o.task_id),
                       (SELECT r.state FROM {schema}.receiver_inbox r WHERE r.tenant_scope=o.tenant_scope AND r.dispatch_id=o.dispatch_id),
                       (SELECT count(*)::bigint FROM {schema}.outbox_attempts a WHERE a.finished_at IS NOT NULL),
                       (SELECT count(*)::bigint FROM {schema}.receiver_frames f),
                       (SELECT count(*)::bigint FROM {schema}.artifact_manifests m)
                     FROM {schema}.outbox o WHERE o.dispatch_id=$1"
                ),
                &[&envelope.correlation().dispatch_id()],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, String>(0), "leased");
        assert_eq!(row.get::<_, i64>(1), 1);
        assert_eq!(row.get::<_, String>(2), reservation.binding_digest);
        assert_eq!(row.get::<_, String>(3), reservation.reservation_id);
        assert_eq!(row.get::<_, i64>(4), 1);
        assert_eq!(row.get::<_, i64>(5), i64::try_from(envelope.budget().max_output_bytes()).unwrap());
        assert_eq!(row.get::<_, i64>(6), i64::try_from(envelope.budget().max_event_count()).unwrap());
        assert_eq!(row.get::<_, String>(7), "\"TASK_STATE_SUBMITTED\"");
        let stored: a2a::Task = serde_json::from_str(&row.get::<_, String>(8)).unwrap();
        assert_eq!(stored.id, envelope.request().task_id);
        assert_eq!(stored.context_id, envelope.request().context_id);
        assert!(!stored.status.state.is_terminal());
        assert!(stored.artifacts.is_none());
        assert_eq!(row.get::<_, String>(9), "processing");
        assert_eq!(row.get::<_, i64>(10), 0);
        assert_eq!(row.get::<_, i64>(11), 0);
        assert_eq!(row.get::<_, i64>(12), 0);

        transaction.rollback().await.unwrap();
        drop(client);
        connection.await.unwrap();

        worker.shutdown().await.unwrap();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    })
    .await
    .expect("PostgreSQL runtime builder watchdog");
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn text_concordance_profile_runs_independent_evidence_and_publishes() {
    tokio::time::timeout(WATCHDOG, async {
        let Some(admin) = required_url("SMESH_TEST_POSTGRES_ADMIN_URL") else {
            return;
        };
        let Some(runtime_url) = required_url("SMESH_TEST_POSTGRES_RUNTIME_URL") else {
            return;
        };
        let schema = format!("smesh_semantic_builder_{:016x}", rand::random::<u64>());
        let config = PostgresStoreConfig::new(&admin, &runtime_url, &schema)
            .unwrap()
            .with_test_only_insecure_loopback(true)
            .with_test_only_parent_managed_cleanup()
            .with_quota_policy(quota_policy());
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        store
            .initialize_text_concordance_authority(
                "tenant-builder",
                "builder-agent",
                &smesh_a2a::content_digest(
                    b"quota-principal-v1\0test:postgres-builder\0builder-agent",
                ),
                &semantic_enrollments(),
                1_700_000_000_000,
            )
            .await
            .unwrap();

        let mut network = Network::new();
        network.add_node(Node::named("builder-runtime"));
        let runtime = Arc::new(SmeshRuntime::with_network(
            network,
            RuntimeConfig::default(),
        ));
        let (dispatcher, worker) = RuntimeWorker::spawn(
            runtime,
            "builder-runtime",
            CompletingProcessor,
            2,
        )
        .await
        .unwrap();
        let fixture = IssuerFixture::new();
        let gateway = build_authorized_postgres_text_concordance_runtime_gateway(
            GatewayConfig::new("http://127.0.0.1:1", "postgres-semantic-builder"),
            store,
            Arc::new(dispatcher),
            fixture.issuer_set(),
            Duration::from_secs(5),
            InjectedClock::new(1_700_000_000_000),
            AuthState::new(Arc::new(BuilderVerifier), [0x95; 32]),
            Arc::new(authorization_policy()),
        )
        .unwrap();

        let router = gateway.router();
        let mut invalid = a2a::Message::new(
            a2a::Role::User,
            vec![a2a::Part::text("builder"), a2a::Part::text(" work")],
        );
        invalid.message_id = "postgres-semantic-builder-invalid".to_owned();
        invalid.context_id = Some("postgres-semantic-builder-context".to_owned());
        let invalid_params = serde_json::to_value(a2a::SendMessageRequest {
            message: invalid,
            configuration: None,
            metadata: None,
            tenant: None,
        })
        .unwrap();
        let invalid_response = router
            .clone()
            .oneshot(
                Request::post("/jsonrpc")
                    .header("authorization", "Bearer builder-agent")
                    .header("x-smesh-tenant", "tenant-builder")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "jsonrpc":"2.0",
                            "id":"semantic-builder-invalid",
                            "method":a2a::jsonrpc::methods::SEND_MESSAGE,
                            "params":invalid_params
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let invalid_body = invalid_response.into_body().collect().await.unwrap().to_bytes();
        let invalid_json: serde_json::Value = serde_json::from_slice(&invalid_body).unwrap();
        assert!(
            invalid_json.get("error").is_some(),
            "closed profile admitted multi-part input: {invalid_json}"
        );

        let mut message = a2a::Message::new(a2a::Role::User, vec![a2a::Part::text("builder work")]);
        message.message_id = "postgres-semantic-builder-message".to_owned();
        message.context_id = Some("postgres-semantic-builder-context".to_owned());
        let params = serde_json::to_value(a2a::SendMessageRequest {
            message,
            configuration: None,
            metadata: None,
            tenant: None,
        })
        .unwrap();
        let response = gateway
            .router()
            .oneshot(
                Request::post("/jsonrpc")
                    .header("authorization", "Bearer builder-agent")
                    .header("x-smesh-tenant", "tenant-builder")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "jsonrpc":"2.0",
                            "id":"semantic-builder-request",
                            "method":a2a::jsonrpc::methods::SEND_MESSAGE,
                            "params":params
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("error").is_none(), "semantic profile failed: {json}");

        gateway.shutdown().await.unwrap();
        worker.shutdown().await.unwrap();

        let (mut client, connection) = tokio_postgres::connect(&runtime_url, NoTls).await.unwrap();
        let connection = tokio::spawn(async move { connection.await.unwrap() });
        client
            .batch_execute(&format!("SET ROLE \"{schema}_runtime\""))
            .await
            .unwrap();
        let tx = client.transaction().await.unwrap();
        tx.query_one(
            "SELECT set_config('smesh.tenant_scope',$1,true)",
            &[&"tenant-builder"],
        )
        .await
        .unwrap();
        let row = tx
            .query_one(
                &format!(
                    "SELECT
                       (SELECT count(*)::bigint FROM {schema}.candidate_generations WHERE state='sealed'),
                       (SELECT count(*)::bigint FROM {schema}.issuer_evidence),
                       (SELECT count(*)::bigint FROM {schema}.receiver_inbox WHERE state='completed'),
                       (SELECT count(*)::bigint FROM {schema}.outbox WHERE state='delivered'),
                       (SELECT count(*)::bigint FROM {schema}.artifact_manifests),
                       (SELECT count(*)::bigint FROM {schema}.loopback_effects),
                       (SELECT count(*)::bigint FROM {schema}.tasks WHERE state='\"TASK_STATE_COMPLETED\"'),
                       (SELECT task_json FROM {schema}.tasks WHERE state='\"TASK_STATE_COMPLETED\"')"
                ),
                &[],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, i64>(0), 1);
        assert_eq!(row.get::<_, i64>(1), 3);
        assert_eq!(row.get::<_, i64>(2), 1);
        assert_eq!(row.get::<_, i64>(3), 1);
        assert_eq!(row.get::<_, i64>(4), 0);
        assert_eq!(row.get::<_, i64>(5), 0);
        assert_eq!(row.get::<_, i64>(6), 1);
        let task: a2a::Task = serde_json::from_str(&row.get::<_, String>(7)).unwrap();
        assert_eq!(task.artifacts.as_ref().map(Vec::len), Some(1));
        tx.rollback().await.unwrap();
        drop(client);
        connection.await.unwrap();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    })
    .await
    .expect("PostgreSQL semantic builder watchdog");
}

#[derive(Clone, Copy)]
enum PostApprovalInvalidation {
    Revoke,
    Expire,
}

#[allow(clippy::too_many_lines)] // Keep the trigger, runtime result, and atomic database witnesses in one regression.
async fn post_approval_invalidation_fails_closed(invalidation: PostApprovalInvalidation) {
    tokio::time::timeout(WATCHDOG, async {
        let Some(admin) = required_url("SMESH_TEST_POSTGRES_ADMIN_URL") else {
            return;
        };
        let Some(runtime_url) = required_url("SMESH_TEST_POSTGRES_RUNTIME_URL") else {
            return;
        };
        let schema = format!("smesh_semantic_stale_{:016x}", rand::random::<u64>());
        let config = PostgresStoreConfig::new(&admin, &runtime_url, &schema)
            .unwrap()
            .with_test_only_insecure_loopback(true)
            .with_test_only_trust_injected_time(false)
            .with_test_only_parent_managed_cleanup()
            .with_quota_policy(quota_policy());
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();
        let (clock_client, clock_connection) = tokio_postgres::connect(&admin, NoTls).await.unwrap();
        let clock_join = tokio::spawn(clock_connection);
        let db_now: i64 = clock_client
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        drop(clock_client);
        clock_join.await.unwrap().unwrap();
        store
            .initialize_text_concordance_authority(
                "tenant-builder",
                "builder-agent",
                &smesh_a2a::content_digest(
                    b"quota-principal-v1\0test:postgres-builder\0builder-agent",
                ),
                &semantic_enrollments_at(u64::try_from(db_now).unwrap()),
                db_now,
            )
            .await
            .unwrap();

        let invalidation_sql = match invalidation {
            PostApprovalInvalidation::Revoke => {
                format!(
                    "UPDATE {schema}.issuer_enrollments SET revoked_at={schema}.db_millis()
                       WHERE tenant_scope=NEW.tenant_scope
                         AND issuer_role='text-concordance-review/v1'
                         AND issuer_identity='builder-review';"
                )
            }
            PostApprovalInvalidation::Expire => {
                format!(
                    "LOOP
                       EXIT WHEN EXISTS(
                         SELECT 1 FROM {schema}.issuer_enrollments
                          WHERE tenant_scope=NEW.tenant_scope
                            AND issuer_role='text-concordance-review/v1'
                            AND issuer_identity='builder-review'
                            AND expires_at <= {schema}.db_millis()
                       );
                       PERFORM pg_catalog.pg_sleep(0.01);
                     END LOOP;"
                )
            }
        };
        let (trigger_client, trigger_connection) = tokio_postgres::connect(&admin, NoTls).await.unwrap();
        let trigger_join = tokio::spawn(trigger_connection);
        trigger_client
            .batch_execute(&format!(
                "CREATE FUNCTION {schema}.invalidate_review_after_approval() RETURNS trigger
                 LANGUAGE plpgsql SET search_path=pg_catalog AS $$
                 BEGIN
                   {invalidation_sql}
                   RETURN NEW;
                 END $$;
                 CREATE TRIGGER invalidate_review_after_approval
                 AFTER UPDATE OF completion_receipt ON {schema}.candidate_generations
                 FOR EACH ROW WHEN (OLD.completion_receipt IS NULL AND NEW.completion_receipt IS NOT NULL)
                 EXECUTE FUNCTION {schema}.invalidate_review_after_approval();"
            ))
            .await
            .unwrap();
        drop(trigger_client);
        trigger_join.await.unwrap().unwrap();

        let mut network = Network::new();
        network.add_node(Node::named("builder-runtime"));
        let runtime = Arc::new(SmeshRuntime::with_network(
            network,
            RuntimeConfig::default(),
        ));
        let (dispatcher, worker) = RuntimeWorker::spawn(
            runtime,
            "builder-runtime",
            CompletingProcessor,
            2,
        )
        .await
        .unwrap();
        let fixture = IssuerFixture::new();
        let gateway = build_authorized_postgres_text_concordance_runtime_gateway(
            GatewayConfig::new("http://127.0.0.1:1", "postgres-semantic-stale"),
            store,
            Arc::new(dispatcher),
            fixture.issuer_set(),
            Duration::from_secs(5),
            InjectedClock::new(db_now),
            AuthState::new(Arc::new(BuilderVerifier), [0x96; 32]),
            Arc::new(authorization_policy()),
        )
        .unwrap();

        let mut message = a2a::Message::new(
            a2a::Role::User,
            vec![a2a::Part::text("post approval invalidation")],
        );
        message.message_id = format!(
            "postgres-semantic-stale-{}",
            match invalidation {
                PostApprovalInvalidation::Revoke => "revoke",
                PostApprovalInvalidation::Expire => "expire",
            }
        );
        message.context_id = Some("postgres-semantic-stale-context".to_owned());
        let params = serde_json::to_value(a2a::SendMessageRequest {
            message,
            configuration: None,
            metadata: None,
            tenant: None,
        })
        .unwrap();
        let response = gateway
            .router()
            .oneshot(
                Request::post("/jsonrpc")
                    .header("authorization", "Bearer builder-agent")
                    .header("x-smesh-tenant", "tenant-builder")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "jsonrpc":"2.0",
                            "id":"semantic-stale-request",
                            "method":a2a::jsonrpc::methods::SEND_MESSAGE,
                            "params":params
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json.get("error").is_some(),
            "stale post-approval evidence resolved publicly: {json}"
        );

        assert!(gateway.shutdown().await.is_err());
        worker.shutdown().await.unwrap();
        let (mut witness, witness_connection) = tokio_postgres::connect(&runtime_url, NoTls).await.unwrap();
        let witness_join = tokio::spawn(witness_connection);
        witness
            .batch_execute(&format!("SET ROLE \"{schema}_runtime\""))
            .await
            .unwrap();
        let tx = witness.transaction().await.unwrap();
        tx.query_one(
            "SELECT set_config('smesh.tenant_scope',$1,true)",
            &[&"tenant-builder"],
        )
        .await
        .unwrap();
        let row = tx
            .query_one(
                &format!(
                    "SELECT
                       (SELECT count(*)::bigint FROM {schema}.candidate_generations WHERE state='open' AND completion_receipt IS NOT NULL),
                       (SELECT count(*)::bigint FROM {schema}.candidate_generations WHERE state='sealed'),
                       (SELECT count(*)::bigint FROM {schema}.receiver_inbox WHERE state='processing'),
                       (SELECT count(*)::bigint FROM {schema}.receiver_inbox WHERE state='completed'),
                       (SELECT count(*)::bigint FROM {schema}.outbox WHERE state='leased'),
                       (SELECT count(*)::bigint FROM {schema}.outbox WHERE state='delivered'),
                       (SELECT count(*)::bigint FROM {schema}.receiver_frames),
                       (SELECT count(*)::bigint FROM {schema}.artifact_manifests),
                       (SELECT count(*)::bigint FROM {schema}.tasks WHERE state='\"TASK_STATE_COMPLETED\"'),
                       (SELECT count(*)::bigint FROM {schema}.tasks WHERE task_json::text LIKE '%artifacts%'),
                       (SELECT count(*)::bigint FROM {schema}.issuer_enrollments
                         WHERE issuer_role='text-concordance-review/v1' AND
                           (revoked_at IS NOT NULL OR expires_at <= {schema}.db_millis()))"
                ),
                &[],
            )
            .await
            .unwrap();
        let counts: Vec<i64> = (0..11).map(|column| row.get(column)).collect();
        assert_eq!(counts, vec![1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1]);
        tx.rollback().await.unwrap();
        drop(witness);
        witness_join.await.unwrap().unwrap();
        PostgresTaskStore::drop_test_schema(&config).await.unwrap();
    })
    .await
    .expect("post-approval invalidation watchdog");
}

#[tokio::test]
async fn revoked_after_approval_cannot_complete_receiver_publication() {
    post_approval_invalidation_fails_closed(PostApprovalInvalidation::Revoke).await;
}

#[tokio::test]
async fn expired_after_approval_cannot_complete_receiver_publication() {
    post_approval_invalidation_fails_closed(PostApprovalInvalidation::Expire).await;
}
