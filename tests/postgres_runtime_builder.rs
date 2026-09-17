#![cfg(debug_assertions)]

use std::env;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt as _;
use smesh_a2a::auth::{
    AuthState, AuthenticationError, BearerVerifier, PresentedBearer, Principal, PrincipalLimits,
};
use smesh_a2a::{
    AuthorizationPolicy, DispatchError, DurableWorkEnvelope, GatewayConfig, InjectedClock,
    PostgresStoreConfig, PostgresTaskStore, QuotaPolicy, RuntimeEventSink, RuntimeTask,
    RuntimeTaskProcessor, RuntimeWorker, VisibilityScope,
    build_authorized_postgres_runtime_gateway,
};
use smesh_core::{Network, Node};
use smesh_runtime::{RuntimeConfig, SmeshRuntime};
use tokio::sync::oneshot;
use tokio_postgres::NoTls;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt as _;

const WATCHDOG: Duration = Duration::from_secs(30);

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

struct RecordingProcessor {
    observed: Mutex<Option<oneshot::Sender<DurableWorkEnvelope>>>,
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
        events
            .artifact("forged-runtime.txt", "text/plain", "must remain private")
            .await?;
        events
            .propose_completion("runtime terminal proposal")
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
            .with_quota_policy(quota_policy());
        let store = PostgresTaskStore::open(config.clone()).await.unwrap();

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
