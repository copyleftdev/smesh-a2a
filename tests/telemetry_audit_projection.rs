use std::{
    collections::VecDeque,
    str::FromStr as _,
    sync::{Arc, Mutex},
    time::Duration,
};

#[cfg(debug_assertions)]
use std::collections::BTreeMap;

use a2a::A2AError;
use async_trait::async_trait;
use smesh_a2a::telemetry::{AuditProjectorConfig, AuditProjectorWorker, OtlpOwner};
use smesh_a2a::{
    AuditProjectionAuthority, AuditProjectionCapabilities, AuditProjectionEventKind,
    AuditProjectionLease, AuditProjectionSource, AuditProjectionState, AuthorityCapabilities,
    AuthorityIdentity, AuthorizationAuditInput, AuthorizationAuditSink,
    AuthorizationDecisionEffect, SqliteTaskStore,
};

#[derive(Default)]
struct ProjectionFake {
    rows: Mutex<VecDeque<AuditProjectionLease>>,
    delivered: Mutex<Vec<String>>,
    failed: Mutex<Vec<String>>,
    cleanup_calls: Mutex<u64>,
    claimed_owners: Mutex<Vec<String>>,
}

#[async_trait]
impl AuditProjectionAuthority for ProjectionFake {
    fn audit_projection_capabilities(&self) -> AuditProjectionCapabilities {
        AuditProjectionCapabilities {
            enabled: true,
            starts_at_enable: true,
        }
    }
    async fn claim_audit_projection(
        &self,
        owner: &str,
        _lease_duration_ms: i64,
        limit: usize,
    ) -> Result<Vec<AuditProjectionLease>, A2AError> {
        self.claimed_owners.lock().unwrap().push(owner.to_owned());
        let mut rows = self.rows.lock().unwrap();
        Ok((0..limit).filter_map(|_| rows.pop_front()).collect())
    }
    async fn commit_audit_projection(
        &self,
        lease: &AuditProjectionLease,
    ) -> Result<bool, A2AError> {
        self.delivered
            .lock()
            .unwrap()
            .push(lease.event_id().to_owned());
        Ok(true)
    }
    async fn fail_audit_projection(
        &self,
        lease: &AuditProjectionLease,
        _error_digest: &str,
        _retry_delay_ms: i64,
    ) -> Result<AuditProjectionState, A2AError> {
        self.failed
            .lock()
            .unwrap()
            .push(lease.event_id().to_owned());
        Ok(AuditProjectionState::Pending)
    }
    async fn cleanup_audit_projection(
        &self,
        _retention_ms: i64,
        _limit: usize,
    ) -> Result<u64, A2AError> {
        *self.cleanup_calls.lock().unwrap() += 1;
        Ok(0)
    }
}

struct Authority(Arc<ProjectionFake>);
impl AuthorityIdentity for Authority {
    fn capabilities(&self) -> AuthorityCapabilities {
        AuthorityCapabilities {
            lease_renewal: false,
            quota_reservations: false,
        }
    }
    fn completion_receipt_key(&self) -> Option<[u8; 32]> {
        None
    }
    fn authorization_resource_digest(&self, _: &str) -> Result<String, A2AError> {
        Ok("sha256:0000000000000000000000000000000000000000000000000000000000000000".into())
    }
    fn audit_projection_authority(&self) -> Option<&dyn AuditProjectionAuthority> {
        Some(self.0.as_ref())
    }
}

#[tokio::test]
async fn replica_ids_are_mapped_to_bounded_distinct_projector_owners() {
    let prefix = "r".repeat(64);
    let replica_ids = [format!("{prefix}a"), format!("{prefix}b"), "z".repeat(128)];
    let mut owners = Vec::new();
    for replica_id in replica_ids {
        let fake = Arc::new(ProjectionFake::default());
        let authority: Arc<dyn AuthorityIdentity> = Arc::new(Authority(Arc::clone(&fake)));
        let (telemetry, _receiver) =
            smesh_a2a::telemetry::TelemetryHandle::multisignal_capture_for_test(16, 0.0);
        let config =
            AuditProjectorConfig::for_replica_id(&replica_id, Duration::from_millis(10), 1)
                .unwrap();
        let worker = AuditProjectorWorker::spawn(authority, telemetry, config).unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while fake.claimed_owners.lock().unwrap().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        worker.shutdown(Duration::from_secs(1)).await.unwrap();
        let owner = fake.claimed_owners.lock().unwrap()[0].clone();
        assert!(owner.len() <= 64);
        assert!(owner.is_ascii());
        owners.push(owner);
    }
    assert_ne!(owners[0], owners[1], "similar long IDs must not collide");
    assert_eq!(
        owners.len(),
        owners
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    );
}

#[test]
fn event_identity_is_stable_digest_only_and_types_are_closed() {
    let a = AuditProjectionLease::new(
        "tenant-digest",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        AuditProjectionSource::AuthorizationDecision,
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        AuditProjectionEventKind::AuthorizationDecided,
        42,
        "owner",
        "token",
        3,
        99,
        1,
    )
    .unwrap();
    assert_eq!(
        a.event_id(),
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert!(!a.event_id().contains("tenant-digest"));
    assert_eq!(a.source(), AuditProjectionSource::AuthorizationDecision);
}

#[test]
fn callback_projection_types_are_distinct_and_closed() {
    let sources = [
        AuditProjectionSource::CallbackPolicy,
        AuditProjectionSource::CallbackConfig,
        AuditProjectionSource::CallbackEvent,
        AuditProjectionSource::CallbackAttempt,
    ];
    assert_eq!(
        sources.map(AuditProjectionSource::as_str),
        [
            "callback_policy_snapshots",
            "callback_configs",
            "callback_events",
            "callback_attempts",
        ]
    );
    let kinds = [
        AuditProjectionEventKind::CallbackPolicyReconciled,
        AuditProjectionEventKind::CallbackConfigCreated,
        AuditProjectionEventKind::CallbackConfigDeleted,
        AuditProjectionEventKind::CallbackEventEnqueued,
        AuditProjectionEventKind::CallbackDeliveryAttempted,
        AuditProjectionEventKind::CallbackDelivered,
        AuditProjectionEventKind::CallbackRetryScheduled,
        AuditProjectionEventKind::CallbackDead,
    ];
    assert_eq!(
        kinds.map(AuditProjectionEventKind::as_str),
        [
            "callback_policy_reconciled",
            "callback_config_created",
            "callback_config_deleted",
            "callback_event_enqueued",
            "callback_delivery_attempted",
            "callback_delivered",
            "callback_retry_scheduled",
            "callback_dead",
        ]
    );
}

#[tokio::test]
async fn worker_commits_only_after_queue_acceptance_and_retries_queue_full() {
    let fake = Arc::new(ProjectionFake::default());
    fake.rows.lock().unwrap().push_back(
        AuditProjectionLease::new(
            "tenant-digest",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            AuditProjectionSource::TaskEvent,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            AuditProjectionEventKind::TaskTerminal,
            42,
            "owner",
            "token",
            1,
            99,
            1,
        )
        .unwrap(),
    );
    let owner = OtlpOwner::blocked_for_test(0);
    let authority: Arc<dyn AuthorityIdentity> = Arc::new(Authority(Arc::clone(&fake)));
    let config = AuditProjectorConfig::new("worker-1", Duration::from_millis(10), 10).unwrap();
    let worker = AuditProjectorWorker::spawn(authority, owner.handle(), config).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if !fake.failed.lock().unwrap().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    worker.shutdown(Duration::from_secs(1)).await.unwrap();
    assert!(fake.delivered.lock().unwrap().is_empty());
    assert_eq!(fake.failed.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn worker_emits_complete_projection_record_before_commit() {
    use smesh_a2a::telemetry::{AttributeKey, EventName, TelemetryHandle};

    let fake = Arc::new(ProjectionFake::default());
    fake.rows.lock().unwrap().push_back(
        AuditProjectionLease::new(
            "tenant-digest",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            AuditProjectionSource::AuthorizationDecision,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            AuditProjectionEventKind::AuthorizationDecided,
            42,
            "owner",
            "token",
            1,
            99,
            1,
        )
        .unwrap(),
    );
    let (telemetry, receiver) = TelemetryHandle::multisignal_capture_for_test(64, 0.0);
    let authority: Arc<dyn AuthorityIdentity> = Arc::new(Authority(Arc::clone(&fake)));
    let config = AuditProjectorConfig::new("worker-valid", Duration::from_millis(10), 10).unwrap();
    let worker = AuditProjectorWorker::spawn(authority, telemetry, config).unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if fake.delivered.lock().unwrap().len() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    worker.shutdown(Duration::from_secs(1)).await.unwrap();

    let record = receiver
        .try_iter()
        .find(|record| record.name() == EventName::AuditProjectorState.as_str())
        .expect("accepted projection log");
    let attribute = |key: AttributeKey| {
        record
            .attributes()
            .iter()
            .find(|attribute| attribute.key() == key.as_str())
            .map(smesh_a2a::telemetry::Attribute::value)
    };
    assert_eq!(
        attribute(AttributeKey::EventId),
        Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    assert_eq!(
        attribute(AttributeKey::AuditSource),
        Some("authorization_decisions")
    );
    assert_eq!(
        attribute(AttributeKey::Operation),
        Some("authorization_decision")
    );
    assert_eq!(attribute(AttributeKey::Outcome), Some("ok"));
    assert_eq!(attribute(AttributeKey::Reason), Some("committed"));
    assert!(fake.failed.lock().unwrap().is_empty());
}

#[cfg(debug_assertions)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)] // One real trigger/worker/OTLP/restart path is intentionally linear.
async fn sqlite_worker_exports_one_decoded_projection_log_and_does_not_duplicate() {
    use axum::{Router, body::Bytes, extract::State, http::StatusCode, routing::post};
    use opentelemetry_proto::tonic::{
        collector::logs::v1::ExportLogsServiceRequest, common::v1::any_value::Value,
    };
    use prost::Message as _;
    use smesh_a2a::telemetry::OtlpConfig;
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    async fn collect(
        State(sender): State<Arc<mpsc::Sender<Vec<u8>>>>,
        body: Bytes,
    ) -> (StatusCode, [(&'static str, &'static str); 1], Vec<u8>) {
        sender.send(body.to_vec()).await.unwrap();
        (
            StatusCode::OK,
            [("content-type", "application/x-protobuf")],
            Vec::new(),
        )
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, mut receiver) = mpsc::channel(4);
    let stop = CancellationToken::new();
    let server_stop = stop.clone();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/v1/logs", post(collect))
                .with_state(Arc::new(sender)),
        )
        .with_graceful_shutdown(server_stop.cancelled_owned())
        .await
        .unwrap();
    });

    let root = std::env::temp_dir().join(format!(
        "smesh-audit-projector-worker-{}",
        rand::random::<u64>()
    ));
    std::fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = root.join("authority.db");
    let store = Arc::new(
        SqliteTaskStore::open_with_audit_projection(&path, 10)
            .await
            .unwrap(),
    );
    store
        .append_authorization_decision(audit_at(
            "worker-production",
            chrono::Utc::now().timestamp_millis(),
        ))
        .await
        .unwrap();
    let config = OtlpConfig::parse(BTreeMap::from([
        ("SMESH_A2A_OTLP_MODE".to_owned(), "http-protobuf".to_owned()),
        (
            "SMESH_A2A_OTLP_ENDPOINT".to_owned(),
            format!("http://{address}/"),
        ),
        (
            "SMESH_TEST_OTLP_INSECURE_LOOPBACK".to_owned(),
            "1".to_owned(),
        ),
        ("SMESH_A2A_OTLP_LOG_QUEUE".to_owned(), "64".to_owned()),
        ("SMESH_A2A_OTLP_BATCH_SIZE".to_owned(), "1".to_owned()),
    ]))
    .unwrap();
    let owner = OtlpOwner::start(config).unwrap().unwrap();
    let authority: Arc<dyn AuthorityIdentity> = store.clone();
    let projector_config =
        AuditProjectorConfig::new("sqlite-worker", Duration::from_millis(10), 10).unwrap();
    let worker =
        AuditProjectorWorker::spawn(authority, owner.handle(), projector_config.clone()).unwrap();

    let bytes = tokio::time::timeout(Duration::from_secs(3), receiver.recv())
        .await
        .unwrap()
        .unwrap();
    let export = ExportLogsServiceRequest::decode(bytes.as_slice()).unwrap();
    let logs: Vec<_> = export
        .resource_logs
        .iter()
        .flat_map(|resource| &resource.scope_logs)
        .flat_map(|scope| &scope.log_records)
        .collect();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].event_name, "smesh.audit.projector.state");
    let attributes: BTreeMap<_, _> = logs[0]
        .attributes
        .iter()
        .map(|attribute| {
            let value = match attribute
                .value
                .as_ref()
                .and_then(|value| value.value.as_ref())
            {
                Some(Value::StringValue(value)) => value.as_str(),
                other => panic!("unexpected OTLP attribute value: {other:?}"),
            };
            (attribute.key.as_str(), value)
        })
        .collect();
    assert!(attributes["event.id"].starts_with("sha256:"));
    assert_eq!(attributes["smesh.audit.source"], "authorization_decisions");
    assert_eq!(attributes["smesh.operation"], "authorization_decision");
    assert_eq!(attributes["smesh.outcome"], "ok");
    assert_eq!(attributes["smesh.reason"], "committed");

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let state: String = rusqlite::Connection::open(&path)
                .unwrap()
                .query_row("SELECT state FROM audit_projection_outbox", [], |row| {
                    row.get(0)
                })
                .unwrap();
            if state == "delivered" {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    worker.shutdown(Duration::from_secs(1)).await.unwrap();
    let delivered_before: (String, i64) = rusqlite::Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT state, attempts FROM audit_projection_outbox",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();

    let authority: Arc<dyn AuthorityIdentity> = store.clone();
    let second = AuditProjectorWorker::spawn(authority, owner.handle(), projector_config).unwrap();
    second
        .wait_for_completed_cycle(Duration::from_secs(1))
        .await
        .unwrap();
    second.shutdown(Duration::from_secs(1)).await.unwrap();
    let delivered_after: (String, i64) = rusqlite::Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT state, attempts FROM audit_projection_outbox",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(delivered_after, delivered_before);
    assert_eq!(delivered_after.0, "delivered");
    assert!(
        receiver.try_recv().is_err(),
        "delivered row was exported twice"
    );
    assert!(owner.shutdown(Duration::from_secs(3)));

    stop.cancel();
    tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap();
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn worker_periodically_cleans_and_emits_zero_lag_after_backlog_drains() {
    use smesh_a2a::telemetry::{MetricName, Signal, TelemetryHandle};
    let fake = Arc::new(ProjectionFake::default());
    let (telemetry, receiver) = TelemetryHandle::multisignal_capture_for_test(64, 0.0);
    let authority: Arc<dyn AuthorityIdentity> = Arc::new(Authority(Arc::clone(&fake)));
    let config = AuditProjectorConfig::new("worker-clean", Duration::from_millis(10), 10).unwrap();
    let worker = AuditProjectorWorker::spawn(authority, telemetry, config).unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if *fake.cleanup_calls.lock().unwrap() > 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    worker.shutdown(Duration::from_secs(1)).await.unwrap();
    let records: Vec<_> = receiver.try_iter().collect();
    assert!(records.iter().any(|record| {
        record.signal() == Signal::Metric
            && record.name() == MetricName::AuditProjectionLag.as_str()
    }));
}

fn audit(decision: &str) -> AuthorizationAuditInput {
    audit_at(decision, 1_700_000_000_000)
}

fn audit_at(decision: &str, decided_at: i64) -> AuthorizationAuditInput {
    AuthorizationAuditInput::new(
        decision,
        "tenant",
        "actor",
        "policy",
        1,
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "tasks/get",
        AuthorizationDecisionEffect::Deny,
        "denied",
        "task",
        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        None,
        decided_at,
    )
    .unwrap()
}

#[tokio::test]
async fn sqlite_trigger_projects_committed_authority_rows_and_disabled_is_no_mutation() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = std::env::temp_dir().join(format!("smesh-audit-{}", rand::random::<u64>()));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let enabled_path = root.join("enabled.db");
    let enabled = SqliteTaskStore::open_with_audit_projection(&enabled_path, 10)
        .await
        .unwrap();
    enabled
        .append_authorization_decision(audit("decision-enabled"))
        .await
        .unwrap();
    let rows = enabled
        .claim_audit_projection("worker", 30_000, 10)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].source(),
        AuditProjectionSource::AuthorizationDecision
    );
    assert!(enabled.commit_audit_projection(&rows[0]).await.unwrap());
    drop(enabled);

    let disabled_path = root.join("disabled.db");
    let disabled = SqliteTaskStore::open(&disabled_path, 10).await.unwrap();
    disabled
        .append_authorization_decision(audit("decision-disabled"))
        .await
        .unwrap();
    let reader = rusqlite::Connection::open(&disabled_path).unwrap();
    let count: i64 = reader
        .query_row("SELECT count(*) FROM audit_projection_outbox", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count, 0);
    drop(reader);
    drop(disabled);
    for path in [enabled_path, disabled_path] {
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
        let _ = std::fs::remove_file(format!("{}.lock", path.display()));
    }
    let _ = std::fs::remove_dir(root);
}

#[tokio::test]
async fn sqlite_reopen_rejects_semantically_tampered_projection_digests() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = std::env::temp_dir().join(format!("smesh-audit-tamper-{}", rand::random::<u64>()));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.join("tamper.db");
    let store = SqliteTaskStore::open_with_audit_projection(&path, 10)
        .await
        .unwrap();
    store
        .append_authorization_decision(audit("tampered"))
        .await
        .unwrap();
    drop(store);
    let lock = format!("{}.lock", path.display());
    let _ = std::fs::remove_file(&lock);
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE audit_projection_outbox SET source_pk_digest='sha256:GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG'; PRAGMA ignore_check_constraints=OFF;").unwrap();
    drop(db);
    assert!(
        SqliteTaskStore::open_with_audit_projection(&path, 10)
            .await
            .is_err()
    );
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One real PostgreSQL enable/capability/worker path remains auditable.
async fn postgres_starts_at_enable_and_claims_triggered_commits() {
    let required = std::env::var("SMESH_POSTGRES_TEST_REQUIRED").as_deref() == Ok("1");
    let admin = match std::env::var("SMESH_TEST_POSTGRES_ADMIN_URL") {
        Ok(value) => value,
        Err(error) if required => panic!("SMESH_TEST_POSTGRES_ADMIN_URL is required: {error}"),
        Err(_) => return,
    };
    let runtime = match std::env::var("SMESH_TEST_POSTGRES_RUNTIME_URL") {
        Ok(value) => value,
        Err(error) if required => panic!("SMESH_TEST_POSTGRES_RUNTIME_URL is required: {error}"),
        Err(_) => return,
    };
    let schema = format!("smesh_audit_{:016x}", rand::random::<u64>());
    let base = smesh_a2a::PostgresStoreConfig::new(admin.clone(), runtime.clone(), schema.clone())
        .unwrap()
        .with_test_only_insecure_loopback(true);
    let disabled = smesh_a2a::PostgresTaskStore::open(base.clone())
        .await
        .unwrap();
    disabled
        .append_authorization_decision(audit("before-enable"))
        .await
        .unwrap();
    drop(disabled);
    let enabled = Arc::new(
        smesh_a2a::PostgresTaskStore::open(base.with_audit_projection(true))
            .await
            .unwrap(),
    );
    assert!(
        enabled
            .claim_audit_projection("worker", 30_000, 10)
            .await
            .unwrap()
            .is_empty()
    );
    enabled
        .append_authorization_decision(audit_at(
            "after-enable",
            chrono::Utc::now().timestamp_millis(),
        ))
        .await
        .unwrap();
    let (telemetry, receiver) =
        smesh_a2a::telemetry::TelemetryHandle::multisignal_capture_for_test(64, 0.0);
    let authority: Arc<dyn AuthorityIdentity> = enabled.clone();
    let worker = AuditProjectorWorker::spawn(
        authority,
        telemetry,
        AuditProjectorConfig::new("postgres-worker", Duration::from_millis(10), 10).unwrap(),
    )
    .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if receiver
                .try_iter()
                .any(|record| record.name() == "smesh.audit.projector.state")
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (admin_client, admin_connection) = tokio_postgres::connect(&admin, tokio_postgres::NoTls)
        .await
        .unwrap();
    let admin_driver = tokio::spawn(async move {
        let _ = admin_connection.await;
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let state = admin_client
                .query_opt(
                    &format!("SELECT state FROM {schema}.audit_projection_outbox"),
                    &[],
                )
                .await
                .unwrap()
                .map(|row| row.get::<_, String>(0));
            if state.as_deref().is_none_or(|state| state == "delivered") {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    worker.shutdown(Duration::from_secs(1)).await.unwrap();
    drop(admin_client);
    admin_driver.abort();
    let disabled_concurrent = smesh_a2a::PostgresTaskStore::open(
        smesh_a2a::PostgresStoreConfig::new(admin, runtime.clone(), schema.clone())
            .unwrap()
            .with_test_only_insecure_loopback(true),
    )
    .await
    .unwrap();
    disabled_concurrent
        .append_authorization_decision(audit("disabled-concurrent"))
        .await
        .unwrap();
    assert!(
        enabled
            .claim_audit_projection("worker", 30_000, 10)
            .await
            .unwrap()
            .is_empty()
    );

    // A runtime SQL caller cannot forge the server-owned per-backend projection
    // registration by setting the legacy custom GUC.
    let mut raw = tokio_postgres::Config::from_str(&runtime).unwrap();
    raw.options(format!(
        "-c role={schema}_runtime -c smesh.audit_projection=enabled-v1"
    ));
    let (client, connection) = raw.connect(tokio_postgres::NoTls).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let forged = client
        .query(
            &format!("SELECT * FROM {schema}.claim_audit_projection('forged','token',30000,1)"),
            &[],
        )
        .await;
    assert!(
        forged.is_err(),
        "a forged GUC must not register a projection session"
    );
    drop(client);
    driver.abort();
}
