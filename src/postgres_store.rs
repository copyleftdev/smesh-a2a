//! Executable PostgreSQL schema-v6 durable authority adapter.
#![allow(
    clippy::if_not_else,
    clippy::missing_errors_doc,
    clippy::too_many_lines
)]

use std::{
    collections::VecDeque,
    fmt,
    future::Future,
    pin::Pin,
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use a2a::{
    A2AError, ListTasksRequest, ListTasksResponse, Message, Part, Role, SendMessageRequest,
    SendMessageResponse, StreamResponse, Task,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use deadpool_postgres::{Manager, ManagerConfig, Object, Pool, RecyclingMethod, Runtime};
use hmac::{Hmac, Mac};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio_postgres::{NoTls, Row};
use tokio_postgres_rustls::MakeRustlsConnect;
use url::Url;

use crate::{
    AdmissionOutcome, AdmissionRecord, AtomicRecordCounts, AttemptDisposition,
    AuthorityCapabilities, AuthorityDiagnostics, AuthorityIdentity, AuthorityShutdown,
    AuthorizationAuditInput, AuthorizationAuditParts, AuthorizationAuditSink,
    AuthorizationDecisionEffect, AuthorizedMutation, AuthorizedTaskRead, CancellationAuthority,
    CancellationOutcome, ChangeObservation, ChangeObserver, DurableDispatchEnvelope,
    DurableReceiverResult, DurableReceiverTermination, LeaseRenewalOutcome, MeshEvent, MeshRequest,
    OutboxAuthority, OutboxLease, OwnedTaskScope, QuotaReservationInput, ReceiverAdmission,
    ReceiverAuthority, ReceiverLease, SendMessageAdmission, StreamTranscriptBatch,
    SubscriptionCursor, TaskAdmission, TaskEventBatch, TaskLifecycle, TranscriptAuthority,
    TransitionOutcome, VisibilityScope, authorized_message_identity,
    canonical_send_message_digest_v2, content_digest,
};

const MIGRATION_SQL: &str = include_str!("../migrations/postgres/0001_authority_schema_v6.sql");
const MIGRATION_NAME: &str = "0001_authority_schema_v6";
const QUOTA_MIGRATION_SQL: &str =
    include_str!("../migrations/postgres/0002_quota_reservation_seam.sql");
const QUOTA_MIGRATION_NAME: &str = "0002_quota_reservation_seam";
const RECEIVER_FENCE_MIGRATION_SQL: &str =
    include_str!("../migrations/postgres/0003_receiver_sender_fence.sql");
const RECEIVER_FENCE_MIGRATION_NAME: &str = "0003_receiver_sender_fence";
const LOGICAL_SCHEMA_VERSION: i64 = 6;
const MAX_CONFIG_BYTES: usize = 4096;
const PAGE_TOKEN_VERSION: i64 = 1;
const PAGE_TOKEN_KEY_GENERATION: i64 = 1;
const MAX_PAGE_TOKEN_BYTES: usize = 4096;
const SNAPSHOT_TTL_MILLIS: i64 = 5 * 60 * 1_000;
const MAX_ACTIVE_SNAPSHOTS: i64 = 128;
const MAX_SNAPSHOT_BYTES: i64 = 64 * 1024 * 1024;
const MAX_TRANSACTION_ATTEMPTS: usize = 3;
const RETRYABLE_TRANSACTION_MARKER: &str = "__smesh_retryable_postgres_transaction__";
const FINAL_EXPIRY_ERROR: &str = "final outbox attempt lease expired before receiver acceptance";
const STREAM_INTERRUPTION_PREFIX: &str = "durable stream interrupted: ";

/// Deterministic loopback-only transaction faults used by integration tests.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PostgresTransactionTestFault {
    SerializationFailure,
    DeadlockDetected,
    NonRetryable,
    AmbiguousCommit,
}
const EXPECTED_TABLES: &[&str] = &[
    "authorization_decisions",
    "cancellation_intents",
    "idempotency_records",
    "list_page_tokens",
    "list_snapshot_entries",
    "list_snapshots",
    "loopback_effects",
    "outbox",
    "outbox_attempts",
    "quota_reservations",
    "receiver_frames",
    "receiver_inbox",
    "schema_migrations",
    "store_identity",
    "store_metadata",
    "stream_frames",
    "stream_transcripts",
    "task_events",
    "tasks",
];
const TENANT_TABLES: &[&str] = &[
    "authorization_decisions",
    "cancellation_intents",
    "idempotency_records",
    "list_page_tokens",
    "list_snapshot_entries",
    "list_snapshots",
    "loopback_effects",
    "outbox",
    "outbox_attempts",
    "quota_reservations",
    "receiver_frames",
    "receiver_inbox",
    "stream_frames",
    "stream_transcripts",
    "task_events",
    "tasks",
];
const EXPECTED_CUSTOM_INDEXES: &[&str] = &[
    "authorization_decisions_actor_time",
    "authorization_decisions_resource_time",
    "authorization_decisions_tenant_time",
    "cancellation_intents_dispatch_requested",
    "cancellation_intents_task",
    "idempotency_records_task",
    "list_page_tokens_snapshot",
    "list_snapshots_expiry",
    "outbox_due",
    "outbox_task_state",
    "quota_reservations_principal_state",
    "receiver_inbox_reclaim",
    "stream_transcripts_task",
    "task_events_task_revision",
    "tasks_context_state_time",
    "tasks_tenant_context_time_v6",
    "tasks_tenant_owner_context_state_time_v6",
    "tasks_tenant_owner_context_time_v6",
    "tasks_tenant_owner_state_time_v6",
    "tasks_tenant_owner_time_v6",
    "tasks_tenant_state_time_v6",
    "tasks_tenant_time_v6",
];

#[derive(Clone)]
pub struct PostgresStoreConfig {
    migrator_url: Arc<str>,
    runtime_url: Arc<str>,
    schema: Arc<str>,
    pool_size: usize,
    connect_timeout: Duration,
    acquire_timeout: Duration,
    test_only_insecure_loopback: bool,
    trust_injected_time: bool,
    max_tasks: usize,
    transaction_test_faults: Arc<Mutex<VecDeque<PostgresTransactionTestFault>>>,
    receiver_renewal_test_probe: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
    test_cleanup: Option<Arc<PostgresTestCleanup>>,
}

struct PostgresTestCleanup {
    migrator_url: Arc<str>,
    schema: Arc<str>,
    armed: AtomicBool,
}

impl Drop for PostgresTestCleanup {
    fn drop(&mut self) {
        if !self.armed.load(Ordering::SeqCst) {
            return;
        }
        let url = Arc::clone(&self.migrator_url);
        let schema = Arc::clone(&self.schema);
        let _ = std::thread::spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() else { return; };
            runtime.block_on(async move {
                let Ok(pg) = tokio_postgres::Config::from_str(&url) else { return; };
                let Ok((client, connection)) = pg.connect(NoTls).await else { return; };
                let driver = tokio::spawn(async move { let _ = connection.await; });
                let _ = client.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE; DROP ROLE IF EXISTS {schema}_runtime")).await;
                drop(client);
                driver.abort();
            });
        }).join();
    }
}

impl fmt::Debug for PostgresStoreConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostgresStoreConfig")
            .field("migrator_url", &"<redacted>")
            .field("runtime_url", &"<redacted>")
            .field("schema", &self.schema)
            .field("pool_size", &self.pool_size)
            .field("connect_timeout", &self.connect_timeout)
            .field("acquire_timeout", &self.acquire_timeout)
            .field("max_tasks", &self.max_tasks)
            .field("trust_injected_time", &self.trust_injected_time)
            .field("test_cleanup_enabled", &self.test_cleanup.is_some())
            .field(
                "test_only_insecure_loopback",
                &self.test_only_insecure_loopback,
            )
            .field(
                "transaction_test_fault_count",
                &self
                    .transaction_test_faults
                    .lock()
                    .map_or(0, |faults| faults.len()),
            )
            .field(
                "receiver_renewal_test_probe_enabled",
                &self.receiver_renewal_test_probe.is_some(),
            )
            .finish()
    }
}

impl PostgresStoreConfig {
    pub fn new(
        migrator_url: impl Into<String>,
        runtime_url: impl Into<String>,
        schema: impl Into<String>,
    ) -> Result<Self, PostgresStoreError> {
        let migrator_url = migrator_url.into();
        let runtime_url = runtime_url.into();
        let schema = schema.into();
        if migrator_url.is_empty()
            || migrator_url.len() > MAX_CONFIG_BYTES
            || runtime_url.is_empty()
            || runtime_url.len() > MAX_CONFIG_BYTES
            || migrator_url == runtime_url
            || !valid_identifier(&schema)
        {
            return Err(PostgresStoreError::InvalidConfig);
        }
        for url in [&migrator_url, &runtime_url] {
            let parsed = Url::parse(url).map_err(|_| PostgresStoreError::InvalidConfig)?;
            if !matches!(parsed.scheme(), "postgres" | "postgresql")
                || parsed.host_str().is_none()
                || parsed.username().is_empty()
            {
                return Err(PostgresStoreError::InvalidConfig);
            }
        }
        Ok(Self {
            migrator_url: migrator_url.into(),
            runtime_url: runtime_url.into(),
            schema: schema.into(),
            pool_size: 4,
            connect_timeout: Duration::from_secs(5),
            acquire_timeout: Duration::from_secs(5),
            test_only_insecure_loopback: false,
            trust_injected_time: false,
            max_tasks: 1024,
            transaction_test_faults: Arc::new(Mutex::new(VecDeque::new())),
            receiver_renewal_test_probe: None,
            test_cleanup: None,
        })
    }

    /// Enables plaintext loopback transport and deterministic caller time for the
    /// integration fixture only. Production callers must never enable this escape hatch.
    #[doc(hidden)]
    #[must_use]
    pub fn with_test_only_insecure_loopback(mut self, enabled: bool) -> Self {
        self.test_only_insecure_loopback = enabled;
        self.trust_injected_time = enabled;
        self.test_cleanup = enabled.then(|| {
            Arc::new(PostgresTestCleanup {
                migrator_url: Arc::clone(&self.migrator_url),
                schema: Arc::clone(&self.schema),
                armed: AtomicBool::new(true),
            })
        });
        self
    }

    /// Keep cleanup ownership in a parent process for a shared multi-process fixture.
    #[doc(hidden)]
    #[must_use]
    pub fn with_test_only_parent_managed_cleanup(mut self) -> Self {
        if let Some(cleanup) = self.test_cleanup.take() {
            cleanup.armed.store(false, Ordering::SeqCst);
        }
        self
    }

    /// Keeps the loopback transport fixture while exercising production database time.
    #[doc(hidden)]
    #[must_use]
    pub fn with_test_only_trust_injected_time(mut self, enabled: bool) -> Self {
        self.trust_injected_time = enabled;
        self
    }

    pub fn with_pool_size(mut self, size: usize) -> Result<Self, PostgresStoreError> {
        if !(1..=32).contains(&size) {
            return Err(PostgresStoreError::InvalidConfig);
        }
        self.pool_size = size;
        Ok(self)
    }

    pub fn with_max_tasks(mut self, max_tasks: usize) -> Result<Self, PostgresStoreError> {
        if max_tasks == 0 || max_tasks > 1_000_000 {
            return Err(PostgresStoreError::InvalidConfig);
        }
        self.max_tasks = max_tasks;
        Ok(self)
    }

    pub fn with_timeouts(
        mut self,
        connect: Duration,
        acquire: Duration,
    ) -> Result<Self, PostgresStoreError> {
        if connect.is_zero()
            || acquire.is_zero()
            || connect > Duration::from_secs(30)
            || acquire > Duration::from_secs(30)
        {
            return Err(PostgresStoreError::InvalidConfig);
        }
        self.connect_timeout = connect;
        self.acquire_timeout = acquire;
        Ok(self)
    }

    /// Installs deterministic transaction faults for loopback-only integration tests.
    #[doc(hidden)]
    #[must_use]
    pub fn with_transaction_test_faults(
        mut self,
        faults: impl IntoIterator<Item = PostgresTransactionTestFault>,
    ) -> Self {
        self.transaction_test_faults = Arc::new(Mutex::new(faults.into_iter().collect()));
        self
    }

    /// Installs entry/release checkpoints around receiver renewal for lifecycle tests.
    #[doc(hidden)]
    #[must_use]
    pub fn with_receiver_renewal_test_probe(
        mut self,
        entered: Arc<tokio::sync::Notify>,
        released: Arc<tokio::sync::Notify>,
    ) -> Self {
        self.receiver_renewal_test_probe = Some((entered, released));
        self
    }

    #[must_use]
    pub fn schema_name(&self) -> &str {
        &self.schema
    }

    /// Validate PostgreSQL transport policy without opening a connection.
    ///
    /// This is used by the production binary to reject plaintext configuration
    /// before binding its listener or acquiring durable resources.
    #[doc(hidden)]
    pub fn validate_tls_policy(&self) -> Result<(), PostgresStoreError> {
        validate_tls(self).map(|_| ())
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 48
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PostgresStoreError {
    #[error("invalid PostgreSQL durable-authority configuration")]
    InvalidConfig,
    #[error("PostgreSQL TLS is required")]
    TlsRequired,
    #[error("PostgreSQL durable-authority initialization failed")]
    Initialization,
    #[error("PostgreSQL durable-authority schema is unsupported or corrupt")]
    InvalidSchema,
    #[error("PostgreSQL durable-authority pool is unavailable")]
    Unavailable,
}

#[derive(Clone)]
pub struct PostgresTaskStore {
    pool: Pool,
    schema: Arc<str>,
    cursor_key: Arc<[u8; 32]>,
    receipt_key: Arc<[u8; 32]>,
    acquire_timeout: Duration,
    observation: ChangeObservation,
    max_tasks: usize,
    trust_injected_time: bool,
    transaction_test_faults: Arc<Mutex<VecDeque<PostgresTransactionTestFault>>>,
    transaction_attempts: Arc<AtomicUsize>,
    receiver_renewal_test_probe: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
    _test_cleanup: Option<Arc<PostgresTestCleanup>>,
}

impl PostgresTaskStore {
    pub async fn open(config: PostgresStoreConfig) -> Result<Self, PostgresStoreError> {
        if config.trust_injected_time && !config.test_only_insecure_loopback {
            return Err(PostgresStoreError::InvalidConfig);
        }
        let insecure = validate_tls(&config)?;
        let pg = tokio_postgres::Config::from_str(&config.migrator_url)
            .map_err(|_| PostgresStoreError::InvalidConfig)?;
        let runtime_pg = tokio_postgres::Config::from_str(&config.runtime_url)
            .map_err(|_| PostgresStoreError::InvalidConfig)?;
        let runtime_user = Url::parse(&config.runtime_url)
            .map_err(|_| PostgresStoreError::InvalidConfig)?
            .username()
            .to_owned();
        if !valid_identifier(&runtime_user) {
            return Err(PostgresStoreError::InvalidConfig);
        }
        let (mut migration, driver, manager) = if insecure {
            let (client, connection) =
                tokio::time::timeout(config.connect_timeout, pg.connect(NoTls))
                    .await
                    .map_err(|_| PostgresStoreError::Unavailable)?
                    .map_err(|_| PostgresStoreError::Unavailable)?;
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            let manager = Manager::from_config(
                runtime_pg.clone(),
                NoTls,
                ManagerConfig {
                    recycling_method: RecyclingMethod::Fast,
                },
            );
            (client, driver, manager)
        } else {
            let connector = native_tls_connector()?;
            let (client, connection) =
                tokio::time::timeout(config.connect_timeout, pg.connect(connector.clone()))
                    .await
                    .map_err(|_| PostgresStoreError::Unavailable)?
                    .map_err(|_| PostgresStoreError::Unavailable)?;
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            let manager = Manager::from_config(
                runtime_pg.clone(),
                connector,
                ManagerConfig {
                    recycling_method: RecyclingMethod::Fast,
                },
            );
            (client, driver, manager)
        };
        validate_runtime_login(&migration, &runtime_user).await?;
        migrate(&mut migration, &config.schema, &runtime_user).await?;
        let (cursor_key, receipt_key) = validate_catalog(&migration, &config.schema).await?;
        drop(migration);
        driver.abort();
        let pool = Pool::builder(manager)
            .max_size(config.pool_size)
            .runtime(Runtime::Tokio1)
            .wait_timeout(Some(config.acquire_timeout))
            .create_timeout(Some(config.connect_timeout))
            .recycle_timeout(Some(config.acquire_timeout))
            .build()
            .map_err(|_| PostgresStoreError::Initialization)?;
        let mut object = tokio::time::timeout(config.acquire_timeout, pool.get())
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?
            .map_err(|_| PostgresStoreError::Unavailable)?;
        object
            .simple_query("SELECT 1")
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?;
        // ALLOWLIST: read-only tenant-scoped startup semantic validation.
        let validation = object
            .transaction()
            .await
            .map_err(|_| PostgresStoreError::InvalidSchema)?;
        validation
            .batch_execute(&format!(
                "SET LOCAL ROLE {}_runtime; SET LOCAL statement_timeout='15s'; SET LOCAL lock_timeout='5s'",
                config.schema
            ))
            .await
            .map_err(|_| PostgresStoreError::InvalidSchema)?;
        let task_count: i64 = validation
            .query_one(
                &format!(
                    "SELECT tasks FROM {}.authority_diagnostics_bounded()",
                    config.schema
                ),
                &[],
            )
            .await
            .map_err(|_| PostgresStoreError::InvalidSchema)?
            .get(0);
        if usize::try_from(task_count).unwrap_or(usize::MAX) > config.max_tasks {
            return Err(PostgresStoreError::InvalidSchema);
        }
        let tenants = validation
            .query(
                &format!(
                    "SELECT * FROM {}.authority_tenants_bounded()",
                    config.schema
                ),
                &[],
            )
            .await
            .map_err(|_| PostgresStoreError::InvalidSchema)?;
        for row in tenants {
            let tenant: String = row.get(0);
            validation
                .query_one(
                    "SELECT set_config('smesh.tenant_scope',$1,true), set_config('smesh.account_id','',true)",
                    &[&tenant],
                )
                .await
                .map_err(|_| PostgresStoreError::InvalidSchema)?;
            validate_semantics(&*validation, &config.schema, &cursor_key).await?;
        }
        validation
            .rollback()
            .await
            .map_err(|_| PostgresStoreError::InvalidSchema)?;
        drop(object);
        Ok(Self {
            pool,
            schema: config.schema,
            cursor_key: Arc::new(cursor_key),
            receipt_key: Arc::new(receipt_key),
            acquire_timeout: config.acquire_timeout,
            observation: ChangeObservation::new(Duration::from_millis(100))
                .map_err(|_| PostgresStoreError::Initialization)?,
            max_tasks: config.max_tasks,
            trust_injected_time: config.trust_injected_time,
            transaction_test_faults: config.transaction_test_faults,
            transaction_attempts: Arc::new(AtomicUsize::new(0)),
            receiver_renewal_test_probe: config.receiver_renewal_test_probe,
            _test_cleanup: config.test_cleanup,
        })
    }

    pub async fn drop_test_schema(config: &PostgresStoreConfig) -> Result<(), PostgresStoreError> {
        if !config.test_only_insecure_loopback {
            return Err(PostgresStoreError::InvalidConfig);
        }
        let pg = tokio_postgres::Config::from_str(&config.migrator_url)
            .map_err(|_| PostgresStoreError::InvalidConfig)?;
        let (client, connection) = tokio::time::timeout(config.connect_timeout, pg.connect(NoTls))
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?
            .map_err(|_| PostgresStoreError::Unavailable)?;
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        client
            .batch_execute(&format!(
                "DROP SCHEMA IF EXISTS {} CASCADE; DROP ROLE IF EXISTS {}_runtime",
                config.schema, config.schema
            ))
            .await
            .map_err(|_| PostgresStoreError::Initialization)?;
        drop(client);
        driver.abort();
        Ok(())
    }

    async fn connection(&self) -> Result<Object, A2AError> {
        tokio::time::timeout(self.acquire_timeout, self.pool.get())
            .await
            .map_err(|_| A2AError::internal("PostgreSQL authority pool acquisition timed out"))?
            .map_err(|_| A2AError::internal("PostgreSQL authority is unavailable"))
    }

    /// Number of whole-transaction attempts made by this store instance.
    #[doc(hidden)]
    #[must_use]
    pub fn transaction_attempts(&self) -> usize {
        self.transaction_attempts.load(Ordering::SeqCst)
    }

    /// Holds one pooled runtime connection behind deterministic test barriers.
    #[doc(hidden)]
    pub async fn hold_test_pool_connection(
        &self,
        acquired: Arc<tokio::sync::Barrier>,
        release: Arc<tokio::sync::Barrier>,
    ) -> Result<(), A2AError> {
        if !self.trust_injected_time {
            return Err(A2AError::internal("test pool hold is disabled"));
        }
        let _connection = self.connection().await?;
        acquired.wait().await;
        release.wait().await;
        Ok(())
    }

    fn next_transaction_test_fault(&self) -> Option<PostgresTransactionTestFault> {
        if !self.trust_injected_time {
            return None;
        }
        self.transaction_test_faults
            .lock()
            .ok()
            .and_then(|mut faults| faults.pop_front())
    }

    async fn run_retryable_transaction<T, F>(
        &self,
        tenant: &str,
        account: Option<&str>,
        mut operation: F,
    ) -> Result<T, A2AError>
    where
        T: Send,
        F: for<'a> FnMut(
            &'a Self,
            &'a tokio_postgres::Transaction<'a>,
        ) -> Pin<Box<dyn Future<Output = Result<T, A2AError>> + Send + 'a>>,
    {
        for attempt in 1..=MAX_TRANSACTION_ATTEMPTS {
            self.transaction_attempts.fetch_add(1, Ordering::SeqCst);
            let mut client = self.connection().await?;
            // ALLOWLIST: the central whole-transaction retry runner owns this site.
            let tx = client
                .transaction()
                .await
                .map_err(|_| A2AError::internal("PostgreSQL transaction failed"))?;
            if tenant.is_empty() {
                // Global workers still run as the restricted runtime role. The only
                // cross-tenant authority is inside fixed-search-path SECURITY DEFINER
                // procedures that return one bounded row or one boolean.
                tx.batch_execute(&format!("SET LOCAL ROLE {}_runtime; SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='5s'", self.schema))
                    .await
                    .map_err(|_| A2AError::internal("failed to select PostgreSQL runtime role"))?;
                tx.query_one(
                    "SELECT set_config('smesh.tenant_scope','',true), set_config('smesh.account_id','',true)",
                    &[],
                )
                .await
                .map_err(|_| {
                    A2AError::internal("failed to establish PostgreSQL tenant context")
                })?;
            } else {
                self.set_tenant(&tx, tenant, account).await?;
            }
            self.lock_capacity(&tx).await?;

            let test_fault = self.next_transaction_test_fault();
            match test_fault {
                Some(
                    PostgresTransactionTestFault::SerializationFailure
                    | PostgresTransactionTestFault::DeadlockDetected,
                ) => {
                    let _ = tx.rollback().await;
                    if attempt == MAX_TRANSACTION_ATTEMPTS {
                        return Err(A2AError::internal(
                            "PostgreSQL transaction retry limit reached",
                        ));
                    }
                    continue;
                }
                Some(PostgresTransactionTestFault::NonRetryable) => {
                    let _ = tx.rollback().await;
                    return Err(A2AError::internal("PostgreSQL transaction failed"));
                }
                Some(PostgresTransactionTestFault::AmbiguousCommit) | None => {}
            }

            match operation(self, &tx).await {
                Ok(value) => {
                    if !tenant.is_empty() {
                        self.ensure_capacity(&tx, tenant).await?;
                    }
                    if test_fault == Some(PostgresTransactionTestFault::AmbiguousCommit) {
                        // The test checkpoint is immediately before commit: the closure has run,
                        // but rollback proves no mutation escaped and the command is not retried.
                        let _ = tx.rollback().await;
                        return Err(A2AError::internal("PostgreSQL transaction commit failed"));
                    }
                    // A commit error is potentially ambiguous and is deliberately never retried.
                    tx.commit()
                        .await
                        .map_err(|_| A2AError::internal("PostgreSQL transaction commit failed"))?;
                    return Ok(value);
                }
                Err(error) if error.message == RETRYABLE_TRANSACTION_MARKER => {
                    let _ = tx.rollback().await;
                    if attempt == MAX_TRANSACTION_ATTEMPTS {
                        return Err(A2AError::internal(
                            "PostgreSQL transaction retry limit reached",
                        ));
                    }
                }
                Err(error) => {
                    let _ = tx.rollback().await;
                    return Err(error);
                }
            }
        }
        Err(A2AError::internal(
            "PostgreSQL transaction retry limit reached",
        ))
    }

    fn q(&self, sql: &str) -> String {
        sql.replace("__S__", &self.schema)
    }

    fn transaction_body_error(error: &tokio_postgres::Error, public: A2AError) -> A2AError {
        if error
            .code()
            .is_some_and(|code| matches!(code.code(), "40001" | "40P01"))
        {
            A2AError::internal(RETRYABLE_TRANSACTION_MARKER)
        } else {
            public
        }
    }

    async fn set_tenant(
        &self,
        tx: &tokio_postgres::Transaction<'_>,
        tenant: &str,
        account: Option<&str>,
    ) -> Result<(), A2AError> {
        tx.batch_execute(&format!(
            "SET LOCAL ROLE {}_runtime; SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='5s'",
            self.schema
        ))
            .await
            .map_err(|_| A2AError::internal("failed to select PostgreSQL runtime role"))?;
        tx.query_one("SELECT set_config('smesh.tenant_scope',$1,true), set_config('smesh.account_id',$2,true)", &[&tenant, &account.unwrap_or("")])
            .await.map_err(|_| A2AError::internal("failed to establish PostgreSQL tenant context"))?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn insert_quota_reservation(
        &self,
        tx: &tokio_postgres::Transaction<'_>,
        quota: Option<&QuotaReservationInput>,
        tenant: &str,
        account: &str,
        task_id: &str,
        now: i64,
        insert_if_missing: bool,
    ) -> Result<(), A2AError> {
        if let Some(quota) = quota
            && (quota.tenant_scope() != tenant || quota.account_id() != account)
        {
            return Err(A2AError::invalid_request(
                "quota reservation scope mismatch",
            ));
        }
        if insert_if_missing && let Some(quota) = quota {
            if quota.expires_at() <= now {
                return Err(A2AError::invalid_request("quota reservation expired"));
            }
            let insert = self.q("INSERT INTO __S__.quota_reservations(tenant_scope,reservation_id,account_id,principal_scope,operation,dimension,units,task_id,expires_at,metadata_json,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(tenant_scope,reservation_id) DO NOTHING");
            tx.execute(
                &insert,
                &[
                    &tenant,
                    &quota.reservation_id(),
                    &account,
                    &quota.principal_scope(),
                    &quota.operation(),
                    &quota.dimension(),
                    &i64::try_from(quota.units())
                        .map_err(|_| A2AError::invalid_request("invalid quota units"))?,
                    &task_id,
                    &quota.expires_at(),
                    &quota.metadata(),
                    &now,
                ],
            )
            .await
            .map_err(|error| {
                Self::transaction_body_error(
                    &error,
                    A2AError::internal("quota reservation insert failed"),
                )
            })?;
        }
        let Some(quota) = quota else {
            let lookup = self.q("SELECT 1 FROM __S__.quota_reservations WHERE tenant_scope=$1 AND task_id=$2 LIMIT 1");
            if tx
                .query_opt(&lookup, &[&tenant, &task_id])
                .await
                .map_err(|error| {
                    Self::transaction_body_error(
                        &error,
                        A2AError::internal("quota reservation lookup failed"),
                    )
                })?
                .is_some()
            {
                return Err(A2AError::invalid_request(
                    "quota reservation is required for replay",
                ));
            }
            return Ok(());
        };
        let lookup = self.q("SELECT account_id,principal_scope,operation,dimension,units,task_id,expires_at,metadata_json FROM __S__.quota_reservations WHERE tenant_scope=$1 AND reservation_id=$2");
        let row = tx
            .query_opt(&lookup, &[&tenant, &quota.reservation_id()])
            .await
            .map_err(|error| {
                Self::transaction_body_error(
                    &error,
                    A2AError::internal("quota reservation lookup failed"),
                )
            })?
            .ok_or_else(|| {
                A2AError::invalid_request("quota reservation is not bound to this mutation")
            })?;
        let exact = row.get::<_, String>(0) == account
            && row.get::<_, String>(1) == quota.principal_scope()
            && row.get::<_, String>(2) == quota.operation()
            && row.get::<_, String>(3) == quota.dimension()
            && row.get::<_, i64>(4) == i64::try_from(quota.units()).unwrap_or(-1)
            && row.get::<_, String>(5) == task_id
            && row.get::<_, i64>(6) == quota.expires_at()
            && row.get::<_, Option<String>>(7).as_deref() == quota.metadata();
        if !exact {
            return Err(A2AError::invalid_request("quota reservation key conflict"));
        }
        Ok(())
    }

    async fn insert_audit(
        &self,
        tx: &tokio_postgres::Transaction<'_>,
        audit: AuthorizationAuditInput,
    ) -> Result<(), A2AError> {
        let p = audit.into_parts();
        insert_audit_parts(tx, &self.schema, &p).await
    }

    async fn effective_now(
        &self,
        tx: &tokio_postgres::Transaction<'_>,
        requested: i64,
    ) -> Result<i64, A2AError> {
        if self.trust_injected_time {
            return Ok(requested);
        }
        tx.query_one(&self.q("SELECT __S__.db_millis()"), &[])
            .await
            .map(|row| row.get(0))
            .map_err(|error| {
                Self::transaction_body_error(
                    &error,
                    A2AError::internal("PostgreSQL database clock failed"),
                )
            })
    }

    async fn lock_capacity(&self, tx: &tokio_postgres::Transaction<'_>) -> Result<(), A2AError> {
        tx.query_one("SELECT pg_advisory_xact_lock(6001136200064)", &[])
            .await
            .map_err(|error| {
                Self::transaction_body_error(
                    &error,
                    A2AError::internal("authority capacity lock failed"),
                )
            })?;
        Ok(())
    }

    async fn ensure_capacity(
        &self,
        tx: &tokio_postgres::Transaction<'_>,
        tenant: &str,
    ) -> Result<(), A2AError> {
        tx.query_one("SELECT pg_advisory_xact_lock(6001136200064)", &[])
            .await
            .map_err(|error| {
                Self::transaction_body_error(
                    &error,
                    A2AError::internal("authority capacity lock failed"),
                )
            })?;
        let sql=self.q("SELECT COALESCE(sum(bytes),0)::bigint FROM (
          SELECT octet_length(tenant_scope)+octet_length(task_id)+octet_length(context_id)+octet_length(state)+COALESCE(octet_length(status_timestamp),0)+octet_length(task_json)+octet_length(owner_account_id)::bigint bytes FROM __S__.tasks WHERE tenant_scope=$1
          UNION ALL SELECT octet_length(tenant_scope)+octet_length(task_id)+octet_length(event_kind)+COALESCE(octet_length(from_state),0)+octet_length(to_state)+octet_length(event_json) FROM __S__.task_events WHERE tenant_scope=$1
          UNION ALL SELECT octet_length(tenant_scope)+octet_length(message_id)+octet_length(request_digest)+octet_length(task_id)+octet_length(state)+octet_length(admission_result_json)+COALESCE(octet_length(final_result_json),0)+COALESCE(octet_length(actor_account_id),0)+COALESCE(octet_length(causative_request_json),0)+COALESCE(octet_length(invocation_kind),0) FROM __S__.idempotency_records WHERE tenant_scope=$1
          UNION ALL SELECT octet_length(dispatch_id)+octet_length(tenant_scope)+octet_length(task_id)+octet_length(message_id)+octet_length(payload_json)+octet_length(payload_digest)+octet_length(state)+COALESCE(octet_length(lease_owner),0)+COALESCE(octet_length(lease_token),0)+COALESCE(octet_length(last_error),0) FROM __S__.outbox WHERE tenant_scope=$1
          UNION ALL SELECT octet_length(tenant_scope)+octet_length(lease_token)+COALESCE(octet_length(outcome),0)+COALESCE(octet_length(error),0) FROM __S__.outbox_attempts WHERE tenant_scope=$1
          UNION ALL SELECT octet_length(tenant_scope)+octet_length(dispatch_id)+octet_length(payload_digest)+octet_length(payload_json)+octet_length(task_id)+octet_length(context_id)+octet_length(state)+COALESCE(octet_length(lease_owner),0)+COALESCE(octet_length(lease_token),0)+COALESCE(octet_length(completion_kind),0)+COALESCE(octet_length(termination_json),0)+COALESCE(octet_length(transcript_digest),0) FROM __S__.receiver_inbox WHERE tenant_scope=$1
          UNION ALL SELECT octet_length(tenant_scope)+octet_length(dispatch_id)+octet_length(frame_kind)+octet_length(frame_json)+octet_length(frame_digest) FROM __S__.receiver_frames WHERE tenant_scope=$1
          UNION ALL SELECT octet_length(tenant_scope)+octet_length(dispatch_id)+octet_length(effect_kind) FROM __S__.loopback_effects WHERE tenant_scope=$1
          UNION ALL SELECT octet_length(tenant_scope)+octet_length(message_id)+octet_length(dispatch_id)+octet_length(task_id)+octet_length(state)+COALESCE(octet_length(transcript_digest),0)+COALESCE(octet_length(interruption_error),0) FROM __S__.stream_transcripts WHERE tenant_scope=$1
          UNION ALL SELECT octet_length(tenant_scope)+octet_length(message_id)+octet_length(frame_kind)+octet_length(frame_json)+octet_length(frame_digest) FROM __S__.stream_frames WHERE tenant_scope=$1
          UNION ALL SELECT octet_length(tenant_scope)+octet_length(dispatch_id)+octet_length(task_id)+octet_length(state) FROM __S__.cancellation_intents WHERE tenant_scope=$1
          UNION ALL SELECT octet_length(decision_id)+octet_length(tenant_scope)+octet_length(actor_account_id)+octet_length(policy_id)+octet_length(policy_digest)+octet_length(operation)+octet_length(effect)+octet_length(reason)+octet_length(resource_kind)+octet_length(resource_digest)+COALESCE(octet_length(task_id),0) FROM __S__.authorization_decisions WHERE tenant_scope=$1
          UNION ALL SELECT octet_length(tenant_scope)+octet_length(reservation_id)+octet_length(account_id)+octet_length(principal_scope)+octet_length(operation)+octet_length(dimension)+octet_length(task_id)+COALESCE(octet_length(metadata_json),0) FROM __S__.quota_reservations WHERE tenant_scope=$1
          UNION ALL SELECT octet_length(tenant_scope)+octet_length(snapshot_id)+octet_length(owner_account_id)+octet_length(scope_digest)+octet_length(query_digest)+octet_length(metadata_digest) FROM __S__.list_snapshots WHERE tenant_scope=$1
          UNION ALL SELECT octet_length(tenant_scope)+octet_length(snapshot_id)+octet_length(task_id)+octet_length(task_digest)+octet_length(task_json) FROM __S__.list_snapshot_entries WHERE tenant_scope=$1
          UNION ALL SELECT octet_length(tenant_scope)+octet_length(token_hash)+octet_length(snapshot_id)+octet_length(scope_digest)+octet_length(query_digest) FROM __S__.list_page_tokens WHERE tenant_scope=$1
        ) authority_bytes");
        let bytes: i64 = tx
            .query_one(&sql, &[&tenant])
            .await
            .map_err(|error| {
                Self::transaction_body_error(
                    &error,
                    A2AError::internal("authority capacity check failed"),
                )
            })?
            .get(0);
        if bytes > 64 * 1024 * 1024 {
            return Err(A2AError::internal("authority capacity reached"));
        }
        Ok(())
    }

    async fn ensure_all_tenant_capacity(
        &self,
        tx: &tokio_postgres::Transaction<'_>,
    ) -> Result<(), A2AError> {
        let sql = self.q("SELECT * FROM __S__.authority_tenants_bounded()");
        let tenants = tx.query(&sql, &[]).await.map_err(|error| {
            Self::transaction_body_error(
                &error,
                A2AError::internal("authority tenant capacity lookup failed"),
            )
        })?;
        for row in tenants {
            let tenant: String = row.get(0);
            tx.query_one(
                "SELECT set_config('smesh.tenant_scope',$1,true)",
                &[&tenant],
            )
            .await
            .map_err(|error| {
                Self::transaction_body_error(
                    &error,
                    A2AError::internal("authority tenant capacity context failed"),
                )
            })?;
            self.ensure_capacity(tx, &tenant).await?;
        }
        Ok(())
    }

    async fn diagnostics_row(&self) -> Result<Row, A2AError> {
        self.run_retryable_transaction("", None, |store, tx| {
            Box::pin(async move {
                let sql = store.q("SELECT * FROM __S__.authority_diagnostics_bounded()");
                tx.query_one(&sql, &[]).await.map_err(|error| {
                    Self::transaction_body_error(
                        &error,
                        A2AError::internal("authority diagnostics failed"),
                    )
                })
            })
        })
        .await
    }
}

fn validate_tls(config: &PostgresStoreConfig) -> Result<bool, PostgresStoreError> {
    let classify = |url: &str| -> Result<bool, PostgresStoreError> {
        let parsed = Url::parse(url).map_err(|_| PostgresStoreError::InvalidConfig)?;
        let loopback = matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
        let secure = parsed.query_pairs().any(|(k, v)| {
            k == "sslmode" && matches!(v.as_ref(), "require" | "verify-ca" | "verify-full")
        });
        if secure {
            Ok(false)
        } else if config.test_only_insecure_loopback && loopback {
            Ok(true)
        } else {
            Err(PostgresStoreError::TlsRequired)
        }
    };
    let migrator = classify(&config.migrator_url)?;
    let runtime = classify(&config.runtime_url)?;
    if migrator != runtime {
        return Err(PostgresStoreError::InvalidConfig);
    }
    Ok(migrator)
}

fn native_tls_connector() -> Result<MakeRustlsConnect, PostgresStoreError> {
    let loaded = rustls_native_certs::load_native_certs();
    if loaded.certs.is_empty() {
        return Err(PostgresStoreError::Initialization);
    }
    let mut roots = rustls::RootCertStore::empty();
    for certificate in loaded.certs {
        roots
            .add(certificate)
            .map_err(|_| PostgresStoreError::Initialization)?;
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(MakeRustlsConnect::new(config))
}

async fn validate_runtime_login(
    client: &tokio_postgres::Client,
    runtime_user: &str,
) -> Result<(), PostgresStoreError> {
    let row = client
        .query_opt(
            "SELECT rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=$1",
            &[&runtime_user],
        )
        .await
        .map_err(|_| PostgresStoreError::Initialization)?
        .ok_or(PostgresStoreError::Initialization)?;
    if row.get::<_, bool>(0)
        || row.get::<_, bool>(1)
        || row.get::<_, bool>(2)
        || row.get::<_, bool>(3)
        || !row.get::<_, bool>(4)
        || row.get::<_, bool>(5)
        || row.get::<_, bool>(6)
    {
        return Err(PostgresStoreError::Initialization);
    }
    Ok(())
}

async fn migrate(
    client: &mut tokio_postgres::Client,
    schema: &str,
    runtime_user: &str,
) -> Result<(), PostgresStoreError> {
    // ALLOWLIST: migration uses advisory-lock fencing and is never retried after
    // commit ambiguity.
    let tx = client
        .transaction()
        .await
        .map_err(|_| PostgresStoreError::Initialization)?;
    tx.batch_execute("SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='15s'; SELECT pg_advisory_xact_lock(6001136200062);")
        .await.map_err(|_| PostgresStoreError::Initialization)?;
    let migrator_user: String = tx
        .query_one("SELECT current_user", &[])
        .await
        .map_err(|_| PostgresStoreError::Initialization)?
        .get(0);
    if runtime_user == migrator_user
        || tx
            .query_one(
                "SELECT pg_has_role($1,$2,'MEMBER')",
                &[&runtime_user, &migrator_user],
            )
            .await
            .map_err(|_| PostgresStoreError::Initialization)?
            .get::<_, bool>(0)
    {
        return Err(PostgresStoreError::InvalidSchema);
    }
    let role = format!("{schema}_runtime");
    if let Some(attributes) = tx
        .query_opt(
            "SELECT rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=$1",
            &[&role],
        )
        .await
        .map_err(|_| PostgresStoreError::Initialization)?
    {
        if attributes.get::<_, bool>(0)
            || attributes.get::<_, bool>(1)
            || attributes.get::<_, bool>(2)
            || attributes.get::<_, bool>(3)
            || attributes.get::<_, bool>(4)
            || attributes.get::<_, bool>(5)
            || attributes.get::<_, bool>(6)
        {
            return Err(PostgresStoreError::InvalidSchema);
        }
        let memberships = tx
            .query(
                "SELECT member.rolname,parent.rolname,am.admin_option FROM pg_auth_members am JOIN pg_roles member ON member.oid=am.member JOIN pg_roles parent ON parent.oid=am.roleid WHERE member.rolname=$1 OR parent.rolname=$1",
                &[&role],
            )
            .await
            .map_err(|_| PostgresStoreError::InvalidSchema)?;
        if memberships.iter().any(|row| {
            let member = row.get::<_, String>(0);
            let parent = row.get::<_, String>(1);
            let admin = row.get::<_, bool>(2);
            parent != role
                || !((member == runtime_user && !admin)
                    || (member == migrator_user && admin))
        }) {
            return Err(PostgresStoreError::InvalidSchema);
        }
    }
    let exists: bool = tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=$1)",
            &[&schema],
        )
        .await
        .map_err(|_| PostgresStoreError::Initialization)?
        .get(0);
    let checksum = content_digest(MIGRATION_SQL.as_bytes());
    if !exists {
        let sql = MIGRATION_SQL
            .replace("__SCHEMA__", schema)
            .replace("__ROLE__", &format!("{schema}_runtime"))
            .replace("__MIGRATOR__", &migrator_user.replace('\'', "''"));
        tx.batch_execute(&sql)
            .await
            .map_err(|_| PostgresStoreError::Initialization)?;
        tx.batch_execute(&format!("GRANT {role} TO {runtime_user}"))
            .await
            .map_err(|_| PostgresStoreError::Initialization)?;
        let cursor: [u8; 32] = rand::random();
        let receipt: [u8; 32] = rand::random();
        let store: [u8; 32] = rand::random();
        let catalog = catalog_digest(&tx, schema).await?;
        let insert_metadata =
            format!("INSERT INTO {schema}.store_metadata VALUES(1,6,$1,$2,$3,$4)");
        tx.execute(
            &insert_metadata,
            &[&checksum, &catalog, &&cursor[..], &&receipt[..]],
        )
        .await
        .map_err(|_| PostgresStoreError::Initialization)?;
        let insert_identity =
            format!("INSERT INTO {schema}.store_identity VALUES(1,$1,{schema}.db_millis())");
        tx.execute(&insert_identity, &[&&store[..]])
            .await
            .map_err(|_| PostgresStoreError::Initialization)?;
        let insert_migration = format!(
            "INSERT INTO {schema}.schema_migrations VALUES(1,6,$1,$2,{schema}.db_millis())"
        );
        tx.execute(&insert_migration, &[&MIGRATION_NAME, &checksum])
            .await
            .map_err(|_| PostgresStoreError::Initialization)?;
    } else {
        let query = format!(
            "SELECT logical_schema_version,checksum FROM {schema}.schema_migrations WHERE revision=1"
        );
        let row = tx
            .query_opt(&query, &[])
            .await
            .map_err(|_| PostgresStoreError::InvalidSchema)?
            .ok_or(PostgresStoreError::InvalidSchema)?;
        if row.get::<_, i64>(0) != LOGICAL_SCHEMA_VERSION || row.get::<_, String>(1) != checksum {
            return Err(PostgresStoreError::InvalidSchema);
        }
    }
    let quota_checksum = content_digest(QUOTA_MIGRATION_SQL.as_bytes());
    let quota_row = tx
        .query_opt(
            &format!("SELECT logical_schema_version,checksum FROM {schema}.schema_migrations WHERE revision=2"),
            &[],
        )
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?;
    if let Some(row) = quota_row {
        if row.get::<_, i64>(0) != LOGICAL_SCHEMA_VERSION
            || row.get::<_, String>(1) != quota_checksum
        {
            return Err(PostgresStoreError::InvalidSchema);
        }
    } else {
        let sql = QUOTA_MIGRATION_SQL
            .replace("__SCHEMA__", schema)
            .replace("__ROLE__", &format!("{schema}_runtime"));
        tx.batch_execute(&sql)
            .await
            .map_err(|_| PostgresStoreError::Initialization)?;
        tx.execute(
            &format!(
                "INSERT INTO {schema}.schema_migrations VALUES(2,6,$1,$2,{schema}.db_millis())"
            ),
            &[&QUOTA_MIGRATION_NAME, &quota_checksum],
        )
        .await
        .map_err(|_| PostgresStoreError::Initialization)?;
        let catalog = catalog_digest(&tx, schema).await?;
        tx.batch_execute(&format!(
            "ALTER TABLE {schema}.store_metadata DISABLE TRIGGER store_metadata_immutable"
        ))
        .await
        .map_err(|_| PostgresStoreError::Initialization)?;
        tx.execute(
            &format!("UPDATE {schema}.store_metadata SET catalog_hash=$1 WHERE singleton=1"),
            &[&catalog],
        )
        .await
        .map_err(|_| PostgresStoreError::Initialization)?;
        tx.batch_execute(&format!(
            "ALTER TABLE {schema}.store_metadata ENABLE TRIGGER store_metadata_immutable"
        ))
        .await
        .map_err(|_| PostgresStoreError::Initialization)?;
    }
    let fence_checksum = content_digest(RECEIVER_FENCE_MIGRATION_SQL.as_bytes());
    let fence_row = tx
        .query_opt(
            &format!("SELECT logical_schema_version,checksum FROM {schema}.schema_migrations WHERE revision=3"),
            &[],
        )
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?;
    if let Some(row) = fence_row {
        if row.get::<_, i64>(0) != LOGICAL_SCHEMA_VERSION
            || row.get::<_, String>(1) != fence_checksum
        {
            return Err(PostgresStoreError::InvalidSchema);
        }
    } else {
        let sql = RECEIVER_FENCE_MIGRATION_SQL
            .replace("__SCHEMA__", schema)
            .replace("__MIGRATOR__", &migrator_user.replace('\'', "''"));
        tx.batch_execute(&sql)
            .await
            .map_err(|_| PostgresStoreError::Initialization)?;
        tx.execute(
            &format!(
                "INSERT INTO {schema}.schema_migrations VALUES(3,6,$1,$2,{schema}.db_millis())"
            ),
            &[&RECEIVER_FENCE_MIGRATION_NAME, &fence_checksum],
        )
        .await
        .map_err(|_| PostgresStoreError::Initialization)?;
        let catalog = catalog_digest(&tx, schema).await?;
        tx.batch_execute(&format!(
            "ALTER TABLE {schema}.store_metadata DISABLE TRIGGER store_metadata_immutable"
        ))
        .await
        .map_err(|_| PostgresStoreError::Initialization)?;
        tx.execute(
            &format!("UPDATE {schema}.store_metadata SET catalog_hash=$1 WHERE singleton=1"),
            &[&catalog],
        )
        .await
        .map_err(|_| PostgresStoreError::Initialization)?;
        tx.batch_execute(&format!(
            "ALTER TABLE {schema}.store_metadata ENABLE TRIGGER store_metadata_immutable"
        ))
        .await
        .map_err(|_| PostgresStoreError::Initialization)?;
    }
    tx.commit()
        .await
        .map_err(|_| PostgresStoreError::Initialization)
}

async fn catalog_digest<C>(client: &C, schema: &str) -> Result<String, PostgresStoreError>
where
    C: tokio_postgres::GenericClient + Sync,
{
    let queries = [
        "SELECT concat_ws('|','relation',c.relname,c.relkind,c.relrowsecurity,c.relforcerowsecurity,c.relpersistence) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 ORDER BY 1",
        "SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,a.attgenerated,COALESCE(pg_get_expr(d.adbin,d.adrelid),'')) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE n.nspname=$1 AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum",
        "SELECT concat_ws('|','constraint',c.relname,x.conname,x.contype,pg_get_constraintdef(x.oid,true)) FROM pg_constraint x JOIN pg_class c ON c.oid=x.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 ORDER BY c.relname,x.conname",
        "SELECT concat_ws('|','index',i.relname,pg_get_indexdef(i.oid)) FROM pg_class i JOIN pg_namespace n ON n.oid=i.relnamespace WHERE n.nspname=$1 AND i.relkind='i' ORDER BY i.relname",
        "SELECT concat_ws('|','trigger',c.relname,t.tgname,pg_get_triggerdef(t.oid,true)) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND NOT t.tgisinternal ORDER BY c.relname,t.tgname",
        "SELECT concat_ws('|','function',p.proname,pg_get_function_identity_arguments(p.oid),owner.rolname,pg_get_functiondef(p.oid)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles owner ON owner.oid=p.proowner WHERE n.nspname=$1 ORDER BY p.proname,pg_get_function_identity_arguments(p.oid)",
        "SELECT concat_ws('|','policy',c.relname,p.polname,p.polcmd,p.polpermissive,COALESCE(pg_get_expr(p.polqual,p.polrelid),''),COALESCE(pg_get_expr(p.polwithcheck,p.polrelid),''),p.polroles::text) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 ORDER BY c.relname,p.polname",
        "SELECT concat_ws('|','grant',table_name,grantee,privilege_type,is_grantable) FROM information_schema.role_table_grants WHERE table_schema=$1 ORDER BY table_name,grantee,privilege_type",
        "SELECT concat_ws('|','sequence-grant',object_name,grantee,privilege_type,is_grantable) FROM information_schema.usage_privileges WHERE object_schema=$1 ORDER BY object_name,grantee,privilege_type",
        "SELECT concat_ws('|','routine-grant',routine_name,grantee,privilege_type,is_grantable) FROM information_schema.role_routine_grants WHERE routine_schema=$1 ORDER BY routine_name,grantee,privilege_type",
        "SELECT concat_ws('|','role',rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls) FROM pg_roles WHERE rolname=$1||'_runtime' ORDER BY rolname",
        "SELECT concat_ws('|','membership',member.rolname,parent.rolname,am.admin_option) FROM pg_auth_members am JOIN pg_roles member ON member.oid=am.member JOIN pg_roles parent ON parent.oid=am.roleid WHERE member.rolname=$1||'_runtime' OR parent.rolname=$1||'_runtime' ORDER BY member.rolname,parent.rolname",
    ];
    let mut manifest = Vec::new();
    for query in queries {
        let rows = client
            .query(query, &[&schema])
            .await
            .map_err(|_| PostgresStoreError::InvalidSchema)?;
        manifest.extend(rows.into_iter().map(|row| row.get::<_, String>(0)));
    }
    let normalized = manifest.join("\n").replace(schema, "__SCHEMA__");
    Ok(content_digest(normalized.as_bytes()))
}

async fn validate_semantics<C>(
    client: &C,
    schema: &str,
    cursor_key: &[u8; 32],
) -> Result<(), PostgresStoreError>
where
    C: tokio_postgres::GenericClient + Sync,
{
    let tasks=client.query(&format!("SELECT task_id,context_id,state,status_timestamp,revision,task_json FROM {schema}.tasks ORDER BY tenant_scope,task_id"),&[]).await.map_err(|_|PostgresStoreError::InvalidSchema)?;
    for row in tasks {
        let id: String = row.get(0);
        let context: String = row.get(1);
        let state: String = row.get(2);
        let timestamp: Option<String> = row.get(3);
        let revision: i64 = row.get(4);
        let json: String = row.get(5);
        let task: Task =
            serde_json::from_str(&json).map_err(|_| PostgresStoreError::InvalidSchema)?;
        if task.id != id
            || task.context_id != context
            || revision <= 0
            || state_key(&task).map_err(|_| PostgresStoreError::InvalidSchema)? != state
            || task.status.timestamp.map(|v| v.to_rfc3339()) != timestamp
            || json.len() > 1_048_576
        {
            return Err(PostgresStoreError::InvalidSchema);
        }
    }
    let events = client.query(&format!("SELECT tenant_scope,task_id,event_seq,task_revision,event_kind,from_state,to_state,event_json FROM {schema}.task_events ORDER BY tenant_scope,task_id,event_seq"), &[])
        .await.map_err(|_| PostgresStoreError::InvalidSchema)?;
    let mut previous: std::collections::HashMap<(String, String), (i64, i64, String, String)> =
        std::collections::HashMap::new();
    for row in events {
        let tenant: String = row.get(0);
        let task_id: String = row.get(1);
        let seq: i64 = row.get(2);
        let revision: i64 = row.get(3);
        let kind: String = row.get(4);
        let from: Option<String> = row.get(5);
        let to: String = row.get(6);
        let encoded: String = row.get(7);
        let event_task: Task =
            serde_json::from_str(&encoded).map_err(|_| PostgresStoreError::InvalidSchema)?;
        let from_state = from
            .as_deref()
            .map(serde_json::from_str::<a2a::TaskState>)
            .transpose()
            .map_err(|_| PostgresStoreError::InvalidSchema)?;
        let to_state: a2a::TaskState =
            serde_json::from_str(&to).map_err(|_| PostgresStoreError::InvalidSchema)?;
        let key = (tenant, task_id.clone());
        let valid_chain = match previous.get(&key) {
            None => seq == 1 && revision == 1 && from.is_none(),
            Some((prior_seq, prior_revision, prior_to, _)) => {
                seq == prior_seq + 1
                    && revision == prior_revision + 1
                    && from.as_deref() == Some(prior_to.as_str())
            }
        };
        if !valid_chain
            || kind.is_empty()
            || kind.len() > 4096
            || event_task.id != task_id
            || state_key(&event_task).map_err(|_| PostgresStoreError::InvalidSchema)? != to
            || from_state
                .as_ref()
                .is_some_and(|state| !legal_transition(state, &to_state))
        {
            return Err(PostgresStoreError::InvalidSchema);
        }
        previous.insert(key, (seq, revision, to, encoded));
    }
    let current = client
        .query(
            &format!("SELECT tenant_scope,task_id,revision,task_json FROM {schema}.tasks"),
            &[],
        )
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?;
    for row in current {
        let key = (row.get::<_, String>(0), row.get::<_, String>(1));
        let Some((_, revision, _, encoded)) = previous.get(&key) else {
            return Err(PostgresStoreError::InvalidSchema);
        };
        if *revision != row.get::<_, i64>(2) || encoded != row.get::<_, String>(3).as_str() {
            return Err(PostgresStoreError::InvalidSchema);
        }
    }
    for (table, json_col, digest_col) in [
        ("outbox", "payload_json", "payload_digest"),
        ("receiver_frames", "frame_json", "frame_digest"),
        ("stream_frames", "frame_json", "frame_digest"),
    ] {
        let sql = format!("SELECT {json_col},{digest_col} FROM {schema}.{table}");
        for row in client
            .query(&sql, &[])
            .await
            .map_err(|_| PostgresStoreError::InvalidSchema)?
        {
            let json: String = row.get(0);
            let digest: String = row.get(1);
            if json.len() > 1_048_576
                || serde_json::from_str::<serde_json::Value>(&json).is_err()
                || content_digest(json.as_bytes()) != digest
            {
                return Err(PostgresStoreError::InvalidSchema);
            }
        }
    }
    let transcripts=client.query(&format!("SELECT t.tenant_scope,t.message_id,t.state,t.frame_count,t.transcript_digest,t.terminal_seq,t.interruption_error,COALESCE((SELECT json_agg(f.frame_json::json ORDER BY f.frame_seq)::text FROM {schema}.stream_frames f WHERE f.tenant_scope=t.tenant_scope AND f.message_id=t.message_id),'[]') FROM {schema}.stream_transcripts t"),&[]).await.map_err(|_|PostgresStoreError::InvalidSchema)?;
    for row in transcripts {
        let state: String = row.get(2);
        let count: i64 = row.get(3);
        let digest: Option<String> = row.get(4);
        let terminal: Option<i64> = row.get(5);
        let interruption: Option<String> = row.get(6);
        let aggregate: String = row.get(7);
        let frames: Vec<StreamResponse> =
            serde_json::from_str(&aggregate).map_err(|_| PostgresStoreError::InvalidSchema)?;
        if i64::try_from(frames.len()).unwrap_or(i64::MAX) != count
            || digest.as_deref()
                != Some(
                    content_digest(
                        &serde_json::to_vec(&frames)
                            .map_err(|_| PostgresStoreError::InvalidSchema)?,
                    )
                    .as_str(),
                )
            || !matches!(state.as_str(), "open" | "terminal" | "interrupted")
            || (state == "terminal") != (terminal == Some(count))
            || (state == "interrupted") != interruption.is_some()
        {
            return Err(PostgresStoreError::InvalidSchema);
        }
    }
    let snapshots=client.query(&format!("SELECT tenant_scope,snapshot_id,scope_digest,query_digest,total_size,page_size,issued_at,expires_at,projection_version,frozen_bytes,metadata_digest FROM {schema}.list_snapshots ORDER BY tenant_scope,snapshot_id"),&[]).await.map_err(|_|PostgresStoreError::InvalidSchema)?;
    for row in snapshots {
        let tenant: String = row.get(0);
        let id: Vec<u8> = row.get(1);
        let scope: String = row.get(2);
        let query: String = row.get(3);
        let total: i64 = row.get(4);
        let page: i64 = row.get(5);
        let issued: i64 = row.get(6);
        let expires: i64 = row.get(7);
        let projection: i64 = row.get(8);
        let bytes: i64 = row.get(9);
        let metadata: Vec<u8> = row.get(10);
        let entries=client.query(&format!("SELECT ordinal,task_id,task_revision,task_digest,task_json FROM {schema}.list_snapshot_entries WHERE tenant_scope=$1 AND snapshot_id=$2 ORDER BY ordinal"),&[&tenant,&id]).await.map_err(|_|PostgresStoreError::InvalidSchema)?;
        let mut seals = Vec::with_capacity(entries.len());
        let mut actual_bytes = 0_i64;
        for (n, entry) in entries.iter().enumerate() {
            let ordinal: i64 = entry.get(0);
            let task_id: String = entry.get(1);
            let revision: i64 = entry.get(2);
            let digest: String = entry.get(3);
            let json: String = entry.get(4);
            let task: Task =
                serde_json::from_str(&json).map_err(|_| PostgresStoreError::InvalidSchema)?;
            actual_bytes = actual_bytes
                .checked_add(
                    i64::try_from(json.len()).map_err(|_| PostgresStoreError::InvalidSchema)?,
                )
                .ok_or(PostgresStoreError::InvalidSchema)?;
            if ordinal != i64::try_from(n).unwrap_or(i64::MAX)
                || task.id != task_id
                || content_digest(json.as_bytes()) != digest
            {
                return Err(PostgresStoreError::InvalidSchema);
            }
            seals.push((ordinal, task_id, revision, digest));
        }
        if i64::try_from(seals.len()).unwrap_or(i64::MAX) != total
            || actual_bytes != bytes
            || issued.checked_add(SNAPSHOT_TTL_MILLIS) != Some(expires)
            || metadata.as_slice()
                != snapshot_metadata_digest(
                    cursor_key, &id, &scope, &query, total, page, issued, expires, projection,
                    bytes, &seals,
                )
        {
            return Err(PostgresStoreError::InvalidSchema);
        }
    }
    let invalid_receiver_fences: i64 = client
        .query_one(
            &format!(
                "SELECT count(*) FROM {schema}.receiver_inbox r
                 LEFT JOIN {schema}.outbox o
                   ON o.tenant_scope=r.tenant_scope AND o.dispatch_id=r.dispatch_id
                  AND o.task_id=r.task_id AND o.payload_digest=r.payload_digest
                 LEFT JOIN {schema}.outbox_attempts a
                   ON a.tenant_scope=r.tenant_scope AND a.outbox_id=o.outbox_id
                  AND a.attempt_no=r.sender_attempt_no
                  AND a.lease_token=r.sender_lease_token
                 LEFT JOIN {schema}.tasks t
                   ON t.tenant_scope=r.tenant_scope AND t.task_id=r.task_id
                 WHERE o.outbox_id IS NULL OR a.outbox_id IS NULL OR t.task_id IS NULL
                    OR r.sender_attempt_no<1 OR r.sender_attempt_no>o.max_attempts"
            ),
            &[],
        )
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?
        .get(0);
    if invalid_receiver_fences != 0 {
        return Err(PostgresStoreError::InvalidSchema);
    }
    let quota_rows = client.query(
        &format!("SELECT q.tenant_scope,q.reservation_id,q.account_id,q.principal_scope,q.operation,q.dimension,q.units,q.task_id,q.expires_at,q.metadata_json,q.created_at,t.owner_account_id FROM {schema}.quota_reservations q LEFT JOIN {schema}.tasks t ON t.tenant_scope=q.tenant_scope AND t.task_id=q.task_id"),
        &[],
    ).await.map_err(|_| PostgresStoreError::InvalidSchema)?;
    for row in quota_rows {
        let metadata: Option<String> = row.get(9);
        let tenant: String = row.get(0);
        let reservation_id: String = row.get(1);
        let account: String = row.get(2);
        let principal: String = row.get(3);
        let operation: String = row.get(4);
        let dimension: String = row.get(5);
        let units: i64 = row.get(6);
        let task_id: String = row.get(7);
        let expires_at: i64 = row.get(8);
        let created_at: i64 = row.get(10);
        let owner: Option<String> = row.get(11);
        let reconstructed = u64::try_from(units).ok().and_then(|units| {
            QuotaReservationInput::new(
                tenant.clone(),
                account.clone(),
                principal,
                operation,
                dimension,
                units,
                reservation_id,
                expires_at,
                metadata.clone(),
            )
            .ok()
        });
        if reconstructed.is_none()
            || task_id.is_empty()
            || task_id.len() > 4_096
            || created_at <= 0
            || created_at > 253_402_300_799_999
            || expires_at <= created_at
            || owner.as_deref() != Some(account.as_str())
        {
            return Err(PostgresStoreError::InvalidSchema);
        }
    }
    Ok(())
}

async fn validate_catalog(
    client: &tokio_postgres::Client,
    schema: &str,
) -> Result<([u8; 32], [u8; 32]), PostgresStoreError> {
    let expected_owner: String = client
        .query_one("SELECT current_user", &[])
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?
        .get(0);
    let definer_rows = client
        .query(
            "SELECT p.proname,owner.rolname,p.proconfig FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles owner ON owner.oid=p.proowner WHERE n.nspname=$1 AND p.prosecdef ORDER BY p.proname",
            &[&schema],
        )
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?;
    let definer_names = definer_rows
        .iter()
        .map(|row| row.get::<_, &str>(0))
        .collect::<Vec<_>>();
    if definer_names
        != [
            "authority_diagnostics_bounded",
            "authority_tenants_bounded",
            "cancellation_requested_bounded",
            "claim_outbox_bounded",
        ]
        || definer_rows.iter().any(|row| {
            row.get::<_, &str>(1) != expected_owner
                || row.get::<_, Option<Vec<String>>>(2).is_none_or(|settings| {
                    settings.len() != 1 || settings[0] != "search_path=pg_catalog"
                })
        })
    {
        return Err(PostgresStoreError::InvalidSchema);
    }
    let rows = client.query("SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relkind IN ('r','p') ORDER BY c.relname", &[&schema]).await.map_err(|_| PostgresStoreError::InvalidSchema)?;
    let actual: Vec<&str> = rows.iter().map(|r| r.get(0)).collect();
    if actual != EXPECTED_TABLES {
        return Err(PostgresStoreError::InvalidSchema);
    }
    for row in &rows {
        let name: &str = row.get(0);
        let tenant = TENANT_TABLES.contains(&name);
        if row.get::<_, bool>(1) != tenant || row.get::<_, bool>(2) != tenant {
            return Err(PostgresStoreError::InvalidSchema);
        }
    }
    let policy_count: i64 = client.query_one("SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND p.polname='tenant_isolation'", &[&schema]).await.map_err(|_| PostgresStoreError::InvalidSchema)?.get(0);
    if policy_count != i64::try_from(TENANT_TABLES.len()).unwrap_or(-1) {
        return Err(PostgresStoreError::InvalidSchema);
    }
    let policy_rows = client.query("SELECT pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND p.polname='tenant_isolation'", &[&schema]).await.map_err(|_|PostgresStoreError::InvalidSchema)?;
    if policy_rows.iter().any(|r| {
        let using: String = r.get(0);
        let check: String = r.get(1);
        !using.contains("current_setting('smesh.tenant_scope'::text, true)") || using != check
    }) {
        return Err(PostgresStoreError::InvalidSchema);
    }
    let index_rows=client.query("SELECT i.relname FROM pg_index x JOIN pg_class i ON i.oid=x.indexrelid JOIN pg_class t ON t.oid=x.indrelid JOIN pg_namespace n ON n.oid=t.relnamespace LEFT JOIN pg_constraint c ON c.conindid=i.oid WHERE n.nspname=$1 AND c.oid IS NULL ORDER BY i.relname", &[&schema]).await.map_err(|_|PostgresStoreError::InvalidSchema)?;
    let indexes: Vec<&str> = index_rows.iter().map(|r| r.get(0)).collect();
    if indexes != EXPECTED_CUSTOM_INDEXES {
        return Err(PostgresStoreError::InvalidSchema);
    }
    let migration_rows = client
        .query(
            &format!(
                "SELECT revision,logical_schema_version,name,checksum FROM {schema}.schema_migrations ORDER BY revision"
            ),
            &[],
        )
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?;
    let expected_migrations = [
        (
            1_i64,
            MIGRATION_NAME,
            content_digest(MIGRATION_SQL.as_bytes()),
        ),
        (
            2_i64,
            QUOTA_MIGRATION_NAME,
            content_digest(QUOTA_MIGRATION_SQL.as_bytes()),
        ),
        (
            3_i64,
            RECEIVER_FENCE_MIGRATION_NAME,
            content_digest(RECEIVER_FENCE_MIGRATION_SQL.as_bytes()),
        ),
    ];
    if migration_rows.len() != expected_migrations.len()
        || migration_rows
            .iter()
            .zip(expected_migrations.iter())
            .any(|(row, expected)| {
                row.get::<_, i64>(0) != expected.0
                    || row.get::<_, i64>(1) != LOGICAL_SCHEMA_VERSION
                    || row.get::<_, &str>(2) != expected.1
                    || row.get::<_, &str>(3) != expected.2
            })
    {
        return Err(PostgresStoreError::InvalidSchema);
    }
    let query = format!(
        "SELECT schema_version,migration_hash,catalog_hash,cursor_key,receipt_key FROM {schema}.store_metadata WHERE singleton=1"
    );
    let row = client
        .query_opt(&query, &[])
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?
        .ok_or(PostgresStoreError::InvalidSchema)?;
    let cursor: Vec<u8> = row.get(3);
    let receipt: Vec<u8> = row.get(4);
    let stored_catalog = row.get::<_, String>(2);
    let actual_catalog = catalog_digest(client, schema).await?;
    if row.get::<_, i64>(0) != 6
        || row.get::<_, String>(1) != content_digest(MIGRATION_SQL.as_bytes())
        || stored_catalog != actual_catalog
    {
        return Err(PostgresStoreError::InvalidSchema);
    }
    let cursor: [u8; 32] = cursor
        .try_into()
        .map_err(|_| PostgresStoreError::InvalidSchema)?;
    let receipt: [u8; 32] = receipt
        .try_into()
        .map_err(|_| PostgresStoreError::InvalidSchema)?;
    Ok((cursor, receipt))
}

async fn insert_audit_parts(
    tx: &tokio_postgres::Transaction<'_>,
    schema: &str,
    p: &AuthorizationAuditParts,
) -> Result<(), A2AError> {
    let effect = match p.effect {
        AuthorizationDecisionEffect::Allow => "allow",
        AuthorizationDecisionEffect::Deny => "deny",
    };
    let sql = format!(
        "INSERT INTO {schema}.authorization_decisions(decision_id,tenant_scope,actor_account_id,policy_id,policy_revision,policy_digest,operation,effect,reason,resource_kind,resource_digest,task_id,decided_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)"
    );
    let revision = i64::try_from(p.policy_revision)
        .map_err(|_| A2AError::invalid_request("policy revision is too large"))?;
    tx.execute(
        &sql,
        &[
            &p.decision_id,
            &p.tenant_scope,
            &p.actor_account_id,
            &p.policy_id,
            &revision,
            &p.policy_digest,
            &p.operation,
            &effect,
            &p.reason,
            &p.resource_kind,
            &p.resource_digest,
            &p.task_id,
            &p.decided_at,
        ],
    )
    .await
    .map_err(|error| {
        PostgresTaskStore::transaction_body_error(
            &error,
            A2AError::internal("authorization audit persistence failed"),
        )
    })?;
    Ok(())
}

fn task_from_row(row: &Row) -> Result<Task, A2AError> {
    serde_json::from_str(row.get::<_, &str>(0))
        .map_err(|_| A2AError::internal("stored task is corrupt"))
}
fn state_key(task: &Task) -> Result<String, A2AError> {
    serde_json::to_string(&task.status.state)
        .map_err(|_| A2AError::internal("failed to encode task state"))
}
fn frame_kind(frame: &StreamResponse) -> &'static str {
    match frame {
        StreamResponse::Task(_) => "task",
        StreamResponse::Message(_) => "message",
        StreamResponse::StatusUpdate(_) => "status_update",
        StreamResponse::ArtifactUpdate(_) => "artifact_update",
    }
}
fn transcript_digest(frames: &[StreamResponse]) -> Result<String, A2AError> {
    serde_json::to_vec(frames)
        .map(|v| content_digest(&v))
        .map_err(|_| A2AError::internal("failed to digest transcript"))
}

#[allow(clippy::too_many_arguments)] // One atomic lifecycle needs the complete durable identity.
async fn materialize_postgres_dead_letter(
    store: &PostgresTaskStore,
    tx: &tokio_postgres::Transaction<'_>,
    tenant: &str,
    task_id: &str,
    message_id: &str,
    dispatch_id: &str,
    error: &str,
    now: i64,
) -> Result<bool, A2AError> {
    let task_sql = store.q(
        "SELECT task_json,state,revision FROM __S__.tasks WHERE tenant_scope=$1 AND task_id=$2 FOR UPDATE",
    );
    let task_row = tx
        .query_one(&task_sql, &[&tenant, &task_id])
        .await
        .map_err(|error| {
            PostgresTaskStore::transaction_body_error(
                &error,
                A2AError::internal("dead-letter task lookup failed"),
            )
        })?;
    let mut task: Task = serde_json::from_str(task_row.get::<_, &str>(0))
        .map_err(|_| A2AError::internal("stored task is corrupt"))?;
    let prior_state: String = task_row.get(1);
    let revision: i64 = task_row.get(2);
    let was_terminal = task.status.state.is_terminal();
    if was_terminal {
        return Ok(true);
    }
    task.status.state = a2a::TaskState::Failed;
    task.status.timestamp = chrono::DateTime::from_timestamp_millis(now);
    let mut message = Message::new(
        Role::Agent,
        vec![Part::text(format!(
            "Dispatch dead-lettered after bounded retries: {error}"
        ))],
    );
    message.task_id = Some(task.id.clone());
    message.context_id = Some(task.context_id.clone());
    task.status.message = Some(message);
    let next_revision = revision
        .checked_add(1)
        .ok_or_else(|| A2AError::internal("persistent task revision exhausted"))?;
    let task_json = serde_json::to_string(&task)
        .map_err(|_| A2AError::internal("dead-letter task encoding failed"))?;
    let failed_state = state_key(&task)?;
    let update_task = store.q("UPDATE __S__.tasks SET state=$1,status_timestamp=$2,revision=$3,task_json=$4 WHERE tenant_scope=$5 AND task_id=$6 AND revision=$7");
    if tx
        .execute(
            &update_task,
            &[
                &failed_state,
                &task.status.timestamp.map(|value| value.to_rfc3339()),
                &next_revision,
                &task_json,
                &tenant,
                &task_id,
                &revision,
            ],
        )
        .await
        .map_err(|error| {
            PostgresTaskStore::transaction_body_error(
                &error,
                A2AError::internal("dead-letter task CAS failed"),
            )
        })?
        != 1
    {
        return Err(A2AError::internal("dead-letter task arbitration failed"));
    }
    let event = store.q("INSERT INTO __S__.task_events(tenant_scope,task_id,event_seq,task_revision,event_kind,from_state,to_state,event_json,created_at) SELECT $1,$2,COALESCE(max(event_seq),0)+1,$3,'dead_lettered',$4,$5,$6,$7 FROM __S__.task_events WHERE tenant_scope=$1 AND task_id=$2");
    tx.execute(
        &event,
        &[
            &tenant,
            &task_id,
            &next_revision,
            &prior_state,
            &failed_state,
            &task_json,
            &now,
        ],
    )
    .await
    .map_err(|error| {
        PostgresTaskStore::transaction_body_error(
            &error,
            A2AError::internal("dead-letter event append failed"),
        )
    })?;
    let final_json = serde_json::to_string(&SendMessageResponse::Task(task))
        .map_err(|_| A2AError::internal("dead-letter result encoding failed"))?;
    let idem = store.q("UPDATE __S__.idempotency_records SET state='completed',final_result_json=$1,updated_at=$2 WHERE tenant_scope=$3 AND message_id=$4 AND task_id=$5 AND state='in_progress'");
    if tx
        .execute(&idem, &[&final_json, &now, &tenant, &message_id, &task_id])
        .await
        .map_err(|error| {
            PostgresTaskStore::transaction_body_error(
                &error,
                A2AError::internal("dead-letter idempotency completion failed"),
            )
        })?
        != 1
    {
        return Err(A2AError::internal(
            "dead-letter idempotency binding is corrupt",
        ));
    }
    let diagnostic_limit = 4096_usize.saturating_sub(STREAM_INTERRUPTION_PREFIX.len());
    let mut end = error.len().min(diagnostic_limit);
    while !error.is_char_boundary(end) {
        end -= 1;
    }
    let interruption = format!("{STREAM_INTERRUPTION_PREFIX}{}", &error[..end]);
    let transcript = store.q("UPDATE __S__.stream_transcripts SET state='interrupted',interruption_error=$1,updated_at=$2 WHERE tenant_scope=$3 AND message_id=$4 AND dispatch_id=$5 AND task_id=$6 AND state='open'");
    tx.execute(
        &transcript,
        &[
            &interruption,
            &now,
            &tenant,
            &message_id,
            &dispatch_id,
            &task_id,
        ],
    )
    .await
    .map_err(|error| {
        PostgresTaskStore::transaction_body_error(
            &error,
            A2AError::internal("dead-letter stream interruption failed"),
        )
    })?;
    Ok(false)
}

fn is_dispatch_closed(state: &a2a::TaskState) -> bool {
    state.is_terminal()
        || matches!(
            state,
            a2a::TaskState::InputRequired | a2a::TaskState::AuthRequired
        )
}

fn legal_transition(from: &a2a::TaskState, to: &a2a::TaskState) -> bool {
    use a2a::TaskState;
    if from == to {
        return true;
    }
    match from {
        TaskState::Unspecified => matches!(
            to,
            TaskState::Submitted | TaskState::Failed | TaskState::Rejected
        ),
        TaskState::Submitted => matches!(
            to,
            TaskState::Working
                | TaskState::InputRequired
                | TaskState::AuthRequired
                | TaskState::Completed
                | TaskState::Failed
                | TaskState::Canceled
                | TaskState::Rejected
        ),
        TaskState::Working => matches!(
            to,
            TaskState::InputRequired
                | TaskState::AuthRequired
                | TaskState::Completed
                | TaskState::Failed
                | TaskState::Canceled
                | TaskState::Rejected
        ),
        TaskState::InputRequired | TaskState::AuthRequired => matches!(
            to,
            TaskState::Working | TaskState::Failed | TaskState::Canceled | TaskState::Rejected
        ),
        TaskState::Completed | TaskState::Failed | TaskState::Canceled | TaskState::Rejected => {
            false
        }
    }
}

fn final_result_matches_task(result: &SendMessageResponse, task: &Task) -> bool {
    matches!(result, SendMessageResponse::Task(result_task) if result_task == task)
}

fn validate_terminal_public_transcript(
    frames: &[StreamResponse],
    final_task: &Task,
) -> Result<(), A2AError> {
    if frames.is_empty() || frames.len() > 1024 {
        return Err(A2AError::invalid_agent_response());
    }
    let Some(StreamResponse::Task(initial)) = frames.first() else {
        return Err(A2AError::invalid_agent_response());
    };
    if is_dispatch_closed(&initial.status.state)
        || frames
            .iter()
            .filter(|frame| matches!(frame, StreamResponse::Task(_)))
            .count()
            != 1
    {
        return Err(A2AError::invalid_agent_response());
    }
    let mut reconstructed = initial.clone();
    let mut terminal_count = 0;
    for (index, frame) in frames.iter().enumerate().skip(1) {
        match frame {
            StreamResponse::Task(_) | StreamResponse::Message(_) => {
                return Err(A2AError::invalid_agent_response());
            }
            StreamResponse::StatusUpdate(update) => {
                if update.task_id != final_task.id || update.context_id != final_task.context_id {
                    return Err(A2AError::invalid_agent_response());
                }
                reconstructed.status = update.status.clone();
                if is_dispatch_closed(&update.status.state) {
                    terminal_count += 1;
                    if index + 1 != frames.len() {
                        return Err(A2AError::invalid_agent_response());
                    }
                }
            }
            StreamResponse::ArtifactUpdate(update) => {
                if update.task_id != final_task.id || update.context_id != final_task.context_id {
                    return Err(A2AError::invalid_agent_response());
                }
                reconstructed
                    .artifacts
                    .get_or_insert_with(Vec::new)
                    .push(update.artifact.clone());
            }
        }
    }
    if terminal_count != 1 || reconstructed != *final_task {
        return Err(A2AError::invalid_agent_response());
    }
    Ok(())
}

fn receiver_request_is_valid(request: &MeshRequest, payload_bytes: usize) -> bool {
    payload_bytes <= 1_048_576
        && !request.protocol.is_empty()
        && request.protocol.len() <= 4096
        && !request.task_id.is_empty()
        && request.task_id.len() <= 4096
        && !request.context_id.is_empty()
        && request.context_id.len() <= 4096
        && request.text.len() <= 1_048_576
}

fn decode_receiver_termination(
    kind: Option<&str>,
    payload: Option<&str>,
) -> Result<DurableReceiverTermination, A2AError> {
    match (kind, payload) {
        (Some("success"), None) => Ok(DurableReceiverTermination::Success),
        (Some(expected @ ("input_required" | "auth_required")), Some(encoded))
            if encoded.len() <= 4096 =>
        {
            let termination: DurableReceiverTermination = serde_json::from_str(encoded)
                .map_err(|_| A2AError::internal("receiver termination is corrupt"))?;
            let actual = match &termination {
                DurableReceiverTermination::InputRequired { message } if !message.is_empty() => {
                    "input_required"
                }
                DurableReceiverTermination::AuthRequired { message } if !message.is_empty() => {
                    "auth_required"
                }
                _ => return Err(A2AError::internal("receiver termination is corrupt")),
            };
            if actual != expected {
                return Err(A2AError::internal("receiver termination is corrupt"));
            }
            Ok(termination)
        }
        _ => Err(A2AError::internal("receiver termination is corrupt")),
    }
}

fn validate_snapshot_request(request: &ListTasksRequest) -> Result<(i32, String), A2AError> {
    if request
        .history_length
        .is_some_and(|length| !(0..=100).contains(&length))
    {
        return Err(A2AError::invalid_params(
            "historyLength must be between 0 and 100",
        ));
    }
    let page_size = request.page_size.unwrap_or(50);
    if !(1..=100).contains(&page_size) {
        return Err(A2AError::invalid_params(
            "pageSize must be between 1 and 100",
        ));
    }
    let encoded = serde_json::to_vec(&serde_json::json!({
        "contextId": request.context_id,
        "status": request.status,
        "pageSize": page_size,
        "historyLength": request.history_length,
        "statusTimestampAfter": request.status_timestamp_after,
        "includeArtifacts": request.include_artifacts.unwrap_or(false),
        "projectionVersion": 1,
    }))
    .map_err(|_| A2AError::internal("failed to normalize task-list request"))?;
    Ok((page_size, content_digest(&encoded)))
}

fn project_snapshot_task(mut task: Task, request: &ListTasksRequest) -> Task {
    if !request.include_artifacts.unwrap_or(false) {
        task.artifacts = None;
    }
    let length = request
        .history_length
        .and_then(|value| usize::try_from(value).ok());
    if length == Some(0) {
        task.history = None;
    } else if let (Some(limit), Some(history)) = (length, task.history.as_mut())
        && history.len() > limit
    {
        history.drain(..history.len() - limit);
    }
    task
}

fn mac_field(mac: &mut Hmac<Sha256>, bytes: &[u8]) {
    mac.update(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    mac.update(bytes);
}

#[allow(clippy::too_many_arguments)]
fn snapshot_metadata_digest(
    key: &[u8; 32],
    snapshot_id: &[u8],
    scope: &str,
    query: &str,
    total: i64,
    page: i64,
    issued: i64,
    expires: i64,
    projection: i64,
    frozen_bytes: i64,
    entries: &[(i64, String, i64, String)],
) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts 32-byte keys");
    mac.update(b"smesh-list-snapshot-metadata-v1\0");
    mac_field(&mut mac, snapshot_id);
    mac_field(&mut mac, scope.as_bytes());
    mac_field(&mut mac, query.as_bytes());
    for value in [
        total,
        page,
        issued,
        expires,
        projection,
        frozen_bytes,
        PAGE_TOKEN_VERSION,
        PAGE_TOKEN_KEY_GENERATION,
    ] {
        mac.update(&value.to_be_bytes());
    }
    for (ordinal, id, revision, digest) in entries {
        mac.update(&ordinal.to_be_bytes());
        mac_field(&mut mac, id.as_bytes());
        mac.update(&revision.to_be_bytes());
        mac_field(&mut mac, digest.as_bytes());
    }
    mac.finalize().into_bytes().into()
}

fn derive_page_token(
    key: &[u8; 32],
    snapshot_id: &[u8],
    position: i64,
    metadata: &[u8; 32],
) -> Result<(String, [u8; 32]), A2AError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| A2AError::internal("page-token derivation failed"))?;
    mac.update(b"smesh-list-tasks-page-v1\0");
    mac.update(&PAGE_TOKEN_VERSION.to_be_bytes());
    mac.update(&PAGE_TOKEN_KEY_GENERATION.to_be_bytes());
    mac_field(&mut mac, snapshot_id);
    mac.update(&position.to_be_bytes());
    mac.update(metadata);
    let raw: [u8; 32] = mac.finalize().into_bytes().into();
    Ok((URL_SAFE_NO_PAD.encode(raw), Sha256::digest(raw).into()))
}

fn decode_page_token_hash(token: &str) -> Result<[u8; 32], A2AError> {
    if token.len() > MAX_PAGE_TOKEN_BYTES {
        return Err(A2AError::invalid_params("invalid pageToken"));
    }
    let raw = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| A2AError::invalid_params("invalid pageToken"))?;
    if raw.len() != 32 {
        return Err(A2AError::invalid_params("invalid pageToken"));
    }
    Ok(Sha256::digest(raw).into())
}

impl crate::IntoDurableAuthority for PostgresTaskStore {
    fn into_durable_authority(self) -> Arc<dyn crate::DurableAuthority> {
        Arc::new(self)
    }
}

impl AuthorityIdentity for PostgresTaskStore {
    fn capabilities(&self) -> AuthorityCapabilities {
        AuthorityCapabilities {
            lease_renewal: true,
            quota_reservations: true,
        }
    }

    fn completion_receipt_key(&self) -> Option<[u8; 32]> {
        Some(*self.receipt_key)
    }
    fn authorization_resource_digest(&self, resource: &str) -> Result<String, A2AError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.cursor_key.as_slice())
            .map_err(|_| A2AError::internal("resource key is invalid"))?;
        mac.update(b"smesh-authorization-resource-v1\0");
        mac.update(resource.as_bytes());
        Ok(content_digest(&mac.finalize().into_bytes()))
    }
}
impl ChangeObserver for PostgresTaskStore {
    fn change_observation(&self) -> ChangeObservation {
        self.observation
    }
}

#[async_trait]
impl AuthorizationAuditSink for PostgresTaskStore {
    async fn append_denied_authorization_decision(
        &self,
        audit: AuthorizationAuditInput,
    ) -> Result<(), A2AError> {
        if audit.effect() != AuthorizationDecisionEffect::Deny {
            return Err(A2AError::invalid_request(
                "denied audit must contain a deny decision",
            ));
        }
        self.append_authorization_decision(audit).await
    }
    async fn append_authorization_decision(
        &self,
        audit: AuthorizationAuditInput,
    ) -> Result<(), A2AError> {
        let tenant = audit.tenant_scope().to_owned();
        let account = audit.actor_account_id().to_owned();
        self.run_retryable_transaction(&tenant, Some(&account), |store, tx| {
            let audit = audit.clone();
            let tenant = tenant.clone();
            Box::pin(async move {
                store.insert_audit(tx, audit).await?;
                store.ensure_capacity(tx, &tenant).await
            })
        })
        .await
    }
}

#[async_trait]
impl TaskAdmission for PostgresTaskStore {
    async fn replay_authorized(
        &self,
        scope: &OwnedTaskScope,
        actor: &str,
        request: &SendMessageRequest,
        streaming: bool,
        audit: AuthorizationAuditInput,
    ) -> Result<Option<SendMessageResponse>, A2AError> {
        if audit.tenant_scope() != scope.tenant_scope()
            || audit.actor_account_id() != actor
            || actor != scope.owner_account_id()
            || audit.effect() != AuthorizationDecisionEffect::Allow
        {
            return Err(A2AError::invalid_request(
                "authorized replay scope mismatch",
            ));
        }
        let storage =
            authorized_message_identity(scope.tenant_scope(), actor, &request.message.message_id);
        let digest =
            canonical_send_message_digest_v2(scope.tenant_scope(), actor, request, streaming)?;
        let tenant = scope.tenant_scope().to_owned();
        let account = scope.owner_account_id().to_owned();
        let own = scope.visibility() == VisibilityScope::Own;
        self.run_retryable_transaction(&tenant, Some(&account), |store, tx| {
            let tenant = tenant.clone();
            let account = account.clone();
            let storage = storage.clone();
            let digest = digest.clone();
            let audit = audit.clone();
            Box::pin(async move {
        let sql=store.q("SELECT i.request_digest,i.admission_result_json,i.final_result_json FROM __S__.idempotency_records i JOIN __S__.tasks t ON t.tenant_scope=i.tenant_scope AND t.task_id=i.task_id WHERE i.tenant_scope=$1 AND i.message_id=$2 AND ($3::boolean=false OR t.owner_account_id=$4)");
        let row = tx
            .query_opt(
                &sql,
                &[
                    &tenant,
                    &storage,
                    &own,
                    &account,
                ],
            )
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("authorized replay lookup failed")))?;
        let Some(row) = row else { return Ok(None) };
        let stored: String = row.get(0);
        if stored != digest {
            return Err(A2AError::invalid_request(
                "idempotency key is already bound to different request semantics",
            ));
        }
        let admission: String = row.get(1);
        let final_json: Option<String> = row.get(2);
        let result = serde_json::from_str(final_json.as_deref().unwrap_or(&admission))
            .map_err(|_| A2AError::internal("stored idempotency result is corrupt"))?;
        store.insert_audit(
            tx,
            audit.decided(
                AuthorizationDecisionEffect::Allow,
                "idempotent_replay",
                None,
            ),
        )
        .await?;
                Ok(Some(result))
            })
        })
        .await
    }

    async fn authorize_and_admit(
        &self,
        scope: &OwnedTaskScope,
        command: SendMessageAdmission,
        audit: AuthorizationAuditInput,
    ) -> Result<AdmissionOutcome, A2AError> {
        self.authorize_and_admit_mutation(scope, AuthorizedMutation::without_quota(command), audit)
            .await
    }

    async fn authorize_and_continue(
        &self,
        scope: &OwnedTaskScope,
        command: SendMessageAdmission,
        audit: AuthorizationAuditInput,
    ) -> Result<AdmissionOutcome, A2AError> {
        self.authorize_and_continue_mutation(
            scope,
            AuthorizedMutation::without_quota(command),
            audit,
        )
        .await
    }

    async fn authorize_and_admit_mutation(
        &self,
        scope: &OwnedTaskScope,
        mutation: AuthorizedMutation<SendMessageAdmission>,
        audit: AuthorizationAuditInput,
    ) -> Result<AdmissionOutcome, A2AError> {
        let (command, quota_reservation) = mutation.into_parts();
        if audit.tenant_scope() != scope.tenant_scope()
            || audit.actor_account_id() != scope.owner_account_id()
            || audit.effect() != AuthorizationDecisionEffect::Allow
        {
            return Err(A2AError::invalid_request(
                "authorized admission scope mismatch",
            ));
        }
        let history_ok =
            command.task.history.as_deref() == Some(std::slice::from_ref(&command.request.message));
        if !history_ok || command.task.status.state != a2a::TaskState::Submitted {
            return Err(A2AError::invalid_params(
                "admission task and result must exactly match the canonical request",
            ));
        }
        let raw = &command.request.message.message_id;
        if raw.is_empty() {
            return Err(A2AError::invalid_params(
                "messageId is required for durable admission",
            ));
        }
        let tenant = scope.tenant_scope().to_owned();
        let owner = scope.owner_account_id().to_owned();
        let message_id = authorized_message_identity(&tenant, &owner, raw);
        let request_digest =
            canonical_send_message_digest_v2(&tenant, &owner, &command.request, command.streaming)?;
        let dispatch = MeshRequest::from_a2a(
            command.task.id.clone(),
            command.task.context_id.clone(),
            &command.request.message,
            command.input_limits,
        )
        .map_err(|e| A2AError::invalid_params(e.to_string()))?;
        let payload_json = serde_json::to_string(&dispatch)
            .map_err(|_| A2AError::internal("failed to encode outbox payload"))?;
        let payload_digest = content_digest(payload_json.as_bytes());
        let task_json = serde_json::to_string(&command.task)
            .map_err(|_| A2AError::internal("failed to encode task"))?;
        let result_json = serde_json::to_string(&command.original_result)
            .map_err(|_| A2AError::internal("failed to encode admission result"))?;
        let request_json = serde_json::to_string(&command.request)
            .map_err(|_| A2AError::internal("failed to encode causative request"))?;
        if task_json.len() > 1_048_576
            || result_json.len() > 1_048_576
            || payload_json.len() > 1_048_576
        {
            return Err(A2AError::invalid_params(
                "durable admission payload exceeds limit",
            ));
        }
        let state = state_key(&command.task)?;
        let timestamp = command.task.status.timestamp.map(|v| v.to_rfc3339());
        let dispatch_id =
            content_digest(format!("{tenant}\0send-message\0{message_id}").as_bytes());
        self.run_retryable_transaction(&tenant, Some(&owner), |store, tx| {
            let command = command.clone();
            let audit = audit.clone();
            let tenant = tenant.clone();
            let owner = owner.clone();
            let message_id = message_id.clone();
            let request_digest = request_digest.clone();
            let payload_json = payload_json.clone();
            let payload_digest = payload_digest.clone();
            let task_json = task_json.clone();
            let result_json = result_json.clone();
            let request_json = request_json.clone();
            let state = state.clone();
            let timestamp = timestamp.clone();
            let dispatch_id = dispatch_id.clone();
            let quota_reservation = quota_reservation.clone();
            Box::pin(async move {
        let quota_now = store.effective_now(tx, command.now).await?;
        tx.query_one("SELECT pg_advisory_xact_lock(6001136200063)", &[])
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("admission capacity lock failed")))?;
        let existing_sql=store.q("SELECT request_digest,admission_result_json,final_result_json,task_id FROM __S__.idempotency_records WHERE tenant_scope=$1 AND message_id=$2 FOR UPDATE");
        if let Some(row) = tx
            .query_opt(&existing_sql, &[&tenant, &message_id])
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("idempotency lookup failed")))?
        {
            let stored: String = row.get(0);
            let admission: String = row.get(1);
            let final_json: Option<String> = row.get(2);
            let stored_task_id: String = row.get(3);
            if stored != request_digest {
                return Err(A2AError::invalid_request(
                    "idempotency key is already bound to different request or admission semantics",
                ));
            }
            store.insert_quota_reservation(tx, quota_reservation.as_ref(), &tenant, &owner, &stored_task_id, quota_now, false).await?;
            return serde_json::from_str(final_json.as_deref().unwrap_or(&admission))
                .map(AdmissionOutcome::Replay)
                .map_err(|_| A2AError::internal("stored idempotency result is corrupt"));
        }
        let max_attempts = i64::from(command.max_attempts);
        if !(1..=1000).contains(&max_attempts) {
            return Err(A2AError::invalid_params("invalid durable admission"));
        }
        let count_sql = store.q("SELECT count(*) FROM __S__.tasks WHERE tenant_scope=$1");
        let count: i64 = tx
            .query_one(&count_sql, &[&tenant])
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("task capacity check failed")))?
            .get(0);
        if usize::try_from(count).unwrap_or(usize::MAX) >= store.max_tasks {
            return Err(A2AError::internal("task capacity reached"));
        }
        let tasks=store.q("INSERT INTO __S__.tasks(tenant_scope,task_id,context_id,state,status_timestamp,revision,task_json,owner_account_id) VALUES($1,$2,$3,$4,$5,1,$6,$7)");
        tx.execute(
            &tasks,
            &[
                &tenant,
                &command.task.id,
                &command.task.context_id,
                &state,
                &timestamp,
                &task_json,
                &owner,
            ],
        )
        .await
        .map_err(|error| {
            Self::transaction_body_error(&error, A2AError::invalid_request("task already exists"))
        })?;
        store.insert_quota_reservation(tx, quota_reservation.as_ref(), &tenant, &owner, &command.task.id, quota_now, true).await?;
        let event=store.q("INSERT INTO __S__.task_events(tenant_scope,task_id,event_seq,task_revision,event_kind,from_state,to_state,event_json,created_at) VALUES($1,$2,1,1,'admitted',NULL,$3,$4,$5)");
        tx.execute(
            &event,
            &[&tenant, &command.task.id, &state, &task_json, &command.now],
        )
        .await
        .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("atomic event append failed")))?;
        let idem=store.q("INSERT INTO __S__.idempotency_records(tenant_scope,message_id,request_digest,task_id,state,admission_result_json,created_at,updated_at,digest_version,actor_account_id,causative_request_json,invocation_kind) VALUES($1,$2,$3,$4,'in_progress',$5,$6,$6,2,$7,$8,$9)");
        let invocation = if command.streaming {
            "streaming"
        } else {
            "unary"
        };
        tx.execute(
            &idem,
            &[
                &tenant,
                &message_id,
                &request_digest,
                &command.task.id,
                &result_json,
                &command.now,
                &owner,
                &request_json,
                &invocation,
            ],
        )
        .await
        .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("idempotency reservation failed")))?;
        let outbox=store.q("INSERT INTO __S__.outbox(dispatch_id,tenant_scope,task_id,message_id,causative_revision,payload_json,payload_digest,state,max_attempts,available_at,created_at,updated_at,dispatch_identity_version) VALUES($1,$2,$3,$4,1,$5,$6,'pending',$7,$8,$8,$8,2)");
        tx.execute(
            &outbox,
            &[
                &dispatch_id,
                &tenant,
                &command.task.id,
                &message_id,
                &payload_json,
                &payload_digest,
                &max_attempts,
                &command.now,
            ],
        )
        .await
        .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("atomic outbox enqueue failed")))?;
        if command.streaming {
            let initial = StreamResponse::Task(command.task.clone());
            let json = serde_json::to_string(&initial)
                .map_err(|_| A2AError::internal("failed to encode stream frame"))?;
            let digest = transcript_digest(std::slice::from_ref(&initial))?;
            let transcript=store.q("INSERT INTO __S__.stream_transcripts(tenant_scope,message_id,dispatch_id,task_id,transcript_version,state,frame_count,transcript_digest,created_at,updated_at) VALUES($1,$2,$3,$4,1,'open',1,$5,$6,$6)");
            tx.execute(
                &transcript,
                &[
                    &tenant,
                    &message_id,
                    &dispatch_id,
                    &command.task.id,
                    &digest,
                    &command.now,
                ],
            )
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("stream transcript admission failed")))?;
            let frame=store.q("INSERT INTO __S__.stream_frames(tenant_scope,message_id,frame_seq,frame_version,frame_kind,frame_json,frame_digest,created_at) VALUES($1,$2,1,1,'task',$3,$4,$5)");
            tx.execute(
                &frame,
                &[
                    &tenant,
                    &message_id,
                    &json,
                    &content_digest(json.as_bytes()),
                    &command.now,
                ],
            )
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("initial stream frame append failed")))?;
        }
        store.insert_audit(
            tx,
            audit.decided(
                AuthorizationDecisionEffect::Allow,
                "admission_committed",
                None,
            ),
        )
        .await?;
        store.ensure_capacity(tx, &tenant).await?;
                Ok(AdmissionOutcome::Admitted(AdmissionRecord {
                    task_id: command.task.id,
                    revision: 1,
                    dispatch_id,
                }))
            })
        })
        .await
    }

    async fn authorize_and_continue_mutation(
        &self,
        scope: &OwnedTaskScope,
        mutation: AuthorizedMutation<SendMessageAdmission>,
        audit: AuthorizationAuditInput,
    ) -> Result<AdmissionOutcome, A2AError> {
        let (command, quota_reservation) = mutation.into_parts();
        if audit.tenant_scope() != scope.tenant_scope()
            || audit.actor_account_id() != scope.owner_account_id()
            || audit.effect() != AuthorizationDecisionEffect::Allow
        {
            return Err(A2AError::invalid_request(
                "authorized continuation scope mismatch",
            ));
        }
        let raw = &command.request.message.message_id;
        let result_matches = matches!(&command.original_result,SendMessageResponse::Task(task) if task==&command.task);
        if raw.is_empty()
            || raw.len() > 4096
            || !(1..=1000).contains(&command.max_attempts)
            || !result_matches
            || command
                .request
                .message
                .task_id
                .as_deref()
                .is_some_and(|id| id != command.task.id)
            || command
                .request
                .message
                .context_id
                .as_deref()
                .is_some_and(|id| id != command.task.context_id)
        {
            return Err(A2AError::invalid_params("invalid durable continuation"));
        }
        let tenant = scope.tenant_scope().to_owned();
        let owner = scope.owner_account_id().to_owned();
        let message_id = authorized_message_identity(&tenant, &owner, raw);
        let digest =
            canonical_send_message_digest_v2(&tenant, &owner, &command.request, command.streaming)?;
        let dispatch_id =
            content_digest(format!("{tenant}\0send-message\0{message_id}").as_bytes());
        let request_json = serde_json::to_string(&command.request)
            .map_err(|_| A2AError::internal("failed to encode causative request"))?;
        let own = scope.visibility() == VisibilityScope::Own;
        self.run_retryable_transaction(&tenant, Some(&owner), |store, tx| {
            let command = command.clone();
            let audit = audit.clone();
            let tenant = tenant.clone();
            let owner = owner.clone();
            let message_id = message_id.clone();
            let digest = digest.clone();
            let dispatch_id = dispatch_id.clone();
            let request_json = request_json.clone();
            let quota_reservation = quota_reservation.clone();
            Box::pin(async move {
        let quota_now = store.effective_now(tx, command.now).await?;
        let existing=store.q("SELECT request_digest,admission_result_json,final_result_json FROM __S__.idempotency_records WHERE tenant_scope=$1 AND message_id=$2 FOR UPDATE");
        if let Some(row) = tx
            .query_opt(&existing, &[&tenant, &message_id])
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("continuation idempotency lookup failed")))?
        {
            if row.get::<_, String>(0) != digest {
                return Err(A2AError::invalid_request(
                    "idempotency key is already bound to different request or continuation semantics",
                ));
            }
            let admission: String = row.get(1);
            let final_json: Option<String> = row.get(2);
            store.insert_quota_reservation(tx, quota_reservation.as_ref(), &tenant, &owner, &command.task.id, quota_now, false).await?;
            let replay = serde_json::from_str(final_json.as_deref().unwrap_or(&admission))
                .map_err(|_| A2AError::internal("stored continuation result is corrupt"))?;
            store.insert_audit(
                tx,
                audit.decided(
                    AuthorizationDecisionEffect::Allow,
                    "continuation_replay",
                    None,
                ),
            )
            .await?;
            return Ok(AdmissionOutcome::Replay(replay));
        }
        let lookup=store.q("SELECT task_json,state,revision,context_id FROM __S__.tasks WHERE tenant_scope=$1 AND task_id=$2 AND ($3::boolean=false OR owner_account_id=$4) FOR UPDATE");
        let row = tx
            .query_opt(&lookup, &[&tenant, &command.task.id, &own, &owner])
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("continuation task lookup failed")))?
            .ok_or_else(|| A2AError::task_not_found(&command.task.id))?;
        store.insert_quota_reservation(tx, quota_reservation.as_ref(), &tenant, &owner, &command.task.id, quota_now, true).await?;
        let durable_json: String = row.get(0);
        let old_state: String = row.get(1);
        let revision: i64 = row.get(2);
        let context: String = row.get(3);
        if !matches!(
            old_state.as_str(),
            "\"TASK_STATE_INPUT_REQUIRED\"" | "\"TASK_STATE_AUTH_REQUIRED\""
        ) {
            return Err(A2AError::unsupported_operation(
                "task no longer accepts continuation",
            ));
        }
        let mut task: Task = serde_json::from_str(&durable_json)
            .map_err(|_| A2AError::internal("stored task is corrupt"))?;
        if task != command.task || task.context_id != context {
            return Err(A2AError::invalid_params(
                "continuation task identity mismatch",
            ));
        }
        task.history
            .get_or_insert_with(Vec::new)
            .push(command.request.message.clone());
        task.status.state = a2a::TaskState::Working;
        task.status.message = None;
        task.status.timestamp = chrono::DateTime::from_timestamp_millis(command.now);
        let task_json = serde_json::to_string(&task)
            .map_err(|_| A2AError::internal("failed to encode continuation task"))?;
        let result = SendMessageResponse::Task(task.clone());
        let result_json = serde_json::to_string(&result)
            .map_err(|_| A2AError::internal("failed to encode continuation admission"))?;
        let dispatch = MeshRequest::from_a2a(
            task.id.clone(),
            task.context_id.clone(),
            &command.request.message,
            command.input_limits,
        )
        .map_err(|e| A2AError::invalid_params(e.to_string()))?;
        let payload = serde_json::to_string(&dispatch)
            .map_err(|_| A2AError::internal("failed to encode continuation dispatch"))?;
        if task_json.len() > 1_048_576 || result_json.len() > 1_048_576 || payload.len() > 1_048_576
        {
            return Err(A2AError::invalid_params(
                "durable continuation payload exceeds limit",
            ));
        }
        let next = revision
            .checked_add(1)
            .ok_or_else(|| A2AError::internal("persistent task revision exhausted"))?;
        let working = state_key(&task)?;
        let timestamp = task.status.timestamp.map(|v| v.to_rfc3339());
        let update=store.q("UPDATE __S__.tasks SET state=$1,status_timestamp=$2,revision=$3,task_json=$4 WHERE tenant_scope=$5 AND task_id=$6 AND revision=$7 AND state=$8");
        if tx
            .execute(
                &update,
                &[
                    &working, &timestamp, &next, &task_json, &tenant, &task.id, &revision,
                    &old_state,
                ],
            )
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("continuation task update failed")))?
            != 1
        {
            return Err(A2AError::unsupported_operation(
                "task no longer accepts continuation",
            ));
        }
        let event=store.q("INSERT INTO __S__.task_events(tenant_scope,task_id,event_seq,task_revision,event_kind,from_state,to_state,event_json,created_at) SELECT $1,$2,COALESCE(max(event_seq),0)+1,$3,'continued',$4,$5,$6,$7 FROM __S__.task_events WHERE tenant_scope=$1 AND task_id=$2");
        tx.execute(
            &event,
            &[
                &tenant,
                &task.id,
                &next,
                &old_state,
                &working,
                &task_json,
                &command.now,
            ],
        )
        .await
        .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("continuation event append failed")))?;
        let invocation = if command.streaming {
            "streaming"
        } else {
            "unary"
        };
        let idem=store.q("INSERT INTO __S__.idempotency_records(tenant_scope,message_id,request_digest,task_id,state,admission_result_json,created_at,updated_at,digest_version,actor_account_id,causative_request_json,invocation_kind) VALUES($1,$2,$3,$4,'in_progress',$5,$6,$6,2,$7,$8,$9)");
        tx.execute(
            &idem,
            &[
                &tenant,
                &message_id,
                &digest,
                &task.id,
                &result_json,
                &command.now,
                &owner,
                &request_json,
                &invocation,
            ],
        )
        .await
        .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("continuation idempotency reservation failed")))?;
        let outbox=store.q("INSERT INTO __S__.outbox(dispatch_id,tenant_scope,task_id,message_id,causative_revision,payload_json,payload_digest,state,max_attempts,available_at,created_at,updated_at,dispatch_identity_version) VALUES($1,$2,$3,$4,$5,$6,$7,'pending',$8,$9,$9,$9,2)");
        tx.execute(
            &outbox,
            &[
                &dispatch_id,
                &tenant,
                &task.id,
                &message_id,
                &next,
                &payload,
                &content_digest(payload.as_bytes()),
                &i64::from(command.max_attempts),
                &command.now,
            ],
        )
        .await
        .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("continuation outbox enqueue failed")))?;
        if command.streaming {
            let initial = StreamResponse::Task(task.clone());
            let json = serde_json::to_string(&initial)
                .map_err(|_| A2AError::internal("failed to encode continuation stream"))?;
            let transcript=store.q("INSERT INTO __S__.stream_transcripts(tenant_scope,message_id,dispatch_id,task_id,transcript_version,state,frame_count,transcript_digest,created_at,updated_at) VALUES($1,$2,$3,$4,1,'open',1,$5,$6,$6)");
            tx.execute(
                &transcript,
                &[
                    &tenant,
                    &message_id,
                    &dispatch_id,
                    &task.id,
                    &transcript_digest(std::slice::from_ref(&initial))?,
                    &command.now,
                ],
            )
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("continuation stream admission failed")))?;
            let frame = store.q("INSERT INTO __S__.stream_frames VALUES($1,$2,1,1,'task',$3,$4,$5)");
            tx.execute(
                &frame,
                &[
                    &tenant,
                    &message_id,
                    &json,
                    &content_digest(json.as_bytes()),
                    &command.now,
                ],
            )
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("continuation initial stream append failed")))?;
        }
        store.insert_audit(
            tx,
            audit.decided(
                AuthorizationDecisionEffect::Allow,
                "continuation_committed",
                None,
            ),
        )
        .await?;
        store.ensure_capacity(tx, &tenant).await?;
                Ok(AdmissionOutcome::Admitted(AdmissionRecord {
                    task_id: task.id,
                    revision: u64::try_from(next)
                        .map_err(|_| A2AError::internal("task revision corrupt"))?,
                    dispatch_id,
                }))
            })
        })
        .await
    }
}

#[async_trait]
impl AuthorizedTaskRead for PostgresTaskStore {
    async fn get_authorized(
        &self,
        scope: &OwnedTaskScope,
        task_id: &str,
        audit: AuthorizationAuditInput,
    ) -> Result<Option<Task>, A2AError> {
        if audit.tenant_scope() != scope.tenant_scope()
            || audit.actor_account_id() != scope.owner_account_id()
        {
            return Err(A2AError::invalid_request("authorized read scope mismatch"));
        }
        let tenant = scope.tenant_scope().to_owned();
        let account = scope.owner_account_id().to_owned();
        let own = scope.visibility() == VisibilityScope::Own;
        let task_id = task_id.to_owned();
        self.run_retryable_transaction(&tenant, Some(&account), |store, tx| {
            let tenant = tenant.clone();
            let account = account.clone();
            let task_id = task_id.clone();
            let audit = audit.clone();
            Box::pin(async move {
        let sql=store.q("SELECT task_json FROM __S__.tasks WHERE tenant_scope=$1 AND task_id=$2 AND ($3::boolean=false OR owner_account_id=$4)");
        let result = tx
            .query_opt(
                &sql,
                &[
                    &tenant,
                    &task_id,
                    &own,
                    &account,
                ],
            )
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("authorized task lookup failed")))?
            .map(|r| task_from_row(&r))
            .transpose()?;
        let decision = if result.is_some() {
            audit.decided(AuthorizationDecisionEffect::Allow, "visible_resource", None)
        } else {
            audit.decided(
                AuthorizationDecisionEffect::Deny,
                "resource_unavailable",
                None,
            )
        };
        store.insert_audit(tx, decision).await?;
                Ok(result)
            })
        })
        .await
    }
    async fn list_authorized(
        &self,
        scope: &OwnedTaskScope,
        request: &ListTasksRequest,
        audit: AuthorizationAuditInput,
        cursor_scope_digest: &str,
    ) -> Result<ListTasksResponse, A2AError> {
        if audit.tenant_scope() != scope.tenant_scope()
            || audit.actor_account_id() != scope.owner_account_id()
            || audit.effect() != AuthorizationDecisionEffect::Allow
            || cursor_scope_digest.is_empty()
            || cursor_scope_digest.len() > 256
        {
            return Err(A2AError::invalid_request("authorized list scope mismatch"));
        }
        let (page_size, query_digest) = validate_snapshot_request(request)?;
        let size = i64::from(page_size);
        let tenant = scope.tenant_scope().to_owned();
        let owner = scope.owner_account_id().to_owned();
        let own = scope.visibility() == VisibilityScope::Own;

        // Expired snapshots are independently committed so a later capacity
        // failure cannot roll cleanup back. The GC transaction is itself retry-safe.
        let now = self
            .run_retryable_transaction(&tenant, Some(&owner), |store, tx| {
                let tenant = tenant.clone();
                Box::pin(async move {
                    let now_sql = store.q("SELECT __S__.db_millis()");
                    let now: i64 = tx
                        .query_one(&now_sql, &[])
                        .await
                        .map_err(|error| {
                            Self::transaction_body_error(
                                &error,
                                A2AError::internal("task snapshot clock failed"),
                            )
                        })?
                        .get(0);
                    let delete = store.q(
                        "DELETE FROM __S__.list_snapshots WHERE tenant_scope=$1 AND expires_at<=$2",
                    );
                    tx.execute(&delete, &[&tenant, &now])
                        .await
                        .map_err(|error| {
                            Self::transaction_body_error(
                                &error,
                                A2AError::internal("task snapshot cleanup failed"),
                            )
                        })?;
                    Ok(now)
                })
            })
            .await?;

        let cursor_scope_digest = cursor_scope_digest.to_owned();
        let request = request.clone();
        self.run_retryable_transaction(&tenant, Some(&owner), |store, tx| {
            let tenant = tenant.clone();
            let owner = owner.clone();
            let request = request.clone();
            let audit = audit.clone();
            let query_digest = query_digest.clone();
            let cursor_scope_digest = cursor_scope_digest.clone();
            Box::pin(async move {
        let response = if let Some(token) = request.page_token.as_deref().filter(|v| !v.is_empty())
        {
            let hash = decode_page_token_hash(token)?;
            let lookup=store.q("SELECT p.snapshot_id,p.next_position,p.scope_digest,p.query_digest,p.token_version,p.key_generation,p.issued_at,p.expires_at,s.total_size,s.page_size,s.projection_version,s.frozen_bytes,s.metadata_digest,s.owner_account_id FROM __S__.list_page_tokens p JOIN __S__.list_snapshots s ON s.tenant_scope=p.tenant_scope AND s.snapshot_id=p.snapshot_id WHERE p.tenant_scope=$1 AND p.token_hash=$2");
            let row = tx
                .query_opt(&lookup, &[&tenant, &&hash[..]])
                .await
                .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("page-token lookup failed")))?
                .ok_or_else(|| A2AError::invalid_params("invalid pageToken"))?;
            let snapshot: Vec<u8> = row.get(0);
            let position: i64 = row.get(1);
            let stored_scope: String = row.get(2);
            let stored_query: String = row.get(3);
            let version: i64 = row.get(4);
            let generation: i64 = row.get(5);
            let issued: i64 = row.get(6);
            let expires: i64 = row.get(7);
            let total: i64 = row.get(8);
            let stored_page: i64 = row.get(9);
            let projection: i64 = row.get(10);
            let frozen_bytes: i64 = row.get(11);
            let metadata: Vec<u8> = row.get(12);
            let stored_owner: String = row.get(13);
            if stored_scope != cursor_scope_digest
                || stored_query != query_digest
                || stored_owner != owner
                || version != PAGE_TOKEN_VERSION
                || generation != PAGE_TOKEN_KEY_GENERATION
                || issued < 0
                || issued > now
                || issued.checked_add(SNAPSHOT_TTL_MILLIS) != Some(expires)
                || expires <= now
                || position <= 0
                || position >= total
                || position % size != 0
                || stored_page != size
                || projection != 1
                || frozen_bytes < 0
                || metadata.len() != 32
            {
                return Err(A2AError::invalid_params("invalid pageToken"));
            }
            let seals_sql=store.q("SELECT ordinal,task_id,task_revision,task_digest FROM __S__.list_snapshot_entries WHERE tenant_scope=$1 AND snapshot_id=$2 ORDER BY ordinal");
            let seals = tx
                .query(&seals_sql, &[&tenant, &snapshot])
                .await
                .map_err(|error| {
                    Self::transaction_body_error(
                        &error,
                        A2AError::invalid_params("invalid pageToken"),
                    )
                })?
                .iter()
                .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
                .collect::<Vec<_>>();
            if i64::try_from(seals.len()).unwrap_or(i64::MAX) != total
                || seals
                    .iter()
                    .enumerate()
                    .any(|(n, e)| e.0 != i64::try_from(n).unwrap_or(i64::MAX))
            {
                return Err(A2AError::invalid_params("invalid pageToken"));
            }
            let expected = snapshot_metadata_digest(
                &store.cursor_key,
                &snapshot,
                &stored_scope,
                &stored_query,
                total,
                stored_page,
                issued,
                expires,
                projection,
                frozen_bytes,
                &seals,
            );
            if metadata.as_slice() != expected {
                return Err(A2AError::invalid_params("invalid pageToken"));
            }
            let page_sql=store.q("SELECT ordinal,task_id,task_digest,task_json FROM __S__.list_snapshot_entries WHERE tenant_scope=$1 AND snapshot_id=$2 AND ordinal>=$3 ORDER BY ordinal LIMIT $4");
            let rows = tx
                .query(&page_sql, &[&tenant, &snapshot, &position, &size])
                .await
                .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("task snapshot page failed")))?;
            let expected_len = (total - position).min(size);
            if i64::try_from(rows.len()).unwrap_or(i64::MAX) != expected_len {
                return Err(A2AError::invalid_params("invalid pageToken"));
            }
            let mut tasks = Vec::with_capacity(rows.len());
            for (offset, row) in rows.iter().enumerate() {
                let ordinal: i64 = row.get(0);
                let id: String = row.get(1);
                let digest: String = row.get(2);
                let encoded: String = row.get(3);
                if ordinal != position + i64::try_from(offset).unwrap_or(i64::MAX)
                    || digest != content_digest(encoded.as_bytes())
                {
                    return Err(A2AError::invalid_params("invalid pageToken"));
                }
                let task: Task = serde_json::from_str(&encoded)
                    .map_err(|_| A2AError::invalid_params("invalid pageToken"))?;
                if task.id != id {
                    return Err(A2AError::invalid_params("invalid pageToken"));
                }
                tasks.push(task);
            }
            let end = position + i64::try_from(tasks.len()).unwrap_or(i64::MAX);
            let metadata: [u8; 32] = metadata
                .try_into()
                .map_err(|_| A2AError::invalid_params("invalid pageToken"))?;
            let next = if end < total {
                derive_page_token(&store.cursor_key, &snapshot, end, &metadata)?.0
            } else {
                String::new()
            };
            ListTasksResponse {
                tasks,
                next_page_token: next,
                page_size,
                total_size: i32::try_from(total).unwrap_or(i32::MAX),
            }
        } else {
            let context = request.context_id.as_deref();
            let state = request
                .status
                .as_ref()
                .map(|value| serde_json::to_string(value).unwrap_or_default());
            let after = request
                .status_timestamp_after
                .map(|value| value.to_rfc3339());
            let rows = match (own, context, state.as_deref()) {
                (false, None, None) => tx.query(&store.q("SELECT task_id,revision,task_json FROM __S__.tasks WHERE tenant_scope=$1 AND ($2::text IS NULL OR status_timestamp>=$2) ORDER BY status_timestamp DESC NULLS LAST,task_id ASC"), &[&tenant,&after]).await,
                (false, None, Some(state)) => tx.query(&store.q("SELECT task_id,revision,task_json FROM __S__.tasks WHERE tenant_scope=$1 AND state=$2 AND ($3::text IS NULL OR status_timestamp>=$3) ORDER BY status_timestamp DESC NULLS LAST,task_id ASC"), &[&tenant,&state,&after]).await,
                (false, Some(context), None) => tx.query(&store.q("SELECT task_id,revision,task_json FROM __S__.tasks WHERE tenant_scope=$1 AND context_id=$2 AND ($3::text IS NULL OR status_timestamp>=$3) ORDER BY status_timestamp DESC NULLS LAST,task_id ASC"), &[&tenant,&context,&after]).await,
                (false, Some(context), Some(state)) => tx.query(&store.q("SELECT task_id,revision,task_json FROM __S__.tasks WHERE tenant_scope=$1 AND context_id=$2 AND state=$3 AND ($4::text IS NULL OR status_timestamp>=$4) ORDER BY status_timestamp DESC NULLS LAST,task_id ASC"), &[&tenant,&context,&state,&after]).await,
                (true, None, None) => tx.query(&store.q("SELECT task_id,revision,task_json FROM __S__.tasks WHERE tenant_scope=$1 AND owner_account_id=$2 AND ($3::text IS NULL OR status_timestamp>=$3) ORDER BY status_timestamp DESC NULLS LAST,task_id ASC"), &[&tenant,&owner,&after]).await,
                (true, None, Some(state)) => tx.query(&store.q("SELECT task_id,revision,task_json FROM __S__.tasks WHERE tenant_scope=$1 AND owner_account_id=$2 AND state=$3 AND ($4::text IS NULL OR status_timestamp>=$4) ORDER BY status_timestamp DESC NULLS LAST,task_id ASC"), &[&tenant,&owner,&state,&after]).await,
                (true, Some(context), None) => tx.query(&store.q("SELECT task_id,revision,task_json FROM __S__.tasks WHERE tenant_scope=$1 AND owner_account_id=$2 AND context_id=$3 AND ($4::text IS NULL OR status_timestamp>=$4) ORDER BY status_timestamp DESC NULLS LAST,task_id ASC"), &[&tenant,&owner,&context,&after]).await,
                (true, Some(context), Some(state)) => tx.query(&store.q("SELECT task_id,revision,task_json FROM __S__.tasks WHERE tenant_scope=$1 AND owner_account_id=$2 AND context_id=$3 AND state=$4 AND ($5::text IS NULL OR status_timestamp>=$5) ORDER BY status_timestamp DESC NULLS LAST,task_id ASC"), &[&tenant,&owner,&context,&state,&after]).await,
            }.map_err(|error| Self::transaction_body_error(
                &error,
                A2AError::internal("indexed task snapshot query failed"),
            ))?;
            let mut frozen = Vec::with_capacity(rows.len());
            let mut frozen_bytes = 0_i64;
            for row in rows {
                let id: String = row.get(0);
                let revision: i64 = row.get(1);
                let stored: String = row.get(2);
                let task: Task = serde_json::from_str(&stored)
                    .map_err(|_| A2AError::internal("persistent task record is corrupt"))?;
                if task.id != id {
                    return Err(A2AError::internal("persistent task record is corrupt"));
                }
                let task = project_snapshot_task(task, &request);
                let encoded = serde_json::to_string(&task)
                    .map_err(|_| A2AError::internal("task snapshot encoding failed"))?;
                frozen_bytes = frozen_bytes
                    .checked_add(
                        i64::try_from(encoded.len())
                            .map_err(|_| A2AError::internal("task snapshot capacity reached"))?,
                    )
                    .ok_or_else(|| A2AError::internal("task snapshot capacity reached"))?;
                frozen.push((id, revision, encoded, task));
            }
            let total = i64::try_from(frozen.len()).unwrap_or(i64::MAX);
            let first_len = usize::try_from(size).unwrap_or(100).min(frozen.len());
            let tasks = frozen[..first_len]
                .iter()
                .map(|e| e.3.clone())
                .collect::<Vec<_>>();
            if total <= size {
                ListTasksResponse {
                    tasks,
                    next_page_token: String::new(),
                    page_size,
                    total_size: i32::try_from(total).unwrap_or(i32::MAX),
                }
            } else {
                tx.query_one("SELECT pg_advisory_xact_lock(6001136200064)", &[])
                    .await
                    .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("task snapshot capacity lock failed")))?;
                let capacity=store.q("SELECT count(*),COALESCE(sum(frozen_bytes),0)::bigint FROM __S__.list_snapshots WHERE tenant_scope=$1");
                let cap = tx
                    .query_one(&capacity, &[&tenant])
                    .await
                    .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("task snapshot capacity check failed")))?;
                let active: i64 = cap.get(0);
                let bytes: i64 = cap.get(1);
                if active >= MAX_ACTIVE_SNAPSHOTS
                    || bytes.saturating_add(frozen_bytes) > MAX_SNAPSHOT_BYTES
                {
                    return Err(A2AError::internal("task snapshot capacity reached"));
                }
                let snapshot: [u8; 32] = rand::random();
                let expires = now
                    .checked_add(SNAPSHOT_TTL_MILLIS)
                    .ok_or_else(|| A2AError::internal("task snapshot clock exhausted"))?;
                let seals = frozen
                    .iter()
                    .enumerate()
                    .map(|(n, (id, rev, json, _))| {
                        (
                            i64::try_from(n).unwrap_or(i64::MAX),
                            id.clone(),
                            *rev,
                            content_digest(json.as_bytes()),
                        )
                    })
                    .collect::<Vec<_>>();
                let metadata = snapshot_metadata_digest(
                    &store.cursor_key,
                    &snapshot,
                    &cursor_scope_digest,
                    &query_digest,
                    total,
                    size,
                    now,
                    expires,
                    1,
                    frozen_bytes,
                    &seals,
                );
                let insert_snapshot=store.q("INSERT INTO __S__.list_snapshots(tenant_scope,snapshot_id,owner_account_id,scope_digest,query_digest,total_size,page_size,issued_at,expires_at,projection_version,frozen_bytes,metadata_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,1,$10,$11)");
                tx.execute(
                    &insert_snapshot,
                    &[
                        &tenant,
                        &&snapshot[..],
                        &owner,
                        &cursor_scope_digest,
                        &query_digest,
                        &total,
                        &size,
                        &now,
                        &expires,
                        &frozen_bytes,
                        &&metadata[..],
                    ],
                )
                .await
                .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("task snapshot persistence failed")))?;
                let insert_entry=store.q("INSERT INTO __S__.list_snapshot_entries(tenant_scope,snapshot_id,ordinal,task_id,task_revision,task_digest,task_json) VALUES($1,$2,$3,$4,$5,$6,$7)");
                for (n, (id, rev, json, _)) in frozen.iter().enumerate() {
                    let ordinal = i64::try_from(n).unwrap_or(i64::MAX);
                    let digest = content_digest(json.as_bytes());
                    tx.execute(
                        &insert_entry,
                        &[&tenant, &&snapshot[..], &ordinal, id, rev, &digest, json],
                    )
                    .await
                    .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("task snapshot entry persistence failed")))?;
                }
                let insert_token=store.q("INSERT INTO __S__.list_page_tokens(tenant_scope,token_hash,snapshot_id,next_position,scope_digest,query_digest,token_version,key_generation,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,1,1,$7,$8)");
                let mut position = size;
                let mut next = String::new();
                while position < total {
                    let (token, hash) =
                        derive_page_token(&store.cursor_key, &snapshot, position, &metadata)?;
                    tx.execute(
                        &insert_token,
                        &[
                            &tenant,
                            &&hash[..],
                            &&snapshot[..],
                            &position,
                            &cursor_scope_digest,
                            &query_digest,
                            &now,
                            &expires,
                        ],
                    )
                    .await
                    .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("page-token persistence failed")))?;
                    if position == size {
                        next = token;
                    }
                    position = position
                        .checked_add(size)
                        .ok_or_else(|| A2AError::internal("task snapshot position exhausted"))?;
                }
                ListTasksResponse {
                    tasks,
                    next_page_token: next,
                    page_size,
                    total_size: i32::try_from(total).unwrap_or(i32::MAX),
                }
            }
        };
        store.insert_audit(
            tx,
            audit.decided(AuthorizationDecisionEffect::Allow, "visible_set", None),
        )
        .await?;
        store.ensure_capacity(tx, &tenant).await?;
                Ok(response)
            })
        })
        .await
    }
}

#[async_trait]
impl TaskLifecycle for PostgresTaskStore {
    async fn final_result_scoped(
        &self,
        tenant: &str,
        message_id: &str,
    ) -> Result<Option<SendMessageResponse>, A2AError> {
        // ALLOWLIST: read-only consistent final-result lookup; no writes/audit.
        let mut client = self.connection().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|_| A2AError::internal("final result transaction failed"))?;
        self.set_tenant(&tx, tenant, None).await?;
        let sql=self.q("SELECT final_result_json FROM __S__.idempotency_records WHERE tenant_scope=$1 AND message_id=$2 AND state='completed'");
        let row = tx
            .query_opt(&sql, &[&tenant, &message_id])
            .await
            .map_err(|_| A2AError::internal("final result lookup failed"))?;
        tx.commit()
            .await
            .map_err(|_| A2AError::internal("final result commit failed"))?;
        row.map(|r| {
            serde_json::from_str(r.get::<_, &str>(0))
                .map_err(|_| A2AError::internal("stored final result is corrupt"))
        })
        .transpose()
    }
}

#[async_trait]
impl OutboxAuthority for PostgresTaskStore {
    async fn claim_outbox(
        &self,
        lease_owner: &str,
        now: i64,
        lease_duration: i64,
    ) -> Result<Option<OutboxLease>, A2AError> {
        if lease_owner.is_empty() || lease_owner.len() > 4096 || lease_duration <= 0 {
            return Err(A2AError::invalid_params("invalid outbox lease"));
        }
        let token = content_digest(&rand::random::<[u8; 32]>());
        let lease_owner = lease_owner.to_owned();
        // Claiming is intentionally global; the candidate CTE establishes the tenant.
        self.run_retryable_transaction("", None, |store, tx| {
            let lease_owner = lease_owner.clone();
            let token = token.clone();
            Box::pin(async move {
        let now = store.effective_now(tx, now).await?;
        let until = now
            .checked_add(lease_duration)
            .ok_or_else(|| A2AError::invalid_params("outbox lease time overflow"))?;
        let sql=store.q("SELECT tenant_scope,outbox_id,dispatch_id,task_id,attempt_no,max_attempts,payload_json FROM __S__.claim_outbox_bounded($1,$2,$3,$4)");
        let row = tx
            .query_opt(&sql, &[&now, &lease_owner, &token, &until])
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("outbox claim failed")))?;
        let Some(row) = row else {
            store.ensure_all_tenant_capacity(tx).await?;
            return Ok(None);
        };
        let tenant: String = row.get(0);
        let outbox_id: i64 = row.get(1);
        let dispatch_id: String = row.get(2);
        let task_id: String = row.get(3);
        let encoded_attempt_no: i64 = row.get(4);
        let expired_final = encoded_attempt_no < 0;
        let attempt_no = if expired_final {
            encoded_attempt_no
                .checked_neg()
                .ok_or_else(|| A2AError::internal("outbox attempt is corrupt"))?
        } else {
            encoded_attempt_no
        };
        let max_attempts: i64 = row.get(5);
        let payload: String = row.get(6);

        if expired_final {
            store.set_tenant(tx, &tenant, None).await?;
            let final_fence = store.q("SELECT message_id,payload_digest FROM __S__.outbox WHERE tenant_scope=$1 AND outbox_id=$2 AND dispatch_id=$3 AND task_id=$4 AND state='leased' AND lease_owner=$5 AND lease_token=$6 AND lease_until=$7 AND attempt_count=$8 AND max_attempts=$9 FOR UPDATE");
            let Some(fence) = tx.query_opt(&final_fence, &[&tenant, &outbox_id, &dispatch_id, &task_id, &lease_owner, &token, &until, &attempt_no, &max_attempts]).await
                .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("expired final attempt fence failed")))?
            else {
                return Ok(None);
            };
            let message_id: String = fence.get(0);
            let payload_digest: String = fence.get(1);
            let receiver_sql = store.q("SELECT payload_digest,state,lease_until,sender_attempt_no,sender_lease_token FROM __S__.receiver_inbox WHERE tenant_scope=$1 AND dispatch_id=$2 AND task_id=$3 FOR UPDATE");
            let receiver = tx.query_opt(&receiver_sql, &[&tenant, &dispatch_id, &task_id]).await
                .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("final attempt receiver lookup failed")))?;
            if let Some(receiver) = &receiver {
                if receiver.get::<_, String>(0) != payload_digest {
                    return Err(A2AError::internal("receiver dispatch identity is bound to a conflicting payload"));
                }
                let receiver_state: String = receiver.get(1);
                let receiver_until: Option<i64> = receiver.get(2);
                if receiver_state == "processing" && receiver_until.is_some_and(|value| value > now) {
                    store.ensure_capacity(tx, &tenant).await?;
                    return Ok(None);
                }
                if receiver_state == "processing" {
                    let receiver_attempt: i64 = receiver.get(3);
                    let receiver_sender_token: String = receiver.get(4);
                    let receiver_fence = store.q("UPDATE __S__.receiver_inbox SET sender_attempt_no=$1,sender_lease_token=$2 WHERE tenant_scope=$3 AND dispatch_id=$4 AND task_id=$5 AND payload_digest=$6 AND state='processing' AND sender_attempt_no=$7 AND sender_lease_token=$8");
                    if tx.execute(&receiver_fence, &[&attempt_no, &token, &tenant, &dispatch_id, &task_id, &payload_digest, &receiver_attempt, &receiver_sender_token]).await
                        .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("final attempt receiver fence update failed")))? != 1
                    {
                        return Err(A2AError::internal("final attempt receiver fence is stale"));
                    }
                }
                if matches!(receiver_state.as_str(), "processing" | "completed") {
                    store.ensure_capacity(tx, &tenant).await?;
                    let request = serde_json::from_str(&payload)
                        .map_err(|_| A2AError::internal("outbox payload is corrupt"))?;
                    return Ok(Some(OutboxLease {
                        tenant_scope: tenant,
                        outbox_id,
                        dispatch_id,
                        task_id,
                        attempt_no: u32::try_from(attempt_no).map_err(|_| A2AError::internal("outbox attempt is corrupt"))?,
                        max_attempts: u32::try_from(max_attempts).map_err(|_| A2AError::internal("outbox bound is corrupt"))?,
                        lease_owner: lease_owner.clone(),
                        lease_token: token,
                        lease_until: until,
                        request,
                    }));
                }
            }

            let was_terminal = materialize_postgres_dead_letter(
                store,
                tx,
                &tenant,
                &task_id,
                &message_id,
                &dispatch_id,
                FINAL_EXPIRY_ERROR,
                now,
            )
            .await?;
            let attempt = store.q("UPDATE __S__.outbox_attempts SET finished_at=$1,outcome='dead',error=$2,next_attempt_at=NULL WHERE tenant_scope=$3 AND outbox_id=$4 AND attempt_no=$5 AND lease_token=$6 AND finished_at IS NULL");
            if tx.execute(&attempt, &[&now, &FINAL_EXPIRY_ERROR, &tenant, &outbox_id, &attempt_no, &token]).await
                .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("expired final attempt close failed")))? != 1
            {
                return Err(A2AError::internal("expired final attempt fence is corrupt"));
            }
            let terminal_state = if was_terminal { "superseded" } else { "dead" };
            let dead = store.q("UPDATE __S__.outbox SET state=$1,lease_owner=NULL,lease_token=NULL,lease_until=NULL,last_error=$2,updated_at=$3 WHERE tenant_scope=$4 AND outbox_id=$5 AND dispatch_id=$6 AND task_id=$7 AND state='leased' AND lease_owner=$8 AND lease_token=$9 AND lease_until=$10 AND attempt_count=$11 AND max_attempts=$12");
            if tx.execute(&dead, &[&terminal_state, &FINAL_EXPIRY_ERROR, &now, &tenant, &outbox_id, &dispatch_id, &task_id, &lease_owner, &token, &until, &attempt_no, &max_attempts]).await
                .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("expired final dead-letter failed")))? != 1
            {
                return Err(A2AError::internal("expired final dead-letter fence is stale"));
            }
            store.ensure_capacity(tx, &tenant).await?;
            return Ok(None);
        }

        store.ensure_all_tenant_capacity(tx).await?;
        let request = serde_json::from_str(&payload)
            .map_err(|_| A2AError::internal("outbox payload is corrupt"))?;
        let lease = OutboxLease {
            tenant_scope: tenant,
            outbox_id,
            dispatch_id,
            task_id,
            attempt_no: u32::try_from(attempt_no)
                .map_err(|_| A2AError::internal("outbox attempt is corrupt"))?,
            max_attempts: u32::try_from(max_attempts)
                .map_err(|_| A2AError::internal("outbox bound is corrupt"))?,
            lease_owner: lease_owner.clone(),
            lease_token: token,
            lease_until: until,
            request,
        };
                Ok(Some(lease))
            })
        })
        .await
    }

    async fn renew_outbox_lease(
        &self,
        lease: &OutboxLease,
        lease_duration: i64,
    ) -> Result<LeaseRenewalOutcome, A2AError> {
        if !(10..=300_000).contains(&lease_duration) {
            return Err(A2AError::invalid_params("invalid outbox renewal duration"));
        }
        let tenant = lease.tenant_scope.clone();
        self.run_retryable_transaction(&tenant, None, |store, tx| {
            let lease = lease.clone();
            Box::pin(async move {
                let now: i64 = tx.query_one(&store.q("SELECT __S__.db_millis()"), &[]).await
                    .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("lease database clock failed")))?.get(0);
                let until = now.checked_add(lease_duration)
                    .ok_or_else(|| A2AError::invalid_params("outbox renewal time overflow"))?;
                let sql = store.q("UPDATE __S__.outbox SET lease_until=$1,updated_at=$2 WHERE tenant_scope=$3 AND outbox_id=$4 AND dispatch_id=$5 AND task_id=$6 AND state='leased' AND lease_owner=$7 AND lease_token=$8 AND attempt_count=$9 AND max_attempts=$10 AND lease_until=$11 AND lease_until>$2");
                let changed = tx.execute(&sql, &[&until, &now, &lease.tenant_scope, &lease.outbox_id, &lease.dispatch_id, &lease.task_id, &lease.lease_owner, &lease.lease_token, &i64::from(lease.attempt_no), &i64::from(lease.max_attempts), &lease.lease_until]).await
                    .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("outbox lease renewal failed")))?;
                Ok(if changed == 1 { LeaseRenewalOutcome::Applied { lease_until: until } } else { LeaseRenewalOutcome::Stale })
            })
        }).await
    }

    async fn task_for_outbox(&self, lease: &OutboxLease) -> Result<Option<Task>, A2AError> {
        // ALLOWLIST: read-only task/lease snapshot; no serialization writes.
        let mut client = self.connection().await?;
        let tx = client.transaction().await.map_err(|error| {
            Self::transaction_body_error(
                &error,
                A2AError::internal("outbox task transaction failed"),
            )
        })?;
        self.set_tenant(&tx, &lease.tenant_scope, None).await?;
        let sql=self.q("SELECT t.task_json FROM __S__.tasks t JOIN __S__.outbox o ON o.tenant_scope=t.tenant_scope AND o.task_id=t.task_id WHERE o.tenant_scope=$1 AND o.outbox_id=$2 AND o.dispatch_id=$3 AND o.lease_token=$4");
        let row = tx
            .query_opt(
                &sql,
                &[
                    &lease.tenant_scope,
                    &lease.outbox_id,
                    &lease.dispatch_id,
                    &lease.lease_token,
                ],
            )
            .await
            .map_err(|error| {
                Self::transaction_body_error(
                    &error,
                    A2AError::internal("outbox task lookup failed"),
                )
            })?;
        tx.commit().await.map_err(|error| {
            Self::transaction_body_error(&error, A2AError::internal("outbox task commit failed"))
        })?;
        row.map(|r| task_from_row(&r)).transpose()
    }
    async fn finish_outbox_attempt(
        &self,
        lease: &OutboxLease,
        disposition: AttemptDisposition,
        now: i64,
    ) -> Result<TransitionOutcome, A2AError> {
        let tenant = lease.tenant_scope.clone();
        self.run_retryable_transaction(&tenant, None, |store, tx| {
            let lease = lease.clone();
            let disposition = disposition.clone();
            Box::pin(async move {
        let now = store.effective_now(tx, now).await?;
        let fence = store.q("SELECT message_id,payload_digest FROM __S__.outbox WHERE tenant_scope=$1 AND outbox_id=$2 AND dispatch_id=$3 AND task_id=$4 AND state='leased' AND lease_owner=$5 AND lease_token=$6 AND lease_until=$7 AND attempt_count=$8 AND max_attempts=$9 AND lease_until>$10 FOR UPDATE");
        let Some(row) = tx.query_opt(&fence, &[&lease.tenant_scope, &lease.outbox_id, &lease.dispatch_id, &lease.task_id, &lease.lease_owner, &lease.lease_token, &lease.lease_until, &i64::from(lease.attempt_no), &i64::from(lease.max_attempts), &now]).await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("outbox fence lookup failed")))?
        else { return Ok(TransitionOutcome::Stale); };
        let message_id: String = row.get(0);
        let payload_digest: String = row.get(1);
        let cancellation: bool = tx.query_one(
            &store.q("SELECT EXISTS(SELECT 1 FROM __S__.cancellation_intents WHERE tenant_scope=$1 AND dispatch_id=$2 AND task_id=$3 AND state='requested')"),
            &[&lease.tenant_scope, &lease.dispatch_id, &lease.task_id],
        ).await.map_err(|error| Self::transaction_body_error(&error, A2AError::internal("outbox cancellation arbitration failed")))?.get(0);
        if cancellation { return Ok(TransitionOutcome::Stale); }
        let exhausted = lease.attempt_no >= lease.max_attempts;
        let dead = exhausted || matches!(disposition, AttemptDisposition::Permanent { .. });
        let (available, error) = match disposition {
            AttemptDisposition::Retry { available_at, error } => (Some(available_at), error),
            AttemptDisposition::Permanent { error } => (None, error),
        };
        if error.len() > 4096 {
            return Err(A2AError::invalid_params("outbox error diagnostic exceeds limit"));
        }
        if dead {
            let receiver = tx.query_opt(
                &store.q("SELECT payload_digest,state FROM __S__.receiver_inbox WHERE tenant_scope=$1 AND dispatch_id=$2 AND task_id=$3 FOR UPDATE"),
                &[&lease.tenant_scope, &lease.dispatch_id, &lease.task_id],
            ).await.map_err(|error| Self::transaction_body_error(&error, A2AError::internal("outbox finish receiver lookup failed")))?;
            if let Some(receiver) = receiver {
                if receiver.get::<_, String>(0) != payload_digest {
                    return Err(A2AError::internal("receiver dispatch identity is bound to a conflicting payload"));
                }
                if matches!(receiver.get::<_, &str>(1), "processing" | "completed") {
                    let token = content_digest(&rand::random::<[u8; 32]>());
                    let update = store.q("UPDATE __S__.outbox SET lease_owner='receiver-reconciliation',lease_token=$1,lease_until=$2,updated_at=$2 WHERE tenant_scope=$3 AND outbox_id=$4 AND lease_token=$5");
                    tx.execute(&update, &[&token, &now, &lease.tenant_scope, &lease.outbox_id, &lease.lease_token]).await
                        .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("outbox finish reconciliation fence failed")))?;
                    let attempt = store.q("UPDATE __S__.outbox_attempts SET lease_token=$1,started_at=$2,finished_at=NULL,outcome=NULL,error=NULL,next_attempt_at=NULL WHERE tenant_scope=$3 AND outbox_id=$4 AND attempt_no=$5 AND finished_at IS NULL");
                    tx.execute(&attempt, &[&token, &now, &lease.tenant_scope, &lease.outbox_id, &i64::from(lease.attempt_no)]).await
                        .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("outbox finish reconciliation attempt failed")))?;
                    let receiver_fence = store.q("UPDATE __S__.receiver_inbox SET sender_lease_token=$1 WHERE tenant_scope=$2 AND dispatch_id=$3 AND task_id=$4 AND sender_attempt_no=$5 AND sender_lease_token=$6");
                    if tx.execute(&receiver_fence, &[&token, &lease.tenant_scope, &lease.dispatch_id, &lease.task_id, &i64::from(lease.attempt_no), &lease.lease_token]).await
                        .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("receiver reconciliation fence update failed")))? != 1
                    {
                        return Err(A2AError::internal("receiver reconciliation fence is stale"));
                    }
                    return Ok(TransitionOutcome::Applied);
                }
            }
        }
        let attempt_outcome = if dead { "dead" } else { "retry" };
        let attempt=store.q("UPDATE __S__.outbox_attempts SET finished_at=$1,outcome=$2,error=$3,next_attempt_at=$4 WHERE tenant_scope=$5 AND outbox_id=$6 AND attempt_no=$7 AND lease_token=$8 AND finished_at IS NULL");
        if tx.execute(&attempt, &[&now, &attempt_outcome, &error, &available, &lease.tenant_scope, &lease.outbox_id, &i64::from(lease.attempt_no), &lease.lease_token]).await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("outbox attempt close failed")))? != 1
        { return Ok(TransitionOutcome::Stale); }
        if !dead {
            let retry = store.q("UPDATE __S__.outbox SET state='pending',available_at=$1,last_error=$2,lease_owner=NULL,lease_token=NULL,lease_until=NULL,updated_at=$3 WHERE tenant_scope=$4 AND outbox_id=$5 AND lease_token=$6");
            if tx.execute(&retry, &[&available, &error, &now, &lease.tenant_scope, &lease.outbox_id, &lease.lease_token]).await
                .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("outbox retry schedule failed")))? != 1
            { return Ok(TransitionOutcome::Stale); }
            return Ok(TransitionOutcome::Applied);
        }
        let was_terminal = materialize_postgres_dead_letter(store, tx, &lease.tenant_scope, &lease.task_id, &message_id, &lease.dispatch_id, &error, now).await?;
        let terminal_state = if was_terminal { "superseded" } else { "dead" };
        let finish = store.q("UPDATE __S__.outbox SET state=$1,last_error=$2,lease_owner=NULL,lease_token=NULL,lease_until=NULL,updated_at=$3 WHERE tenant_scope=$4 AND outbox_id=$5 AND lease_token=$6");
        if tx.execute(&finish, &[&terminal_state, &error, &now, &lease.tenant_scope, &lease.outbox_id, &lease.lease_token]).await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("outbox dead-letter failed")))? != 1
        { return Ok(TransitionOutcome::Stale); }
        Ok(TransitionOutcome::DeadLettered)
            })
        })
        .await
    }
    async fn append_stream_progress(
        &self,
        tenant: &str,
        dispatch: &str,
        frame: StreamResponse,
        now: i64,
    ) -> Result<Option<StreamResponse>, A2AError> {
        let StreamResponse::StatusUpdate(update) = &frame else {
            return Err(A2AError::invalid_params(
                "invalid durable stream progress frame",
            ));
        };
        if update.status.state != a2a::TaskState::Working
            || update.task_id.is_empty()
            || update.task_id.len() > 4096
            || update.context_id.is_empty()
            || update.context_id.len() > 4096
        {
            return Err(A2AError::invalid_params(
                "invalid durable stream progress frame",
            ));
        }
        let json = serde_json::to_string(&frame)
            .map_err(|_| A2AError::internal("failed to encode stream frame"))?;
        let kind = frame_kind(&frame);
        let tenant = tenant.to_owned();
        let dispatch = dispatch.to_owned();
        self.run_retryable_transaction(&tenant, None, |store, tx| {
            let tenant = tenant.clone();
            let dispatch = dispatch.clone();
            let frame = frame.clone();
            let json = json.clone();
            Box::pin(async move {
        let lookup=store.q("SELECT s.message_id,s.frame_count,s.transcript_digest,t.task_id,t.context_id FROM __S__.stream_transcripts s JOIN __S__.tasks t ON t.tenant_scope=s.tenant_scope AND t.task_id=s.task_id WHERE s.tenant_scope=$1 AND s.dispatch_id=$2 AND s.state='open' FOR UPDATE OF s");
        let Some(row) = tx.query_opt(&lookup, &[&tenant, &dispatch]).await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("stream transcript lookup failed")))?
        else { return Ok(None); };
        let message: String = row.get(0);
        let count: i64 = row.get(1);
        let expected_digest: String = row.get(2);
        if let StreamResponse::StatusUpdate(update) = &frame
            && (update.task_id != row.get::<_, String>(3) || update.context_id != row.get::<_, String>(4))
        {
            return Err(A2AError::invalid_params("invalid durable stream progress frame"));
        }
        let rows=store.q("SELECT frame_seq,frame_version,frame_kind,frame_json,frame_digest FROM __S__.stream_frames WHERE tenant_scope=$1 AND message_id=$2 ORDER BY frame_seq");
        let stored = tx.query(&rows, &[&tenant, &message]).await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("stream transcript digest failed")))?;
        let mut all = Vec::with_capacity(stored.len());
        for (index, stored) in stored.iter().enumerate() {
            let encoded: String = stored.get(3);
            let existing: StreamResponse = serde_json::from_str(&encoded)
                .map_err(|_| A2AError::internal("stored stream frame corrupt"))?;
            if stored.get::<_, i64>(0) != i64::try_from(index + 1).unwrap_or(i64::MAX)
                || stored.get::<_, i64>(1) != 1
                || stored.get::<_, String>(2) != frame_kind(&existing)
                || stored.get::<_, String>(4) != content_digest(encoded.as_bytes())
            {
                return Err(A2AError::internal("stored stream frame corrupt"));
            }
            all.push(existing);
        }
        if i64::try_from(all.len()).ok() != Some(count) || transcript_digest(&all)? != expected_digest {
            return Err(A2AError::internal("stored stream transcript corrupt"));
        }
        if let Some(existing) = all.iter().find(|existing| matches!(existing, StreamResponse::StatusUpdate(update) if update.status.state == a2a::TaskState::Working)) {
            return Ok(Some(existing.clone()));
        }
        all.push(frame.clone());
        let seq = i64::try_from(all.len()).map_err(|_| A2AError::internal("stream progress sequence exhausted"))?;
        let insert = store.q("INSERT INTO __S__.stream_frames VALUES($1,$2,$3,1,$4,$5,$6,$7)");
        tx.execute(&insert, &[&tenant, &message, &seq, &kind, &json, &content_digest(json.as_bytes()), &now]).await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("stream progress append failed")))?;
        let update=store.q("UPDATE __S__.stream_transcripts SET frame_count=$1,transcript_digest=$2,updated_at=$3 WHERE tenant_scope=$4 AND message_id=$5 AND state='open'");
        if tx.execute(&update, &[&seq, &transcript_digest(&all)?, &now, &tenant, &message]).await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("stream progress seal failed")))? != 1
        {
            return Err(A2AError::internal("stale stream progress"));
        }
                Ok(Some(frame))
            })
        })
        .await
    }
    async fn commit_delivery(
        &self,
        lease: &OutboxLease,
        task: Task,
        result: SendMessageResponse,
        public_transcript: &[StreamResponse],
        now: i64,
    ) -> Result<TransitionOutcome, A2AError> {
        if task.id != lease.task_id
            || !is_dispatch_closed(&task.status.state)
            || !final_result_matches_task(&result, &task)
        {
            return Err(A2AError::invalid_params("invalid durable delivery result"));
        }
        validate_terminal_public_transcript(public_transcript, &task)?;
        let transcript_bytes = serde_json::to_vec(public_transcript)
            .map_err(|_| A2AError::internal("failed to encode delivery transcript"))?;
        if transcript_bytes.len() > 64 * 1024 * 1024
            || public_transcript.iter().any(|frame| {
                serde_json::to_vec(frame).map_or(true, |encoded| encoded.len() > 1_048_576)
            })
        {
            return Err(A2AError::invalid_params(
                "public stream transcript exceeds limit",
            ));
        }
        let task_json = serde_json::to_string(&task)
            .map_err(|_| A2AError::internal("failed to encode delivered task"))?;
        let final_json = serde_json::to_string(&result)
            .map_err(|_| A2AError::internal("failed to encode delivery result"))?;
        let state = state_key(&task)?;
        let tenant = lease.tenant_scope.clone();
        let public_transcript = public_transcript.to_vec();
        self.run_retryable_transaction(&tenant, None, |store, tx| {
            let lease = lease.clone();
            let task = task.clone();
            let public_transcript = public_transcript.clone();
            let task_json = task_json.clone();
            let final_json = final_json.clone();
            let state = state.clone();
            Box::pin(async move {
        let now = store.effective_now(tx, now).await?;
        let fence=store.q("SELECT message_id,causative_revision FROM __S__.outbox WHERE tenant_scope=$1 AND outbox_id=$2 AND dispatch_id=$3 AND task_id=$4 AND state='leased' AND lease_owner=$5 AND lease_token=$6 AND lease_until=$7 AND attempt_count=$8 AND max_attempts=$9 AND lease_until>$10 FOR UPDATE");
        let Some(row) = tx
            .query_opt(
                &fence,
                &[
                    &lease.tenant_scope,
                    &lease.outbox_id,
                    &lease.dispatch_id,
                    &lease.task_id,
                    &lease.lease_owner,
                    &lease.lease_token,
                    &lease.lease_until,
                    &i64::from(lease.attempt_no),
                    &i64::from(lease.max_attempts),
                    &now,
                ],
            )
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("delivery fence lookup failed")))?
        else {
            return Ok(TransitionOutcome::Stale);
        };
        let message: String = row.get(0);
        let causative_revision: i64 = row.get(1);
        let revision = causative_revision
            .checked_add(1)
            .ok_or_else(|| A2AError::internal("persistent task revision exhausted"))?;
        let prior_state_sql =
            store.q("SELECT revision,state FROM __S__.tasks WHERE tenant_scope=$1 AND task_id=$2 FOR UPDATE");
        let prior = tx
            .query_one(&prior_state_sql, &[&lease.tenant_scope, &lease.task_id])
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("delivery prior state lookup failed")))?;
        if prior.get::<_, i64>(0) != causative_revision {
            return Ok(TransitionOutcome::Stale);
        }
        let prior_state: String = prior.get(1);
        let update_task=store.q("UPDATE __S__.tasks SET state=$1,status_timestamp=$2,revision=$3,task_json=$4 WHERE tenant_scope=$5 AND task_id=$6");
        let timestamp = task.status.timestamp.map(|v| v.to_rfc3339());
        tx.execute(
            &update_task,
            &[
                &state,
                &timestamp,
                &revision,
                &task_json,
                &lease.tenant_scope,
                &lease.task_id,
            ],
        )
        .await
        .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("delivery task update failed")))?;
        let event=store.q("INSERT INTO __S__.task_events(tenant_scope,task_id,event_seq,task_revision,event_kind,from_state,to_state,event_json,created_at) SELECT $1,$2,COALESCE(max(event_seq),0)+1,$3,'durable_completed',$4,$5,$6,$7 FROM __S__.task_events WHERE tenant_scope=$1 AND task_id=$2");
        tx.execute(
            &event,
            &[
                &lease.tenant_scope,
                &lease.task_id,
                &revision,
                &prior_state,
                &state,
                &task_json,
                &now,
            ],
        )
        .await
        .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("delivery event append failed")))?;
        let idem=store.q("UPDATE __S__.idempotency_records SET state='completed',final_result_json=$1,updated_at=$2 WHERE tenant_scope=$3 AND message_id=$4 AND task_id=$5");
        tx.execute(
            &idem,
            &[
                &final_json,
                &now,
                &lease.tenant_scope,
                &message,
                &lease.task_id,
            ],
        )
        .await
        .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("delivery idempotency update failed")))?;
        let outbox=store.q("UPDATE __S__.outbox SET state='delivered',lease_owner=NULL,lease_token=NULL,lease_until=NULL,updated_at=$1 WHERE tenant_scope=$2 AND outbox_id=$3");
        tx.execute(&outbox, &[&now, &lease.tenant_scope, &lease.outbox_id])
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("delivery outbox update failed")))?;
        let attempt=store.q("UPDATE __S__.outbox_attempts SET finished_at=$1,outcome='delivered' WHERE tenant_scope=$2 AND outbox_id=$3 AND attempt_no=$4");
        tx.execute(
            &attempt,
            &[
                &now,
                &lease.tenant_scope,
                &lease.outbox_id,
                &i64::from(lease.attempt_no),
            ],
        )
        .await
        .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("delivery attempt close failed")))?;
        let lookup=store.q("SELECT frame_count,transcript_digest FROM __S__.stream_transcripts WHERE tenant_scope=$1 AND message_id=$2 AND dispatch_id=$3 AND task_id=$4 AND state='open' FOR UPDATE");
        if let Some(meta) = tx
            .query_opt(&lookup, &[&lease.tenant_scope, &message, &lease.dispatch_id, &lease.task_id])
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("delivery transcript lookup failed")))?
        {
            let persisted_count: i64 = meta.get(0);
            let persisted_digest: String = meta.get(1);
            if persisted_count < 0 || usize::try_from(persisted_count).unwrap_or(usize::MAX) > public_transcript.len() {
                return Err(A2AError::internal("persisted public stream prefix diverges from delivery transcript"));
            }
            let existing_sql = store.q("SELECT frame_seq,frame_version,frame_kind,frame_json,frame_digest FROM __S__.stream_frames WHERE tenant_scope=$1 AND message_id=$2 ORDER BY frame_seq");
            let rows = tx.query(&existing_sql, &[&lease.tenant_scope, &message]).await
                .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("delivery transcript lookup failed")))?;
            let mut persisted = Vec::with_capacity(rows.len());
            for (index, row) in rows.iter().enumerate() {
                let json: String = row.get(3);
                let frame: StreamResponse = serde_json::from_str(&json)
                    .map_err(|_| A2AError::internal("persisted public stream prefix is corrupt"))?;
                if row.get::<_, i64>(0) != i64::try_from(index + 1).unwrap_or(i64::MAX)
                    || row.get::<_, i64>(1) != 1
                    || row.get::<_, String>(2) != frame_kind(&frame)
                    || row.get::<_, String>(4) != content_digest(json.as_bytes())
                {
                    return Err(A2AError::internal("persisted public stream prefix is corrupt"));
                }
                persisted.push(frame);
            }
            if i64::try_from(persisted.len()).ok() != Some(persisted_count)
                || transcript_digest(&persisted)? != persisted_digest
                || persisted != public_transcript[..persisted.len()]
            {
                return Err(A2AError::internal("persisted public stream prefix diverges from delivery transcript"));
            }
            let insert=store.q("INSERT INTO __S__.stream_frames(tenant_scope,message_id,frame_seq,frame_version,frame_kind,frame_json,frame_digest,created_at) VALUES($1,$2,$3,1,$4,$5,$6,$7)");
            for (seq, frame) in public_transcript.iter().enumerate().skip(persisted.len()) {
                let json = serde_json::to_string(frame)
                    .map_err(|_| A2AError::internal("failed to encode delivery frame"))?;
                let n = i64::try_from(seq + 1)
                    .map_err(|_| A2AError::internal("too many delivery frames"))?;
                tx.execute(&insert, &[&lease.tenant_scope, &message, &n, &frame_kind(frame), &json, &content_digest(json.as_bytes()), &now])
                    .await
                    .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("delivery frame append failed")))?;
            }
            let count = i64::try_from(public_transcript.len())
                .map_err(|_| A2AError::internal("too many delivery frames"))?;
            let update=store.q("UPDATE __S__.stream_transcripts SET state='terminal',frame_count=$1,transcript_digest=$2,terminal_seq=$1,updated_at=$3 WHERE tenant_scope=$4 AND message_id=$5 AND state='open'");
            if tx.execute(&update, &[&count, &transcript_digest(&public_transcript)?, &now, &lease.tenant_scope, &message]).await
                .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("delivery transcript seal failed")))? != 1
            {
                return Err(A2AError::internal("stale public stream completion"));
            }
        }
        store.ensure_capacity(tx, &lease.tenant_scope).await?;
                Ok(TransitionOutcome::Applied)
            })
        })
        .await
    }
}

#[async_trait]
impl ReceiverAuthority for PostgresTaskStore {
    async fn begin_receive(
        &self,
        envelope: DurableDispatchEnvelope,
        owner: &str,
        now: i64,
        duration: i64,
    ) -> Result<ReceiverAdmission, A2AError> {
        let payload = serde_json::to_string(&envelope.request)
            .map_err(|_| A2AError::internal("failed to encode receiver payload"))?;
        if envelope.tenant_scope.is_empty()
            || envelope.tenant_scope.len() > 64
            || envelope.dispatch_id.is_empty()
            || envelope.dispatch_id.len() > 256
            || owner.is_empty()
            || owner.len() > 4096
            || duration <= 0
            || !receiver_request_is_valid(&envelope.request, payload.len())
            || content_digest(payload.as_bytes()) != envelope.payload_digest
        {
            return Err(A2AError::invalid_params(
                "invalid durable receiver envelope",
            ));
        }
        let token = content_digest(&rand::random::<[u8; 32]>());
        let tenant = envelope.tenant_scope.clone();
        let owner = owner.to_owned();
        self.run_retryable_transaction(&tenant, None, |store, tx| {
            let envelope = envelope.clone();
            let owner = owner.clone();
            let payload = payload.clone();
            let token = token.clone();
            Box::pin(async move {
        let now = store.effective_now(tx, now).await?;
        let until = now
            .checked_add(duration)
            .ok_or_else(|| A2AError::invalid_params("receiver lease overflow"))?;
        let ownership_sql=store.q("SELECT attempt_count,lease_token FROM __S__.outbox WHERE tenant_scope=$1 AND dispatch_id=$2 AND task_id=$3 AND payload_digest=$4 AND payload_json=$5 AND state='leased' AND lease_token IS NOT NULL FOR UPDATE");
        let Some(sender) = tx.query_opt(&ownership_sql, &[&envelope.tenant_scope, &envelope.dispatch_id, &envelope.request.task_id, &envelope.payload_digest, &payload]).await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("receiver outbox ownership lookup failed")))?
        else {
            return Err(A2AError::invalid_params("invalid durable receiver envelope"));
        };
        let sender_attempt: i64 = sender.get(0);
        let sender_token: String = sender.get(1);
        let lookup=store.q("SELECT payload_digest,state,lease_until,lease_epoch,completion_kind,termination_json,frame_count,transcript_digest FROM __S__.receiver_inbox WHERE tenant_scope=$1 AND dispatch_id=$2 FOR UPDATE");
        if let Some(row) = tx
            .query_opt(&lookup, &[&envelope.tenant_scope, &envelope.dispatch_id])
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("receiver lookup failed")))?
        {
            let digest: String = row.get(0);
            if digest != envelope.payload_digest {
                return Err(A2AError::invalid_request(
                    "dispatch identity is already bound to another payload",
                ));
            }
            let state: String = row.get(1);
            if state == "completed" {
                let frames=store.q("SELECT frame_seq,frame_version,frame_kind,frame_json,frame_digest FROM __S__.receiver_frames WHERE tenant_scope=$1 AND dispatch_id=$2 ORDER BY frame_seq");
                let rows = tx
                    .query(&frames, &[&envelope.tenant_scope, &envelope.dispatch_id])
                    .await
                    .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("receiver replay failed")))?;
                let mut events = Vec::with_capacity(rows.len());
                for (index, frame) in rows.iter().enumerate() {
                    let encoded: String = frame.get(3);
                    if frame.get::<_, i64>(0) != i64::try_from(index + 1).unwrap_or(i64::MAX)
                        || frame.get::<_, i64>(1) != 1
                        || frame.get::<_, String>(2) != "mesh_event"
                        || frame.get::<_, String>(4) != content_digest(encoded.as_bytes())
                    {
                        return Err(A2AError::internal("receiver replay transcript is corrupt"));
                    }
                    events.push(serde_json::from_str::<MeshEvent>(&encoded)
                        .map_err(|_| A2AError::internal("receiver frame corrupt"))?);
                }
                let expected_count: Option<i64> = row.get(6);
                let expected_digest: Option<String> = row.get(7);
                if expected_count != i64::try_from(events.len()).ok()
                    || expected_digest.as_deref() != Some(content_digest(&serde_json::to_vec(&events).map_err(|_| A2AError::internal("receiver replay transcript is corrupt"))?).as_str())
                {
                    return Err(A2AError::internal("receiver replay transcript is corrupt"));
                }
                let termination = decode_receiver_termination(row.get::<_, Option<String>>(4).as_deref(), row.get::<_, Option<String>>(5).as_deref())?;
                return Ok(match termination {
                    DurableReceiverTermination::Success => ReceiverAdmission::Replay(events),
                    termination => ReceiverAdmission::ReplayOutcome(DurableReceiverResult { events, termination }),
                });
            }
            let old_until: Option<i64> = row.get(2);
            if old_until.is_some_and(|v| v > now) {
                return Ok(ReceiverAdmission::Busy);
            }
            let epoch = row.get::<_, i64>(3) + 1;
            let update=store.q("UPDATE __S__.receiver_inbox SET lease_epoch=$1,lease_owner=$2,lease_token=$3,lease_until=$4,updated_at=$5,sender_attempt_no=$6,sender_lease_token=$7 WHERE tenant_scope=$8 AND task_id=$9 AND dispatch_id=$10 AND payload_digest=$11 AND state='processing'");
            tx.execute(
                &update,
                &[
                    &epoch,
                    &owner,
                    &token,
                    &until,
                    &now,
                    &sender_attempt,
                    &sender_token,
                    &envelope.tenant_scope,
                    &envelope.request.task_id,
                    &envelope.dispatch_id,
                    &envelope.payload_digest,
                ],
            )
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("receiver reclaim failed")))?;
            return Ok(ReceiverAdmission::Execute(ReceiverLease {
                tenant_scope: envelope.tenant_scope,
                task_id: envelope.request.task_id,
                dispatch_id: envelope.dispatch_id,
                payload_digest: envelope.payload_digest,
                sender_attempt_no: u32::try_from(sender_attempt)
                    .map_err(|_| A2AError::internal("sender attempt corrupt"))?,
                sender_lease_token: sender_token,
                lease_owner: owner.clone(),
                lease_token: token,
                lease_epoch: u64::try_from(epoch)
                    .map_err(|_| A2AError::internal("receiver epoch corrupt"))?,
                lease_until: until,
            }));
        }
        let insert=store.q("INSERT INTO __S__.receiver_inbox(tenant_scope,dispatch_id,payload_digest,payload_json,task_id,context_id,state,lease_epoch,lease_owner,lease_token,lease_until,accepted_at,updated_at,sender_attempt_no,sender_lease_token) VALUES($1,$2,$3,$4,$5,$6,'processing',1,$7,$8,$9,$10,$10,$11,$12)");
        tx.execute(
            &insert,
            &[
                &envelope.tenant_scope,
                &envelope.dispatch_id,
                &envelope.payload_digest,
                &payload,
                &envelope.request.task_id,
                &envelope.request.context_id,
                &owner,
                &token,
                &until,
                &now,
                &sender_attempt,
                &sender_token,
            ],
        )
        .await
        .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("receiver admission failed")))?;
                Ok(ReceiverAdmission::Execute(ReceiverLease {
            tenant_scope: envelope.tenant_scope,
            task_id: envelope.request.task_id,
            dispatch_id: envelope.dispatch_id,
            payload_digest: envelope.payload_digest,
            sender_attempt_no: u32::try_from(sender_attempt)
                .map_err(|_| A2AError::internal("sender attempt corrupt"))?,
            sender_lease_token: sender_token,
            lease_owner: owner.clone(),
            lease_token: token,
            lease_epoch: 1,
            lease_until: until,
                }))
            })
        })
        .await
    }

    async fn renew_receiver_lease(
        &self,
        lease: &ReceiverLease,
        lease_duration: i64,
    ) -> Result<LeaseRenewalOutcome, A2AError> {
        struct RenewalProbe(Arc<tokio::sync::Notify>);
        impl Drop for RenewalProbe {
            fn drop(&mut self) {
                self.0.notify_one();
            }
        }
        let _probe = self
            .receiver_renewal_test_probe
            .as_ref()
            .map(|(entered, released)| {
                entered.notify_one();
                RenewalProbe(Arc::clone(released))
            });
        if !(10..=300_000).contains(&lease_duration) {
            return Err(A2AError::invalid_params(
                "invalid receiver renewal duration",
            ));
        }
        let tenant = lease.tenant_scope.clone();
        self.run_retryable_transaction(&tenant, None, |store, tx| {
            let lease = lease.clone();
            Box::pin(async move {
                let now: i64 = tx.query_one(&store.q("SELECT __S__.db_millis()"), &[]).await
                    .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("lease database clock failed")))?.get(0);
                let until = now.checked_add(lease_duration)
                    .ok_or_else(|| A2AError::invalid_params("receiver renewal time overflow"))?;
                let epoch = i64::try_from(lease.lease_epoch)
                    .map_err(|_| A2AError::invalid_params("receiver lease epoch overflow"))?;
                let sql = store.q("UPDATE __S__.receiver_inbox SET lease_until=$1,updated_at=$2 WHERE tenant_scope=$3 AND task_id=$4 AND dispatch_id=$5 AND payload_digest=$6 AND sender_attempt_no=$7 AND sender_lease_token=$8 AND state='processing' AND lease_owner=$9 AND lease_token=$10 AND lease_epoch=$11 AND lease_until=$12 AND lease_until>$2");
                let changed = tx.execute(&sql, &[&until, &now, &lease.tenant_scope, &lease.task_id, &lease.dispatch_id, &lease.payload_digest, &i64::from(lease.sender_attempt_no), &lease.sender_lease_token, &lease.lease_owner, &lease.lease_token, &epoch, &lease.lease_until]).await
                    .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("receiver lease renewal failed")))?;
                Ok(if changed == 1 { LeaseRenewalOutcome::Applied { lease_until: until } } else { LeaseRenewalOutcome::Stale })
            })
        }).await
    }

    async fn complete_loopback_receive(
        &self,
        lease: &ReceiverLease,
        events: &[MeshEvent],
        now: i64,
    ) -> Result<(), A2AError> {
        self.complete_receiver(
            lease,
            events,
            DurableReceiverTermination::Success,
            now,
            true,
            false,
        )
        .await
    }
    async fn complete_loopback_outcome(
        &self,
        lease: &ReceiverLease,
        outcome: &DurableReceiverResult,
        now: i64,
    ) -> Result<(), A2AError> {
        self.complete_receiver(
            lease,
            &outcome.events,
            outcome.termination.clone(),
            now,
            true,
            false,
        )
        .await
    }
    async fn complete_canceled_receive(
        &self,
        lease: &ReceiverLease,
        events: &[MeshEvent],
        now: i64,
    ) -> Result<(), A2AError> {
        self.complete_receiver(
            lease,
            events,
            DurableReceiverTermination::Success,
            now,
            false,
            true,
        )
        .await
    }
    async fn cancellation_requested(&self, dispatch: &str) -> Result<bool, A2AError> {
        let dispatch = dispatch.to_owned();
        self.run_retryable_transaction("", None, |store, tx| {
            let dispatch = dispatch.clone();
            Box::pin(async move {
                let sql = store.q("SELECT __S__.cancellation_requested_bounded($1)");
                tx.query_one(&sql, &[&dispatch])
                    .await
                    .map(|row| row.get(0))
                    .map_err(|error| {
                        Self::transaction_body_error(
                            &error,
                            A2AError::internal("cancellation lookup failed"),
                        )
                    })
            })
        })
        .await
    }
}

impl PostgresTaskStore {
    async fn complete_receiver(
        &self,
        lease: &ReceiverLease,
        events: &[MeshEvent],
        termination: DurableReceiverTermination,
        now: i64,
        loopback_effect: bool,
        completion_canceled: bool,
    ) -> Result<(), A2AError> {
        if events.len() > 1024 {
            return Err(A2AError::invalid_params(
                "receiver transcript exceeds limit",
            ));
        }
        let (kind, termination_json) = match &termination {
            DurableReceiverTermination::Success => ("success", None),
            DurableReceiverTermination::InputRequired { message } => {
                if message.is_empty() || message.len() > 4096 {
                    return Err(A2AError::invalid_params("invalid receiver termination"));
                }
                (
                    "input_required",
                    Some(serde_json::to_string(&termination).map_err(|_| {
                        A2AError::internal("failed to encode receiver termination")
                    })?),
                )
            }
            DurableReceiverTermination::AuthRequired { message } => {
                if message.is_empty() || message.len() > 4096 {
                    return Err(A2AError::invalid_params("invalid receiver termination"));
                }
                (
                    "auth_required",
                    Some(serde_json::to_string(&termination).map_err(|_| {
                        A2AError::internal("failed to encode receiver termination")
                    })?),
                )
            }
        };
        let encoded = events
            .iter()
            .map(|event| {
                serde_json::to_string(event)
                    .map_err(|_| A2AError::internal("failed to encode receiver event"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if encoded.iter().any(|frame| frame.len() > 1_048_576) {
            return Err(A2AError::invalid_params(
                "receiver transcript exceeds limit",
            ));
        }
        let transcript =
            serde_json::to_vec(events).map_err(|_| A2AError::internal("receiver digest failed"))?;
        if transcript.len() > 64 * 1024 * 1024 {
            return Err(A2AError::invalid_params(
                "receiver transcript exceeds byte limit",
            ));
        }
        let tenant = lease.tenant_scope.clone();
        self.run_retryable_transaction(&tenant, None, |store, tx| {
            let lease = lease.clone();
            let encoded = encoded.clone();
            let transcript = transcript.clone();
            let termination_json = termination_json.clone();
            Box::pin(async move {
        let now = store.effective_now(tx, now).await?;
        let fence=store.q("SELECT 1 FROM __S__.receiver_inbox WHERE tenant_scope=$1 AND task_id=$2 AND dispatch_id=$3 AND payload_digest=$4 AND sender_attempt_no=$5 AND sender_lease_token=$6 AND state='processing' AND lease_owner=$7 AND lease_token=$8 AND lease_epoch=$9 AND lease_until=$10 AND lease_until>$11 AND (EXISTS(SELECT 1 FROM __S__.cancellation_intents c WHERE c.tenant_scope=$1 AND c.dispatch_id=$3 AND c.state='requested'))=$12 FOR UPDATE");
        if tx
            .query_opt(
                &fence,
                &[
                    &lease.tenant_scope,
                    &lease.task_id,
                    &lease.dispatch_id,
                    &lease.payload_digest,
                    &i64::from(lease.sender_attempt_no),
                    &lease.sender_lease_token,
                    &lease.lease_owner,
                    &lease.lease_token,
                    &i64::try_from(lease.lease_epoch).unwrap_or(i64::MAX),
                    &lease.lease_until,
                    &now,
                    &completion_canceled,
                ],
            )
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("receiver fence lookup failed")))?
            .is_none()
        {
            return Err(A2AError::invalid_request("receiver lease is stale"));
        }
        if completion_canceled {
            let cancel=store.q("UPDATE __S__.cancellation_intents SET state='receiver_canceled',completed_at=$1 WHERE tenant_scope=$2 AND dispatch_id=$3 AND state='requested'");
            if tx
                .execute(&cancel, &[&now, &lease.tenant_scope, &lease.dispatch_id])
                .await
                .map_err(|error| {
                    Self::transaction_body_error(
                        &error,
                        A2AError::internal(
                            "receiver cancellation transcript arbitration failed",
                        ),
                    )
                })?
                != 1
            {
                return Err(A2AError::invalid_request("receiver lease is stale"));
            }
        }
        if loopback_effect {
            let effect = store.q("INSERT INTO __S__.loopback_effects VALUES($1,$2,'accepted',$3)");
            tx.execute(&effect, &[&lease.tenant_scope, &lease.dispatch_id, &now])
                .await
                .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("receiver effect commit failed")))?;
        }
        let insert =
            store.q("INSERT INTO __S__.receiver_frames VALUES($1,$2,$3,1,'mesh_event',$4,$5,$6)");
        for (seq, json) in encoded.iter().enumerate() {
            let n = i64::try_from(seq + 1)
                .map_err(|_| A2AError::internal("too many receiver frames"))?;
            tx.execute(
                &insert,
                &[
                    &lease.tenant_scope,
                    &lease.dispatch_id,
                    &n,
                    json,
                    &content_digest(json.as_bytes()),
                    &now,
                ],
            )
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("receiver frame append failed")))?;
        }
        let count = i64::try_from(encoded.len())
            .map_err(|_| A2AError::internal("too many receiver frames"))?;
        let digest = content_digest(&transcript);
        let update=store.q("UPDATE __S__.receiver_inbox SET state='completed',completion_kind=$1,termination_json=$2,frame_count=$3,transcript_digest=$4,completed_at=$5,updated_at=$5,lease_owner=NULL,lease_token=NULL,lease_until=NULL WHERE tenant_scope=$6 AND dispatch_id=$7 AND state='processing' AND lease_token=$8 AND lease_epoch=$9");
        if tx
            .execute(
                &update,
                &[
                    &kind,
                    &termination_json,
                    &count,
                    &digest,
                    &now,
                    &lease.tenant_scope,
                    &lease.dispatch_id,
                    &lease.lease_token,
                    &i64::try_from(lease.lease_epoch).unwrap_or(i64::MAX),
                ],
            )
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("receiver completion failed")))?
            != 1
        {
            return Err(A2AError::invalid_request("receiver lease is stale"));
        }
        store.ensure_capacity(tx, &lease.tenant_scope).await?;
                Ok(())
            })
        })
        .await
    }
}

#[async_trait]
impl TranscriptAuthority for PostgresTaskStore {
    async fn stream_frames_after_scoped(
        &self,
        tenant: &str,
        message: &str,
        last: usize,
    ) -> Result<StreamTranscriptBatch, A2AError> {
        // ALLOWLIST: read-only transcript snapshot; no serialization writes.
        let mut client = self.connection().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|_| A2AError::internal("stream read transaction failed"))?;
        self.set_tenant(&tx, tenant, None).await?;
        let meta=self.q("SELECT state,frame_count,transcript_digest,terminal_seq,interruption_error FROM __S__.stream_transcripts WHERE tenant_scope=$1 AND message_id=$2");
        let Some(row) = tx
            .query_opt(&meta, &[&tenant, &message])
            .await
            .map_err(|_| A2AError::internal("stream transcript lookup failed"))?
        else {
            return Err(A2AError::invalid_request(
                "message identity is not bound to a streaming request",
            ));
        };
        let state: String = row.get(0);
        let count: i64 = row.get(1);
        let expected_digest: Option<String> = row.get(2);
        let terminal_seq: Option<i64> = row.get(3);
        let interruption: Option<String> = row.get(4);
        if count < 0
            || usize::try_from(count).unwrap_or(usize::MAX) > 1024
            || expected_digest.is_none()
            || !matches!(state.as_str(), "open" | "terminal" | "interrupted")
            || (state == "terminal") != (terminal_seq == Some(count))
            || (state == "interrupted") != interruption.is_some()
        {
            return Err(A2AError::internal("stream transcript is corrupt"));
        }
        let query=self.q("SELECT frame_seq,frame_version,frame_kind,frame_json,frame_digest FROM __S__.stream_frames WHERE tenant_scope=$1 AND message_id=$2 ORDER BY frame_seq");
        let rows = tx
            .query(&query, &[&tenant, &message])
            .await
            .map_err(|_| A2AError::internal("stream frames lookup failed"))?;
        let mut all = Vec::with_capacity(rows.len());
        for (index, stored) in rows.iter().enumerate() {
            let encoded: String = stored.get(3);
            let frame: StreamResponse = serde_json::from_str(&encoded)
                .map_err(|_| A2AError::internal("stored stream frame corrupt"))?;
            if stored.get::<_, i64>(0) != i64::try_from(index + 1).unwrap_or(i64::MAX)
                || stored.get::<_, i64>(1) != 1
                || stored.get::<_, String>(2) != frame_kind(&frame)
                || stored.get::<_, String>(4) != content_digest(encoded.as_bytes())
            {
                return Err(A2AError::internal("stored stream frame corrupt"));
            }
            all.push(frame);
        }
        if i64::try_from(all.len()).ok() != Some(count)
            || expected_digest.as_deref() != Some(transcript_digest(&all)?.as_str())
            || last > all.len()
        {
            return Err(A2AError::internal("stream replay cursor is corrupt"));
        }
        if state == "terminal" {
            let final_sql=self.q("SELECT i.final_result_json FROM __S__.idempotency_records i WHERE i.tenant_scope=$1 AND i.message_id=$2 AND i.state='completed'");
            let encoded: String = tx
                .query_one(&final_sql, &[&tenant, &message])
                .await
                .map_err(|_| A2AError::internal("canonical stream result is corrupt"))?
                .get(0);
            let SendMessageResponse::Task(final_task) =
                serde_json::from_str::<SendMessageResponse>(&encoded)
                    .map_err(|_| A2AError::internal("canonical stream result is corrupt"))?
            else {
                return Err(A2AError::internal("canonical stream result is corrupt"));
            };
            validate_terminal_public_transcript(&all, &final_task)
                .map_err(|_| A2AError::internal("public stream terminal transcript is corrupt"))?;
        }
        let frames = all.into_iter().skip(last).collect();
        tx.commit()
            .await
            .map_err(|_| A2AError::internal("stream read commit failed"))?;
        Ok(StreamTranscriptBatch {
            frames,
            closed: state != "open",
            interruption,
        })
    }
    async fn subscription_snapshot_authorized(
        &self,
        scope: &OwnedTaskScope,
        task_id: &str,
    ) -> Result<Option<(Task, SubscriptionCursor)>, A2AError> {
        // ALLOWLIST: read-only subscription snapshot; no serialization writes.
        let mut client = self.connection().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|_| A2AError::internal("subscription transaction failed"))?;
        self.set_tenant(&tx, scope.tenant_scope(), Some(scope.owner_account_id()))
            .await?;
        let own = scope.visibility() == VisibilityScope::Own;
        let sql=self.q("SELECT t.task_json,t.revision,s.message_id,s.frame_count,s.transcript_digest FROM __S__.tasks t LEFT JOIN __S__.stream_transcripts s ON s.tenant_scope=t.tenant_scope AND s.task_id=t.task_id AND s.state='open' WHERE t.tenant_scope=$1 AND t.task_id=$2 AND ($3::boolean=false OR t.owner_account_id=$4)");
        let row = tx
            .query_opt(
                &sql,
                &[
                    &scope.tenant_scope(),
                    &task_id,
                    &own,
                    &scope.owner_account_id(),
                ],
            )
            .await
            .map_err(|_| A2AError::internal("subscription lookup failed"))?;
        let result = if let Some(row) = row {
            let mut task = task_from_row(&row)?;
            let message: Option<String> = row.get(2);
            let count: Option<i64> = row.get(3);
            let digest: Option<String> = row.get(4);
            let cursor = match (message, count, digest) {
                (Some(message), Some(count), Some(digest)) => {
                    let frames_sql=self.q("SELECT frame_seq,frame_version,frame_kind,frame_json,frame_digest FROM __S__.stream_frames WHERE tenant_scope=$1 AND message_id=$2 ORDER BY frame_seq");
                    let rows = tx
                        .query(&frames_sql, &[&scope.tenant_scope(), &message])
                        .await
                        .map_err(|_| A2AError::internal("subscription transcript lookup failed"))?;
                    let mut frames = Vec::with_capacity(rows.len());
                    for (index, stored) in rows.iter().enumerate() {
                        let encoded: String = stored.get(3);
                        let frame: StreamResponse =
                            serde_json::from_str(&encoded).map_err(|_| {
                                A2AError::internal("subscription transcript is corrupt")
                            })?;
                        if stored.get::<_, i64>(0) != i64::try_from(index + 1).unwrap_or(i64::MAX)
                            || stored.get::<_, i64>(1) != 1
                            || stored.get::<_, String>(2) != frame_kind(&frame)
                            || stored.get::<_, String>(4) != content_digest(encoded.as_bytes())
                        {
                            return Err(A2AError::internal("subscription transcript is corrupt"));
                        }
                        frames.push(frame);
                    }
                    if i64::try_from(frames.len()).ok() != Some(count)
                        || transcript_digest(&frames)? != digest
                    {
                        return Err(A2AError::internal("subscription transcript is corrupt"));
                    }
                    for frame in frames.into_iter().skip(1) {
                        match frame {
                            StreamResponse::StatusUpdate(update) => task.status = update.status,
                            StreamResponse::ArtifactUpdate(update) => task
                                .artifacts
                                .get_or_insert_with(Vec::new)
                                .push(update.artifact),
                            StreamResponse::Task(_) | StreamResponse::Message(_) => {}
                        }
                    }
                    SubscriptionCursor::Transcript {
                        message_id: message,
                        cursor: usize::try_from(count)
                            .map_err(|_| A2AError::internal("subscription cursor is corrupt"))?,
                    }
                }
                (None, None, None) => SubscriptionCursor::TaskRevision(
                    u64::try_from(row.get::<_, i64>(1))
                        .map_err(|_| A2AError::internal("task revision corrupt"))?,
                ),
                _ => return Err(A2AError::internal("subscription cursor is corrupt")),
            };
            Some((task, cursor))
        } else {
            None
        };
        tx.commit()
            .await
            .map_err(|_| A2AError::internal("subscription commit failed"))?;
        Ok(result)
    }
    async fn task_events_after_scoped(
        &self,
        scope: &OwnedTaskScope,
        task_id: &str,
        last: u64,
    ) -> Result<TaskEventBatch, A2AError> {
        // ALLOWLIST: read-only event snapshot; no serialization writes.
        let mut client = self.connection().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|_| A2AError::internal("event read transaction failed"))?;
        self.set_tenant(&tx, scope.tenant_scope(), Some(scope.owner_account_id()))
            .await?;
        let own = scope.visibility() == VisibilityScope::Own;
        let sql=self.q("SELECT e.event_json,e.task_revision FROM __S__.task_events e JOIN __S__.tasks t ON t.tenant_scope=e.tenant_scope AND t.task_id=e.task_id WHERE e.tenant_scope=$1 AND e.task_id=$2 AND e.task_revision>$3 AND ($4::boolean=false OR t.owner_account_id=$5) ORDER BY e.task_revision");
        let last = i64::try_from(last).unwrap_or(i64::MAX);
        let rows = tx
            .query(
                &sql,
                &[
                    &scope.tenant_scope(),
                    &task_id,
                    &last,
                    &own,
                    &scope.owner_account_id(),
                ],
            )
            .await
            .map_err(|_| A2AError::internal("event lookup failed"))?;
        let baseline_sql=self.q("SELECT e.event_json FROM __S__.task_events e JOIN __S__.tasks t ON t.tenant_scope=e.tenant_scope AND t.task_id=e.task_id WHERE e.tenant_scope=$1 AND e.task_id=$2 AND e.task_revision<=$3 AND ($4::boolean=false OR t.owner_account_id=$5) ORDER BY e.task_revision DESC LIMIT 1");
        let mut previous = tx
            .query_opt(
                &baseline_sql,
                &[
                    &scope.tenant_scope(),
                    &task_id,
                    &last,
                    &own,
                    &scope.owner_account_id(),
                ],
            )
            .await
            .map_err(|_| A2AError::internal("subscription baseline lookup failed"))?
            .map(|row| {
                serde_json::from_str::<Task>(row.get(0))
                    .map_err(|_| A2AError::internal("subscription baseline task is corrupt"))
            })
            .transpose()?;
        let mut frames = Vec::new();
        let mut revision = last;
        let mut terminal = false;
        for row in &rows {
            let task: Task = serde_json::from_str(row.get(0))
                .map_err(|_| A2AError::internal("stored event corrupt"))?;
            revision = row.get(1);
            let previous_artifacts = previous
                .as_ref()
                .and_then(|task| task.artifacts.as_deref())
                .unwrap_or_default();
            for artifact in task.artifacts.as_deref().unwrap_or_default() {
                if !previous_artifacts
                    .iter()
                    .any(|existing| existing.artifact_id == artifact.artifact_id)
                {
                    frames.push(StreamResponse::ArtifactUpdate(
                        a2a::TaskArtifactUpdateEvent {
                            task_id: task.id.clone(),
                            context_id: task.context_id.clone(),
                            artifact: artifact.clone(),
                            append: Some(false),
                            last_chunk: Some(true),
                            metadata: None,
                        },
                    ));
                }
            }
            if previous
                .as_ref()
                .is_none_or(|prior| prior.status != task.status)
            {
                frames.push(StreamResponse::StatusUpdate(a2a::TaskStatusUpdateEvent {
                    task_id: task.id.clone(),
                    context_id: task.context_id.clone(),
                    status: task.status.clone(),
                    metadata: None,
                }));
            }
            terminal = task.status.state.is_terminal();
            previous = Some(task);
        }
        tx.commit()
            .await
            .map_err(|_| A2AError::internal("event read commit failed"))?;
        Ok(TaskEventBatch {
            frames,
            closed: terminal,
            last_revision: u64::try_from(revision).unwrap_or(u64::MAX),
        })
    }
}

#[async_trait]
impl CancellationAuthority for PostgresTaskStore {
    async fn cancel_authorized(
        &self,
        scope: &OwnedTaskScope,
        task_id: &str,
        now: i64,
        audit: AuthorizationAuditInput,
    ) -> Result<CancellationOutcome, A2AError> {
        self.cancel_authorized_with_quota(scope, task_id, now, audit, None)
            .await
    }

    async fn cancel_authorized_with_quota(
        &self,
        scope: &OwnedTaskScope,
        task_id: &str,
        now: i64,
        audit: AuthorizationAuditInput,
        quota_reservation: Option<&QuotaReservationInput>,
    ) -> Result<CancellationOutcome, A2AError> {
        if audit.tenant_scope() != scope.tenant_scope()
            || audit.actor_account_id() != scope.owner_account_id()
            || audit.effect() != AuthorizationDecisionEffect::Allow
        {
            return Err(A2AError::invalid_request(
                "authorized cancellation scope mismatch",
            ));
        }
        let tenant = scope.tenant_scope().to_owned();
        let account = scope.owner_account_id().to_owned();
        let own = scope.visibility() == VisibilityScope::Own;
        let task_id = task_id.to_owned();
        let quota_reservation = quota_reservation.cloned();
        self.run_retryable_transaction(&tenant, Some(&account), |store, tx| {
            let tenant = tenant.clone();
            let account = account.clone();
            let task_id = task_id.clone();
            let audit = audit.clone();
            let quota_reservation = quota_reservation.clone();
            Box::pin(async move {
        let now = store.effective_now(tx, now).await?;
        let sql=store.q("SELECT t.task_json,t.revision,i.message_id,o.dispatch_id,o.state FROM __S__.tasks t JOIN __S__.outbox o ON o.tenant_scope=t.tenant_scope AND o.task_id=t.task_id JOIN __S__.idempotency_records i ON i.tenant_scope=o.tenant_scope AND i.message_id=o.message_id AND i.task_id=o.task_id WHERE t.tenant_scope=$1 AND t.task_id=$2 AND ($3::boolean=false OR t.owner_account_id=$4) ORDER BY (o.state IN ('pending','leased','delivered')) DESC,o.outbox_id DESC LIMIT 1 FOR UPDATE OF t,o");
        let row = tx
            .query_opt(
                &sql,
                &[
                    &tenant,
                    &task_id,
                    &own,
                    &account,
                ],
            )
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("cancellation lookup failed")))?
            .ok_or_else(|| A2AError::task_not_found(&task_id))?;
        store.insert_quota_reservation(tx, quota_reservation.as_ref(), &tenant, &account, &task_id, now, true).await?;
        let mut task: Task = serde_json::from_str(row.get::<_, &str>(0))
            .map_err(|_| A2AError::internal("stored task is corrupt"))?;
        let revision: i64 = row.get(1);
        let message_id: String = row.get(2);
        let dispatch: String = row.get(3);
        if task.status.state.is_terminal() {
            return Err(A2AError::task_not_cancelable(&task_id));
        }
        let receiver = store
            .q("SELECT state,lease_until FROM __S__.receiver_inbox WHERE tenant_scope=$1 AND dispatch_id=$2");
        let receiver_state = tx
            .query_opt(&receiver, &[&tenant, &dispatch])
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("cancellation receiver lookup failed")))?
            .map(|r| (r.get::<_, String>(0), r.get::<_, Option<i64>>(1)));
        let active = matches!(
            task.status.state,
            a2a::TaskState::Submitted | a2a::TaskState::Working
        );
        if active
            && receiver_state
                .as_ref()
                .is_some_and(|(state, until)| state == "completed" || until.is_some_and(|v| v > now))
        {
            if receiver_state.as_ref().is_some_and(|(state, until)| {
                state == "processing" && until.is_some_and(|v| v > now)
            }) {
                let insert=store.q("INSERT INTO __S__.cancellation_intents(tenant_scope,dispatch_id,task_id,state,requested_at) VALUES($1,$2,$3,'requested',$4) ON CONFLICT(tenant_scope,dispatch_id) DO NOTHING");
                tx.execute(&insert, &[&tenant, &dispatch, &task_id, &now])
                    .await
                    .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("cancellation intent commit failed")))?;
            }
            store.insert_audit(
                tx,
                audit.decided(
                    AuthorizationDecisionEffect::Allow,
                    "cancellation_requested",
                    None,
                ),
            )
            .await?;
            return Ok(CancellationOutcome::AwaitReceiver {
                dispatch_id: dispatch,
                message_id,
            });
        }
        let previous = state_key(&task)?;
        let mut message = Message::new(Role::Agent, vec![Part::text("SMESH task canceled")]);
        message.message_id = format!("cancel-{}", &content_digest(dispatch.as_bytes())[..32]);
        message.task_id = Some(task.id.clone());
        message.context_id = Some(task.context_id.clone());
        task.status = a2a::TaskStatus {
            state: a2a::TaskState::Canceled,
            message: Some(message),
            timestamp: chrono::DateTime::from_timestamp_millis(now),
        };
        let encoded = serde_json::to_string(&task)
            .map_err(|_| A2AError::internal("failed to encode cancellation task"))?;
        let state = state_key(&task)?;
        let next = revision
            .checked_add(1)
            .ok_or_else(|| A2AError::internal("persistent task revision exhausted"))?;
        let timestamp = task.status.timestamp.map(|v| v.to_rfc3339());
        let update=store.q("UPDATE __S__.tasks SET state=$1,status_timestamp=$2,revision=$3,task_json=$4 WHERE tenant_scope=$5 AND task_id=$6 AND revision=$7 AND state NOT IN ('\"TASK_STATE_COMPLETED\"','\"TASK_STATE_FAILED\"','\"TASK_STATE_CANCELED\"','\"TASK_STATE_REJECTED\"')");
        if tx
            .execute(
                &update,
                &[
                    &state,
                    &timestamp,
                    &next,
                    &encoded,
                    &tenant,
                    &task_id,
                    &revision,
                ],
            )
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("cancellation task commit failed")))?
            != 1
        {
            return Err(A2AError::task_not_cancelable(&task_id));
        }
        let event=store.q("INSERT INTO __S__.task_events(tenant_scope,task_id,event_seq,task_revision,event_kind,from_state,to_state,event_json,created_at) SELECT $1,$2,COALESCE(max(event_seq),0)+1,$3,'durable_canceled',$4,$5,$6,$7 FROM __S__.task_events WHERE tenant_scope=$1 AND task_id=$2");
        tx.execute(
            &event,
            &[
                &tenant,
                &task_id,
                &next,
                &previous,
                &state,
                &encoded,
                &now,
            ],
        )
        .await
        .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("cancellation event append failed")))?;
        let transcript=store.q("SELECT message_id FROM __S__.stream_transcripts WHERE tenant_scope=$1 AND dispatch_id=$2 AND state='open' FOR UPDATE");
        if let Some(meta) = tx
            .query_opt(&transcript, &[&tenant, &dispatch])
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("cancellation stream lookup failed")))?
        {
            let stream_message: String = meta.get(0);
            let rows_sql=store.q("SELECT frame_json FROM __S__.stream_frames WHERE tenant_scope=$1 AND message_id=$2 ORDER BY frame_seq");
            let mut frames = tx
                .query(&rows_sql, &[&tenant, &stream_message])
                .await
                .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("cancellation stream lookup failed")))?
                .iter()
                .map(|r| {
                    serde_json::from_str(r.get::<_, &str>(0))
                        .map_err(|_| A2AError::internal("stored stream frame corrupt"))
                })
                .collect::<Result<Vec<StreamResponse>, _>>()?;
            let terminal = StreamResponse::StatusUpdate(a2a::TaskStatusUpdateEvent {
                task_id: task.id.clone(),
                context_id: task.context_id.clone(),
                status: task.status.clone(),
                metadata: None,
            });
            frames.push(terminal.clone());
            let seq = i64::try_from(frames.len())
                .map_err(|_| A2AError::internal("cancellation stream sequence exhausted"))?;
            let json = serde_json::to_string(&terminal)
                .map_err(|_| A2AError::internal("failed to encode cancellation stream frame"))?;
            let insert = store
                .q("INSERT INTO __S__.stream_frames VALUES($1,$2,$3,1,'status_update',$4,$5,$6)");
            tx.execute(
                &insert,
                &[
                    &tenant,
                    &stream_message,
                    &seq,
                    &json,
                    &content_digest(json.as_bytes()),
                    &now,
                ],
            )
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("cancellation stream append failed")))?;
            let update=store.q("UPDATE __S__.stream_transcripts SET state='terminal',frame_count=$1,transcript_digest=$2,terminal_seq=$1,updated_at=$3 WHERE tenant_scope=$4 AND message_id=$5 AND state='open'");
            tx.execute(
                &update,
                &[
                    &seq,
                    &transcript_digest(&frames)?,
                    &now,
                    &tenant,
                    &stream_message,
                ],
            )
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("cancellation stream completion failed")))?;
        }
        let final_json = serde_json::to_string(&SendMessageResponse::Task(task.clone()))
            .map_err(|_| A2AError::internal("failed to encode cancellation result"))?;
        let idem=store.q("UPDATE __S__.idempotency_records SET state='completed',final_result_json=$1,updated_at=$2 WHERE tenant_scope=$3 AND message_id=$4 AND task_id=$5 AND state='in_progress' AND final_result_json IS NULL");
        tx.execute(
            &idem,
            &[
                &final_json,
                &now,
                &tenant,
                &message_id,
                &task_id,
            ],
        )
        .await
        .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("cancellation replay commit failed")))?;
        let attempts=store.q("UPDATE __S__.outbox_attempts SET finished_at=$1,outcome='superseded' WHERE tenant_scope=$2 AND finished_at IS NULL AND outbox_id=(SELECT outbox_id FROM __S__.outbox WHERE tenant_scope=$2 AND dispatch_id=$3)");
        tx.execute(&attempts, &[&now, &tenant, &dispatch])
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("cancellation attempt close failed")))?;
        let outbox=store.q("UPDATE __S__.outbox SET state='superseded',lease_owner=NULL,lease_token=NULL,lease_until=NULL,updated_at=$1 WHERE tenant_scope=$2 AND dispatch_id=$3 AND state!='dead'");
        tx.execute(&outbox, &[&now, &tenant, &dispatch])
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("cancellation outbox supersede failed")))?;
        store.insert_audit(
            tx,
            audit.decided(
                AuthorizationDecisionEffect::Allow,
                "cancellation_committed",
                None,
            ),
        )
        .await?;
        store.ensure_capacity(tx, &tenant).await?;
                Ok(CancellationOutcome::Canceled(task))
            })
        })
        .await
    }
}

#[async_trait]
impl AuthorityDiagnostics for PostgresTaskStore {
    async fn authorization_decision_count(&self) -> Result<u64, A2AError> {
        let row = self.diagnostics_row().await?;
        Ok(u64::try_from(row.get::<_, i64>(0)).unwrap_or(0))
    }
    async fn atomic_record_counts(&self) -> Result<AtomicRecordCounts, A2AError> {
        let row = self.diagnostics_row().await?;
        Ok(AtomicRecordCounts {
            tasks: u64::try_from(row.get::<_, i64>(1)).unwrap_or(0),
            events: u64::try_from(row.get::<_, i64>(2)).unwrap_or(0),
            idempotency_records: u64::try_from(row.get::<_, i64>(3)).unwrap_or(0),
            outbox: u64::try_from(row.get::<_, i64>(4)).unwrap_or(0),
        })
    }
    async fn durable_effect_count(&self) -> Result<u64, A2AError> {
        let row = self.diagnostics_row().await?;
        Ok(u64::try_from(row.get::<_, i64>(5)).unwrap_or(0))
    }
}

#[async_trait]
impl AuthorityShutdown for PostgresTaskStore {
    async fn shutdown(&self) -> Result<(), A2AError> {
        self.pool.close();
        Ok(())
    }
    fn close_owned_sync(&self) {
        self.pool.close();
    }
}
